"""Step 1b + 5: swap identifiers for placeholders, and restore them in the AI's answer.

Why consistent placeholders instead of blacking out (████)? If "Rachel Tan" becomes
[PERSON_1] everywhere, the outside AI can still reason ("[PERSON_1] asked for leave,
so [PERSON_1]'s manager should...") and we can put the real name back in its answer.

The vault (placeholder -> real value) is the most sensitive thing in the system, so values
are stored encrypted (Fernet = AES-128 + HMAC from the `cryptography` package). On
LinuxONE, OpenSSL-backed AES can use the CPU's built-in crypto instructions (CPACF);
verify on your instance before claiming it.
"""
import re

from . import config
from .detector import Entity, detect

try:
    from cryptography.fernet import Fernet
except ImportError:          # still runs, but say so loudly: values are NOT encrypted
    Fernet = None

_TITLES = {"Mr", "Ms", "Mrs", "Mdm", "Dr", "Miss", "Mr.", "Ms.", "Mrs.", "Dr."}
_CONNECTORS = {"bin", "binte", "s/o", "d/o"}
PLACEHOLDER_RE = re.compile(r"\[[A-Z]+_\d+\]")


def _canonical_name(name: str) -> str:
    return " ".join(w for w in name.split() if w not in _TITLES)


class Vault:
    def __init__(self, key: str | None = None):
        key = key or config.VAULT_KEY
        self.encrypted = Fernet is not None
        if self.encrypted:
            self._fernet = Fernet(key.encode() if key else Fernet.generate_key())
        self._store: dict[str, bytes] = {}      # placeholder -> encrypted real value
        self._lookup: dict[tuple, str] = {}     # (kind, normalised value) -> placeholder
        self._counts: dict[str, int] = {}

    # --- encryption helpers ---
    def _seal(self, value: str) -> bytes:
        return self._fernet.encrypt(value.encode()) if self.encrypted else value.encode()

    def _open(self, token: bytes) -> str:
        return self._fernet.decrypt(token).decode() if self.encrypted else token.decode()

    # --- placeholders ---
    def placeholder_for(self, kind: str, value: str) -> str:
        norm = _canonical_name(value).lower() if kind == "PERSON" else re.sub(r"\s", "", value).lower()
        if (kind, norm) not in self._lookup:
            self._counts[kind] = self._counts.get(kind, 0) + 1
            ph = f"[{kind}_{self._counts[kind]}]"
            self._lookup[(kind, norm)] = ph
            self._store[ph] = self._seal(_canonical_name(value) if kind == "PERSON" else value)
        return self._lookup[(kind, norm)]

    def swap(self, text: str, entities: list[Entity] | None = None) -> str:
        """Replace every detected identifier with its placeholder."""
        entities = detect(text) if entities is None else entities
        out, last = [], 0
        name_parts: dict[str, str] = {}
        for e in entities:
            ph = self.placeholder_for(e.kind, e.text)
            out += [text[last:e.start], ph]
            last = e.end
            if e.kind == "PERSON":    # remember "Rachel" from "Ms Rachel Tan" for later mentions
                for word in e.text.split():
                    if word not in _TITLES and word not in _CONNECTORS and len(word) >= 3:
                        name_parts[word] = ph
        out.append(text[last:])
        result = "".join(out)

        # Second pass: a later "Rachel" on its own should become the same [PERSON_1].
        for word, ph in sorted(name_parts.items(), key=lambda kv: -len(kv[0])):
            result = re.sub(rf"(?<![\w\[]){re.escape(word)}\b(?![\w\]])", ph, result)
        # "Wei Ming" -> "[PERSON_1] [PERSON_1]" -> "[PERSON_1]"
        result = re.sub(r"(\[PERSON_\d+\])(?:\s+\1)+", r"\1", result)
        return result

    def restore(self, text: str) -> str:
        """Put real values back, e.g. into the outside AI's answer."""
        return PLACEHOLDER_RE.sub(lambda m: self._open(self._store[m.group(0)])
                                  if m.group(0) in self._store else m.group(0), text)

    def placeholders(self) -> list[str]:
        return list(self._store)

    def ciphertext_preview(self) -> dict[str, str]:
        """For the demo: show that the vault holds ciphertext, not names."""
        return {ph: tok.decode()[:24] + "..." for ph, tok in self._store.items()}
