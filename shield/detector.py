"""Step 1a: find DIRECT identifiers (names, NRIC, phone, email, address, bank accounts).

Direct identifiers point to one person on their own. They are the easy part: patterns
and name detection catch most of them. The hard part (job, age, place hints) is what
the attacker loop handles later.

Two layers:
  - Singapore regex rules (always on): NRIC/FIN with check letter, +65 phones,
    emails, postal codes, HDB block addresses, unit numbers.
  - Names: Microsoft Presidio if installed and SHIELD_USE_PRESIDIO=1, otherwise a
    simple rule-based stand-in (titles, greetings, common Singapore surnames,
    bin/binte and s/o/d/o patterns). The stand-in is for development only.
"""
import os
import re
from dataclasses import dataclass

from .schema import PLACE_REGION


@dataclass(frozen=True)
class Entity:
    kind: str   # PERSON, NRIC, PHONE, EMAIL, POSTAL, ADDRESS, UNIT, BANK
    start: int
    end: int
    text: str


# ---------- NRIC / FIN ----------
# Format: prefix letter + 7 digits + check letter. The check letter is computed from the
# digits, so "S1234567A" may LOOK like an NRIC but be invalid. Validating cuts false hits.
_WEIGHTS = [2, 7, 6, 5, 4, 3, 2]
_ST_LETTERS = "JZIHGFEDCBA"   # for S and T prefixes
_FG_LETTERS = "XWUTRQPNMLK"   # for F and G prefixes


def nric_check_letter(prefix: str, digits: str) -> str:
    total = sum(int(d) * w for d, w in zip(digits, _WEIGHTS))
    if prefix in "TG":          # people born / registered from 2000 get an offset of 4
        total += 4
    remainder = total % 11
    return (_ST_LETTERS if prefix in "ST" else _FG_LETTERS)[remainder]


def is_valid_nric(value: str) -> bool:
    value = value.upper()
    if not re.fullmatch(r"[STFGM]\d{7}[A-Z]", value):
        return False
    if value[0] == "M":         # M-series (2022+) uses a different table; accept on format
        return True
    return nric_check_letter(value[0], value[1:8]) == value[8]


# ---------- regex rules ----------
_STREET = r"(?:Avenue|Ave|Street|St|Road|Rd|Drive|Dr|Crescent|Cres|Lane|Ln|Central|Way|Close)"
_RULES = [
    ("EMAIL", r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"),
    ("NRIC", r"\b[STFGM]\d{7}[A-Z]\b"),
    ("PHONE", r"(?:\+65[\s-]?)?\b[689]\d{3}[\s-]?\d{4}\b"),
    ("ADDRESS", rf"\b(?:Blk|Block)\s+\d+[A-Z]?\s+(?:[A-Z][a-z]+\s){{1,3}}{_STREET}(?:\s\d+)?\b"),
    ("UNIT", r"#\d{2}-\d{2,4}\b"),
    ("POSTAL", r"\b(?:Singapore|S)\s?\(?\d{6}\)?"),
    # Bank accounts in typical Singapore dashed formats: 123-45678-9, 123-456789-001, 123-456-789-0
    ("BANK", r"\b\d{3}-(?:\d{5,6}-\d{1,3}|\d{3}-\d{3}-\d)\b"),
    # International bank account numbers (IBAN): country code + 2 check digits + 11-30 characters
    ("BANK", r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b"),
]

# Plain digit runs are only a bank account if a banking word comes just before them;
# otherwise "1234567890" could be an invoice or a tracking number.
_BANK_WORDS = (r"(?:account|acct|a/c|bank|DBS|POSB|OCBC|UOB|Maybank|HSBC|Citibank|"
               r"Standard Chartered|Trust Bank|GXS|savings|current)")
_BANK_CONTEXT = rf"\b{_BANK_WORDS}\b[^\d\n]{{0,30}}?(?:no\.?|number|#)?\s*:?\s*(\d(?:[ -]?\d){{8,15}})\b"

# ---------- names (rule-based stand-in) ----------
_SURNAMES = {
    "Tan", "Lim", "Lee", "Ng", "Ong", "Wong", "Goh", "Chua", "Chan", "Koh", "Teo", "Ang",
    "Yeo", "Tay", "Ho", "Low", "Toh", "Sim", "Chong", "Chia", "Seah", "Foo", "Leong", "Yap",
}
_CAP = r"[A-Z][a-z]+"
_NAME_RULES = [
    # Title + name: "Ms Rachel Tan", "Dr Kumar"
    rf"\b(?:Mr|Ms|Mrs|Mdm|Dr|Miss)\.?\s+{_CAP}(?:\s+{_CAP}){{0,2}}",
    # Malay / Indian naming: "Nurul Aisyah binte Rahman", "Arun s/o Rajan"
    rf"\b{_CAP}(?:\s+{_CAP})?\s+(?:bin|binte|s/o|d/o)\s+{_CAP}",
    # Two or three capitalised words that include a common Singapore surname
    rf"\b{_CAP}(?:\s+{_CAP}){{1,2}}\b",
]
_GREETING = rf"\b(?:Hi|Hello|Dear|Hey|Thanks|Regards|Cheers),?\s+({_CAP})\b"
_NOT_NAMES = {"Singapore", "Team", "All", "Doctor", "Sir", "Madam", "Everyone"}


def _is_place(words: str) -> bool:
    # "Ang Mo Kio" starts with a common surname but is a place, not a person.
    return any(place in words for place in PLACE_REGION) or words in " ".join(PLACE_REGION)


def _rule_names(text: str) -> list[Entity]:
    found = []
    for i, pattern in enumerate(_NAME_RULES):
        for m in re.finditer(pattern, text):
            words = m.group(0).split()
            if i == 2 and (not any(w in _SURNAMES for w in words) or _is_place(m.group(0))):
                continue    # plain capitalised pairs ("Bukit Batok") and place names are not names
            found.append(Entity("PERSON", m.start(), m.end(), m.group(0)))
    for m in re.finditer(_GREETING, text):
        if m.group(1) not in _NOT_NAMES:
            found.append(Entity("PERSON", m.start(1), m.end(1), m.group(1)))
    return found


def _presidio_names(text: str) -> list[Entity]:
    from presidio_analyzer import AnalyzerEngine   # optional dependency
    analyzer = _presidio_names.__dict__.setdefault("engine", AnalyzerEngine())
    results = analyzer.analyze(text=text, entities=["PERSON"], language="en")
    return [Entity("PERSON", r.start, r.end, text[r.start:r.end]) for r in results]


def _use_presidio() -> bool:
    if os.getenv("SHIELD_USE_PRESIDIO") != "1":
        return False
    try:
        import presidio_analyzer  # noqa: F401
        return True
    except ImportError:
        return False


def detect(text: str) -> list[Entity]:
    """Return non-overlapping direct identifiers, longest match wins."""
    candidates = []
    for kind, pattern in _RULES:
        for m in re.finditer(pattern, text):
            if kind == "NRIC" and not is_valid_nric(m.group(0)):
                continue
            candidates.append(Entity(kind, m.start(), m.end(), m.group(0)))
    for m in re.finditer(_BANK_CONTEXT, text, re.I):
        candidates.append(Entity("BANK", m.start(1), m.end(1), m.group(1)))
    candidates +=_presidio_names(text) if _use_presidio() else _rule_names(text)

    # Resolve overlaps: prefer longer spans (e.g. a full address over the street name).
    chosen: list[Entity] = []
    for e in sorted(candidates, key=lambda e: (-(e.end - e.start), e.start)):
        if all(e.end <= c.start or e.start >= c.end for c in chosen):
            chosen.append(e)
    return sorted(chosen, key=lambda e: e.start)
