"""The whole loop: detect + swap -> attack -> rewrite -> attack again ... -> clean text.

    clean = protect(document)          # everything here runs locally / on LinuxONE
    answer = ask_external(clean.text, "Summarise this")   # only cleaned text leaves
    print(clean.vault.restore(answer))                     # real names come back locally

Every round is recorded, so the demo can show the attacker succeeding, then failing.
"""
import time
from dataclasses import asdict, dataclass, field

from . import config, llm
from .attacker import Guess, attack, is_leak
from .config import LLMSettings
from .rewriter import neutralise_gender, rewrite
from .schema import AGE_TOLERANCE
from .vault import Vault


@dataclass
class Round:
    number: int
    text_before: str
    guesses: list[Guess]
    leaks: list[Guess]          # guesses confident enough to count as a leak
    text_after: str
    used_ai_rewrite: bool
    seconds: float


@dataclass
class Result:
    original: str
    redacted: str               # after step 1 only (what basic tools produce)
    text: str                   # final, attack-tested text
    rounds: list[Round] = field(default_factory=list)
    passed: bool = False        # True if the attacker found no confident leaks at the end
    seconds: float = 0.0
    vault: Vault | None = None
    error: str = ""             # set if the attacker failed; the document is then NOT cleared

    def to_dict(self) -> dict:
        return {
            "original": self.original, "redacted": self.redacted, "text": self.text,
            "rounds": [asdict(r) for r in self.rounds], "passed": self.passed, "error": self.error,
            "seconds": round(self.seconds, 3),
            "placeholders": self.vault.placeholders() if self.vault else [],
        }


def _consistent(g: Guess, earlier: dict) -> bool:
    """The consistency rule. Once we remove the attacker's evidence, a small model often keeps
    "finding" leaks in harmless text, and its answer flips (age 45 -> 30, married -> single).
    A real remaining clue points to the same answer as before; a flipped answer means the
    attacker has lost the trail. Attributes it hasn't mentioned before always count."""
    if g.attribute not in earlier:
        return True
    if g.attribute == "age":
        return abs(int(g.value) - int(earlier["age"])) <= AGE_TOLERANCE
    return g.value == earlier[g.attribute]


def protect(document: str, max_rounds: int | None = None, backend: str | None = None,
            settings: LLMSettings | None = None, vault: Vault | None = None) -> Result:
    max_rounds = config.MAX_ROUNDS if max_rounds is None else max_rounds
    start = time.perf_counter()
    vault = vault or Vault()
    redacted = vault.swap(document)
    result = Result(original=document, redacted=redacted, text=redacted, vault=vault)

    text = neutralise_gender(redacted) if config.NEUTRAL_PRONOUNS else redacted
    earlier: dict[str, object] = {}       # attribute -> what the attacker concluded in earlier rounds
    try:
        for n in range(1, max_rounds + 1):
            t0 = time.perf_counter()
            guesses = attack(text, settings, backend)
            leaks = [g for g in guesses if is_leak(g) and _consistent(g, earlier)]
            for g in leaks:
                earlier.setdefault(g.attribute, g.value)
            if not leaks:
                result.rounds.append(Round(n, text, guesses, [], text, False, time.perf_counter() - t0))
                result.passed = True
                break
            new_text, used_ai = rewrite(text, leaks, None, backend)   # rewriter uses REWRITE_LLM
            result.rounds.append(Round(n, text, guesses, leaks, new_text, used_ai, time.perf_counter() - t0))
            text = new_text
        else:
            # Out of rounds: one last check so we report honestly whether it passed.
            final = [g for g in attack(text, settings, backend) if is_leak(g) and _consistent(g, earlier)]
            result.passed = not final
    except llm.LLMError as exc:
        # Fail safe: if we couldn't attack the document properly, it is NOT cleared.
        result.passed = False
        result.error = str(exc)

    result.text = text
    result.seconds = time.perf_counter() - start
    return result


def ask_external(clean_text: str, question: str, settings: LLMSettings | None = None) -> str:
    """Send ONLY the cleaned text to an outside AI (ChatGPT, Claude, ...).

    Needs EXTERNAL_LLM_BASE_URL, EXTERNAL_LLM_MODEL and EXTERNAL_LLM_API_KEY set by a
    teammate (never hard-code keys). Placeholders are explained so the answer keeps them.
    """
    settings = settings or config.EXTERNAL_LLM
    if not settings.model:
        raise llm.LLMError("Set EXTERNAL_LLM_MODEL (and _BASE_URL, _API_KEY) to use an outside AI.")
    system = ("Some details in the user's document were replaced with placeholders like [PERSON_1]. "
              "Treat them as normal names and keep them exactly as written in your answer.")
    reply, _ = llm.chat(settings, system, f"{question}\n\nDocument:\n{clean_text}", temperature=0.3)
    return reply
