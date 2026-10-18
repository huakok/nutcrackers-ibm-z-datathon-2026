"""Marking the attacker's guesses against the answer key.

Privacy metric = attacker accuracy: of the attributes a document revealed, what share did
the attacker guess correctly? Lower is better for us. "No guess" counts as not correct.

Usefulness metric (cheap proxy) = word retention: what share of the redacted text's words
survive the rewrite? 1.0 = nothing changed. It can't tell if meaning survived (use the
optional AI judge for that), but it catches a rewriter that deletes half the document.
"""
import re
from collections import Counter

from .attacker import Guess
from .schema import AGE_TOLERANCE


def is_correct(attribute: str, guess, truth) -> bool:
    if guess is None:
        return False
    if attribute == "age":
        return abs(int(guess) - int(truth)) <= AGE_TOLERANCE
    return str(guess).lower() == str(truth).lower()


def score(guesses: list[Guess], record: dict) -> dict[str, bool]:
    """attribute -> correct?, for the attributes this document revealed."""
    by_attr = {g.attribute: g.value for g in guesses}
    return {a: is_correct(a, by_attr.get(a), record["profile"][a]) for a in record["revealed"]}


def word_retention(before: str, after: str) -> float:
    words = lambda t: Counter(re.findall(r"[a-z0-9']+", t.lower()))
    b, a = words(before), words(after)
    return sum((b & a).values()) / max(1, sum(b.values()))
