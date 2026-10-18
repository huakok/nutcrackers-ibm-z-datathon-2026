"""Step 3: blur the phrases the attacker used, and nothing else.

Minimal edits matter: rewriting the whole document would hide everything but also destroy
its usefulness. We generalise only the leaking clues ("Bukit Batok" -> "in Singapore").

Safety check: an AI rewriter can misbehave (drop a placeholder, or even guess a real name
back in). Every rewrite is checked; if it fails, we fall back to the rule-based rewrite.
"""
import json
import re

from . import config, llm
from .attacker import Guess, occurs, whole_phrase
from .config import LLMSettings
from .detector import detect
from .schema import TAGS
from .vault import PLACEHOLDER_RE

_PRONOUNS = {"she": "they", "he": "they", "her": "their", "his": "their", "him": "them",
             "hers": "theirs", "herself": "themselves", "himself": "themselves",
             "husband": "partner", "wife": "partner", "boyfriend": "partner",
             "girlfriend": "partner", "widow": "widowed person", "widower": "widowed person"}


_THEY_VERBS = {"is": "are", "was": "were", "has": "have", "does": "do", "lives": "live",
               "works": "work", "takes": "take", "needs": "need", "shares": "share", "runs": "run",
               "teaches": "teach", "covers": "cover", "says": "say", "wants": "want", "goes": "go"}


def _neutral_pronouns(text: str) -> str:
    def swap(m):
        word = _PRONOUNS[m.group(0).lower()]
        return word.capitalize() if m.group(0)[0].isupper() else word
    text = re.sub(rf"\b(?:{'|'.join(_PRONOUNS)})\b", swap, text, flags=re.I)
    # "They is" -> "They are", "they lives" -> "they live" (also across "They also ...")
    return re.sub(rf"\b([Tt]hey(?: also| still| just)?) ({'|'.join(_THEY_VERBS)})\b",
                  lambda m: f"{m.group(1)} {_THEY_VERBS[m.group(2)]}", text)


def neutralise_gender(text: str) -> str:
    """Pronouns and gendered family words almost always reveal sex, so remove them up front
    instead of waiting for the attacker to flag them. (In run 2, sex leaked in 50% of
    documents where the loop's attacker never mentioned it.)"""
    return _neutral_pronouns(text)


def suppress_rewrite(text: str, leaks: list[Guess]) -> str:
    """Default: replace exactly the phrases the attacker quoted with a category label
    ("just turned 45" -> "[AGE]"). The detail is guaranteed gone, unlike an AI paraphrase,
    which small models often get wrong ("O levels" -> "completed secondary education")."""
    for g in sorted(leaks, key=lambda g: g.attribute == "sex"):   # pronouns last (see llm_rewrite)
        if g.attribute == "sex":
            text = _neutral_pronouns(text)
            continue
        for phrase in sorted(g.evidence, key=len, reverse=True):
            # Never touch placeholders, and don't wipe out whole sentences: a long quote
            # means the attacker didn't pin down the clue, and replacing it wrecks the text.
            if _ANY_LABEL.search(phrase) or len(phrase.split()) > 8:
                continue
            text = whole_phrase(phrase).sub(TAGS[g.attribute], text)
    return re.sub(r"(\[[A-Z ]+\])(?:\s+\1)+", r"\1", text)    # "[JOB] [JOB]" -> "[JOB]"


_ANY_LABEL = re.compile(r"\[[A-Z_ 0-9]+\]")   # placeholders like [PHONE_1] and labels like [AGE]


heuristic_rewrite = suppress_rewrite   # older name, kept for scripts that use it


REWRITER_SYSTEM = """You protect privacy in documents. Each numbered phrase below gives away a personal \
detail. Write a replacement for each phrase that hides the detail completely.

Your replacement is dropped in EXACTLY where the phrase was, so:
- it must fit the surrounding sentence grammatically;
- do not repeat words that come before or after the phrase;
- remove the specific detail itself (the number, the place name, the job title, the school, \
the family member), not the words around it.

Examples (the phrase -> your replacement):
- "turned 52 in May" -> "had a birthday recently"
- "lives near Holland Village" -> "lives in Singapore"
- "works as a dental nurse" -> "works in a clinic"
- "graduated from SMU in 2019" -> "finished studying"
- "since his wife left" -> "since a family change"

Answer with JSON: {"replacements": ["<replacement 1>", "<replacement 2>", ...]}, one per phrase, \
in the same order. Write plain words only: no numbering, no underscores. Do not add new details."""


def _leaking_phrases(leaks: list[Guess]) -> list[tuple[str, str]]:
    """(attribute, exact phrase) pairs to rewrite. The attacker already gave us exact quotes,
    checked against the document, so the rewriter never has to copy text: it only writes the
    replacement. Small models are bad at copying exactly but fine at rewording."""
    seen, phrases = set(), []
    for g in leaks:
        if g.attribute == "sex":
            continue          # handled by neutral pronouns
        for e in g.evidence:
            if e not in seen and not _ANY_LABEL.search(e):
                seen.add(e)
                phrases.append((g.attribute, e))
    return phrases


def _rewriter_schema(n: int) -> dict:
    """Exactly n replacement strings: the model can't skip one or invent extra ones."""
    return {"type": "object", "required": ["replacements"], "properties": {"replacements": {
        "type": "array", "minItems": n, "maxItems": n, "items": {"type": "string", "maxLength": 80}}}}


def _rewriter_user_prompt(text: str, phrases: list[tuple[str, str]]) -> str:
    # A JSON list, not "1. ...": numbered lists made the model copy the numbers into its answers.
    listed = json.dumps([p for _, p in phrases])
    return f"Document:\n\"\"\"\n{text}\n\"\"\"\n\nPhrases to rewrite (in order):\n{listed}"


def is_safe_rewrite(before: str, after: str) -> bool:
    """Same placeholders survive, and no new direct identifier appeared."""
    if set(PLACEHOLDER_RE.findall(before)) - set(PLACEHOLDER_RE.findall(after)):
        return False
    return not detect(PLACEHOLDER_RE.sub("", after))


def apply_replacements(text: str, phrases: list[str], replacements: list) -> tuple[str, int]:
    """Swap each leaking phrase for its replacement. Returns (text, number applied)."""
    applied = 0
    for old, new in zip(phrases, replacements):
        if not isinstance(new, str):
            continue
        new = re.sub(r"^\s*\d+[.)]\s*", "", new).strip()       # drop copied list numbers
        if new and old[:1].islower():
            new = new[0].lower() + new[1:]                       # keep mid-sentence lowercase
        if new and new != old and occurs(old, text) and not PLACEHOLDER_RE.search(new) and "_" not in new:
            text = whole_phrase(old).sub(lambda _: new, text)
            applied += 1
    return text, applied


def llm_rewrite(text: str, leaks: list[Guess], settings: LLMSettings) -> str:
    """The model only writes short replacements, not the whole document again: far fewer
    words to generate (faster on CPU), and it can't drop a placeholder."""
    new_text = text
    phrases = _leaking_phrases(leaks)
    if phrases:
        reply, _ = llm.chat(settings, REWRITER_SYSTEM, _rewriter_user_prompt(text, phrases),
                            max_tokens=60 * len(phrases) + 40, schema=_rewriter_schema(len(phrases)))
        replacements = llm.extract_json(reply).get("replacements", [])
        new_text, applied = apply_replacements(text, [p for _, p in phrases], replacements)
        if not applied:
            raise llm.LLMError("rewriter returned no usable replacements")
    # Pronouns last: the attacker's quotes contain the original "he"/"her", so swapping
    # pronouns first would stop those quotes from matching the text.
    if any(g.attribute == "sex" for g in leaks):
        new_text = _neutral_pronouns(new_text)
    return new_text


def rewrite(text: str, leaks: list[Guess], settings: LLMSettings | None = None,
            backend: str | None = None) -> tuple[str, bool]:
    """Returns (new text, whether the AI rewrite was used).

    Default (SHIELD_REWRITE_MODE=suppress): replace leaking phrases with labels; no model call.
    SHIELD_REWRITE_MODE=ai: ask the model for natural rewording, falling back to labels if its
    reply is unusable or unsafe."""
    backend = backend or config.BACKEND
    if backend != "heuristic" and config.REWRITE_MODE == "ai":
        try:
            candidate = llm_rewrite(text, leaks, settings or config.REWRITE_LLM)
            if is_safe_rewrite(text, candidate):
                return candidate, True
        except (llm.LLMError, ValueError):   # unusable reply: fall back to labels
            pass
    return suppress_rewrite(text, leaks), False
