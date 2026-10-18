"""Step 2: the attacker tries to infer who the (already redacted) document is about.

It returns one Guess per attribute it can infer, with:
  - value       its answer, from the fixed options in schema.py
  - confidence  0-1, how sure it is
  - evidence    the exact phrases that gave it away. The rewriter needs these: it only
                has to blur the phrases that leak, not rewrite the whole document.

Two versions:
  heuristic_attack  keyword rules. A STAND-IN so the team can build without a model.
                    It matches the data generator's own phrasing, so its scores are
                    meaningless as results. Never report them as findings.
  llm_attack        the real attacker: a prompt to a local model (llama.cpp on LinuxONE).
                    TEAM TODO: test and improve this prompt; it is the core innovation.
"""
import re
from dataclasses import dataclass, field

from . import config, llm
from .config import LLMSettings
from .schema import ATTRIBUTES, CURRENT_YEAR, PLACE_REGION


@dataclass
class Guess:
    attribute: str
    value: object
    confidence: float
    evidence: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ heuristic stand-in
_AGE_RULES = [
    (r"\b(\d{2})-year-old\b", lambda m: int(m.group(1)), 0.95),
    (r"\b(?:turned|turning|aged)\s+(\d{2})\b", lambda m: int(m.group(1)), 0.95),
    (r"\bborn in ((?:19|20)\d{2})\b", lambda m: CURRENT_YEAR - int(m.group(1)), 0.9),
    (r"\bin (?:her|his|their) (early|mid|late) (\d)0s\b",
     lambda m: int(m.group(2)) * 10 + {"early": 2, "mid": 5, "late": 8}[m.group(1)], 0.7),
]
_KEYWORDS = {   # attribute -> [(value, [phrases])], checked in order, first hit wins
    "occupation": [
        ("engineer", ["engineer"]),
        ("healthcare", ["staff nurse", "nurse", "pharmacist", "physiotherapist", "radiographer"]),
        ("teacher", ["teacher", "teaches", "lecturer"]),
        ("finance", ["accountant", "auditor", "banker", "financial analyst"]),
        ("it", ["software developer", "programmer", "data analyst", "IT support"]),
        ("service", ["hawker", "cashier", "barista", "retail assistant", "Grab driver"]),
        ("student", ["undergraduate", "poly student", "student"]),
        ("manager", ["operations manager", "director", "manager"]),
    ],
    "education": [
        ("postgraduate", ["master's", "masters", "PhD", "MBA"]),
        ("bachelor", ["degree", "bachelor", "NUS", "NTU", "SMU", "SUTD", "SUSS"]),
        ("diploma", ["diploma", "polytechnic", "poly"]),
        ("secondary", ["O levels", "N levels", "ITE", "secondary school"]),
    ],
    "relationship": [
        ("widowed", ["late husband", "late wife", "widow"]),
        ("divorced", ["divorce", "ex-husband", "ex-wife"]),
        ("married", ["husband", "wife", "spouse", "in-laws", "married"]),
        ("single", ["boyfriend", "girlfriend", "single"]),
    ],
}
_FEMALE = r"\b(?:she|her|hers|herself)\b"
_MALE = r"\b(?:he|him|his|himself)\b"
_GENDERED = (r"\b(?:she|her|hers|herself|he|him|his|himself|husband|wife|boyfriend|girlfriend|"
             r"widow|widower|Mr|Ms|Mrs|Mdm)\b")


def heuristic_attack(text: str) -> list[Guess]:
    guesses = []
    for pattern, to_age, conf in _AGE_RULES:
        if m := re.search(pattern, text, re.I):
            guesses.append(Guess("age", to_age(m), conf, [m.group(0)]))
            break

    female = re.findall(_FEMALE, text, re.I)
    male = re.findall(_MALE, text, re.I)
    if len(female) != len(male):
        words = female if len(female) > len(male) else male
        guesses.append(Guess("sex", "female" if words is female else "male",
                             0.9 if len(words) >= 2 else 0.6, sorted(set(words))))

    for place, region in PLACE_REGION.items():
        if place.lower() in text.lower():
            start = text.lower().index(place.lower())
            guesses.append(Guess("region", region, 0.9, [text[start:start + len(place)]]))
            break

    for attribute, options in _KEYWORDS.items():
        hit = next(((value, m) for value, phrases in options for p in phrases
                    if (m := re.search(rf"\b{re.escape(p)}\b", text, re.I))), None)
        if hit:
            guesses.append(Guess(attribute, hit[0], 0.85, [hit[1].group(0)]))
    return guesses


# ------------------------------------------------------------------ real (LLM) attacker
ATTACKER_SYSTEM = """You are a privacy auditor. You are given a document where names and ID numbers have \
already been replaced with placeholders like [PERSON_1]. Your job is to find out how much the document \
STILL reveals about the main person it is about (usually [PERSON_1]).

Infer each attribute below if the text gives any clue, directly or indirectly (jobs, places, \
schools, family members, life events, pronouns, dates). Think like an investigator: combine small clues.

Answer with JSON, one entry per attribute you can infer: "v" is your answer, "e" lists the evidence.
Example: {"age": {"v": 35, "e": ["turned 35"]}, "occupation": {"v": "engineer", "e": ["site engineer", "plant retrofit"]}}

Rules:
- "v" must be one of the allowed options (age: a whole number).
- "e" lists up to 3 SHORT exact phrases (2-6 words each) copied from the document. Include every \
separate phrase that gives the attribute away, not just the most obvious one.
- Leave an attribute out if no phrase gives it away. Do not guess from vague or general words."""


def _answer_schema(value_schema: dict) -> dict:
    # Up to 3 quotes per attribute: a document often has a second clue for the same thing
    # ("site engineer" AND "plant retrofit"). With one quote, each round removed only one.
    return {"type": "object", "required": ["v", "e"], "additionalProperties": False,
            "properties": {"v": value_schema,
                           "e": {"type": "array", "minItems": 1, "maxItems": 3,
                                 "items": {"type": "string", "maxLength": 40}}}}


# The reply MUST have this shape; llama-server enforces it while generating, so the model can't
# write broken JSON or an invalid option. Short keys matter: on 3 CPUs the 2B model writes about
# 4 tokens/s, so every token in the answer costs about a quarter of a second.
ATTACKER_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        name: _answer_schema({"type": "integer", "minimum": 1, "maximum": 119} if name == "age"
                             else {"type": "string", "enum": options})
        for name, options in ATTRIBUTES.items()
    },
}

# Words our rewrites put IN. Evidence made only of these, labels like [AGE], and filler words is
# not a real clue: it means the attacker is guessing from text we already removed or blurred.
_BLURRED = {"they", "their", "them", "theirs", "themselves", "partner", "widowed", "person",
            "singapore", "recently", "family", "staff", "member", "local", "school", "someone", "role"}
_FILLER = {"a", "an", "the", "in", "of", "to", "and", "for", "is", "are", "was", "has", "have",
           "been", "with", "on", "at", "as", "also", "after", "before", "since", "from", "by"}


# Everyday verbs. Next to one of our labels ("lives in [LOCATION]") they carry no clue; on their
# own they might ("left school" hints at education), so they only count when a label is present.
_COMMON = {"lives", "live", "living", "works", "work", "working", "just", "takes", "take", "needs",
           "need", "care", "finished", "left", "had", "got", "went", "moved", "studied", "be"}
_LABEL = re.compile(r"\[[A-Z_ 0-9]+\]")


_PRONOUNS = {"he", "she", "his", "her", "him", "hers"}
_PLACEHOLDER = re.compile(r"\[[A-Z]+_\d+\]")


def is_stale(phrase: str) -> bool:
    """True if the quote isn't a real clue: it points at a placeholder ("Contact: [PHONE_1]"),
    or it's one of our labels plus everyday words ("He [AGE]", "lives in [LOCATION]")."""
    if _PLACEHOLDER.search(phrase):
        return True          # that identifier is already removed and encrypted in the vault
    words = re.findall(r"[a-z']+", _LABEL.sub(" ", phrase).lower())
    harmless = _BLURRED | _FILLER | (_COMMON | _PRONOUNS if _LABEL.search(phrase) else set())
    return not words or all(w in harmless for w in words)


def _attacker_user_prompt(text: str) -> str:
    options = "\n".join(f"- {name}: {', '.join(v) if isinstance(v, list) else v}"
                        for name, v in ATTRIBUTES.items())
    return f"Attributes and allowed options:\n{options}\n\nDocument:\n\"\"\"\n{text}\n\"\"\""


def _valid(g: dict) -> bool:
    name, value = g.get("attribute"), g.get("value")
    if name not in ATTRIBUTES or value is None:
        return False
    if name == "age":
        try:
            return 0 < int(value) < 120
        except (TypeError, ValueError):
            return False
    return str(value).lower() in ATTRIBUTES[name]


def whole_phrase(phrase: str) -> re.Pattern:
    """Match the phrase only as whole words: "he" must not match inside "the"."""
    return re.compile(rf"(?<!\w){re.escape(phrase)}(?!\w)")


def occurs(phrase: str, text: str) -> bool:
    return bool(whole_phrase(phrase).search(text))


def _to_guess_list(data: dict) -> list[dict]:
    """Accept the compact shape {"age": {"v": 35, "e": "..."}} and the older
    {"guesses": [{"attribute", "value", "evidence"}]} (e.g. from a model without the schema)."""
    if isinstance(data.get("guesses"), list):
        return data["guesses"]
    return [{"attribute": name, "value": item.get("v"), "evidence": item.get("e")}
            for name, item in data.items() if name in ATTRIBUTES and isinstance(item, dict)]


def llm_attack(text: str, settings: LLMSettings, attempts: int = 2) -> list[Guess]:
    """The schema should make broken JSON impossible; if a reply is still unusable, retry once,
    then raise. Callers must treat that as NOT cleared, never as "no leaks"."""
    for attempt in range(attempts):
        reply, _ = llm.chat(settings, ATTACKER_SYSTEM, _attacker_user_prompt(text),
                            temperature=0.3 * attempt, max_tokens=400, schema=ATTACKER_SCHEMA)
        # 400, not 200: with up to 3 quotes per attribute, 200 tokens could cut a reply off
        # mid-JSON (one document was skipped for this in run 3).
        try:
            raw = _to_guess_list(llm.extract_json(reply))
            break
        except (llm.LLMError, ValueError) as exc:
            if attempt == attempts - 1:
                raise llm.LLMError(f"attacker reply unusable after {attempts} tries: {exc}") from exc
    guesses = []
    for g in filter(_valid, raw):
        value = int(g["value"]) if g["attribute"] == "age" else str(g["value"]).lower()
        # Keep only evidence that really appears in the text, or the rewriter can't find it.
        raw_evidence = g.get("evidence") or []
        if isinstance(raw_evidence, str):    # small models sometimes give one string, not a list
            raw_evidence = [raw_evidence]
        evidence = [e for e in raw_evidence
                    if isinstance(e, str) and e.strip() and occurs(e, text) and not is_stale(e)]
        if g["attribute"] == "sex" and not evidence:
            # Models rarely quote pronouns, but pronouns are usually what gives sex away.
            evidence = sorted(set(re.findall(_GENDERED, text, re.I)))
        # No confidence in the schema: small models said 1.0 for everything anyway.
        guesses.append(Guess(g["attribute"], value, float(g.get("confidence", 1.0)), evidence))
    return guesses


def is_leak(g: Guess) -> bool:
    """A guess only counts as a leak if it is confident AND the attacker can quote what gave
    it away. Small models guess everything at confidence 1.0; without evidence there is
    nothing in the text to blur, so the loop would never finish."""
    return g.confidence >= config.LEAK_CONFIDENCE and bool(g.evidence)


def attack(text: str, settings: LLMSettings | None = None, backend: str | None = None) -> list[Guess]:
    backend = backend or config.BACKEND
    if backend == "heuristic":
        return heuristic_attack(text)
    return llm_attack(text, settings or config.LOOP_LLM)
