"""All settings come from environment variables, so the same code runs on a laptop and on LinuxONE.

BACKEND
  heuristic  rule-based stand-ins for the attacker and rewriter (no AI model needed;
             use while building, NOT for final results)
  llm        a real model behind an OpenAI-compatible endpoint
             (llama.cpp's llama-server on LinuxONE, or Ollama on a laptop)
"""
import os
from dataclasses import dataclass


@dataclass
class LLMSettings:
    base_url: str      # e.g. http://localhost:8080/v1 (llama-server) or http://localhost:11434/v1 (Ollama)
    model: str
    api_key: str = ""  # local servers ignore it; external providers need one
    timeout: int = 300


def _llm(prefix: str, default_url: str, default_model: str) -> LLMSettings:
    return LLMSettings(
        base_url=os.getenv(f"{prefix}_BASE_URL", default_url).rstrip("/"),
        model=os.getenv(f"{prefix}_MODEL", default_model),
        api_key=os.getenv(f"{prefix}_API_KEY", ""),
        timeout=int(os.getenv(f"{prefix}_TIMEOUT", "300")),
    )


BACKEND = os.getenv("SHIELD_BACKEND", "heuristic")
MAX_ROUNDS = int(os.getenv("SHIELD_MAX_ROUNDS", "3"))
# How leaking phrases are removed: "suppress" = replace with labels like [AGE] (default:
# guaranteed and fast), "ai" = ask the model for natural rewording (slower, can miss).
REWRITE_MODE = os.getenv("SHIELD_REWRITE_MODE", "suppress")
# Replace he/she, his/her, husband/wife with neutral words before the first attack round.
NEUTRAL_PRONOUNS = os.getenv("SHIELD_NEUTRAL_PRONOUNS", "1") == "1"
# An attacker guess only counts as a leak if it is at least this confident (0-1).
LEAK_CONFIDENCE = float(os.getenv("SHIELD_LEAK_CONFIDENCE", "0.6"))

# The attacker used inside the loop, running locally / on LinuxONE. Finding clues is the hard
# job, so this should be the stronger model: a weak attacker makes the loop look safe when it isn't.
LOOP_LLM = _llm("LOOP_LLM", "http://localhost:8080/v1", "local-model")
# The rewriter inside the loop. Writing short edits is easy, so a smaller, faster model is fine.
REWRITE_LLM = _llm("REWRITE_LLM", LOOP_LLM.base_url, LOOP_LLM.model)
# The attacker used for EVALUATION. Ideally a different, stronger model than the loop's,
# so we don't grade our own homework. Defaults to the loop model.
EVAL_LLM = _llm("EVAL_LLM", LOOP_LLM.base_url, LOOP_LLM.model)
# The outside AI (ChatGPT, Claude, ...) that only ever receives cleaned text.
EXTERNAL_LLM = _llm("EXTERNAL_LLM", "https://api.openai.com/v1", "")

# Key for encrypting the placeholder vault. If unset, a random key is made per process.
VAULT_KEY = os.getenv("SHIELD_VAULT_KEY", "")
