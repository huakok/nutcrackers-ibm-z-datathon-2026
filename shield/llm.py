"""A tiny client for any OpenAI-compatible chat endpoint, using only the standard library.

llama.cpp's `llama-server` (what we run on LinuxONE), Ollama, and most hosted providers
all accept the same request shape: POST {base_url}/chat/completions with a list of
messages. Standard library only, so nothing extra has to compile on s390x.
"""
import json
import re
import time
import urllib.request

from .config import LLMSettings


class LLMError(RuntimeError):
    pass


def chat(settings: LLMSettings, system: str, user: str, temperature: float = 0.0,
         max_tokens: int = 800, schema: dict | None = None) -> tuple[str, float]:
    """Send one chat request. Returns (reply text, seconds taken).

    schema: a JSON schema the reply MUST match. llama-server turns it into a grammar that
    stops the model from writing anything else, so small models can't produce broken JSON.
    """
    payload = {
        "model": settings.model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "temperature": temperature,   # 0 = as repeatable as possible, which experiments need
        "max_tokens": max_tokens,
    }
    if schema:
        payload["response_format"] = {"type": "json_schema",
                                      "json_schema": {"name": "reply", "schema": schema}}
    body = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if settings.api_key:
        headers["Authorization"] = f"Bearer {settings.api_key}"
    req = urllib.request.Request(f"{settings.base_url}/chat/completions", data=body, headers=headers)
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=settings.timeout) as resp:
            data = json.load(resp)
    except Exception as exc:
        raise LLMError(f"Request to {settings.base_url} failed: {exc}") from exc
    return data["choices"][0]["message"]["content"], time.perf_counter() - start


def extract_json(text: str) -> dict:
    """Small models often wrap JSON in prose or ```fences```. Pull out the first {...} block."""
    text = re.sub(r"```(?:json)?", "", text)
    start = text.find("{")
    if start == -1:
        raise LLMError(f"No JSON object in model reply: {text[:200]!r}")
    depth = 0
    for i in range(start, len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return json.loads(text[start:i + 1])
    raise LLMError(f"Unterminated JSON in model reply: {text[:200]!r}")
