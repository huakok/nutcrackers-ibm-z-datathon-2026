"""HTTP API for the gateway. Standard library only, so it runs on LinuxONE with nothing to install.

    python3 api.py                      # listens on 0.0.0.0:8000 (API_PORT to change)

    GET  /health                        machine architecture (s390x on LinuxONE), backend, model
    POST /protect  {"text": "...", "max_rounds": 3}     -> cleaned text, every round, session_id
    POST /restore  {"session_id": "...", "text": "..."} -> placeholders replaced with real values
    POST /ask      {"session_id": "...", "question": "..."}
                   -> sends ONLY the cleaned text to the outside AI, returns its answer restored

Sessions (and their encrypted vaults) live in memory only and vanish on restart.
"""
import json
import os
import platform
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from shield import config, llm
from shield.pipeline import ask_external, protect

SESSIONS: dict[str, object] = {}   # session_id -> pipeline Result (holds the vault)
INDEX_HTML = Path(__file__).parent / "static" / "index.html"   # the demo page, served at /


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = INDEX_HTML.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if self.path == "/health":
            return self._send(200, {
                "status": "ok", "machine": platform.machine(), "system": platform.platform(),
                "backend": config.BACKEND, "loop_model": config.LOOP_LLM.model,
                "max_rounds": config.MAX_ROUNDS, "sessions": len(SESSIONS),
            })
        self._send(404, {"error": "not found"})

    def do_POST(self):
        try:
            data = self._body()
            if self.path == "/protect":
                result = protect(data["text"], max_rounds=data.get("max_rounds"))
                session_id = uuid.uuid4().hex
                SESSIONS[session_id] = result
                return self._send(200, {"session_id": session_id, "encrypted_vault": result.vault.encrypted,
                                        "vault_preview": result.vault.ciphertext_preview(),
                                        **result.to_dict()})
            result = SESSIONS.get(data.get("session_id"))
            if result is None:
                return self._send(404, {"error": "unknown session_id; call /protect first"})
            if self.path == "/restore":
                return self._send(200, {"text": result.vault.restore(data["text"])})
            if self.path == "/ask":
                answer = ask_external(result.text, data["question"])
                return self._send(200, {"sent_to_outside_ai": result.text,
                                        "answer_with_placeholders": answer,
                                        "answer": result.vault.restore(answer)})
            self._send(404, {"error": "not found"})
        except KeyError as exc:
            self._send(400, {"error": f"missing field {exc}"})
        except llm.LLMError as exc:
            self._send(502, {"error": str(exc)})


if __name__ == "__main__":
    host, port = os.getenv("API_HOST", "0.0.0.0"), int(os.getenv("API_PORT", "8000"))
    print(f"Listening on http://{host}:{port}  (machine={platform.machine()}, backend={config.BACKEND})")
    ThreadingHTTPServer((host, port), Handler).serve_forever()
