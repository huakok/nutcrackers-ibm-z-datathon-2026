#!/usr/bin/env bash
# Start the local model on LinuxONE.
#   port 8080: IBM Granite 3.3 2B -> attacker, rewriter and evaluation attacker
#
#   bash scripts/start_models.sh            start it if it isn't running
#   bash scripts/start_models.sh --restart  stop it and start it with the current settings
#
# -np 2 gives the server two "slots", each remembering the last prompt it read. The attacker and
# the rewriter use different instructions; with one slot they would keep wiping each other's
# memory, and re-reading the instructions costs ~25 s on 3 CPUs (about 11 tokens/s).
# Then load the settings into your shell with:   source scripts/env.sh
set -euo pipefail
ROOT="$HOME/llm"
SERVER="$ROOT/llama.cpp/build/bin/llama-server"
MODEL="$ROOT/models/model-be.gguf"

if [ "${1:-}" = "--restart" ]; then
  pkill -f "llama-server.*--port 8080" && echo "stopped port 8080" || true
  sleep 2
fi

if curl -s "http://127.0.0.1:8080/health" | grep -q ok; then
  echo "port 8080 already running (use --restart to apply new settings)"
else
  nohup "$SERVER" -m "$MODEL" --host 127.0.0.1 --port 8080 -c 8192 -np 2 -t "$(nproc)" \
    > "$ROOT/server-2b.log" 2>&1 &
  echo "starting port 8080 (log: $ROOT/server-2b.log)"
fi

until curl -s "http://127.0.0.1:8080/health" | grep -q ok; do sleep 2; done
echo "port 8080 ready"
