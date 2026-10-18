#!/usr/bin/env bash
# Build llama.cpp on LinuxONE (s390x) and start an OpenAI-compatible model server.
# Based on llama.cpp's docs/build-s390x.md. Run on the LinuxONE instance:
#
#   bash scripts/setup_llamacpp_s390x.sh <URL-of-a-big-endian-.gguf-model>
#
# IMPORTANT: LinuxONE is big-endian, so normal .gguf models from the internet will NOT load.
# Pick a small pre-converted model (about 1-4B parameters, Q4/Q8) from the Hugging Face
# collections "s390x Verified Models" / "s390x Runnable Models" by the user `taronaeo`,
# and copy the direct download link of the .gguf file.
set -euo pipefail

MODEL_URL="${1:-}"
ROOT="$HOME/llm"
mkdir -p "$ROOT/models"
cd "$ROOT"

echo "== 1. Build tools (needs sudo) =="
sudo apt-get update
sudo apt-get install -y build-essential cmake git libopenblas-dev curl pkg-config

echo "== 2. Build llama.cpp with OpenBLAS (vector acceleration is on by default) =="
[ -d llama.cpp ] || git clone --depth 1 https://github.com/ggml-org/llama.cpp
cd llama.cpp
# On z17 (LinuxONE 5), llama.cpp asks for -march=arch15, which needs GCC 15. Ubuntu 24.04
# ships GCC 13, so target z16 instead: z17 runs z16 code, and VXE2 vectors stay enabled.
if [ "$(gcc -dumpversion | cut -d. -f1)" -lt 15 ]; then
  sed -i 's/-march=arch15/-march=z16/' ggml/src/ggml-cpu/CMakeLists.txt
fi
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DGGML_BLAS=ON -DGGML_BLAS_VENDOR=OpenBLAS
cmake --build build --config Release -j "$(nproc)"

if [ -n "$MODEL_URL" ]; then
  echo "== 3. Download model =="
  curl -L --fail -o "$ROOT/models/model-be.gguf" "$MODEL_URL"
fi

cat <<EOF

Done. Start the model server with:

  $ROOT/llama.cpp/build/bin/llama-server -m $ROOT/models/model-be.gguf \\
      --host 127.0.0.1 --port 8080 -c 4096 -t \$(nproc)

Then, in another terminal, point our code at it and time one attacker call:

  export SHIELD_BACKEND=llm LOOP_LLM_BASE_URL=http://127.0.0.1:8080/v1
  python3 -m shield.benchmark

If one call takes more than ~30 s, use a smaller model or lower SHIELD_MAX_ROUNDS.
EOF
