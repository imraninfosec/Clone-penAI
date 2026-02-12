#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
LOG_FILE="$BACKEND_DIR/server.log"

mkdir -p "$ROOT_DIR/data" "$ROOT_DIR/logs" "$ROOT_DIR/reports" "$ROOT_DIR/models" "$ROOT_DIR/tools"

if [ -f "$ROOT_DIR/.env.offline" ]; then
  # shellcheck disable=SC1091
  source "$ROOT_DIR/.env.offline"
fi

# Load defaults if variables are missing.
if [ -f "$ROOT_DIR/.env.offline.example" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT_DIR/.env.offline.example"
  set +a
fi

# Stop prior uvicorn if running from this bundle.
pkill -f "uvicorn main:app" 2>/dev/null || true
sleep 1

# Optional local llama-server (only if binary and model are present)
LLAMA_SERVER_BIN="$ROOT_DIR/tools/llama-server"
if [ ! -x "$LLAMA_SERVER_BIN" ] && [ -x "$ROOT_DIR/llama.cpp/build/bin/llama-server" ]; then
  LLAMA_SERVER_BIN="$ROOT_DIR/llama.cpp/build/bin/llama-server"
fi

LLAMA_MODEL=""
for cand in \
  "$ROOT_DIR/models/qwen2.5-3b-instruct-q4_k_m.gguf" \
  "$ROOT_DIR/models/mistral-7b-instruct-v0.2.Q4_K_M.gguf" \
  "$ROOT_DIR/models/tinyllama.gguf"; do
  if [ -f "$cand" ]; then
    LLAMA_MODEL="$cand"
    break
  fi
done

if [ -x "$LLAMA_SERVER_BIN" ] && [ -n "$LLAMA_MODEL" ]; then
  if ! ss -ltn '( sport = :8080 )' 2>/dev/null | grep -q ':8080'; then
    nohup "$LLAMA_SERVER_BIN" -m "$LLAMA_MODEL" --host 0.0.0.0 --port 8080 \
      --ctx-size "${LLAMA_CTX:-2048}" --batch-size "${LLAMA_BATCH:-256}" \
      --threads "${LLAMA_THREADS:-4}" --gpu-layers "${LLAMA_GPU_LAYERS:-0}" \
      > "$BACKEND_DIR/llama_server.log" 2>&1 &
  fi
fi

cd "$BACKEND_DIR"
touch "$LOG_FILE"
if [ -f "$ROOT_DIR/data/bootstrap_admin_credentials.txt" ]; then
  echo "Bootstrap credentials file detected: $ROOT_DIR/data/bootstrap_admin_credentials.txt"
  echo "Use once, then change password immediately."
fi

uvicorn_cmd=(python3 -m uvicorn main:app --host 0.0.0.0 --port 8000)
case "${UVICORN_RELOAD,,}" in
  1|true|yes|on)
    uvicorn_cmd+=(--reload)
    ;;
esac

"${uvicorn_cmd[@]}" 2>&1 | tee -a "$LOG_FILE"
