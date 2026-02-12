#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$ROOT_DIR/backend/server.log"

echo "Security Platform Offline Bundle Status"
echo "======================================"

if pgrep -f "uvicorn main:app" >/dev/null 2>&1; then
  echo "Backend process: running"
else
  echo "Backend process: stopped"
fi

if command -v curl >/dev/null 2>&1; then
  echo
  echo "Health endpoint:"
  curl -s http://localhost:8000/api/health | python3 -m json.tool 2>/dev/null || echo "Not reachable"
fi

echo
echo "Recent backend log lines:"
if [ -f "$LOG_FILE" ]; then
  tail -20 "$LOG_FILE"
else
  echo "No log file found at $LOG_FILE"
fi
