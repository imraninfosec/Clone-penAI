#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="$ROOT_DIR/backend/server.log"

echo "Security Platform Offline Status"
echo "================================"

if pgrep -f "uvicorn main:app" >/dev/null 2>&1; then
  echo "Backend: running"
else
  echo "Backend: stopped"
fi

echo
if command -v curl >/dev/null 2>&1; then
  echo "Health:"
  curl -s http://localhost:8000/api/health | python3 -m json.tool 2>/dev/null || echo "not reachable"
else
  echo "Health: curl not available"
fi

echo
echo "Tools:"
for f in \
  "$ROOT_DIR/tools/nuclei" \
  "$ROOT_DIR/tools/katana" \
  "$ROOT_DIR/tools/sqlmap/sqlmap.py" \
  "$ROOT_DIR/tools/nikto/program/nikto.pl"; do
  if [ -e "$f" ]; then
    echo "  OK  $(basename "$f")"
  else
    echo "  MISSING  $f"
  fi
done

echo
echo "Recent log lines:"
if [ -f "$LOG_FILE" ]; then
  tail -10 "$LOG_FILE"
else
  echo "No log file at $LOG_FILE"
fi
