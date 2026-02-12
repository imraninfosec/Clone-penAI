#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MISSING=0

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[MISSING] command: $1"
    MISSING=1
  else
    echo "[OK] command: $1"
  fi
}

need_file() {
  if [ ! -e "$1" ]; then
    echo "[MISSING] file: $1"
    MISSING=1
  else
    echo "[OK] file: $1"
  fi
}

echo "Verifying offline prerequisites in: $ROOT_DIR"
need_cmd python3
need_cmd perl
need_cmd ss

need_file "$ROOT_DIR/backend/main.py"
need_file "$ROOT_DIR/frontend/index.html"
need_file "$ROOT_DIR/newreports/report.css"

# Tooling checks (drop binaries here for offline execution)
need_file "$ROOT_DIR/tools/nuclei"
need_file "$ROOT_DIR/tools/katana"
need_file "$ROOT_DIR/tools/sqlmap/sqlmap.py"
need_file "$ROOT_DIR/tools/nikto/program/nikto.pl"

# Model check (at least one)
if ls "$ROOT_DIR/models"/*.gguf >/dev/null 2>&1; then
  echo "[OK] model: GGUF file found"
else
  echo "[MISSING] model: place at least one .gguf file under $ROOT_DIR/models"
  MISSING=1
fi

if [ "$MISSING" -eq 0 ]; then
  echo "All offline prerequisites are present."
  exit 0
fi

echo "Prerequisite verification failed. Add missing dependencies and rerun."
exit 1
