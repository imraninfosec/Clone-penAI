#!/usr/bin/env bash
set -euo pipefail

pkill -f "uvicorn main:app" 2>/dev/null || true
pkill -f "llama-server" 2>/dev/null || true

echo "Offline bundle services stopped."
