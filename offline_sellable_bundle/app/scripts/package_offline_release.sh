#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$DIST_DIR/ai-pentest-offline-ready-${STAMP}.tar.gz"

mkdir -p "$DIST_DIR"

tar -C "$ROOT_DIR" \
  --exclude='dist' \
  --exclude='backend/__pycache__' \
  --exclude='frontend/__pycache__' \
  --exclude='*.log' \
  -czf "$OUT" .

echo "Created offline release bundle: $OUT"
