#!/usr/bin/env bash
set -euo pipefail

# Sync prebuilt tools + local model from an installed platform into this offline bundle.
# Default source root assumes this repo layout:
#   /opt/ai-pentest/                    (source tools/models)
#   /opt/ai-pentest/offline_sellable_bundle/app/
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_ROOT="${SOURCE_ROOT:-$(cd "$APP_DIR/../.." && pwd)}"

SRC_TOOLS="$SOURCE_ROOT/tools"
SRC_MODELS="$SOURCE_ROOT/models"
DST_TOOLS="$APP_DIR/tools"
DST_MODELS="$APP_DIR/models"

if [ ! -d "$SRC_TOOLS" ]; then
  echo "Missing source tools directory: $SRC_TOOLS"
  exit 1
fi

if [ ! -d "$SRC_MODELS" ]; then
  echo "Missing source models directory: $SRC_MODELS"
  exit 1
fi

mkdir -p "$DST_TOOLS" "$DST_MODELS"

echo "Syncing tools from: $SRC_TOOLS"
rsync -a --delete "$SRC_TOOLS/" "$DST_TOOLS/"

echo "Syncing models from: $SRC_MODELS"
rsync -a --delete "$SRC_MODELS/" "$DST_MODELS/"

echo
echo "Verifying required prebuilt files..."
required=(
  "$DST_TOOLS/nuclei"
  "$DST_TOOLS/katana"
  "$DST_TOOLS/sqlmap/sqlmap.py"
  "$DST_TOOLS/nikto/program/nikto.pl"
  "$DST_TOOLS/llama-server"
)

for p in "${required[@]}"; do
  if [ ! -e "$p" ]; then
    echo "Missing required file: $p"
    exit 1
  fi
done

if ! ls "$DST_MODELS"/*.gguf >/dev/null 2>&1; then
  echo "No GGUF model found under $DST_MODELS"
  exit 1
fi

echo "Prebuilt asset sync complete."
