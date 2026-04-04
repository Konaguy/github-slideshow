#!/usr/bin/env bash
# ── OmniManager Mac build script ─────────────────────────────────────────────
# Usage: ./build.sh
# Output: dist/OmniManager.app  (drag to /Applications)
set -e

echo "==> Activating virtual environment"
source .venv/bin/activate

echo "==> Installing build dependencies"
pip install pyinstaller pywebview --quiet

echo "==> Cleaning previous build"
rm -rf build dist

echo "==> Building OmniManager.app"
pyinstaller OmniManager.spec

echo ""
echo "✓ Build complete: dist/OmniManager.app"
echo "  Drag OmniManager.app to your Applications folder to install."
