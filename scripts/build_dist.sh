#!/usr/bin/env bash
set -e

DIST_NAME="ULPF-X-Standalone-v1.0.0"
DIST_DIR="dist/$DIST_NAME"

echo "📦 Packaging ULPF-X Standalone Offline Bundle..."

# Clean old builds
rm -rf dist "$DIST_NAME.zip"
mkdir -p "$DIST_DIR/wheels"

# 1. Download offline wheels for air-gapped target devices
echo "  • Downloading offline wheel dependencies (rich, psutil, pytest)..."
python3 -m pip download -d "$DIST_DIR/wheels" rich psutil pytest --quiet

# 2. Copy source repository files
echo "  • Bundling system engine and scripts..."
cp -r scripts packages requirements.txt install.sh README.md "$DIST_DIR/" 2>/dev/null || true

# 3. Create Distribution Archive
cd dist
zip -rq "../$DIST_NAME.zip" "$DIST_NAME"
cd ..

echo "✅ Distribution package created: $DIST_NAME.zip"