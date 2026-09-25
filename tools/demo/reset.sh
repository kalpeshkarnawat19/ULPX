#!/usr/bin/env bash
# Reset only generated non-frontend demo output. Fixtures and source code remain immutable.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEMO_WORK="$ROOT_DIR/work/demo"

if [ -d "$DEMO_WORK" ]; then
    rm -rf "$DEMO_WORK"
fi
mkdir -p "$DEMO_WORK"
