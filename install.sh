#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Strip macOS quarantine attributes if present (fixes Gatekeeper "Operation not permitted" on downloaded zip)
if command -v xattr >/dev/null 2>&1; then
    xattr -cr "$SCRIPT_DIR" 2>/dev/null || true
fi

exec bash "$SCRIPT_DIR/scripts/install.sh" "$@"