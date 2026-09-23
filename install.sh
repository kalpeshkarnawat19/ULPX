#!/usr/bin/env bash
# ==============================================================================
# ULPF-X Autonomous Engine Installer Launcher (Unix/Linux/macOS/Git Bash)
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/scripts/install.sh" "$@"