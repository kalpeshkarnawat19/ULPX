#!/usr/bin/env bash
# ULPF-X Environment Profile & Global Shorthand Registration
ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_BIN="$(cd "$ENV_DIR/../bin" 2>/dev/null && pwd)"

if [ -n "$REPO_BIN" ] && [ -d "$REPO_BIN" ]; then
    export PATH="$REPO_BIN:$HOME/.ulpx/bin:$PATH"
else
    export PATH="$HOME/.ulpx/bin:$PATH"
fi

# Shorthand Command Aliases
alias ulpx-text="ulpx export --format text"
alias ulpx-json="ulpx export --format ndjson"
alias ulpx-csv="ulpx export --format csv"
alias ulpx-term="ulpx watch"
alias ulpx-api="ulpx api"
alias ulpx-on="ulpx daemon start"
alias ulpx-off="ulpx daemon stop"
alias ulpx-test="ulpx test"
