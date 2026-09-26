#!/usr/bin/env bash
# ULPF-X Environment Profile & Global Shorthand Registration
export PATH="$HOME/.ulpx/bin:$PATH"

# Shorthand Command Aliases
alias ulpx-text="ulpx export --format text"
alias ulpx-json="ulpx export --format ndjson"
alias ulpx-csv="ulpx export --format csv"
alias ulpx-term="ulpx watch"
alias ulpx-api="ulpx api"
alias ulpx-on="ulpx daemon start"
alias ulpx-off="ulpx daemon stop"
alias ulpx-test="ulpx test"
