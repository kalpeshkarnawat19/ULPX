# ADR-0001: Add CSV Format and Parser Support to ParserSpec Contract

- **Status:** Accepted
- **Date:** 2026-09-17
- **Authors:** Workstream A (Kalpesh), Workstream C (Sachi)
- **Target Schema:** `packages/contracts/parser_spec.schema.json`

## Context

Per the ULPF-X Build Guide Stage 3 ("Deterministic Parser Runtime") and PRD §5, the parsing runtime must execute declarative DSL specifications for heterogeneous log formats including JSON, Key-Value, Syslog, CEF, LEEF, and CSV.

While JSON, Key-Value, Syslog, CEF, and LEEF were enumerated in the initial `parser_spec.schema.json` v1.0 draft, CSV was omitted from the format enum and body parser options.

## Decision

We update `packages/contracts/parser_spec.schema.json` to:
1. Add `"csv"` to the `match.format` enum.
2. Add `"csv"` to the `body_parser.type` enum.
3. Add optional `delimiter` and `headers` string array properties to `body_parser`.
4. Add `"csv_parse"` to the `$defs/operation` whitelisted operations enum.

## Consequences

- **Backwards Compatibility:** This is a purely additive, backwards-compatible contract update. Existing schemas and fixtures continue to validate without error.
- **Contract Test Verification:** `make test-contracts` passes without regressions.
