# ULPF-X repository rules

## Stage gate

This repository is currently at Stage 4: ULPF Canonical IR. Only
`apps/ingest-gateway`, `packages/parser-runtime`, and `apps/normalize-worker`
may contain service code. Do not implement databases, UI, AI, or
control-plane services until the relevant versioned contract exists and
its examples validate.

## Non-negotiable rules

1. Contract first: services may only exchange artifacts defined in
   `packages/contracts/*.schema.json`.
2. Raw events are immutable. Preserve their bytes through `raw_ref`, SHA-256, and
   byte length; do not replace them with parsed representations.
3. The parser DSL is data, not code. Only documented whitelist operations are
   valid; never introduce eval, shell commands, dynamic imports, or network calls.
4. Preserve unknown fields. Abstain instead of inventing an uncertain mapping.
5. Breaking contract changes require an ADR and a schema version increment.
6. Every contract change must add/update an example and pass `make test-contracts`.

## Layout

- `packages/contracts/`: versioned JSON Schema contracts.
- `fixtures/contracts/`: valid, human-readable examples for each contract.
- `tests/contracts/`: contract-only validation; must not import application code.
- `apps/`, `ml/`, `infra/`: reserved skeletons for later approved stages.
