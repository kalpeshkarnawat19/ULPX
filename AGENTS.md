# ULPF-X repository rules

## Stage gate

This repository is currently at Stage 18: Safe Self-Healing. Stages 1-17 are
complete. The assurance record may use completed validation evidence, but it
must never manufacture numeric metrics, certification, or drift observations.
Do not implement Stage 19+ performance benchmarking, database, UI, or API work
until its versioned contract exists and its examples validate.

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
7. A Telemetry Passport is certified only from a passed validation run with a
   complete measured metric set and a measured drift state. Otherwise expose
   `NOT YET MEASURED`, never a placeholder number.

## Layout

- `packages/contracts/`: versioned JSON Schema contracts.
- `fixtures/contracts/`: valid, human-readable examples for each contract.
- `tests/contracts/`: contract-only validation; must not import application code.
- `apps/`, `ml/`, `infra/`: reserved skeletons for later approved stages.
