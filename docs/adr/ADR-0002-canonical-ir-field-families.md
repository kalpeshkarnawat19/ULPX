# ADR-0002: Add Canonical Field Families to NormalizedEvent Contract

- **Status:** Accepted
- **Date:** 2026-09-17
- **Authors:** Workstream A (Kalpesh), Workstream C (Sachi)
- **Target Schema:** `packages/contracts/normalized_event.schema.json`

## Context

Per the ULPF-X Build Guide Stage 4 ("ULPF Canonical IR") and PRD §4, the canonical intermediate representation must accommodate standard schema-neutral field families across diverse log types:
- `event`
- `source`
- `src`
- `dst`
- `network`
- `user`
- `device`
- `http`
- `dns`
- `alert`
- `raw`
- `parser`
- `quality`
- `extensions`

## Decision

We update `packages/contracts/normalized_event.schema.json` to include optional object definitions for `user`, `device`, `http`, `dns`, and `alert` with strict `additionalProperties: false`.

## Consequences

- **Scope Guard Integrity:** Guarantees that internal IR is schema-neutral and does not use ECS or OCSF as the internal source of truth.
- **Backwards Compatibility:** All existing examples and contracts remain completely valid.
- **Contract Test Verification:** `make test-contracts` passes cleanly.
