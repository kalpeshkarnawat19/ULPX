# ULPF-X

Universal Log Pre-processing Framework (ULPF-X) starts contract-first. This Stage
0 repository defines the stable exchanges between future ingestion, normalization,
validation, and assurance components.

## Stage 0 scope

- JSON Schema contracts for raw envelopes, normalized events, field lineage,
  parser specifications, and telemetry passports.
- Valid examples and a local contract-validation test.
- Repository, Docker Compose, and CI skeletons only.

No application service, parser runtime, UI, AI, database, or external dependency
is implemented in this stage.

## Verify

Run `make test-contracts`. The test uses Python's standard library and validates
every `fixtures/contracts/*.json` file against its declared schema.

## Contracts

| Contract | Purpose |
| --- | --- |
| `raw_event_envelope` | Immutable identity and storage reference for received bytes. |
| `normalized_event` | Canonical ULPF event with provenance and quality status. |
| `field_lineage` | Raw-to-normalized field trace and mapping evidence. |
| `parser_spec` | Declarative, deterministic parser DSL restricted to whitelisted operations. |
| `telemetry_passport` | Validation-linked assurance record; metrics must be measured. |
