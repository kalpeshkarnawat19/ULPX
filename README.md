# ULPF-X

Universal Log Pre-processing Framework (ULPF-X) is contract-first. The current
Stage 14 delivers a measured, validation-linked Telemetry Passport.

## Stage 14 scope

- A versioned Telemetry Passport contract with certified and unmeasured states.
- An evidence-only passport builder and a local assurance gate.
- Certification, metric, drift, and validation linkage rules that reject
  fabricated or placeholder numeric values.

No Stage 15+ validation, drift repair, database, UI, or API functionality is
implemented by this stage.

## Verify

Run `make test-passport`. The test uses Python's standard library and validates
the contract plus both certified and uncertified assurance behavior.

## Contracts

| Contract | Purpose |
| --- | --- |
| `raw_event_envelope` | Immutable identity and storage reference for received bytes. |
| `normalized_event` | Canonical ULPF event with provenance and quality status. |
| `field_lineage` | Raw-to-normalized field trace and mapping evidence. |
| `parser_spec` | Declarative, deterministic parser DSL restricted to whitelisted operations. |
| `telemetry_passport` | Validation-linked assurance record; metrics must be measured. |
