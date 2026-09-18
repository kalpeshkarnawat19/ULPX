# ADR-0006: Structural Drift Detection Contract and Engine

## Status

Accepted - Stage 15.

## Context

Security telemetry parsing pipelines face continuous, unannounced upstream format changes,
including new log fields, type mutations (e.g. integer ports becoming strings), delimiter shifts,
and parsing failure spikes. Without empirical drift detection, silent schema degradation causes
critical detection fields to be dropped or misparsed without operator notice.

`AGENTS.md` Rule 1 mandates contract-first architecture where components exchange versioned
schema artifacts defined under `packages/contracts/`. Furthermore, the Build Guide scope guard
specifies that drift thresholds must be configurable defaults rather than hardcoded scientific constants.

## Decision

1. Introduce `packages/contracts/drift_report.schema.json` (version 1.0) defining structured drift
   evaluations, including signals (`parse_failure_rate`, `unknown_field_ratio`, `type_violation_rate`,
   `key_set_distance`, `distribution_divergence`), applied thresholds, qualitative drift observations,
   and remediation recommendations.
2. Implement `StructuralDriftDetector` in `ml/drift/structural.py` that computes rolling comparisons
   between baseline profiles and current log profiles or raw batches.
3. Emit drift states (`STABLE`, `SUSPECTED`, `DRIFTED`) that integrate directly into the `drift`
   section of the `TelemetryPassport` contract (`telemetry_passport.schema.json`).
4. Support runtime configuration of all drift thresholds, reporting the applied threshold bounds in
   every generated report.

## Consequences

Downstream assurance components and the Telemetry Passport can continuously verify parser stability
using measured drift observations. Parsers experiencing structural drift or type mutations can be
flagged immediately for candidate repair generation and shadow parsing before production disruption occurs.
