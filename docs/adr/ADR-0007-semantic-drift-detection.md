# ADR-0007: Semantic Drift Detection and Behavioral Verification

## Status

Accepted - Stage 16.

## Context

Structural drift detection (Stage 15) successfully flags syntax-level changes, missing fields,
and data type mutations. However, security telemetry can experience catastrophic semantic degradation
while remaining structurally valid:
1. Enum meaning shifts: A firewall action `deny` starts being parsed as `allowed`, or new vendor codes
   (e.g. `quarantine`, `teardown`) are introduced and mapped to safe defaults.
2. Critical field remapping: Essential security fields (`src.ip`, `dst.port`, `event.action`, `user.name`)
   suffer mapping confidence drops or inadvertent reassignments.
3. Event-family context drift: Logs from a registered firewall endpoint unexpectedly shift from network
   traffic to authentication or DNS events.
4. Detection regressions: Security detection contracts (Stage 12) begin failing because essential
   attributes are normalized incorrectly.

The Build Guide explicitly states the non-negotiable scope guard for Stage 16:
> *"Do not equate structural stability with semantic stability."*

## Decision

1. Extend `packages/contracts/drift_report.schema.json` with semantic signals:
   - `dps_regression`: Regression in Detection Preservation Score against mandatory rules.
   - `enum_drift_score`: Proportion of unmapped, inverted, or shifted categorical enum values.
   - `critical_mapping_drift`: Detected shift or confidence drop on critical security fields.
   - `event_family_drift`: Divergence in the inferred event family context.
2. Implement `SemanticDriftDetector` in `ml/drift/semantic.py` evaluating both candidate parser behavior
   and incoming normalized event streams against certified baselines.
3. Enforce the PRD threshold: `mandatory DPS regression > 0 percentage points` immediately triggers `DRIFTED`.
4. Ensure `SemanticDriftDetector` flags behavioral anomalies even when `StructuralDriftDetector`
   reports `STABLE`.

## Consequences

Pipelines gain end-to-end assurance that normalized security telemetry preserves intended detection
semantics and behavior across parser revisions and upstream vendor modifications.
