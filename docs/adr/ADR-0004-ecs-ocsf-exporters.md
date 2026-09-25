# ADR-0004: Pure ECS and OCSF Exporters with Zero-Mutation Guarantees

## Status
Accepted

## Date
2026-09-18

## Context
In Stage 4, ULPF-X established a vendor-neutral Canonical Intermediate Representation (IR) (`NormalizedEvent`) across 14 field families. A non-negotiable architectural requirement (Build Guide Stage 6 & PRD Section 4) is that ULPF-IR remains the internal source of truth and must never be coupled to external vendor schemas like Elastic Common Schema (ECS) or Open Cybersecurity Schema Framework (OCSF).

Downstream SIEMs, data lakes, and detection engines require standard schemas. We must provide adapters that project Canonical IR events into ECS and OCSF while enforcing:
1. **Pure Projection:** Exporters act as deterministic adapters; source events must never be mutated during or after export.
2. **Standard Alignment:**
   - ECS target: ECS v8.11.0 schema compatibility.
   - OCSF target: OCSF v1.1.0 class-based schema compatibility (e.g. Network Activity `4001`, Authentication `3002`, HTTP Activity `6003`, Security Finding `2001`, System Activity `1001`).
3. **Lossless Evidence:** Cryptographic raw reference, SHA-256 digests, and unmapped extension fields are preserved in labels/unmapped metadata.

## Decision
1. Implement pure Go packages `packages/exporters/ecs` and `packages/exporters/ocsf`.
2. Both packages consume `*NormalizedEvent` as read-only input, perform deep-copy safety checks, and emit standard JSON-serializable structures (`ECSEvent`, `OCSFEvent`).
3. Test suite asserts deterministic output, 100% field mapping accuracy across all 6 golden log corpora, and strict zero-mutation scope guards.

## Consequences
- **Positive:** Downstream systems ingest native ECS and OCSF events without polluting the internal ULPF data plane.
- **Positive:** Zero risk of state corruption across concurrent export pipelines.
- **Positive:** Independent versioning for ECS and OCSF schemas without touching Canonical IR contracts.
