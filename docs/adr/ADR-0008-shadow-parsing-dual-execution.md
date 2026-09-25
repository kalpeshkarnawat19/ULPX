# ADR-0008: Shadow Parsing and Dual Execution Runtime

## Status

Accepted - Stage 17.

## Context

When parser drift is detected or a new candidate parser specification is generated, deploying the candidate directly
to production risks undetected regressions, data loss, and alert flooding.
Air-gapped enterprise SOCs require validation on live or replay traffic under realistic operational conditions
before promotion.

The Build Guide establishes strict exit criteria and a mandatory scope guard for Stage 17:
> **Objective**: Run candidate on copies without downstream publication.
> **Scope guard**: "No production side effects." Candidate output never reaches normal downstream bus; comparison persisted.

Candidate parsers must run alongside active parsers in an isolated shadow execution environment, comparing outputs
across:
1. Field matching and value equality.
2. Critical security semantics and enum mappings.
3. Unknown field retention (preserving unmapped raw fields per Rule 4).
4. Detection Preservation Score (DPS) preservation across mandatory detection contracts (DET-001 through DET-006).
5. Execution latency delta (ensuring candidates do not degrade pipeline throughput).

## Decision

1. Create a versioned contract `packages/contracts/shadow_comparison.schema.json` (v1.0) and example fixture
   `fixtures/contracts/shadow_comparison.example.json` to define machine-readable shadow evaluation reports.
2. Implement `ShadowRunner` in `ml/shadow/runner.py` providing dual execution:
   - Duplicates raw event envelopes for parallel execution through both active and candidate parsers.
   - Enforces strict isolation: Candidate outputs are directed exclusively to an in-memory shadow sink and
     are cryptographically prevented from being published to downstream event brokers or external SIEM exporters.
   - Measures fine-grained per-event parsing latency.
3. Implement `ShadowComparator` in `ml/shadow/comparator.py`:
   - Computes field-by-field match rate, critical semantic divergence, unknown retention, DPS delta, and latency delta.
   - Generates recommendation (`READY_FOR_PROMOTION`, `REJECT`, `REQUIRE_HUMAN_REVIEW`) and sets `shadow_state`.
   - Requires explicit verification of downstream isolation (`downstream_isolation_verified = True`).
4. Stage 18 safe self-healing promotion policies will strictly require a passing shadow comparison report
   (`shadow_state == "PASSED"` and `downstream_isolation_verified == True`) before hot promotion.

## Consequences

- Candidate parsers can be rigorously evaluated against live operational traffic with zero risk of polluting downstream data lakes or triggering false alerts.
- Every promotion decision is backed by an auditable, machine-readable shadow comparison artifact.
