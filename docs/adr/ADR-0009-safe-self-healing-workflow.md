# ADR-0009: Safe Self-Healing Workflow and Promotion Policy

## Status

Accepted - Stage 18.

## Context

Production security operations centers (SOCs) ingest telemetry from hundreds of evolving log sources. When an upstream
vendor modifies formatting, structural drift (Stage 15) or semantic drift (Stage 16) is flagged. While the intelligence
plane can synthesize candidate parsers (Stages 7-10), validate them against golden corpora (Stage 11), and execute them in
shadow isolation (Stage 17), deploying repairs directly to production without a formal policy gate risks service disruption,
detection blindness, and data loss.

The Build Guide specifies strict exit criteria and a non-negotiable scope guard for Stage 18:
> **Objective**: Connect drift -> candidate -> validation -> shadow -> approval.
> **Exit criteria**: Promotion blocked unless every mandatory gate passes.
> **Scope guard**: "Keep automatic promotion disabled for SIH unless all policy conditions are unambiguous."

## Decision

1. Author a versioned contract `packages/contracts/self_healing_report.schema.json` (v1.0) and example fixture
   `fixtures/contracts/self_healing_report.example.json` capturing the full machine-readable audit trail of self-healing
   incidents, gate evaluations, and promotion decisions.
2. Implement `PromotionPolicy` in `ml/self_healing/policy.py` enforcing the 5 mandatory refusal conditions:
   - `REFUSAL_1: Schema invalid`: Candidate spec violates `packages/contracts/parser_spec.schema.json`.
   - `REFUSAL_2: Validation incomplete`: Empirical validation metrics missing or failed.
   - `REFUSAL_3: Mandatory detection tests failed`: Candidate causes DPS regression or fails detection contracts (DET-001–DET-006).
   - `REFUSAL_4: Raw or unknown-field retention below 100%`: Candidate drops raw bytes or fails to preserve unknown fields (Rule 4).
   - `REFUSAL_5: Candidate has not passed shadow state`: Candidate failed shadow evaluation or violated downstream bus isolation.
3. Enforce safe promotion modes:
   - Default mode: `MANUAL_APPROVAL` / `ESCALATED_FOR_APPROVAL` (requires operator sign-off).
   - Conditional mode: `AUTOMATIC_CONDITIONAL` (promotes only when all 5 refusal checks pass with zero ambiguity).
4. Implement `SelfHealingWorkflow` in `ml/self_healing/workflow.py` linking:
   `drift_report` -> `synthesize_candidate` -> `validate_candidate` -> `shadow_evaluate` -> `evaluate_policy` -> `deploy_spec`
   with atomic rollback on any subsequent operational regression.

## Consequences

- Log parsing pipelines gain autonomous resilience against format and semantic drift.
- Production is safeguarded by mathematically provable refusal gates and complete auditability.
