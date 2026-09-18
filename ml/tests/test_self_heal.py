"""
Unit and Integration Tests for Stage 18: Safe Self-Healing Workflow & Promotion Policy.
Verifies the closed-loop repair lifecycle, all 5 PRD refusal conditions, and contract compliance.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import pytest

from ml.deployment.deployer import SpecDeploymentEngine
from ml.drift.structural import DriftReport, DriftSignals, DriftState, DriftThresholds
from ml.self_healing import (
    GateResults,
    PromotionDecision,
    PromotionMode,
    PromotionPolicy,
    SelfHealingReport,
    SelfHealingWorkflow,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "packages" / "contracts" / "self_healing_report.schema.json"


@pytest.fixture
def active_spec():
    return {
        "parser": {"id": "cisco.firewall", "version": "1.0.0"},
        "match": {"format": "key_value"},
        "fields": {
            "src": {"type": "ip", "map_to": "src.ip"},
            "dst": {"type": "ip", "map_to": "dst.ip"},
            "srcport": {"type": "integer", "map_to": "src.port"},
            "dstport": {"type": "integer", "map_to": "dst.port"},
            "act": {"type": "string", "map_to": "event.action", "enum": {"deny": "blocked", "permit": "allowed"}},
            "user": {"type": "string", "map_to": "user.name"},
        },
    }


@pytest.fixture
def candidate_spec():
    return {
        "parser": {"id": "cisco.firewall", "version": "1.1.0"},
        "match": {"format": "key_value"},
        "fields": {
            "src": {"type": "ip", "map_to": "src.ip"},
            "dst": {"type": "ip", "map_to": "dst.ip"},
            "srcport": {"type": "integer", "map_to": "src.port"},
            "dstport": {"type": "integer", "map_to": "dst.port"},
            "act": {"type": "string", "map_to": "event.action", "enum": {"deny": "blocked", "permit": "allowed"}},
            "user": {"type": "string", "map_to": "user.name"},
            "session_id": {"type": "string", "map_to": "session.id"},
        },
    }


@pytest.fixture
def raw_firewall_events():
    return [
        "src=192.168.1.10 dst=10.0.0.5 srcport=49152 dstport=443 act=deny user=bob session_id=sess-100 unk_meta=alpha",
        "src=192.168.1.11 dst=10.0.0.6 srcport=49153 dstport=80 act=permit user=alice session_id=sess-101 unk_meta=beta",
        "src=192.168.1.12 dst=10.0.0.7 srcport=49154 dstport=22 act=deny user=root session_id=sess-102 unk_meta=gamma",
    ]


@pytest.fixture
def drift_report():
    now = datetime.now(timezone.utc)
    return DriftReport(
        source_id="cisco_firewall",
        parser_id="cisco.firewall",
        parser_version="1.0.0",
        drift_state=DriftState.DRIFTED,
        observed_at=now,
        start_time=now,
        end_time=now,
        sample_count=500,
        signals=DriftSignals(
            parse_failure_rate=0.0,
            unknown_field_ratio=0.15,
            type_violation_rate=0.0,
            key_set_distance=0.20,
            distribution_divergence=0.05,
        ),
        thresholds=DriftThresholds(),
        drift_details=["Key-set distance 0.20 exceeds threshold 0.15: new field session_id observed"],
        remediation_recommended=True,
    )


def test_self_healing_end_to_end_promotion(active_spec, candidate_spec, raw_firewall_events, drift_report):
    """Full repair lifecycle under AUTOMATIC_CONDITIONAL mode results in PROMOTED."""
    deployer = SpecDeploymentEngine()
    workflow = SelfHealingWorkflow(deployer=deployer)

    report = workflow.handle_repair(
        source_id="cisco_firewall",
        drift_report=drift_report,
        active_spec=active_spec,
        candidate_spec=candidate_spec,
        recent_log_samples=raw_firewall_events,
        promotion_mode=PromotionMode.AUTOMATIC_CONDITIONAL,
    )

    assert report.decision == PromotionDecision.PROMOTED
    assert report.applied_by == "POLICY_ENGINE"
    assert report.schema_passed is True
    assert report.validation_passed is True
    assert report.shadow_passed is True
    assert len(report.refusal_reasons) == 0

    # Verify atomic deployment succeeded
    active = deployer.get_active_spec("cisco_firewall")
    assert active is not None
    assert active.spec_id == "cisco.firewall:1.1.0"


def test_self_healing_escalation_by_default(active_spec, candidate_spec, raw_firewall_events, drift_report):
    """
    Scope Guard: Keep automatic promotion disabled for SIH unless explicitly authorized.
    Default mode MANUAL_APPROVAL escalates to operator even when all gates pass.
    """
    workflow = SelfHealingWorkflow()

    report = workflow.handle_repair(
        source_id="cisco_firewall",
        drift_report=drift_report,
        active_spec=active_spec,
        candidate_spec=candidate_spec,
        recent_log_samples=raw_firewall_events,
        promotion_mode=PromotionMode.MANUAL_APPROVAL,
    )

    assert report.decision == PromotionDecision.ESCALATED_FOR_APPROVAL
    assert report.applied_by == "OPERATOR_ESCALATION"
    assert len(report.refusal_reasons) == 0


def test_refusal_1_schema_invalid(active_spec, raw_firewall_events, drift_report):
    """Refusal condition 1: Candidate with broken schema is rejected."""
    broken_schema_spec = {
        "parser": {"version": "invalid"},  # missing id
        "fields": "not-a-dict",            # invalid fields type
    }
    workflow = SelfHealingWorkflow()

    report = workflow.handle_repair(
        source_id="cisco_firewall",
        drift_report=drift_report,
        active_spec=active_spec,
        candidate_spec=broken_schema_spec,
        recent_log_samples=raw_firewall_events,
        promotion_mode=PromotionMode.AUTOMATIC_CONDITIONAL,
    )

    assert report.decision == PromotionDecision.REJECTED
    assert any("Refusal condition 1 met" in r for r in report.refusal_reasons)


def test_refusal_2_validation_incomplete(active_spec, candidate_spec, drift_report):
    """Refusal condition 2: Incomplete or empty samples blocks promotion."""
    workflow = SelfHealingWorkflow()

    report = workflow.handle_repair(
        source_id="cisco_firewall",
        drift_report=drift_report,
        active_spec=active_spec,
        candidate_spec=candidate_spec,
        recent_log_samples=[],  # empty samples
        promotion_mode=PromotionMode.AUTOMATIC_CONDITIONAL,
    )

    assert report.decision == PromotionDecision.REJECTED
    assert any("Refusal condition 2 met" in r for r in report.refusal_reasons)


def test_refusal_3_detection_tests_failed():
    """Refusal condition 3: Candidate causing DPS regression is rejected."""
    policy = PromotionPolicy()
    gates = GateResults(
        schema_passed=True,
        schema_details="Valid",
        validation_passed=True,
        extraction_accuracy=1.0,
        semantic_accuracy=1.0,
        dps=0.75,  # Regressed below 1.0
        raw_retention=1.0,
        unknown_retention=1.0,
        shadow_passed=True,
        shadow_state="PASSED",
        field_match_rate=1.0,
        dps_delta=-0.25,  # Regression
        downstream_isolation_verified=True,
    )

    decision, reasons, _ = policy.evaluate(gates, mode=PromotionMode.AUTOMATIC_CONDITIONAL)
    assert decision == PromotionDecision.REJECTED
    assert any("Refusal condition 3 met" in r for r in reasons)


def test_refusal_4_retention_below_100():
    """Refusal condition 4: Candidate dropping unknown fields or raw bytes is rejected."""
    policy = PromotionPolicy()
    gates = GateResults(
        schema_passed=True,
        schema_details="Valid",
        validation_passed=True,
        extraction_accuracy=1.0,
        semantic_accuracy=1.0,
        dps=1.0,
        raw_retention=1.0,
        unknown_retention=0.85,  # Unknown fields dropped (violates Rule 4)
        shadow_passed=True,
        shadow_state="PASSED",
        field_match_rate=1.0,
        dps_delta=0.0,
        downstream_isolation_verified=True,
    )

    decision, reasons, _ = policy.evaluate(gates, mode=PromotionMode.AUTOMATIC_CONDITIONAL)
    assert decision == PromotionDecision.REJECTED
    assert any("Refusal condition 4 met" in r for r in reasons)


def test_refusal_5_shadow_unpassed_or_leaked():
    """Refusal condition 5: Candidate failing shadow or violating isolation is rejected."""
    policy = PromotionPolicy()

    # Case A: Shadow state is FAILED
    gates_failed = GateResults(
        schema_passed=True,
        schema_details="Valid",
        validation_passed=True,
        extraction_accuracy=1.0,
        semantic_accuracy=1.0,
        dps=1.0,
        raw_retention=1.0,
        unknown_retention=1.0,
        shadow_passed=False,
        shadow_state="FAILED",
        field_match_rate=0.70,
        dps_delta=0.0,
        downstream_isolation_verified=True,
    )
    dec_a, reasons_a, _ = policy.evaluate(gates_failed, mode=PromotionMode.AUTOMATIC_CONDITIONAL)
    assert dec_a == PromotionDecision.REJECTED
    assert any("Refusal condition 5 met" in r for r in reasons_a)

    # Case B: Downstream isolation violated
    gates_leaked = GateResults(
        schema_passed=True,
        schema_details="Valid",
        validation_passed=True,
        extraction_accuracy=1.0,
        semantic_accuracy=1.0,
        dps=1.0,
        raw_retention=1.0,
        unknown_retention=1.0,
        shadow_passed=True,
        shadow_state="PASSED",
        field_match_rate=1.0,
        dps_delta=0.0,
        downstream_isolation_verified=False,  # Isolation breach!
    )
    dec_b, reasons_b, _ = policy.evaluate(gates_leaked, mode=PromotionMode.AUTOMATIC_CONDITIONAL)
    assert dec_b == PromotionDecision.REJECTED
    assert any("Refusal condition 5 met" in r for r in reasons_b)


def test_self_healing_report_contract_compliance(active_spec, candidate_spec, raw_firewall_events, drift_report):
    """Verifies that generated SelfHealingReport conforms to self_healing_report.schema.json."""
    from tests.contracts.test_schemas import validate

    schema = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    workflow = SelfHealingWorkflow()

    report = workflow.handle_repair(
        source_id="demo-firewall",
        drift_report=drift_report,
        active_spec=active_spec,
        candidate_spec=candidate_spec,
        recent_log_samples=raw_firewall_events,
        promotion_mode=PromotionMode.AUTOMATIC_CONDITIONAL,
        incident_id="INC-2026-0919-001",
    )

    report_dict = report.to_dict()
    validate(report_dict, schema, schema)
    assert report_dict["schema_version"] == "1.0"
    assert report_dict["decision"] == "PROMOTED"
    assert report_dict["gates"]["shadow_evaluation"]["passed"] is True
