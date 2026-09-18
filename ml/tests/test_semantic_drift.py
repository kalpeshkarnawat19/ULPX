"""
Unit tests for Semantic Drift Detection Engine (Stage 16).
Verifies detection of meaning and security behavioral shifts:
- Enum inversion and unmapped enum values
- Critical field mapping regressions
- Event-family context divergence
- Detection Preservation Score (DPS) regressions
- Scope guard: "Do not equate structural stability with semantic stability"
- Contract schema conformity against packages/contracts/drift_report.schema.json
"""

import json
from pathlib import Path
import pytest

from ml.drift.semantic import (
    SemanticDriftDetector,
    SemanticDriftSignals,
    SemanticDriftThresholds,
)
from ml.drift.structural import (
    DriftReport,
    DriftState,
    DriftThresholds,
    StructuralDriftDetector,
)
from ml.source_profiler.profiler import UnknownSourceProfiler

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "packages" / "contracts" / "drift_report.schema.json"


@pytest.fixture
def detector():
    return SemanticDriftDetector()


@pytest.fixture
def baseline_spec():
    return {
        "parser": {"id": "cisco.firewall", "version": "1.0.0"},
        "match": {"format": "syslog"},
        "fields": {
            "src_ip": {"type": "ip", "map_to": "src.ip"},
            "dst_ip": {"type": "ip", "map_to": "dst.ip"},
            "dst_port": {"type": "integer", "map_to": "dst.port"},
            "action": {
                "type": "string",
                "map_to": "event.action",
                "enum": {"deny": "blocked", "allow": "allowed"},
            },
            "user": {"type": "string", "map_to": "user.name"},
        },
    }


@pytest.fixture
def baseline_events():
    return [
        {"src.ip": "10.0.0.1", "dst.ip": "192.168.1.1", "dst.port": 443, "event.action": "blocked", "user.name": "alice"},
        {"src.ip": "10.0.0.2", "dst.ip": "192.168.1.2", "dst.port": 80, "event.action": "allowed", "user.name": "bob"},
        {"src.ip": "10.0.0.3", "dst.ip": "192.168.1.3", "dst.port": 22, "event.action": "blocked", "user.name": "charlie"},
    ]


def test_stable_semantic_traffic(detector, baseline_spec, baseline_events):
    """When candidate spec and event semantics are identical, status is STABLE."""
    candidate_spec = dict(baseline_spec)
    candidate_events = list(baseline_events)

    report = detector.detect_semantic_drift(
        baseline_spec=baseline_spec,
        candidate_spec=candidate_spec,
        baseline_events=baseline_events,
        candidate_events=candidate_events,
        source_id="cisco_firewall",
        parser_id="cisco.firewall",
    )

    assert report.drift_state == DriftState.STABLE
    assert report.remediation_recommended is False


def test_enum_inversion_semantic_drift(detector, baseline_spec, baseline_events):
    """When action enum values flip meaning (e.g. deny -> allowed), detector flags DRIFTED."""
    # Inverted candidate enum: deny is mistakenly mapped to allowed
    candidate_spec = {
        "parser": {"id": "cisco.firewall", "version": "1.1.0"},
        "match": {"format": "syslog"},
        "fields": {
            "src_ip": {"type": "ip", "map_to": "src.ip"},
            "dst_ip": {"type": "ip", "map_to": "dst.ip"},
            "dst_port": {"type": "integer", "map_to": "dst.port"},
            "action": {
                "type": "string",
                "map_to": "event.action",
                "enum": {"deny": "allowed", "allow": "allowed"},  # Inversion!
            },
            "user": {"type": "string", "map_to": "user.name"},
        },
    }

    report = detector.detect_semantic_drift(
        baseline_spec=baseline_spec,
        candidate_spec=candidate_spec,
        baseline_events=baseline_events,
        candidate_events=baseline_events,
        source_id="cisco_firewall",
        parser_id="cisco.firewall",
    )

    assert report.drift_state == DriftState.DRIFTED
    assert report.remediation_recommended is True
    assert any("Action enum inversion detected" in d for d in report.drift_details)


def test_critical_field_remapping_drift(detector, baseline_spec, baseline_events):
    """Dropping or remapping a critical field (e.g. src.ip) triggers DRIFTED."""
    candidate_spec = {
        "parser": {"id": "cisco.firewall", "version": "1.1.0"},
        "match": {"format": "syslog"},
        "fields": {
            # src_ip now erroneously remapped to device.hostname
            "src_ip": {"type": "string", "map_to": "device.hostname"},
            "dst_ip": {"type": "ip", "map_to": "dst.ip"},
            "dst_port": {"type": "integer", "map_to": "dst.port"},
            "action": {"type": "string", "map_to": "event.action", "enum": {"deny": "blocked", "allow": "allowed"}},
            "user": {"type": "string", "map_to": "user.name"},
        },
    }

    report = detector.detect_semantic_drift(
        baseline_spec=baseline_spec,
        candidate_spec=candidate_spec,
        baseline_events=baseline_events,
        candidate_events=baseline_events,
        source_id="cisco_firewall",
        parser_id="cisco.firewall",
    )

    assert report.drift_state == DriftState.DRIFTED
    assert report.remediation_recommended is True
    assert any("Critical field 'src.ip' mapping dropped" in d for d in report.drift_details)


def test_dps_regression_drift(detector, baseline_spec, baseline_events):
    """When detection preservation regresses on mandatory rules, detector flags DRIFTED."""
    # In candidate events, blocked events are missing endpoints or action is altered, failing DET-002
    corrupted_candidate_events = [
        {"src.ip": None, "dst.ip": None, "dst.port": 443, "event.action": "pass", "user.name": "alice"},
        {"src.ip": None, "dst.ip": None, "dst.port": 80, "event.action": "pass", "user.name": "bob"},
    ]

    report = detector.detect_semantic_drift(
        baseline_spec=baseline_spec,
        candidate_spec=baseline_spec,
        baseline_events=baseline_events,
        candidate_events=corrupted_candidate_events,
        source_id="cisco_firewall",
        parser_id="cisco.firewall",
    )

    assert report.drift_state == DriftState.DRIFTED
    assert report.remediation_recommended is True
    assert any("DPS regression" in d for d in report.drift_details)


def test_structural_stability_with_semantic_drift():
    """
    SCOPE GUARD TEST: 'Do not equate structural stability with semantic stability.'
    A payload with identical keys, identical JSON syntax, and zero parse failures
    passes StructuralDriftDetector as STABLE, but MUST be caught and flagged as
    DRIFTED by SemanticDriftDetector due to inverted security semantics.
    """
    profiler = UnknownSourceProfiler()
    struct_detector = StructuralDriftDetector(profiler=profiler)
    sem_detector = SemanticDriftDetector()

    # Raw baseline logs
    baseline_raw = [
        '{"src": "10.0.0.1", "action": "deny", "user": "alice"}',
        '{"src": "10.0.0.2", "action": "deny", "user": "bob"}',
    ]
    base_profile = profiler.profile(baseline_raw)

    # Current logs: syntactically identical keys ("src", "action", "user") and identical types (strings)
    # BUT semantically, action has silently flipped to "allow" (all security blocks bypassed!)
    current_raw = [
        '{"src": "10.0.0.10", "action": "allow", "user": "alice"}',
        '{"src": "10.0.0.11", "action": "allow", "user": "bob"}',
    ]
    curr_profile = profiler.profile(current_raw)

    # 1. Structural detector sees identical keys, zero parse errors, identical types -> STABLE!
    struct_report = struct_detector.compare_profiles(
        baseline=base_profile,
        current=curr_profile,
        source_id="fw",
        parser_id="fw.json",
    )
    assert struct_report.drift_state == DriftState.STABLE
    assert struct_report.signals.key_set_distance == 0.0
    assert struct_report.signals.type_violation_rate == 0.0

    # 2. Semantic detector inspects security semantics -> catches inverted outcome and flags DRIFTED!
    baseline_spec = {
        "fields": {
            "src": {"type": "ip", "map_to": "src.ip"},
            "action": {"type": "string", "map_to": "event.action", "enum": {"deny": "blocked", "allow": "allowed"}},
            "user": {"type": "string", "map_to": "user.name"},
        }
    }
    # Candidate mapping inversion
    candidate_spec = {
        "fields": {
            "src": {"type": "ip", "map_to": "src.ip"},
            "action": {"type": "string", "map_to": "event.action", "enum": {"deny": "allowed", "allow": "allowed"}},
            "user": {"type": "string", "map_to": "user.name"},
        }
    }
    base_events = [{"src.ip": "10.0.0.1", "event.action": "blocked", "user.name": "alice"}]
    cand_events = [{"src.ip": "10.0.0.1", "event.action": "allowed", "user.name": "alice"}]

    sem_report = sem_detector.detect_semantic_drift(
        baseline_spec=baseline_spec,
        candidate_spec=candidate_spec,
        baseline_events=base_events,
        candidate_events=cand_events,
        source_id="fw",
        parser_id="fw.json",
    )

    # Scope guard verified: Structure is STABLE, but Semantics is DRIFTED!
    assert sem_report.drift_state == DriftState.DRIFTED
    assert sem_report.remediation_recommended is True


def test_semantic_drift_report_contract_compliance(detector, baseline_spec, baseline_events):
    """Verifies that the generated DriftReport dictionary conforms to packages/contracts/drift_report.schema.json."""
    from tests.contracts.test_schemas import validate

    schema = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    report = detector.detect_semantic_drift(
        baseline_spec=baseline_spec,
        candidate_spec=baseline_spec,
        baseline_events=baseline_events,
        candidate_events=baseline_events,
        source_id="demo-firewall",
        parser_id="demo.firewall.kv",
        parser_version="1.0.0",
        baseline_run_id="base-001",
    )

    report_dict = report.to_dict()
    validate(report_dict, schema, schema)
    assert report_dict["schema_version"] == "1.0"
    assert report_dict["drift_state"] == "STABLE"
    assert "dps_regression" in report_dict["signals"]
    assert "enum_drift_score" in report_dict["signals"]
    assert "critical_mapping_drift" in report_dict["signals"]
    assert "event_family_drift" in report_dict["signals"]
    assert "dps_regression" in report_dict["thresholds"]
