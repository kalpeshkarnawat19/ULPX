"""
Unit tests for Structural Drift Detection Engine (Stage 15).
Tests baseline comparison across:
- Stable baseline (no drift)
- New / removed fields (structural Jaccard drift)
- Type mutation drift (e.g., port int -> string)
- Parse failure rate spike (> 2%)
- Configurable thresholds scope guard
- Contract schema conformity against packages/contracts/drift_report.schema.json
"""

import json
from pathlib import Path
import pytest

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
def profiler():
    return UnknownSourceProfiler()


@pytest.fixture
def detector(profiler):
    return StructuralDriftDetector(profiler=profiler)


@pytest.fixture
def baseline_profile(profiler):
    baseline_logs = [
        '{"src_ip": "10.0.0.1", "dst_port": 443, "action": "allow", "user": "alice"}',
        '{"src_ip": "10.0.0.2", "dst_port": 80, "action": "deny", "user": "bob"}',
        '{"src_ip": "10.0.0.3", "dst_port": 22, "action": "allow", "user": "charlie"}',
        '{"src_ip": "10.0.0.4", "dst_port": 443, "action": "allow", "user": "david"}',
        '{"src_ip": "10.0.0.5", "dst_port": 8080, "action": "deny", "user": "eve"}',
    ]
    return profiler.profile(baseline_logs)


def test_stable_baseline_traffic(detector, baseline_profile):
    """Clean, consistent traffic should be evaluated as STABLE with no remediation."""
    current_logs = [
        '{"src_ip": "10.0.0.10", "dst_port": 443, "action": "allow", "user": "frank"}',
        '{"src_ip": "10.0.0.11", "dst_port": 80, "action": "deny", "user": "grace"}',
        '{"src_ip": "10.0.0.12", "dst_port": 22, "action": "allow", "user": "heidi"}',
    ]
    report = detector.detect_from_logs(
        baseline=baseline_profile,
        current_logs=current_logs,
        source_id="app_firewall",
        parser_id="app.firewall.json",
    )

    assert report.drift_state == DriftState.STABLE
    assert report.remediation_recommended is False
    assert report.signals.type_violation_rate == 0.0
    assert report.signals.parse_failure_rate == 0.0
    assert report.signals.key_set_distance == 0.0


def test_new_fields_structural_drift(detector, baseline_profile):
    """Addition of unexpected new fields exceeding Jaccard distance threshold triggers DRIFTED."""
    # Introduce 4 new unexpected fields
    drifted_logs = [
        '{"src_ip": "10.0.0.1", "dst_port": 443, "action": "allow", "user": "alice", "client_os": "linux", "cloud_region": "us-east-1", "tenant_id": 99, "extra_tag": "beta"}',
        '{"src_ip": "10.0.0.2", "dst_port": 80, "action": "deny", "user": "bob", "client_os": "macos", "cloud_region": "eu-west-1", "tenant_id": 100, "extra_tag": "prod"}',
    ]
    report = detector.detect_from_logs(
        baseline=baseline_profile,
        current_logs=drifted_logs,
        source_id="app_firewall",
        parser_id="app.firewall.json",
    )

    assert report.drift_state == DriftState.DRIFTED
    assert report.remediation_recommended is True
    assert report.signals.key_set_distance > detector.thresholds.key_set_distance
    assert any("Key-set structural distance" in d for d in report.drift_details)


def test_field_type_mutation_drift(detector, baseline_profile):
    """When a numerical field (dst_port) mutates into a string, detector flags DRIFTED."""
    # dst_port passed as string e.g. "port-443" instead of integer
    mutated_logs = [
        '{"src_ip": "10.0.0.1", "dst_port": "tcp-443", "action": "allow", "user": "alice"}',
        '{"src_ip": "10.0.0.2", "dst_port": "tcp-80", "action": "deny", "user": "bob"}',
    ]
    report = detector.detect_from_logs(
        baseline=baseline_profile,
        current_logs=mutated_logs,
        source_id="app_firewall",
        parser_id="app.firewall.json",
    )

    assert report.drift_state == DriftState.DRIFTED
    assert report.remediation_recommended is True
    assert report.signals.type_violation_rate > 0.0
    assert any("Type violation rate" in d for d in report.drift_details)


def test_parse_failure_spike_drift(detector, baseline_profile):
    """Malformed or corrupted log lines exceeding 2% trigger DRIFTED."""
    # 2 malformed lines out of 10 = 20% parse failure rate (> 2%)
    mixed_logs = [
        '{"src_ip": "10.0.0.1", "dst_port": 443, "action": "allow", "user": "alice"}',
        '{"src_ip": "10.0.0.2", "dst_port": 80, "action": "deny", "user": "bob"}',
        '{"src_ip": "10.0.0.3", "dst_port": 22, "action": "allow", "user": "charlie"}',
        '{"src_ip": "10.0.0.4", "dst_port": 443, "action": "allow", "user": "david"}',
        '{"src_ip": "10.0.0.5", "dst_port": 8080, "action": "deny", "user": "eve"}',
        '{"src_ip": "10.0.0.6", "dst_port": 443, "action": "allow", "user": "frank"}',
        '{"src_ip": "10.0.0.7", "dst_port": 80, "action": "deny", "user": "grace"}',
        '{"src_ip": "10.0.0.8", "dst_port": 22, "action": "allow", "user": "heidi"}',
        'CORRUPTED GARBAGE LINE 1 {{{ INVALID JSON',
        'CORRUPTED GARBAGE LINE 2 [UNPARSEABLE]',
    ]
    report = detector.detect_from_logs(
        baseline=baseline_profile,
        current_logs=mixed_logs,
        source_id="app_firewall",
        parser_id="app.firewall.json",
    )

    assert report.drift_state == DriftState.DRIFTED
    assert report.remediation_recommended is True
    assert report.signals.parse_failure_rate >= 0.02
    assert any("Parse failure rate" in d for d in report.drift_details)


def test_custom_configurable_thresholds_override(profiler, baseline_profile):
    """Scope guard verification: thresholds are configurable defaults, not universal truths."""
    lenient_thresholds = DriftThresholds(
        parse_failure_rate=0.30,  # 30% tolerance instead of 2%
        key_set_distance=0.50,
    )
    lenient_detector = StructuralDriftDetector(thresholds=lenient_thresholds, profiler=profiler)

    # 10% corrupted lines (1 out of 10)
    logs = [
        '{"src_ip": "10.0.0.1", "dst_port": 443, "action": "allow", "user": "alice"}',
        '{"src_ip": "10.0.0.2", "dst_port": 80, "action": "deny", "user": "bob"}',
        '{"src_ip": "10.0.0.3", "dst_port": 22, "action": "allow", "user": "charlie"}',
        '{"src_ip": "10.0.0.4", "dst_port": 443, "action": "allow", "user": "david"}',
        '{"src_ip": "10.0.0.5", "dst_port": 8080, "action": "deny", "user": "eve"}',
        '{"src_ip": "10.0.0.6", "dst_port": 443, "action": "allow", "user": "frank"}',
        '{"src_ip": "10.0.0.7", "dst_port": 80, "action": "deny", "user": "grace"}',
        '{"src_ip": "10.0.0.8", "dst_port": 22, "action": "allow", "user": "heidi"}',
        '{"src_ip": "10.0.0.9", "dst_port": 80, "action": "allow", "user": "ivan"}',
        'CORRUPTED_LINE_X',
    ]

    report = lenient_detector.detect_from_logs(
        baseline=baseline_profile,
        current_logs=logs,
        source_id="app_firewall",
        parser_id="app.firewall.json",
    )

    # Because 10% is below the 30% custom threshold, it is evaluated as STABLE
    assert report.drift_state == DriftState.STABLE
    assert report.remediation_recommended is False


def test_drift_report_contract_compliance(detector, baseline_profile):
    """Verifies that to_dict() produces valid JSON matching drift_report.schema.json."""
    from tests.contracts.test_schemas import validate

    schema = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    current_logs = [
        '{"src_ip": "10.0.0.1", "dst_port": 443, "action": "allow", "user": "alice"}',
    ]
    report = detector.detect_from_logs(
        baseline=baseline_profile,
        current_logs=current_logs,
        source_id="demo-firewall",
        parser_id="demo.firewall.kv",
        parser_version="1.0.0",
        baseline_run_id="base-001",
    )

    report_dict = report.to_dict()
    # Validate against JSON schema contract
    validate(report_dict, schema, schema)
    assert report_dict["schema_version"] == "1.0"
    assert report_dict["drift_state"] == "STABLE"
    assert "signals" in report_dict
    assert "thresholds" in report_dict
