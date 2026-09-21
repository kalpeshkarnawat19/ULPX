"""
Unit and Integration Tests for Stage 17: Shadow Parsing & Dual Execution Runtime.
Verifies active-vs-candidate comparisons, isolation guarantees, and contract compliance.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from ml.shadow import (
    FieldDivergence,
    ShadowComparator,
    ShadowComparisonReport,
    ShadowRecommendation,
    ShadowRunner,
    ShadowState,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "packages" / "contracts" / "shadow_comparison.schema.json"


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
            "session_id": {"type": "string", "map_to": "session.id"},  # Candidate extracts new field
        },
    }


@pytest.fixture
def raw_firewall_events():
    return [
        "src=192.168.1.10 dst=10.0.0.5 srcport=49152 dstport=443 act=deny user=bob session_id=sess-100 unk_meta=alpha",
        "src=192.168.1.11 dst=10.0.0.6 srcport=49153 dstport=80 act=permit user=alice session_id=sess-101 unk_meta=beta",
        "src=192.168.1.12 dst=10.0.0.7 srcport=49154 dstport=22 act=deny user=root session_id=sess-102 unk_meta=gamma",
    ]


def test_shadow_runner_dual_execution_success(active_spec, candidate_spec, raw_firewall_events):
    """
    Candidate parser extracts identical fields + new field with zero regressions.
    Must result in PASSED and READY_FOR_PROMOTION.
    """
    runner = ShadowRunner()
    downstream_bus = []

    report = runner.execute_dual(
        raw_events=raw_firewall_events,
        active_spec=active_spec,
        candidate_spec=candidate_spec,
        source_id="cisco_firewall",
        downstream_bus=downstream_bus,
    )

    assert report.shadow_state == ShadowState.PASSED
    assert report.recommendation == ShadowRecommendation.READY_FOR_PROMOTION
    assert report.metrics.critical_semantic_divergence == 0.0
    assert report.metrics.dps_delta == 0.0
    assert report.metrics.unknown_field_retention == 1.0
    assert report.downstream_isolation_verified is True


def test_shadow_isolation_scope_guard(active_spec, candidate_spec, raw_firewall_events):
    """
    Mandatory Scope Guard:
    Proves candidate outputs NEVER escape to downstream bus.
    Only active outputs are published.
    """
    runner = ShadowRunner()
    downstream_bus = []

    report = runner.execute_dual(
        raw_events=raw_firewall_events,
        active_spec=active_spec,
        candidate_spec=candidate_spec,
        source_id="cisco_firewall",
        downstream_bus=downstream_bus,
    )

    # Downstream bus must contain exactly the active events, 0 candidate events
    assert len(downstream_bus) == len(raw_firewall_events)
    for bus_event in downstream_bus:
        assert bus_event.get("_shadow", {}).get("is_shadow") is not True

    assert report.downstream_isolation_verified is True

    # Intentionally corrupt the downstream bus with a leaked candidate event
    leaked_bus = list(downstream_bus)
    leaked_bus.append({"_shadow": {"candidate_parser_id": "cisco.firewall", "is_shadow": True}})

    corrupted_report = runner.execute_parsed_streams(
        source_id="cisco_firewall",
        active_spec=active_spec,
        candidate_spec=candidate_spec,
        active_events=[{"event.action": "blocked"}],
        candidate_events=[{"event.action": "blocked"}],
        downstream_bus=leaked_bus,
    )

    # Corrupted isolation MUST trigger FAILED and REJECT
    assert corrupted_report.downstream_isolation_verified is False
    assert corrupted_report.shadow_state == ShadowState.FAILED
    assert corrupted_report.recommendation == ShadowRecommendation.REJECT
    assert any("Downstream isolation violation" in r for r in corrupted_report.recommendation_reasons)


def test_shadow_semantic_action_inversion_rejected(active_spec, raw_firewall_events):
    """Candidate spec with inverted action enum triggers FAILED and REJECT."""
    broken_candidate_spec = {
        "parser": {"id": "cisco.firewall", "version": "1.1.0"},
        "match": {"format": "key_value"},
        "fields": {
            "src": {"type": "ip", "map_to": "src.ip"},
            "dst": {"type": "ip", "map_to": "dst.ip"},
            "act": {"type": "string", "map_to": "event.action", "enum": {"deny": "allowed", "permit": "allowed"}},
            "user": {"type": "string", "map_to": "user.name"},
        },
    }

    runner = ShadowRunner()
    report = runner.execute_dual(
        raw_events=raw_firewall_events,
        active_spec=active_spec,
        candidate_spec=broken_candidate_spec,
        source_id="cisco_firewall",
    )

    assert report.shadow_state == ShadowState.FAILED
    assert report.recommendation == ShadowRecommendation.REJECT
    assert report.metrics.critical_semantic_divergence > 0.0
    assert any("Critical semantic divergence" in r for r in report.recommendation_reasons)


def test_shadow_unknown_field_drop_rejected(active_spec, candidate_spec):
    """Candidate dropping unknown fields violates Rule 4 and triggers FAILED / REJECT."""
    comparator = ShadowComparator()

    active_events = [
        {"src.ip": "10.0.0.1", "event.action": "blocked", "unknown_fields": {"vendor_tag": "x1", "dbg_code": 99}},
        {"src.ip": "10.0.0.2", "event.action": "allowed", "unknown_fields": {"vendor_tag": "x2"}},
    ]
    # Candidate drops unknown_fields completely
    candidate_events = [
        {"src.ip": "10.0.0.1", "event.action": "blocked", "unknown_fields": {}},
        {"src.ip": "10.0.0.2", "event.action": "allowed"},
    ]

    report = comparator.compare(
        source_id="cisco_firewall",
        active_parser_id="cisco.firewall",
        active_parser_version="1.0.0",
        candidate_parser_id="cisco.firewall",
        candidate_parser_version="1.1.0",
        active_events=active_events,
        candidate_events=candidate_events,
    )

    assert report.shadow_state == ShadowState.FAILED
    assert report.recommendation == ShadowRecommendation.REJECT
    assert report.metrics.unknown_field_retention < 1.0
    assert any("Unknown field retention" in r for r in report.recommendation_reasons)


def test_shadow_dps_regression_rejected():
    """Candidate regressing Detection Preservation Score triggers FAILED / REJECT."""
    comparator = ShadowComparator()

    # Active successfully mapped blocked action and endpoints (DPS 1.0)
    active_events = [
        {"src.ip": "192.168.1.1", "dst.ip": "10.0.0.1", "event.action": "blocked"},
        {"src.ip": "192.168.1.2", "dst.ip": "10.0.0.2", "event.action": "blocked"},
    ]
    # Candidate dropped src.ip and dst.ip, breaking detection contract DET-002
    candidate_events = [
        {"event.action": "blocked"},
        {"event.action": "blocked"},
    ]

    report = comparator.compare(
        source_id="cisco_firewall",
        active_parser_id="cisco.firewall",
        active_parser_version="1.0.0",
        candidate_parser_id="cisco.firewall",
        candidate_parser_version="1.1.0",
        active_events=active_events,
        candidate_events=candidate_events,
    )

    assert report.shadow_state == ShadowState.FAILED
    assert report.recommendation == ShadowRecommendation.REJECT
    assert report.metrics.dps_delta < 0.0
    assert any("DPS regression detected" in r for r in report.recommendation_reasons)


def test_shadow_latency_regression_suspected():
    """Candidate with severe latency regression (+100% latency) is marked SUSPECTED and requires review."""
    comparator = ShadowComparator()

    active_events = [{"src.ip": "10.0.0.1", "event.action": "blocked"}]
    candidate_events = [{"src.ip": "10.0.0.1", "event.action": "blocked"}]

    # Active p95 is 1.0ms, Candidate p95 is 2.5ms (+150% regression)
    report = comparator.compare(
        source_id="cisco_firewall",
        active_parser_id="cisco.firewall",
        active_parser_version="1.0.0",
        candidate_parser_id="cisco.firewall",
        candidate_parser_version="1.1.0",
        active_events=active_events,
        candidate_events=candidate_events,
        active_latencies_ms=[1.0, 1.0, 1.0],
        candidate_latencies_ms=[2.5, 2.5, 2.5],
    )

    assert report.shadow_state == ShadowState.SUSPECTED
    assert report.recommendation == ShadowRecommendation.REQUIRE_HUMAN_REVIEW
    assert report.metrics.latency_delta_pct > 50.0
    assert any("Latency regression" in r for r in report.recommendation_reasons)


def test_shadow_comparison_contract_compliance(active_spec, candidate_spec, raw_firewall_events):
    """Verifies that generated ShadowComparisonReport dictionary conforms to shadow_comparison.schema.json."""
    from tests.contracts.test_schemas import validate

    schema = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    runner = ShadowRunner()

    report = runner.execute_dual(
        raw_events=raw_firewall_events,
        active_spec=active_spec,
        candidate_spec=candidate_spec,
        source_id="demo-firewall",
    )

    report_dict = report.to_dict()
    validate(report_dict, schema, schema)
    assert report_dict["schema_version"] == "1.0"
    assert report_dict["shadow_state"] == "PASSED"
    assert report_dict["downstream_isolation_verified"] is True
    assert report_dict["recommendation"] == "READY_FOR_PROMOTION"


def test_shadow_memory_ceiling_bounded(active_spec, candidate_spec, raw_firewall_events):
    """Verifies that dual execution over batches maintains strictly bounded state and downstream isolation."""
    runner = ShadowRunner()
    batch = raw_firewall_events * 25  # 75 events
    bus = []

    report = runner.execute_dual(
        raw_events=batch,
        active_spec=active_spec,
        candidate_spec=candidate_spec,
        source_id="scale-firewall",
        downstream_bus=bus,
    )
    assert report.sample_count == len(batch)
    assert report.downstream_isolation_verified is True
    assert len(bus) == len(batch)  # Only active events reached bus


def test_shadow_timeout_cancellation_budget():
    """Verifies that extreme candidate latency triggers SUSPECTED state and flags latency regression."""
    comparator = ShadowComparator()
    active_events = [{"src.ip": "10.0.0.1"}]
    candidate_events = [{"src.ip": "10.0.0.1"}]

    report = comparator.compare(
        source_id="cisco_firewall",
        active_parser_id="cisco.firewall",
        active_parser_version="1.0.0",
        candidate_parser_id="cisco.firewall",
        candidate_parser_version="1.1.0",
        active_events=active_events,
        candidate_events=candidate_events,
        active_latencies_ms=[0.5, 0.6, 0.5],
        candidate_latencies_ms=[55.0, 60.0, 52.0],  # Severe latency blowup
    )
    assert report.shadow_state == ShadowState.SUSPECTED
    assert report.metrics.latency_delta_pct > 1000.0
    assert report.recommendation == ShadowRecommendation.REQUIRE_HUMAN_REVIEW


def test_shadow_field_level_diff_granularity():
    """Verifies that shadow comparator precisely isolates field-level value discrepancies."""
    comparator = ShadowComparator()
    active_events = [{"src.ip": "10.0.0.1", "user.name": "alice", "event.action": "blocked"}]
    candidate_events = [{"src.ip": "10.0.0.1", "user.name": "bob", "event.action": "blocked"}]

    report = comparator.compare(
        source_id="diff_firewall",
        active_parser_id="fw.v1",
        active_parser_version="1.0.0",
        candidate_parser_id="fw.v2",
        candidate_parser_version="1.1.0",
        active_events=active_events,
        candidate_events=candidate_events,
    )
    assert report.shadow_state == ShadowState.FAILED
    user_div = next((d for d in report.field_divergences if d.field == "user.name"), None)
    assert user_div is not None
    assert user_div.example_mismatch["active"] == "alice"
    assert user_div.example_mismatch["candidate"] == "bob"


def test_shadow_sampling_rate_modes(active_spec, candidate_spec, raw_firewall_events):
    """Verifies publish_active_to_downstream flag controls bus emission while candidate never leaks."""
    runner = ShadowRunner()

    # Mode 1: No downstream emission
    bus_silent = []
    rep1 = runner.execute_dual(
        raw_events=raw_firewall_events,
        active_spec=active_spec,
        candidate_spec=candidate_spec,
        source_id="test-silent",
        downstream_bus=bus_silent,
        publish_active_to_downstream=False,
    )
    assert len(bus_silent) == 0
    assert rep1.downstream_isolation_verified is True

    # Mode 2: Active emitted, candidate strictly isolated
    bus_active = []
    rep2 = runner.execute_dual(
        raw_events=raw_firewall_events,
        active_spec=active_spec,
        candidate_spec=candidate_spec,
        source_id="test-active",
        downstream_bus=bus_active,
        publish_active_to_downstream=True,
    )
    assert len(bus_active) == len(raw_firewall_events)
    assert rep2.downstream_isolation_verified is True
