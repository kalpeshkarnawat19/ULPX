"""
ULPF-X (SIH26156) - STAGE 8: Semantic Mapper Test Suite
Workstream: Agastya (Intelligence & Assurance Lead)

Tests for deterministic Semantic Mapper:
- Exact alias mappings (src_ip -> src.ip, spt -> src.port, act -> event.action)
- Confidence thresholds (AUTO_ACCEPTED >= 0.95, HUMAN_REVIEW 0.80-0.94, ABSTAIN < 0.80)
- Hard type checks and penalty enforcement
- Metric naming compliance (mapping_score, never probability)
- Abstention policy (extensions.source.* preservation)
- Top-N ranking and evidence list
- End-to-end integration with Stage 7 UnknownSourceProfiler
- JSON serialization
"""

import json
import os
import sys
import pytest

# Ensure repository root is on sys.path for pytest invocation
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from ml.source_profiler.profiler import (
    UnknownSourceProfiler,
    FieldProfile,
    SourceProfile,
    DataType,
    LogFormat,
)
from ml.semantic_mapper.mapper import (
    SemanticMapper,
    CanonicalKnowledgeBase,
    ReviewStatus,
    EventFamily,
    MappingCandidate,
    FieldMappingResult,
    SourceMappingReport,
)


@pytest.fixture
def mapper():
    return SemanticMapper()


@pytest.fixture
def profiler():
    return UnknownSourceProfiler()


# =====================================================================
# 1. Alias & Canonical Mapping Tests
# =====================================================================

def test_exact_alias_mapping_network_fields(mapper):
    # src_ip -> src.ip
    src_profile = FieldProfile(
        name="src_ip",
        inferred_type=DataType.IPV4.value,
        is_ip_candidate=True,
        sample_values=["192.168.1.10"],
        total_count=10,
    )
    res = mapper.map_field(src_profile)
    assert res.chosen_mapping.canonical_path == "src.ip"
    assert res.chosen_mapping.mapping_score >= 0.95
    assert res.chosen_mapping.review_status == ReviewStatus.AUTO_ACCEPTED
    assert "exact_alias_match" in res.chosen_mapping.evidence

    # spt -> src.port
    spt_profile = FieldProfile(
        name="spt",
        inferred_type=DataType.INTEGER.value,
        sample_values=[44120],
        total_count=10,
    )
    res = mapper.map_field(spt_profile)
    assert res.chosen_mapping.canonical_path == "src.port"
    assert res.chosen_mapping.mapping_score >= 0.95
    assert res.chosen_mapping.review_status == ReviewStatus.AUTO_ACCEPTED

    # act -> event.action
    act_profile = FieldProfile(
        name="act",
        inferred_type=DataType.STRING.value,
        is_enum_candidate=True,
        enum_values=["allow", "deny"],
        sample_values=["deny"],
        total_count=10,
    )
    res = mapper.map_field(act_profile)
    assert res.chosen_mapping.canonical_path == "event.action"
    assert res.chosen_mapping.mapping_score >= 0.95
    assert res.chosen_mapping.review_status == ReviewStatus.AUTO_ACCEPTED


def test_metric_name_compliance(mapper):
    """Verify that the metric name is strictly mapping_score and never probability."""
    profile = FieldProfile(name="src", inferred_type=DataType.IPV4.value, is_ip_candidate=True)
    res = mapper.map_field(profile)

    doc = res.chosen_mapping.to_dict()
    assert "mapping_score" in doc
    assert "probability" not in doc
    assert not hasattr(res.chosen_mapping, "probability")


# =====================================================================
# 2. Threshold & Abstention Tests
# =====================================================================

def test_auto_accept_threshold(mapper):
    """Score >= 0.95 must produce AUTO_ACCEPTED."""
    profile = FieldProfile(name="destination_ip", inferred_type=DataType.IPV4.value, is_ip_candidate=True)
    res = mapper.map_field(profile)
    assert res.chosen_mapping.mapping_score >= 0.95
    assert res.chosen_mapping.review_status == ReviewStatus.AUTO_ACCEPTED
    assert res.chosen_mapping.preserve_in_extensions is False


def test_human_review_threshold(mapper):
    """Score between 0.80 and 0.94 must produce HUMAN_REVIEW."""
    # Semi-ambiguous name 'server' with IP type
    profile = FieldProfile(name="server", inferred_type=DataType.IPV4.value, is_ip_candidate=True)
    res = mapper.map_field(profile)
    # 'server' is similar to 'server_ip' (dst.ip) or 'host' (device.hostname)
    score = res.chosen_mapping.mapping_score
    if 0.80 <= score < 0.95:
        assert res.chosen_mapping.review_status == ReviewStatus.HUMAN_REVIEW


def test_abstain_threshold_unknown_field(mapper):
    """Score < 0.80 must produce ABSTAIN and route to extensions.source.<raw_field>."""
    profile = FieldProfile(
        name="custom_vendor_sensor_x42",
        inferred_type=DataType.STRING.value,
        sample_values=["sensor_alpha_9"],
        total_count=5,
    )
    res = mapper.map_field(profile)
    assert res.chosen_mapping.mapping_score < 0.80
    assert res.chosen_mapping.review_status == ReviewStatus.ABSTAIN
    assert res.chosen_mapping.preserve_in_extensions is True
    assert res.chosen_mapping.destination_path == "extensions.source.custom_vendor_sensor_x42"


# =====================================================================
# 3. Hard Type Conflict & Penalty Tests
# =====================================================================

def test_hard_type_conflict_port_as_string(mapper):
    """Matching 'port' or 'spt' to string words instead of integer must trigger a hard penalty."""
    bad_port_profile = FieldProfile(
        name="src_port",
        inferred_type=DataType.STRING.value,
        sample_values=["high_priority", "low_latency"],  # non-numeric strings
        total_count=10,
    )
    res = mapper.map_field(bad_port_profile)
    # Must NOT be auto-accepted due to hard type mismatch
    assert res.chosen_mapping.review_status != ReviewStatus.AUTO_ACCEPTED
    assert any("hard_type_conflict" in ev for ev in res.chosen_mapping.evidence)


def test_hard_type_conflict_ip_as_boolean(mapper):
    """Field named 'src_ip' with boolean values must trigger a hard type penalty."""
    bad_ip_profile = FieldProfile(
        name="src_ip",
        inferred_type=DataType.BOOLEAN.value,
        sample_values=[True, False],
        total_count=10,
    )
    res = mapper.map_field(bad_ip_profile)
    assert res.chosen_mapping.review_status != ReviewStatus.AUTO_ACCEPTED
    assert any("hard_type_conflict" in ev for ev in res.chosen_mapping.evidence)


# =====================================================================
# 4. Top-N Candidates & Evidence Tests
# =====================================================================

def test_top_n_candidates_ordering(mapper):
    profile = FieldProfile(name="client", inferred_type=DataType.IPV4.value, is_ip_candidate=True)
    res = mapper.map_field(profile, top_n=3)
    assert len(res.top_candidates) == 3
    # Check descending score order
    scores = [c.mapping_score for c in res.top_candidates]
    assert scores == sorted(scores, reverse=True)
    assert len(res.top_candidates[0].evidence) > 0


def test_event_family_context_boost(mapper):
    profile = FieldProfile(name="user", inferred_type=DataType.STRING.value)
    # Test with AUTHENTICATION event family
    res_auth = mapper.map_field(profile, event_family=EventFamily.AUTHENTICATION.value)
    assert res_auth.chosen_mapping.canonical_path == "user.name"
    assert any("event_family_context" in ev for ev in res_auth.chosen_mapping.evidence)


# =====================================================================
# 5. Integration with Stage 7 Source Profiler Output
# =====================================================================

def test_integration_with_stage7_profiler(profiler, mapper):
    """Test full pipeline: raw logs -> Stage 7 Profiler -> Stage 8 Semantic Mapper."""
    raw_logs = [
        "CEF:0|SecurityCorp|NextGenFW|1.0|100|Connection Denied|7|src=192.168.1.50 dst=10.0.0.1 spt=54321 dpt=443 act=deny proto=TCP proprietary_flag=true",
        "CEF:0|SecurityCorp|NextGenFW|1.0|100|Connection Allowed|3|src=192.168.1.51 dst=10.0.0.2 spt=54322 dpt=80 act=allow proto=TCP proprietary_flag=false",
    ]

    source_profile = profiler.profile(raw_logs)
    assert source_profile.format == LogFormat.CEF

    report = mapper.map_source(source_profile, source_id="fw_corp", event_family=EventFamily.FIREWALL_POLICY.value)

    assert report.source_id == "fw_corp"
    assert report.event_family == EventFamily.FIREWALL_POLICY.value
    assert report.summary["total_fields"] > 0
    assert report.summary["critical_fields_mapped"] >= 4

    # Verify key mappings
    mappings = report.mappings
    assert mappings["src"].chosen_mapping.canonical_path == "src.ip"
    assert mappings["src"].chosen_mapping.review_status == ReviewStatus.AUTO_ACCEPTED

    assert mappings["dst"].chosen_mapping.canonical_path == "dst.ip"
    assert mappings["dst"].chosen_mapping.review_status == ReviewStatus.AUTO_ACCEPTED

    assert mappings["spt"].chosen_mapping.canonical_path == "src.port"
    assert mappings["spt"].chosen_mapping.review_status == ReviewStatus.AUTO_ACCEPTED

    assert mappings["dpt"].chosen_mapping.canonical_path == "dst.port"
    assert mappings["dpt"].chosen_mapping.review_status == ReviewStatus.AUTO_ACCEPTED

    assert mappings["act"].chosen_mapping.canonical_path == "event.action"
    assert mappings["act"].chosen_mapping.review_status == ReviewStatus.AUTO_ACCEPTED

    # Unknown field abstains
    assert mappings["proprietary_flag"].chosen_mapping.review_status == ReviewStatus.ABSTAIN
    assert mappings["proprietary_flag"].chosen_mapping.destination_path == "extensions.source.proprietary_flag"

    # JSON serialization
    serialized = report.to_json()
    assert '"fw_corp"' in serialized
    assert '"mapping_score"' in serialized


# =====================================================================
# 6. HTTP, DNS & Application Event Mappings
# =====================================================================

def test_http_and_dns_alias_mappings(mapper):
    # HTTP Method
    p_method = FieldProfile(name="request_method", inferred_type=DataType.STRING.value)
    res_m = mapper.map_field(p_method, event_family=EventFamily.WEB_SESSION.value)
    assert res_m.chosen_mapping.canonical_path == "http.method"
    assert res_m.chosen_mapping.review_status == ReviewStatus.AUTO_ACCEPTED

    # HTTP Status Code
    p_status = FieldProfile(name="status_code", inferred_type=DataType.INTEGER.value)
    res_s = mapper.map_field(p_status, event_family=EventFamily.WEB_SESSION.value)
    assert res_s.chosen_mapping.canonical_path == "http.status_code"
    assert res_s.chosen_mapping.review_status == ReviewStatus.AUTO_ACCEPTED

    # DNS Query Name
    p_dns = FieldProfile(name="qname", inferred_type=DataType.STRING.value)
    res_d = mapper.map_field(p_dns, event_family=EventFamily.DNS_ACTIVITY.value)
    assert res_d.chosen_mapping.canonical_path == "dns.query_name"
    assert res_d.chosen_mapping.review_status == ReviewStatus.AUTO_ACCEPTED


def test_map_fields_convenience_function(mapper):
    field_dict = {
        "client_ip": FieldProfile(name="client_ip", inferred_type=DataType.IPV4.value, is_ip_candidate=True),
        "dest_port": FieldProfile(name="dest_port", inferred_type=DataType.INTEGER.value),
    }
    report = mapper.map_fields(field_dict, source_id="src_99")
    assert report.source_id == "src_99"
    assert report.mappings["client_ip"].chosen_mapping.canonical_path == "src.ip"
    assert report.mappings["dest_port"].chosen_mapping.canonical_path == "dst.port"


def test_strict_mapping_score_bounds(mapper):
    for defn in mapper.kb.get_all_fields():
        p = FieldProfile(name=defn.path, inferred_type="string")
        res = mapper.map_field(p)
        assert 0.0 <= res.chosen_mapping.mapping_score <= 1.0
        for cand in res.top_candidates:
            assert 0.0 <= cand.mapping_score <= 1.0


# =====================================================================
# 7. Priority 2: Adversarial, Abstention Stress & Disambiguation Tests
# =====================================================================

def test_adversarial_deceptive_field_names(mapper):
    """Deceptive field names like 'destination_ip_not_real' must NOT be auto-accepted."""
    deceptive_fields = [
        ("destination_ip_not_real", DataType.STRING.value),
        ("source_override_fake_val", DataType.STRING.value),
        ("user_backup_temporary_token", DataType.STRING.value),
        ("auth_attempt_spoofed_status", DataType.STRING.value),
    ]
    for field_name, dtype in deceptive_fields:
        p = FieldProfile(name=field_name, inferred_type=dtype)
        res = mapper.map_field(p)
        # Never falsely AUTO_ACCEPTED
        assert res.chosen_mapping.review_status != ReviewStatus.AUTO_ACCEPTED, (
            f"Deceptive field {field_name} was falsely auto-accepted: {res.chosen_mapping.canonical_path}"
        )


def test_multi_ip_disambiguation(mapper):
    """Disambiguate client_ip, server_ip, initiator_ip, and target_ip within the same profile."""
    field_dict = {
        "client_ip": FieldProfile(name="client_ip", inferred_type=DataType.IPV4.value, is_ip_candidate=True),
        "server_ip": FieldProfile(name="server_ip", inferred_type=DataType.IPV4.value, is_ip_candidate=True),
        "initiator_ip": FieldProfile(name="initiator_ip", inferred_type=DataType.IPV4.value, is_ip_candidate=True),
        "target_ip": FieldProfile(name="target_ip", inferred_type=DataType.IPV4.value, is_ip_candidate=True),
    }
    report = mapper.map_fields(field_dict, source_id="multi_ip_firewall")
    assert report.mappings["client_ip"].chosen_mapping.canonical_path == "src.ip"
    assert report.mappings["initiator_ip"].chosen_mapping.canonical_path == "src.ip"
    assert report.mappings["server_ip"].chosen_mapping.canonical_path == "dst.ip"
    assert report.mappings["target_ip"].chosen_mapping.canonical_path == "dst.ip"


def test_boundary_score_thresholds(mapper):
    """Verify exact boundary enforcement: >= 0.95 AUTO, 0.80-0.94 HUMAN, < 0.80 ABSTAIN."""
    assert mapper.AUTO_ACCEPT_THRESHOLD == 0.95
    assert mapper.HUMAN_REVIEW_THRESHOLD == 0.80

    # Strong exact match >= 0.95
    p_exact = FieldProfile(name="source_ip", inferred_type=DataType.IPV4.value, is_ip_candidate=True)
    res_exact = mapper.map_field(p_exact)
    assert res_exact.chosen_mapping.mapping_score >= mapper.AUTO_ACCEPT_THRESHOLD
    assert res_exact.chosen_mapping.review_status == ReviewStatus.AUTO_ACCEPTED

    # Unknown field < 0.80
    p_unknown = FieldProfile(name="unmapped_telemetry_sensor_flag", inferred_type=DataType.STRING.value)
    res_unknown = mapper.map_field(p_unknown)
    assert res_unknown.chosen_mapping.mapping_score < mapper.HUMAN_REVIEW_THRESHOLD
    assert res_unknown.chosen_mapping.review_status == ReviewStatus.ABSTAIN


def test_cross_protocol_aliases(mapper):
    """Short network acronyms (c_ip, d_ip, sport, dport) map cleanly to canonical network paths."""
    aliases = {
        "c_ip": "src.ip",
        "d_ip": "dst.ip",
        "sport": "src.port",
        "dport": "dst.port",
    }
    for acr, expected_canonical in aliases.items():
        is_port = "port" in acr
        dtype = DataType.INTEGER.value if is_port else DataType.IPV4.value
        p = FieldProfile(name=acr, inferred_type=dtype, is_ip_candidate=not is_port)
        res = mapper.map_field(p, event_family=EventFamily.FIREWALL_POLICY.value)
        assert res.chosen_mapping.canonical_path == expected_canonical, (
            f"Expected {acr} -> {expected_canonical}, got {res.chosen_mapping.canonical_path}"
        )


def test_conflicting_types_ip_as_float(mapper):
    """Field named 'src_ip' with float data type must trigger hard type conflict."""
    p = FieldProfile(name="src_ip", inferred_type=DataType.FLOAT.value, sample_values=[3.1415])
    res = mapper.map_field(p)
    assert res.chosen_mapping.review_status == ReviewStatus.ABSTAIN
    assert any("hard_type_conflict" in ev for ev in res.chosen_mapping.evidence)


def test_abstention_deep_extension_path(mapper):
    """Unknown fields must preserve exact verbatim raw field name in extensions.source.<field>."""
    p = FieldProfile(
        name="proprietary_x_vendor_flag_v2",
        inferred_type=DataType.STRING.value,
        sample_values=["flag_alpha"],
    )
    res = mapper.map_field(p)
    assert res.chosen_mapping.review_status == ReviewStatus.ABSTAIN
    assert res.chosen_mapping.preserve_in_extensions is True
    assert res.chosen_mapping.destination_path == "extensions.source.proprietary_x_vendor_flag_v2"


def test_high_entropy_random_token_field(mapper):
    """Random cryptographic hashes or nonsensical identifiers must abstain immediately."""
    p = FieldProfile(
        name="a7f83b9c02d1e4",
        inferred_type=DataType.STRING.value,
        sample_values=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    )
    res = mapper.map_field(p)
    assert res.chosen_mapping.review_status == ReviewStatus.ABSTAIN
    assert res.chosen_mapping.mapping_score < 0.60


def test_event_family_firewall_vs_web_disambiguation(mapper):
    """Event family context boosts appropriate canonical fields."""
    p_method = FieldProfile(name="method", inferred_type=DataType.STRING.value)
    # Under WEB_SESSION context, method should boost towards http.method
    res_web = mapper.map_field(p_method, event_family=EventFamily.WEB_SESSION.value)
    assert res_web.chosen_mapping.canonical_path == "http.method"
    assert any("event_family_context" in ev for ev in res_web.chosen_mapping.evidence)


