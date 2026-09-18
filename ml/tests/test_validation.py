"""
Unit tests for Validation Engine (Stage 11 & Stage 14 Evidence Generation).
Verifies calculation of real empirical validation metrics and passport certification linkage.
"""

from pathlib import Path
import pytest

from ml.passport.passport import TelemetryPassportBuilder, NOT_YET_MEASURED
from ml.validation.validator import ValidationEngine, ValidationReport

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "golden"


@pytest.fixture
def engine():
    return ValidationEngine()


def test_validate_cef_golden_fixture(engine):
    cef_dir = FIXTURES_DIR / "cef_edr"
    report = engine.validate_golden_source(cef_dir)

    assert report.passed is True
    assert report.critical_passed is True
    assert report.mandatory_dps_passed is True
    assert report.metrics["extraction_accuracy"] == 1.0
    assert report.metrics["semantic_accuracy"] == 1.0
    assert report.metrics["raw_retention"] == 1.0
    assert report.metrics["unknown_field_retention"] == 1.0
    assert report.metrics["detection_preservation"] == 1.0

    # Test evidence generation and Telemetry Passport certification
    evidence = report.to_evidence()
    passport = TelemetryPassportBuilder().build(
        source_id="cef_edr",
        parser_id=report.parser_id,
        parser_version=report.parser_version,
        evidence=evidence,
    )

    assert passport["certification"]["status"] == "CERTIFIED"
    assert passport["validation"]["status"] == "PASSED"
    assert passport["scores"]["extraction_accuracy"] == 1.0
    assert passport["scores"]["raw_retention"] == 1.0
    assert passport["scores"]["detection_preservation"] == 1.0
    assert passport["drift"]["state"] == "STABLE"


def test_validate_syslog_golden_fixture(engine):
    syslog_dir = FIXTURES_DIR / "syslog_firewall"
    report = engine.validate_golden_source(syslog_dir)

    assert report.passed is True
    assert report.critical_passed is True
    assert report.metrics["raw_retention"] == 1.0
    assert report.metrics["unknown_field_retention"] == 1.0

    evidence = report.to_evidence()
    passport = TelemetryPassportBuilder().build(
        source_id="syslog_firewall",
        parser_id=report.parser_id,
        parser_version=report.parser_version,
        evidence=evidence,
    )

    assert passport["certification"]["status"] == "CERTIFIED"
    assert passport["validation"]["status"] == "PASSED"


def test_validation_failure_blocks_certification(engine):
    # Simulate a corrupted or invalid event specification where critical fields fail
    raw_event = "CEF:0|Vendor|Prod|1.0|100|Event|5|src=10.0.0.1"
    parser_spec = {
        "parser": {"id": "test.fail", "version": "1.0.0"},
        "match": {"format": "cef"},
        "fields": {},
    }
    expected_extracted = {"src.ip": "10.0.0.1", "dst.ip": "192.168.1.1"}
    critical_fields = ["dst.ip"]  # Missing from extraction!
    expected_unknown = {}

    report = engine.validate_event(
        raw_event=raw_event,
        parser_spec=parser_spec,
        expected_extracted=expected_extracted,
        critical_fields=critical_fields,
        expected_unknown=expected_unknown,
    )

    assert report.passed is False
    assert report.critical_passed is False

    # Evidence from failed run must NOT certify passport
    evidence = report.to_evidence()
    passport = TelemetryPassportBuilder().build(
        source_id="fail_source",
        parser_id=report.parser_id,
        parser_version=report.parser_version,
        evidence=evidence,
    )

    assert passport["certification"]["status"] == "NOT_CERTIFIED"
    assert passport["validation"]["status"] == "FAILED"
    # All scores must be NOT YET MEASURED, never fabricated numbers!
    for score_name, score_val in passport["scores"].items():
        assert score_val == NOT_YET_MEASURED


def test_validate_all_golden_corpora(engine):
    golden_dirs = [d for d in FIXTURES_DIR.iterdir() if d.is_dir()]
    assert len(golden_dirs) >= 6
    for g_dir in golden_dirs:
        report = engine.validate_golden_source(g_dir)
        assert report.passed is True, f"Failed on {g_dir.name}: {report.violations}"
        assert report.metrics["raw_retention"] == 1.0
        assert report.metrics["unknown_field_retention"] == 1.0
        assert report.metrics["extraction_accuracy"] >= 0.95

