"""Stage 14 executable assurance rules; uses only the standard library."""
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.passport.passport import (  # noqa: E402
    METRIC_NAMES, NOT_YET_MEASURED, TelemetryPassportBuilder, ValidationEvidence,
)


def evidence(**overrides):
    values = {
        "run_id": "validation-001", "completed_at": datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc),
        "passed": True, "metrics": {name: 1.0 for name in METRIC_NAMES},
        "drift_state": "STABLE", "drift_observed_at": datetime(2026, 9, 18, 12, 1, tzinfo=timezone.utc),
    }
    values.update(overrides)
    return ValidationEvidence(**values)


def test_certified_passport_uses_exact_measured_evidence():
    result = TelemetryPassportBuilder().build("demo-firewall", "demo.firewall.kv", "1.4.0", evidence())
    assert result["certification"]["status"] == "CERTIFIED"
    assert result["validation"]["status"] == "PASSED"
    assert result["validation"]["run_id"] == "validation-001"
    assert result["scores"] == {name: 1.0 for name in METRIC_NAMES}
    assert result["drift"]["state"] == "STABLE"


def test_absent_or_failed_evidence_never_exposes_placeholder_scores():
    builder = TelemetryPassportBuilder()
    for item in (None, evidence(passed=False)):
        result = builder.build("demo-firewall", "demo.firewall.kv", "1.4.0", item)
        assert result["certification"]["status"] == "NOT_CERTIFIED"
        assert set(result["scores"].values()) == {NOT_YET_MEASURED}
        assert result["drift"] == {"state": "NOT_YET_MEASURED", "observed_at": None}
    assert builder.build("demo", "parser", "1.0.0", None)["validation"]["status"] == "NOT_YET_MEASURED"


def test_certification_refuses_incomplete_or_unmeasured_evidence():
    builder = TelemetryPassportBuilder()
    for invalid in (evidence(drift_state=None), evidence(metrics={name: 1.0 for name in METRIC_NAMES if name != "raw_retention"})):
        try:
            builder.build("demo-firewall", "demo.firewall.kv", "1.4.0", invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("incomplete evidence must not certify a passport")


if __name__ == "__main__":
    test_certified_passport_uses_exact_measured_evidence()
    test_absent_or_failed_evidence_never_exposes_placeholder_scores()
    test_certification_refuses_incomplete_or_unmeasured_evidence()
    print("PASS Stage 14 Telemetry Passport gate")
