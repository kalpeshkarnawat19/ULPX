"""Build Telemetry Passports from validation evidence; never invent metrics."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from math import isfinite
from typing import Mapping, Optional

NOT_YET_MEASURED = "NOT YET MEASURED"
METRIC_NAMES = (
    "extraction_accuracy", "semantic_accuracy", "raw_retention",
    "unknown_field_retention", "detection_preservation",
)
DRIFT_STATES = {"STABLE", "SUSPECTED", "DRIFTED"}


@dataclass(frozen=True)
class ValidationEvidence:
    """Immutable measurements produced by a completed validation run."""
    run_id: str
    completed_at: datetime
    passed: bool
    metrics: Mapping[str, float]
    drift_state: Optional[str] = None
    drift_observed_at: Optional[datetime] = None


class TelemetryPassportBuilder:
    """Creates a certified passport only from passed, complete evidence."""

    def build(self, source_id: str, parser_id: str, parser_version: str,
              evidence: Optional[ValidationEvidence] = None) -> dict:
        self._required_text("source_id", source_id)
        self._required_text("parser_id", parser_id)
        self._required_text("parser_version", parser_version)
        if evidence is None or not evidence.passed:
            return self._unmeasured(source_id, parser_id, parser_version, evidence)
        self._validate_evidence(evidence)
        return {
            "schema_version": "1.1",
            "source_id": source_id,
            "parser": {"id": parser_id, "version": parser_version},
            "validation": {
                "status": "PASSED", "run_id": evidence.run_id,
                "completed_at": self._timestamp(evidence.completed_at),
            },
            "certification": {"status": "CERTIFIED", "timestamp": self._timestamp(evidence.completed_at)},
            "scores": {name: evidence.metrics[name] for name in METRIC_NAMES},
            "drift": {"state": evidence.drift_state, "observed_at": self._timestamp(evidence.drift_observed_at)},
        }

    @staticmethod
    def _unmeasured(source_id: str, parser_id: str, parser_version: str,
                    evidence: Optional[ValidationEvidence]) -> dict:
        validation = {"status": "NOT_YET_MEASURED", "run_id": None, "completed_at": None}
        if evidence is not None:
            TelemetryPassportBuilder._required_text("validation run_id", evidence.run_id)
            validation = {"status": "FAILED", "run_id": evidence.run_id,
                          "completed_at": TelemetryPassportBuilder._timestamp(evidence.completed_at)}
        return {
            "schema_version": "1.1", "source_id": source_id,
            "parser": {"id": parser_id, "version": parser_version},
            "validation": validation,
            "certification": {"status": "NOT_CERTIFIED", "timestamp": None},
            "scores": {name: NOT_YET_MEASURED for name in METRIC_NAMES},
            "drift": {"state": "NOT_YET_MEASURED", "observed_at": None},
        }

    @staticmethod
    def _validate_evidence(evidence: ValidationEvidence) -> None:
        TelemetryPassportBuilder._required_text("validation run_id", evidence.run_id)
        if evidence.completed_at.tzinfo is None:
            raise ValueError("validation completed_at must be timezone-aware")
        if evidence.drift_state not in DRIFT_STATES or evidence.drift_observed_at is None:
            raise ValueError("certification requires a measured drift state and observation time")
        if evidence.drift_observed_at.tzinfo is None:
            raise ValueError("drift observed_at must be timezone-aware")
        if set(evidence.metrics) != set(METRIC_NAMES):
            raise ValueError("validation evidence must contain exactly the passport metrics")
        for name, value in evidence.metrics.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"metric {name} must be a finite number from 0 to 1")

    @staticmethod
    def _required_text(name: str, value: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} is required")

    @staticmethod
    def _timestamp(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
