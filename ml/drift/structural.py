"""
Structural Drift Detection Engine for ULPF-X (SIH26156) - Stage 15.
Compares rolling baseline vs. current source profile to detect:
- Field additions and removals (Jaccard structural distance)
- Type mutations across active fields
- Parse failure rate spikes
- Categorical / format distribution divergence

Scope guard:
All thresholds are configurable defaults, not universal truths.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

from ml.source_profiler.profiler import SourceProfile, UnknownSourceProfiler


class DriftState(str, Enum):
    STABLE = "STABLE"
    SUSPECTED = "SUSPECTED"
    DRIFTED = "DRIFTED"


@dataclass(frozen=True)
class DriftThresholds:
    """Configurable drift detection thresholds (PRD Section 9 defaults)."""
    parse_failure_rate: float = 0.02       # 2% parse failure rate
    unknown_field_ratio: float = 0.05      # 5% new/unknown field ratio
    type_violation_rate: float = 0.005     # 0.5% critical type mutations
    key_set_distance: float = 0.15         # 0.15 key-set Jaccard distance
    distribution_divergence: float = 0.20  # 0.20 Total Variation Distance


@dataclass(frozen=True)
class DriftSignals:
    """Measured quantitative drift indicators."""
    parse_failure_rate: float
    unknown_field_ratio: float
    type_violation_rate: float
    key_set_distance: float
    distribution_divergence: float

    def to_dict(self) -> Dict[str, float]:
        return {
            "parse_failure_rate": round(self.parse_failure_rate, 4),
            "unknown_field_ratio": round(self.unknown_field_ratio, 4),
            "type_violation_rate": round(self.type_violation_rate, 4),
            "key_set_distance": round(self.key_set_distance, 4),
            "distribution_divergence": round(self.distribution_divergence, 4),
        }


@dataclass(frozen=True)
class DriftReport:
    """Machine-readable assessment conforming to drift_report.schema.json."""
    source_id: str
    parser_id: str
    parser_version: str
    drift_state: DriftState
    observed_at: datetime
    start_time: datetime
    end_time: datetime
    sample_count: int
    signals: DriftSignals
    thresholds: DriftThresholds
    drift_details: List[str]
    remediation_recommended: bool
    baseline_run_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converts report to dictionary conforming to packages/contracts/drift_report.schema.json."""
        def iso_ts(dt: datetime) -> str:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

        return {
            "schema_version": "1.0",
            "source_id": self.source_id,
            "parser": {
                "id": self.parser_id,
                "version": self.parser_version,
            },
            "drift_state": self.drift_state.value,
            "observed_at": iso_ts(self.observed_at),
            "window": {
                "start_time": iso_ts(self.start_time),
                "end_time": iso_ts(self.end_time),
                "baseline_run_id": self.baseline_run_id,
                "sample_count": self.sample_count,
            },
            "signals": self.signals.to_dict(),
            "thresholds": {
                "parse_failure_rate": self.thresholds.parse_failure_rate,
                "unknown_field_ratio": self.thresholds.unknown_field_ratio,
                "type_violation_rate": self.thresholds.type_violation_rate,
                "key_set_distance": self.thresholds.key_set_distance,
                "distribution_divergence": self.thresholds.distribution_divergence,
            },
            "drift_details": list(self.drift_details),
            "remediation_recommended": self.remediation_recommended,
        }


class StructuralDriftDetector:
    """
    Empirical structural drift detection engine comparing rolling baseline profiles
    against incoming log profiles or sample streams.
    """

    def __init__(
        self,
        thresholds: Optional[DriftThresholds] = None,
        profiler: Optional[UnknownSourceProfiler] = None,
    ):
        self.thresholds = thresholds or DriftThresholds()
        self.profiler = profiler or UnknownSourceProfiler()

    def compare_profiles(
        self,
        baseline: SourceProfile,
        current: SourceProfile,
        source_id: str,
        parser_id: str,
        parser_version: str = "1.0.0",
        baseline_run_id: Optional[str] = None,
        observed_at: Optional[datetime] = None,
    ) -> DriftReport:
        """
        Compares baseline and current source profiles to produce an empirical DriftReport.
        """
        now = observed_at or datetime.now(timezone.utc)
        start_time = now
        end_time = now
        sample_count = current.total_records

        details: List[str] = []

        # 1. Parse Failure Rate
        total_curr = max(1, current.total_records)
        parse_failure_rate = current.corrupted_records / total_curr

        if parse_failure_rate > self.thresholds.parse_failure_rate:
            details.append(
                f"Parse failure rate {parse_failure_rate:.2%} exceeds threshold {self.thresholds.parse_failure_rate:.2%}"
            )

        # 2. Key-set Structural Distance (Jaccard Distance)
        base_keys = set(baseline.fields.keys())
        curr_keys = set(current.fields.keys())
        union_keys = base_keys | curr_keys
        inter_keys = base_keys & curr_keys

        if union_keys:
            jaccard_distance = 1.0 - (len(inter_keys) / len(union_keys))
        else:
            jaccard_distance = 0.0

        new_keys = curr_keys - base_keys
        removed_keys = base_keys - curr_keys

        if jaccard_distance > self.thresholds.key_set_distance:
            details.append(
                f"Key-set structural distance {jaccard_distance:.3f} exceeds threshold {self.thresholds.key_set_distance:.3f} "
                f"(new fields: {sorted(list(new_keys))[:5]}, removed fields: {sorted(list(removed_keys))[:5]})"
            )

        # 3. Unknown Field Ratio
        if curr_keys:
            unknown_field_ratio = len(new_keys) / len(curr_keys)
        else:
            unknown_field_ratio = 0.0

        if unknown_field_ratio > self.thresholds.unknown_field_ratio:
            details.append(
                f"Unknown field ratio {unknown_field_ratio:.2%} exceeds threshold {self.thresholds.unknown_field_ratio:.2%}"
            )

        # 4. Field Type Mutations
        type_violations = 0
        type_mutation_details: List[str] = []
        for k in inter_keys:
            base_type = baseline.fields[k].inferred_type
            curr_type = current.fields[k].inferred_type
            if base_type != curr_type and base_type != "null" and curr_type != "null":
                type_violations += 1
                type_mutation_details.append(f"field '{k}' mutated from {base_type} to {curr_type}")

        if inter_keys:
            type_violation_rate = type_violations / len(inter_keys)
        else:
            type_violation_rate = 0.0

        if type_violation_rate > self.thresholds.type_violation_rate:
            details.append(
                f"Type violation rate {type_violation_rate:.2%} exceeds threshold {self.thresholds.type_violation_rate:.2%}: "
                f"{'; '.join(type_mutation_details[:5])}"
            )

        # 5. Format & Distribution Divergence (Total Variation Distance on formats)
        base_dist = baseline.metadata.get("format_distribution", {})
        curr_dist = current.metadata.get("format_distribution", {})
        dist_divergence = self._calculate_distribution_divergence(base_dist, curr_dist)

        if dist_divergence > self.thresholds.distribution_divergence:
            details.append(
                f"Format distribution divergence {dist_divergence:.3f} exceeds threshold {self.thresholds.distribution_divergence:.3f}"
            )

        # Determine Drift State
        is_drifted = (
            type_violation_rate > self.thresholds.type_violation_rate
            or parse_failure_rate > self.thresholds.parse_failure_rate
            or jaccard_distance > self.thresholds.key_set_distance
        )
        is_suspected = (
            unknown_field_ratio > self.thresholds.unknown_field_ratio
            or dist_divergence > self.thresholds.distribution_divergence
        )

        if is_drifted:
            drift_state = DriftState.DRIFTED
        elif is_suspected:
            drift_state = DriftState.SUSPECTED
        else:
            drift_state = DriftState.STABLE
            if not details:
                details.append("All observed metrics within configured baseline stability bounds")

        signals = DriftSignals(
            parse_failure_rate=parse_failure_rate,
            unknown_field_ratio=unknown_field_ratio,
            type_violation_rate=type_violation_rate,
            key_set_distance=jaccard_distance,
            distribution_divergence=dist_divergence,
        )

        return DriftReport(
            source_id=source_id,
            parser_id=parser_id,
            parser_version=parser_version,
            drift_state=drift_state,
            observed_at=now,
            start_time=start_time,
            end_time=end_time,
            sample_count=sample_count,
            signals=signals,
            thresholds=self.thresholds,
            drift_details=details,
            remediation_recommended=(drift_state != DriftState.STABLE),
            baseline_run_id=baseline_run_id,
        )

    def detect_from_logs(
        self,
        baseline: SourceProfile,
        current_logs: Union[str, List[str], Iterable[str]],
        source_id: str,
        parser_id: str,
        parser_version: str = "1.0.0",
        baseline_run_id: Optional[str] = None,
        observed_at: Optional[datetime] = None,
    ) -> DriftReport:
        """Profiles raw incoming logs and assesses drift against the baseline."""
        current_profile = self.profiler.profile(current_logs)
        return self.compare_profiles(
            baseline=baseline,
            current=current_profile,
            source_id=source_id,
            parser_id=parser_id,
            parser_version=parser_version,
            baseline_run_id=baseline_run_id,
            observed_at=observed_at,
        )

    @staticmethod
    def _calculate_distribution_divergence(
        dist_a: Dict[str, Union[int, float]], dist_b: Dict[str, Union[int, float]]
    ) -> float:
        """Calculates Total Variation Distance (TVD) between two discrete distributions."""
        sum_a = sum(dist_a.values()) if dist_a else 0
        sum_b = sum(dist_b.values()) if dist_b else 0

        if sum_a == 0 or sum_b == 0:
            return 0.0

        p_a = {k: v / sum_a for k, v in dist_a.items()}
        p_b = {k: v / sum_b for k, v in dist_b.items()}

        all_keys = set(p_a.keys()) | set(p_b.keys())
        tvd = 0.5 * sum(abs(p_a.get(k, 0.0) - p_b.get(k, 0.0)) for k in all_keys)
        return min(1.0, max(0.0, tvd))
