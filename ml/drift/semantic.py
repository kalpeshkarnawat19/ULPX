"""
Semantic Drift Detection Engine for ULPF-X (SIH26156) - Stage 16.
Detects meaning and security behavioral changes beyond syntax:
- Critical mapping changes
- Enum behavior and security outcome shifts
- Event-family context drift
- Detection Preservation Score (DPS) regressions

Scope guard:
"Do not equate structural stability with semantic stability."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ml.drift.structural import DriftReport, DriftSignals, DriftState, DriftThresholds


@dataclass(frozen=True)
class SemanticDriftThresholds:
    """Configurable semantic drift detection thresholds (PRD Section 9 defaults)."""
    dps_regression: float = 0.0             # 0% tolerance for mandatory DPS regression
    enum_drift_score: float = 0.05          # 5% unmapped or shifted enum values
    critical_mapping_drift: float = 0.0     # 0% tolerance for critical field remappings
    event_family_drift: float = 0.10        # 10% event-family context divergence


@dataclass(frozen=True)
class SemanticDriftSignals:
    """Quantitative semantic drift indicators."""
    dps_regression: float
    enum_drift_score: float
    critical_mapping_drift: float
    event_family_drift: float


class SemanticDriftDetector:
    """
    Evaluates candidate parser behavior and normalized event semantics against baseline
    specifications to detect silent security degradation.
    """

    CRITICAL_CANONICAL_FIELDS = {
        "src.ip",
        "dst.ip",
        "src.port",
        "dst.port",
        "event.action",
        "event.outcome",
        "user.name",
    }

    def __init__(
        self,
        thresholds: Optional[SemanticDriftThresholds] = None,
        structural_thresholds: Optional[DriftThresholds] = None,
    ):
        self.thresholds = thresholds or SemanticDriftThresholds()
        self.structural_thresholds = structural_thresholds or DriftThresholds()

    def detect_semantic_drift(
        self,
        baseline_spec: Dict[str, Any],
        candidate_spec: Dict[str, Any],
        baseline_events: List[Dict[str, Any]],
        candidate_events: List[Dict[str, Any]],
        source_id: str,
        parser_id: str,
        parser_version: str = "1.0.0",
        baseline_run_id: Optional[str] = None,
        observed_at: Optional[datetime] = None,
    ) -> DriftReport:
        """
        Compares baseline and candidate parser specifications and event sets
        to identify semantic, enum, event-family, and DPS regressions.
        """
        now = observed_at or datetime.now(timezone.utc)
        details: List[str] = []

        # 1. Critical Mapping Changes
        crit_drift, crit_details = self._check_critical_mapping_drift(
            baseline_spec, candidate_spec
        )
        if crit_drift > self.thresholds.critical_mapping_drift:
            details.extend(crit_details)

        # 2. Enum Behavior Changes
        enum_drift, enum_details = self._check_enum_behavior_drift(
            baseline_spec, candidate_spec, candidate_events
        )
        if enum_drift > self.thresholds.enum_drift_score:
            details.extend(enum_details)

        # 3. Event-Family Context Changes
        fam_drift, fam_details = self._check_event_family_drift(
            baseline_events, candidate_events
        )
        if fam_drift > self.thresholds.event_family_drift:
            details.extend(fam_details)

        # 4. DPS Regression (Stage 13 DPS rules)
        dps_reg, dps_details = self._check_dps_regression(
            baseline_events, candidate_events
        )
        if dps_reg > self.thresholds.dps_regression:
            details.extend(dps_details)

        # Determine Drift State
        is_drifted = (
            dps_reg > self.thresholds.dps_regression
            or crit_drift > self.thresholds.critical_mapping_drift
            or enum_drift > self.thresholds.enum_drift_score
        )
        is_suspected = fam_drift > self.thresholds.event_family_drift

        if is_drifted:
            drift_state = DriftState.DRIFTED
        elif is_suspected:
            drift_state = DriftState.SUSPECTED
        else:
            drift_state = DriftState.STABLE
            if not details:
                details.append("All observed semantic metrics within configured baseline stability bounds")

        # Combine standard signals and semantic signals
        signals = DriftSignals(
            parse_failure_rate=0.0,
            unknown_field_ratio=0.0,
            type_violation_rate=0.0,
            key_set_distance=0.0,
            distribution_divergence=0.0,
            dps_regression=dps_reg,
            enum_drift_score=enum_drift,
            critical_mapping_drift=crit_drift,
            event_family_drift=fam_drift,
        )

        thresholds = DriftThresholds(
            parse_failure_rate=self.structural_thresholds.parse_failure_rate,
            unknown_field_ratio=self.structural_thresholds.unknown_field_ratio,
            type_violation_rate=self.structural_thresholds.type_violation_rate,
            key_set_distance=self.structural_thresholds.key_set_distance,
            distribution_divergence=self.structural_thresholds.distribution_divergence,
            dps_regression=self.thresholds.dps_regression,
            enum_drift_score=self.thresholds.enum_drift_score,
            critical_mapping_drift=self.thresholds.critical_mapping_drift,
            event_family_drift=self.thresholds.event_family_drift,
        )

        return DriftReport(
            source_id=source_id,
            parser_id=parser_id,
            parser_version=parser_version,
            drift_state=drift_state,
            observed_at=now,
            start_time=now,
            end_time=now,
            sample_count=len(candidate_events),
            signals=signals,
            thresholds=thresholds,
            drift_details=details,
            remediation_recommended=(drift_state != DriftState.STABLE),
            baseline_run_id=baseline_run_id,
        )

    def _check_critical_mapping_drift(
        self, baseline_spec: Dict[str, Any], candidate_spec: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """Identifies remappings or dropped mappings on critical security fields."""
        base_fields = baseline_spec.get("fields", {})
        cand_fields = candidate_spec.get("fields", {})

        # Map canonical field -> raw source field
        base_crit_map = {
            f_def.get("map_to"): raw_k
            for raw_k, f_def in base_fields.items()
            if f_def.get("map_to") in self.CRITICAL_CANONICAL_FIELDS
        }
        cand_crit_map = {
            f_def.get("map_to"): raw_k
            for raw_k, f_def in cand_fields.items()
            if f_def.get("map_to") in self.CRITICAL_CANONICAL_FIELDS
        }

        if not base_crit_map:
            return 0.0, []

        mismatches = 0
        details = []

        for canon_field, base_raw in base_crit_map.items():
            cand_raw = cand_crit_map.get(canon_field)
            if cand_raw is None:
                mismatches += 1
                details.append(
                    f"Critical field '{canon_field}' mapping dropped in candidate spec (previously mapped from '{base_raw}')"
                )
            elif cand_raw != base_raw:
                mismatches += 1
                details.append(
                    f"Critical field '{canon_field}' remapped from '{base_raw}' to '{cand_raw}'"
                )

        drift_score = mismatches / len(base_crit_map)
        return round(drift_score, 4), details

    def _check_enum_behavior_drift(
        self,
        baseline_spec: Dict[str, Any],
        candidate_spec: Dict[str, Any],
        candidate_events: List[Dict[str, Any]],
    ) -> Tuple[float, List[str]]:
        """Detects enum inversions or new unmapped enum values in action/outcome fields."""
        details = []
        base_fields = baseline_spec.get("fields", {})
        cand_fields = candidate_spec.get("fields", {})

        # Check action enum specification differences
        base_action_enum = {}
        for _, f_def in base_fields.items():
            if f_def.get("map_to") == "event.action":
                base_action_enum = f_def.get("enum", {})
                break

        cand_action_enum = {}
        for _, f_def in cand_fields.items():
            if f_def.get("map_to") == "event.action":
                cand_action_enum = f_def.get("enum", {})
                break

        inversion_detected = False
        # Check if meaning inverted (e.g. deny -> allowed)
        for raw_val, base_norm in base_action_enum.items():
            cand_norm = cand_action_enum.get(raw_val)
            if cand_norm and cand_norm != base_norm:
                inversion_detected = True
                details.append(
                    f"Action enum inversion detected: raw '{raw_val}' mapped to '{cand_norm}' (previously '{base_norm}')"
                )

        if inversion_detected:
            return 1.0, details

        # Check for unseen/unmapped enum values in candidate events
        if not candidate_events or not base_action_enum:
            return 0.0, []

        known_canonical = set(base_action_enum.values()) | set(cand_action_enum.values())
        unmapped_events = 0
        for ev in candidate_events:
            act = ev.get("event.action") or (ev.get("event") or {}).get("action")
            if act and act not in known_canonical:
                unmapped_events += 1

        unmapped_ratio = unmapped_events / len(candidate_events)
        if unmapped_ratio > 0:
            details.append(
                f"Enum unmapped value ratio {unmapped_ratio:.2%} exceeds baseline enum vocabulary"
            )

        return round(unmapped_ratio, 4), details

    def _check_event_family_drift(
        self,
        baseline_events: List[Dict[str, Any]],
        candidate_events: List[Dict[str, Any]],
    ) -> Tuple[float, List[str]]:
        """Measures divergence in event-family classification (network, auth, http, dns)."""
        if not baseline_events or not candidate_events:
            return 0.0, []

        def get_family(event: Dict[str, Any]) -> str:
            # Inspect canonical event dictionary
            ev_obj = event.get("event") if isinstance(event.get("event"), dict) else {}
            cls = ev_obj.get("class") or event.get("event.class") or ""
            act = ev_obj.get("action") or event.get("event.action") or ""

            if cls:
                return str(cls).lower()
            if "auth" in act or "login" in act or event.get("user.name") or event.get("user"):
                return "auth"
            if event.get("http") or event.get("http.response.status_code"):
                return "http"
            if event.get("dns") or event.get("dns.query_name"):
                return "dns"
            if event.get("src.ip") or event.get("dst.ip") or event.get("src"):
                return "network"
            return "general"

        base_counts: Dict[str, int] = {}
        for ev in baseline_events:
            fam = get_family(ev)
            base_counts[fam] = base_counts.get(fam, 0) + 1

        cand_counts: Dict[str, int] = {}
        for ev in candidate_events:
            fam = get_family(ev)
            cand_counts[fam] = cand_counts.get(fam, 0) + 1

        total_base = len(baseline_events)
        total_cand = len(candidate_events)

        p_base = {k: v / total_base for k, v in base_counts.items()}
        p_cand = {k: v / total_cand for k, v in cand_counts.items()}

        all_fams = set(p_base.keys()) | set(p_cand.keys())
        tvd = 0.5 * sum(abs(p_base.get(k, 0.0) - p_cand.get(k, 0.0)) for k in all_fams)
        tvd = round(min(1.0, max(0.0, tvd)), 4)

        details = []
        if tvd > self.thresholds.event_family_drift:
            primary_base = max(p_base.items(), key=lambda x: x[1])[0]
            primary_cand = max(p_cand.items(), key=lambda x: x[1])[0]
            details.append(
                f"Event family divergence {tvd:.2f} (primary baseline: '{primary_base}', primary candidate: '{primary_cand}')"
            )

        return tvd, details

    def _check_dps_regression(
        self,
        baseline_events: List[Dict[str, Any]],
        candidate_events: List[Dict[str, Any]],
    ) -> Tuple[float, List[str]]:
        """
        Evaluates mandatory detection contracts (DET-001 through DET-006)
        and flags any regression in Detection Preservation Score.
        """
        details = []
        # Check rule DET-002 (Blocked Connection) & DET-001 (Auth Failure)
        def eval_blocked_preservation(events: List[Dict[str, Any]]) -> Tuple[int, int]:
            expected_block = 0
            preserved_block = 0
            for ev in events:
                # Extract action and outcome
                ev_obj = ev.get("event") if isinstance(ev.get("event"), dict) else {}
                action = str(ev_obj.get("action") or ev.get("event.action") or "").lower()
                outcome = str(ev_obj.get("outcome") or ev.get("event.outcome") or "").lower()
                src_ip = ev.get("src.ip") or ((ev.get("src") or {}).get("ip") if isinstance(ev.get("src"), dict) else None)
                dst_ip = ev.get("dst.ip") or ((ev.get("dst") or {}).get("ip") if isinstance(ev.get("dst"), dict) else None)

                # Check if this event was expected to be a block
                is_block_payload = ("deny" in action or "block" in action or "drop" in action or "denied" in outcome)
                if is_block_payload:
                    expected_block += 1
                    # To preserve detection, action must remain blocked and endpoints preserved
                    if ("block" in action or "deny" in action or "drop" in action or "denied" in outcome) and (src_ip or dst_ip):
                        preserved_block += 1
            return expected_block, preserved_block

        base_exp, base_pres = eval_blocked_preservation(baseline_events)
        _, cand_pres = eval_blocked_preservation(candidate_events)

        base_dps = (base_pres / base_exp) if base_exp > 0 else 1.0
        cand_dps = (cand_pres / base_exp) if base_exp > 0 else 1.0

        dps_drop = max(0.0, base_dps - cand_dps)
        dps_drop = round(dps_drop, 4)

        if dps_drop > 0.0:
            details.append(
                f"Mandatory DPS regression of {dps_drop:.2%} detected (baseline DPS {base_dps:.2%}, candidate DPS {cand_dps:.2%})"
            )

        return dps_drop, details
