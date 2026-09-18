"""
Promotion Policy Engine for ULPF-X (SIH26156) - Stage 18.
Enforces the mandatory refusal conditions and promotion modes:
1. Schema invalid
2. Validation incomplete
3. Mandatory semantic/detection tests failed
4. Raw or unknown-field retention below 100%
5. Candidate has not passed shadow state or downstream isolation unverified

Scope guard:
"Keep automatic promotion disabled for SIH unless all policy conditions are unambiguous."
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class PromotionMode(str, Enum):
    MANUAL_APPROVAL = "MANUAL_APPROVAL"
    AUTOMATIC_CONDITIONAL = "AUTOMATIC_CONDITIONAL"


class PromotionDecision(str, Enum):
    PROMOTED = "PROMOTED"
    REJECTED = "REJECTED"
    ESCALATED_FOR_APPROVAL = "ESCALATED_FOR_APPROVAL"


@dataclass(frozen=True)
class GateResults:
    """Consolidated assessment across all upstream verification gates."""
    # 1. Schema Validation Gate
    schema_passed: bool
    schema_details: str

    # 2. Empirical Validation Gate (Stage 11)
    validation_passed: bool
    extraction_accuracy: float
    semantic_accuracy: float
    dps: float
    raw_retention: float
    unknown_retention: float

    # 3. Shadow Parsing Gate (Stage 17)
    shadow_passed: bool
    shadow_state: str  # PASSED, FAILED, SUSPECTED
    field_match_rate: float
    dps_delta: float
    downstream_isolation_verified: bool


class PromotionPolicy:
    """
    Evaluates candidate parser readiness for production hot-deployment against
    PRD Section 9 refusal conditions.
    """

    MANDATORY_REFUSAL_CHECKS = [
        "REFUSAL_1_SCHEMA_INVALID",
        "REFUSAL_2_VALIDATION_INCOMPLETE",
        "REFUSAL_3_DETECTION_TESTS_FAILED",
        "REFUSAL_4_RETENTION_BELOW_100",
        "REFUSAL_5_SHADOW_UNPASSED_OR_LEAKED",
    ]

    def __init__(self, default_mode: PromotionMode = PromotionMode.MANUAL_APPROVAL):
        self.default_mode = default_mode

    def evaluate(
        self,
        gates: GateResults,
        mode: Optional[PromotionMode] = None,
    ) -> Tuple[PromotionDecision, List[str], List[str]]:
        """
        Evaluates gate outcomes against refusal conditions and configured promotion mode.
        Returns: (decision, refusal_reasons, refusal_conditions_checked)
        """
        eval_mode = mode or self.default_mode
        reasons: List[str] = []

        # Check Refusal 1: Schema invalid
        if not gates.schema_passed:
            reasons.append(f"Refusal condition 1 met: candidate parser schema is invalid ({gates.schema_details})")

        # Check Refusal 2: Validation incomplete or failed
        if not gates.validation_passed or gates.extraction_accuracy < 0.90 or gates.semantic_accuracy < 0.90:
            reasons.append(
                f"Refusal condition 2 met: empirical validation failed or incomplete "
                f"(passed={gates.validation_passed}, extraction_acc={gates.extraction_accuracy:.2%}, "
                f"semantic_acc={gates.semantic_accuracy:.2%})"
            )

        # Check Refusal 3: Mandatory semantic/detection tests failed
        if gates.dps < 1.0 or gates.dps_delta < 0.0:
            reasons.append(
                f"Refusal condition 3 met: mandatory detection preservation failed "
                f"(candidate DPS={gates.dps:.2%}, DPS delta={gates.dps_delta:+.2%})"
            )

        # Check Refusal 4: Raw or unknown-field retention below 100%
        if gates.raw_retention < 1.0 or gates.unknown_retention < 1.0:
            reasons.append(
                f"Refusal condition 4 met: retention below 100% "
                f"(raw_retention={gates.raw_retention:.2%}, unknown_retention={gates.unknown_retention:.2%})"
            )

        # Check Refusal 5: Candidate has not passed shadow state or downstream isolation unverified
        if not gates.shadow_passed or gates.shadow_state != "PASSED" or not gates.downstream_isolation_verified:
            reasons.append(
                f"Refusal condition 5 met: shadow state unpassed or isolation unverified "
                f"(shadow_passed={gates.shadow_passed}, shadow_state='{gates.shadow_state}', "
                f"downstream_isolation={gates.downstream_isolation_verified})"
            )

        # Final decision calculation
        if reasons:
            decision = PromotionDecision.REJECTED
        else:
            # All 5 refusal checks passed!
            if eval_mode == PromotionMode.AUTOMATIC_CONDITIONAL:
                decision = PromotionDecision.PROMOTED
            else:
                # Default Scope Guard: escalate for audited human operator authorization
                decision = PromotionDecision.ESCALATED_FOR_APPROVAL

        return decision, reasons, list(self.MANDATORY_REFUSAL_CHECKS)
