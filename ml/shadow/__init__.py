"""
Shadow Parsing and Dual Execution Runtime (Stage 17).
Exports the ShadowRunner, ShadowComparator, and related reporting data structures.
"""

from ml.shadow.comparator import (
    FieldDivergence,
    ShadowComparator,
    ShadowComparisonReport,
    ShadowMetrics,
    ShadowRecommendation,
    ShadowState,
)
from ml.shadow.runner import ShadowRunner

__all__ = [
    "FieldDivergence",
    "ShadowComparator",
    "ShadowComparisonReport",
    "ShadowMetrics",
    "ShadowRecommendation",
    "ShadowRunner",
    "ShadowState",
]
