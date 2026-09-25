"""
Performance Metrics and Latency Profiling for ULPF-X Benchmark Harness.
Computes latency percentiles (p50, p90, p99, mean, min, max) and monitors resource utilization.
"""

from __future__ import annotations

import math
import os
import sys
import time
from typing import Any, Dict, List, Optional, Sequence

try:
    import resource
except ImportError:
    resource = None

try:
    import psutil
except ImportError:
    psutil = None


class LatencyTracker:
    def __init__(self) -> None:
        self._samples: List[float] = []

    def record(self, latency_ms: float) -> None:
        self._samples.append(max(0.0, float(latency_ms)))

    def record_batch(self, latencies_ms: Sequence[float]) -> None:
        for lat in latencies_ms:
            self.record(lat)

    @property
    def count(self) -> int:
        return len(self._samples)

    def summary(self) -> Dict[str, float]:
        if not self._samples:
            return {"count": 0, "p50": 0.0, "p90": 0.0, "p99": 0.0, "mean": 0.0, "min": 0.0, "max": 0.0}

        sorted_s = sorted(self._samples)
        n = len(sorted_s)

        def quantile(q: float) -> float:
            if n == 1:
                return sorted_s[0]
            pos = q * (n - 1)
            base = int(pos)
            rest = pos - base
            if base + 1 < n:
                return sorted_s[base] + rest * (sorted_s[base + 1] - sorted_s[base])
            return sorted_s[-1]

        return {
            "min": sorted_s[0],
            "max": sorted_s[-1],
            "mean": sum(sorted_s) / n,
            "p50": quantile(0.50),
            "p90": quantile(0.90),
            "p99": quantile(0.99),
        }


class ResourceMonitor:
    def __init__(self) -> None:
        self._start_time = 0.0
        self._max_queue_depth = 0
        self._peak_memory_mb = 1.0

    def start(self) -> None:
        self._start_time = time.perf_counter()
        self.update_memory()

    def update_queue_depth(self, depth: int) -> None:
        if depth > self._max_queue_depth:
            self._max_queue_depth = depth

    def update_memory(self) -> None:
        mem_mb = self._get_memory_mb()
        if mem_mb > self._peak_memory_mb:
            self._peak_memory_mb = mem_mb

    def stop(self) -> Dict[str, Any]:
        self.update_memory()
        return {
            "cpu_percent": 0.0,
            "memory_peak_mb": self._peak_memory_mb,
            "queue_depth_max": self._max_queue_depth
        }

    def _get_memory_mb(self) -> float:
        if resource is not None:
            peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # macOS reports ru_maxrss in bytes; Linux and other Unix hosts use KB.
            if sys.platform == "darwin":
                return peak_rss / (1024.0 * 1024.0)
            return peak_rss / 1024.0
        if psutil is not None:
            return psutil.Process(os.getpid()).memory_info().rss / (1024.0 * 1024.0)
        raise RuntimeError(
            "Cannot measure process memory: install psutil on platforms without "
            "the resource module."
        )
