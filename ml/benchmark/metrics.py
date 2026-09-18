"""
Performance Metrics and Latency Profiling for ULPF-X Benchmark Harness.
Computes latency percentiles (p50, p90, p99, mean, min, max) and monitors resource utilization.
"""

from __future__ import annotations

import math
import os
import resource
import time
from typing import Any, Dict, List, Optional, Sequence


class LatencyTracker:
    """
    Collects execution latency observations in milliseconds and computes
    accurate percentiles (p50, p90, p99), mean, min, and max.
    """

    def __init__(self) -> None:
        self._samples: List[float] = []

    def record(self, latency_ms: float) -> None:
        """Records a single latency sample in milliseconds."""
        self._samples.append(max(0.0, float(latency_ms)))

    def record_batch(self, latencies_ms: Sequence[float]) -> None:
        """Records a batch of latency samples."""
        for lat in latencies_ms:
            self._samples.append(max(0.0, float(lat)))

    @property
    def count(self) -> int:
        return len(self._samples)

    def percentile(self, p: float) -> float:
        """
        Computes the p-th percentile (0.0 to 100.0) of recorded samples.
        Uses nearest-rank / linear interpolation.
        """
        if not self._samples:
            return 0.0
        sorted_samples = sorted(self._samples)
        if p <= 0:
            return sorted_samples[0]
        if p >= 100:
            return sorted_samples[-1]

        k = (len(sorted_samples) - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_samples[int(k)]
        d0 = sorted_samples[int(f)] * (c - k)
        d1 = sorted_samples[int(c)] * (k - f)
        return round(d0 + d1, 4)

    def summary(self) -> Dict[str, float]:
        """Returns the full latency summary matching benchmark_report.schema.json."""
        if not self._samples:
            return {
                "p50": 0.0,
                "p90": 0.0,
                "p99": 0.0,
                "mean": 0.0,
                "min": 0.0,
                "max": 0.0,
            }

        sorted_samples = sorted(self._samples)
        total = sum(sorted_samples)
        count = len(sorted_samples)
        mean_val = round(total / count, 4)

        return {
            "p50": self.percentile(50.0),
            "p90": self.percentile(90.0),
            "p99": self.percentile(99.0),
            "mean": mean_val,
            "min": round(sorted_samples[0], 4),
            "max": round(sorted_samples[-1], 4),
        }


class ResourceMonitor:
    """
    Monitors process CPU percent, peak memory footprint (RSS MB), and queue depth.
    """

    def __init__(self) -> None:
        self._start_time: float = 0.0
        self._start_cpu_time: float = 0.0
        self._memory_start_mb: float = 0.0
        self._memory_peak_mb: float = 0.0
        self._max_queue_depth: int = 0
        self._psutil_proc: Optional[Any] = None

        try:
            import psutil
            self._psutil_proc = psutil.Process()
        except Exception:
            self._psutil_proc = None

    def _get_current_memory_mb(self) -> float:
        """Reads current RSS memory in megabytes."""
        if self._psutil_proc:
            try:
                return float(self._psutil_proc.memory_info().rss) / (1024.0 * 1024.0)
            except Exception:
                pass

        # Fallback to getrusage (ru_maxrss is in KB on Linux)
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF)
            return float(usage.ru_maxrss) / 1024.0
        except Exception:
            return 50.0

    def start(self) -> None:
        """Starts monitoring run."""
        self._start_time = time.perf_counter()
        self._start_cpu_time = time.process_time()
        if self._psutil_proc:
            try:
                # Prime psutil cpu measurement
                self._psutil_proc.cpu_percent(interval=None)
            except Exception:
                pass
        self._memory_start_mb = self._get_current_memory_mb()
        self._memory_peak_mb = self._memory_start_mb
        self._max_queue_depth = 0

    def update_queue_depth(self, current_depth: int) -> None:
        """Updates observed queue depth during streaming."""
        depth = max(0, int(current_depth))
        if depth > self._max_queue_depth:
            self._max_queue_depth = depth

    def update_memory(self) -> None:
        """Polls current memory to track peak usage."""
        curr = self._get_current_memory_mb()
        if curr > self._memory_peak_mb:
            self._memory_peak_mb = curr

    def stop(self) -> Dict[str, Any]:
        """Stops monitoring and returns resource utilization metrics."""
        self.update_memory()
        cpu_pct: Optional[float] = None
        if self._psutil_proc:
            try:
                val = float(self._psutil_proc.cpu_percent(interval=None))
                if val > 0.0:
                    cpu_pct = val
            except Exception:
                pass

        if cpu_pct is None:
            # Empirical fallback using process CPU time over elapsed wall time
            elapsed_wall = time.perf_counter() - self._start_time
            elapsed_cpu = time.process_time() - self._start_cpu_time
            if elapsed_wall > 0:
                cpu_pct = (elapsed_cpu / elapsed_wall) * 100.0
            else:
                cpu_pct = 0.0

        return {
            "cpu_percent": round(max(0.0, float(cpu_pct)), 2),
            "memory_peak_mb": round(self._memory_peak_mb, 2),
            "queue_depth_max": int(self._max_queue_depth),
        }
