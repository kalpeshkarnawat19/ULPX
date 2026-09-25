"""
Performance Benchmark Harness for ULPF-X (SIH26156) - Stage 19.
Empirically measures throughput (EPS), latency percentiles (p50, p90, p99, mean, min, max),
resource utilization (CPU, RAM, Queue Depth), and captures host reference hardware.

Enforces the non-negotiable scope guard:
"Do not claim 5k EPS until measured. Benchmark report includes reference hardware and actual measured results."
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from ml.benchmark.hardware import get_hardware_profile
from ml.benchmark.load_generator import LoadGenerator
from ml.benchmark.metrics import LatencyTracker, ResourceMonitor
from ml.shadow.runner import ShadowRunner


class BenchmarkHarness:
    """
    Executes automated, empirical performance benchmarks against parsers, shadow runners,
    and ingestion/normalization components, producing contract-compliant BenchmarkReports.
    """

    def __init__(self, shadow_runner: Optional[ShadowRunner] = None) -> None:
        self.shadow_runner = shadow_runner or ShadowRunner()

    def run_parser_benchmark(
        self,
        parser_spec: Dict[str, Any],
        events: Optional[Sequence[Any]] = None,
        event_count: int = 2000,
        format_type: str = "kv",
        batch_size: int = 100,
        target_eps: Optional[float] = None,
        concurrency: int = 1,
        component_name: str = "parser_runtime",
        report_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Runs an empirical benchmark over a parser specification.
        Measures real throughput, latency percentiles, and host hardware footprint.
        """
        # 1. Resolve raw events
        if events is None:
            generator = LoadGenerator(format_type=format_type)
            workload_events: List[Any] = generator.generate_batch(event_count)
        else:
            workload_events = list(events)
            event_count = len(workload_events)

        if not workload_events:
            raise ValueError("Workload event count must be at least 1.")

        parser_info = parser_spec.get("parser", {})
        parser_id = parser_info.get("id", "benchmark.parser")
        parser_version = parser_info.get("version", "1.0.0")

        # 2. Setup instrumentation
        tracker = LatencyTracker()
        monitor = ResourceMonitor()
        monitor.start()

        total_processed = 0
        total_errors = 0

        # 3. Timed execution run
        t0 = time.perf_counter()

        if concurrency > 1:
            from concurrent.futures import ThreadPoolExecutor

            def _worker_parse(ev: Any) -> tuple[float, bool]:
                ts = time.perf_counter()
                is_err = False
                try:
                    res = self.shadow_runner._parse(ev, parser_spec)
                    if not isinstance(res, dict) or not res:
                        is_err = True
                except Exception:
                    is_err = True
                te = time.perf_counter()
                return ((te - ts) * 1000.0, is_err)

            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                exec_results = list(executor.map(_worker_parse, workload_events))

            for lat_ms, is_err in exec_results:
                tracker.record(lat_ms)
                total_processed += 1
                if is_err:
                    total_errors += 1
        else:
            for idx, event in enumerate(workload_events):
                t_event_start = time.perf_counter()
                try:
                    # Use shadow runner parser engine (lossless, deterministic)
                    res = self.shadow_runner._parse(event, parser_spec)
                    if not isinstance(res, dict) or not res:
                        total_errors += 1
                except Exception:
                    total_errors += 1

                t_event_end = time.perf_counter()
                lat_ms = (t_event_end - t_event_start) * 1000.0
                tracker.record(lat_ms)
                total_processed += 1

                if (idx + 1) % 100 == 0:
                    monitor.update_memory()

        t1 = time.perf_counter()
        duration = max(0.0001, t1 - t0)

        # 4. Compute empirical metrics
        measured_eps = round(float(total_processed) / duration, 2)
        success_rate = round(float(total_processed - total_errors) / float(total_processed), 4) if total_processed > 0 else 0.0
        resource_stats = monitor.stop()
        hardware = get_hardware_profile()

        # 5. SCOPE GUARD ENFORCEMENT:
        # "Do not claim 5k EPS until measured. No manually entered success values."
        target_5k_claimed = bool(target_eps and target_eps >= 5000.0)
        target_5k_verified = bool(measured_eps >= 5000.0)

        if target_5k_verified:
            evidence = f"Verified: Measured throughput of {measured_eps:,.2f} EPS meets or exceeds the 5,000 EPS target on reference hardware."
        else:
            evidence = f"Empirical measurement: Achieved {measured_eps:,.2f} EPS across {total_processed} events ({duration:.4f}s) on reference hardware; 5k EPS target NOT verified."

        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        gen_report_id = report_id or f"BENCH-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

        workload_dict: Dict[str, Any] = {
            "event_count": int(total_processed),
            "duration_seconds": round(duration, 4),
            "concurrency": int(concurrency),
            "batch_size": int(batch_size),
        }
        if target_eps is not None:
            workload_dict["target_eps"] = float(target_eps)

        report = {
            "schema_version": "1.0",
            "report_id": gen_report_id,
            "timestamp": now_iso,
            "hardware": hardware,
            "target": {
                "component": component_name,
                "parser_id": str(parser_id),
                "parser_version": str(parser_version),
            },
            "workload": workload_dict,
            "results": {
                "measured_eps": float(measured_eps),
                "total_events_processed": int(total_processed),
                "total_errors": int(total_errors),
                "parse_success_rate": float(success_rate),
                "latency_ms": tracker.summary(),
                "resource_utilization": resource_stats,
            },
            "claims": {
                "target_5k_eps_claimed": target_5k_claimed,
                "target_5k_eps_verified": target_5k_verified,
                "evidence": evidence,
            },
        }

        return report

    def run_callable_benchmark(
        self,
        target_callable: Callable[[Any], Any],
        events: Sequence[Any],
        component_name: str = "parser_runtime",
        parser_id: str = "custom.callable",
        parser_version: str = "1.0.0",
        batch_size: int = 100,
        target_eps: Optional[float] = None,
        concurrency: int = 1,
        report_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Runs an empirical benchmark over any callable transformation function.
        """
        workload_events = list(events)
        total_events = len(workload_events)
        if total_events == 0:
            raise ValueError("Events list cannot be empty.")

        tracker = LatencyTracker()
        monitor = ResourceMonitor()
        monitor.start()

        total_processed = 0
        total_errors = 0

        t0 = time.perf_counter()

        if concurrency > 1:
            from concurrent.futures import ThreadPoolExecutor

            def _worker_call(it: Any) -> tuple[float, bool]:
                ts = time.perf_counter()
                is_err = False
                try:
                    target_callable(it)
                except Exception:
                    is_err = True
                te = time.perf_counter()
                return ((te - ts) * 1000.0, is_err)

            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                exec_results = list(executor.map(_worker_call, workload_events))

            for lat_ms, is_err in exec_results:
                tracker.record(lat_ms)
                total_processed += 1
                if is_err:
                    total_errors += 1
        else:
            for idx, item in enumerate(workload_events):
                t_item_start = time.perf_counter()
                try:
                    target_callable(item)
                except Exception:
                    total_errors += 1

                t_item_end = time.perf_counter()
                tracker.record((t_item_end - t_item_start) * 1000.0)
                total_processed += 1

                if (idx + 1) % 100 == 0:
                    monitor.update_memory()

        t1 = time.perf_counter()
        duration = max(0.0001, t1 - t0)

        measured_eps = round(float(total_processed) / duration, 2)
        success_rate = round(float(total_processed - total_errors) / float(total_processed), 4) if total_processed > 0 else 0.0
        resource_stats = monitor.stop()
        hardware = get_hardware_profile()

        target_5k_claimed = bool(target_eps and target_eps >= 5000.0)
        target_5k_verified = bool(measured_eps >= 5000.0)

        if target_5k_verified:
            evidence = f"Verified: Measured throughput of {measured_eps:,.2f} EPS meets or exceeds the 5,000 EPS target on reference hardware."
        else:
            evidence = f"Empirical measurement: Achieved {measured_eps:,.2f} EPS across {total_processed} events ({duration:.4f}s) on reference hardware; 5k EPS target NOT verified."

        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        gen_report_id = report_id or f"BENCH-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

        workload_dict: Dict[str, Any] = {
            "event_count": int(total_processed),
            "duration_seconds": round(duration, 4),
            "concurrency": int(concurrency),
            "batch_size": int(batch_size),
        }
        if target_eps is not None:
            workload_dict["target_eps"] = float(target_eps)

        return {
            "schema_version": "1.0",
            "report_id": gen_report_id,
            "timestamp": now_iso,
            "hardware": hardware,
            "target": {
                "component": component_name,
                "parser_id": str(parser_id),
                "parser_version": str(parser_version),
            },
            "workload": workload_dict,
            "results": {
                "measured_eps": float(measured_eps),
                "total_events_processed": int(total_processed),
                "total_errors": int(total_errors),
                "parse_success_rate": float(success_rate),
                "latency_ms": tracker.summary(),
                "resource_utilization": resource_stats,
            },
            "claims": {
                "target_5k_eps_claimed": target_5k_claimed,
                "target_5k_eps_verified": target_5k_verified,
                "evidence": evidence,
            },
        }
