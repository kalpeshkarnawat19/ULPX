"""
Comprehensive Unit & Integration Test Suite for ULPF-X Performance Benchmarking (Stage 19).
Validates hardware profiling, latency percentiles, load generation, benchmark execution,
the 5k EPS scope guard, and contract schema compliance.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from ml.benchmark.hardware import get_cpu_model, get_hardware_profile, get_total_memory_mb
from ml.benchmark.harness import BenchmarkHarness
from ml.benchmark.load_generator import LoadGenerator
from ml.benchmark.metrics import LatencyTracker, ResourceMonitor
from tests.contracts.test_schemas import validate


SAMPLE_KV_PARSER_SPEC: Dict[str, Any] = {
    "schema_version": "1.0",
    "parser": {
        "id": "fortinet.fgt.traffic",
        "version": "1.4.0",
    },
    "match": {
        "format": "kv",
    },
    "fields": {
        "srcip": {
            "map_to": "source.ip",
            "type": "ipv4",
        },
        "dstip": {
            "map_to": "destination.ip",
            "type": "ipv4",
        },
        "srcport": {
            "map_to": "source.port",
            "type": "integer",
        },
        "dstport": {
            "map_to": "destination.port",
            "type": "integer",
        },
        "action": {
            "map_to": "event.action",
            "enum": {
                "deny": "blocked",
                "permit": "allowed",
            },
        },
    },
}


def test_hardware_profiling() -> None:
    """Verify host hardware specs are empirically collected from the platform."""
    profile = get_hardware_profile()
    assert isinstance(profile, dict)
    assert profile["cpu_cores"] >= 1
    assert profile["memory_total_mb"] > 0
    assert len(profile["cpu_model"]) > 0
    assert len(profile["os_platform"]) > 0
    assert len(profile["python_version"]) > 0
    assert profile["cpu_model"] == get_cpu_model()
    assert profile["memory_total_mb"] == get_total_memory_mb()


def test_latency_tracker_percentiles() -> None:
    """Verify LatencyTracker computes accurate percentiles against known inputs."""
    tracker = LatencyTracker()
    samples = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    tracker.record_batch(samples)

    assert tracker.count == 10
    summary = tracker.summary()
    assert summary["min"] == 1.0
    assert summary["max"] == 10.0
    assert summary["mean"] == 5.5
    assert summary["p50"] == pytest.approx(5.5, rel=1e-2)
    assert summary["p90"] == pytest.approx(9.1, rel=1e-2)
    assert summary["p99"] == pytest.approx(9.91, rel=1e-2)


def test_resource_monitor() -> None:
    """Verify ResourceMonitor records CPU %, peak RSS memory, and queue depth."""
    monitor = ResourceMonitor()
    monitor.start()
    monitor.update_queue_depth(15)
    monitor.update_queue_depth(8)  # lower, peak should remain 15
    monitor.update_memory()
    stats = monitor.stop()

    assert stats["cpu_percent"] >= 0.0
    assert stats["memory_peak_mb"] > 0.0
    assert stats["queue_depth_max"] == 15


def test_load_generator_formats() -> None:
    """Verify LoadGenerator correctly generates CEF, Syslog, KV, and JSON formats."""
    for fmt in ["cef", "syslog", "kv", "json"]:
        gen = LoadGenerator(format_type=fmt)
        batch = gen.generate_batch(5)
        assert len(batch) == 5
        sample = batch[0]
        if fmt == "cef":
            assert "CEF:0|" in sample
        elif fmt == "syslog":
            assert "<" in sample and " 2026-09-19" in sample
        elif fmt == "kv":
            assert "timestamp=" in sample and "vendor=" in sample
        elif fmt == "json":
            parsed = json.loads(sample)
            assert "timestamp" in parsed


def test_load_generator_custom_corpus() -> None:
    """Verify LoadGenerator replays custom corpus lines deterministically."""
    corpus = ["log line 1", "log line 2", "log line 3"]
    gen = LoadGenerator(custom_corpus=corpus)
    events = [gen.generate_single() for _ in range(5)]
    assert events == ["log line 1", "log line 2", "log line 3", "log line 1", "log line 2"]


def test_benchmark_harness_run() -> None:
    """Verify BenchmarkHarness runs parser benchmark and captures empirical metrics."""
    harness = BenchmarkHarness()
    report = harness.run_parser_benchmark(
        parser_spec=SAMPLE_KV_PARSER_SPEC,
        event_count=200,
        format_type="kv",
        target_eps=2500.0,
        component_name="parser_runtime",
    )

    assert report["schema_version"] == "1.0"
    assert report["results"]["total_events_processed"] == 200
    assert report["results"]["total_errors"] == 0
    assert report["results"]["parse_success_rate"] == 1.0
    assert report["results"]["measured_eps"] > 0.0
    assert report["results"]["latency_ms"]["p50"] >= 0.0
    assert report["claims"]["target_5k_eps_claimed"] is False


def test_scope_guard_do_not_claim_5k_until_measured() -> None:
    """
    Scope Guard Verification:
    'Do not claim 5k EPS until measured. Benchmark report includes reference hardware
    and actual measured results. No manually entered success values.'
    """
    harness = BenchmarkHarness()

    # Case A: Workload where measured throughput does NOT reach 5,000 EPS
    def slow_fn(ev: Any) -> Dict[str, Any]:
        import time
        time.sleep(0.0003)  # ~3,000 EPS max
        return {"parsed": True}

    slow_report = harness.run_callable_benchmark(
        target_callable=slow_fn,
        events=["sample"] * 30,
        target_eps=5000.0,  # Claimed 5k EPS
    )
    assert slow_report["claims"]["target_5k_eps_claimed"] is True
    # MUST be False because measured throughput was below 5,000 EPS
    assert slow_report["claims"]["target_5k_eps_verified"] is False
    assert "NOT verified" in slow_report["claims"]["evidence"]

    # Case B: High-throughput workload that legitimately exceeds 5,000 EPS
    def fast_fn(ev: Any) -> Dict[str, Any]:
        return {"fast": True}

    fast_report = harness.run_callable_benchmark(
        target_callable=fast_fn,
        events=["sample"] * 10000,
        target_eps=5000.0,
    )
    # Measured EPS will be > 5,000 EPS for in-memory transform
    assert fast_report["results"]["measured_eps"] >= 5000.0
    assert fast_report["claims"]["target_5k_eps_claimed"] is True
    assert fast_report["claims"]["target_5k_eps_verified"] is True
    assert "meets or exceeds the 5,000 EPS target" in fast_report["claims"]["evidence"]


def test_benchmark_report_contract_compliance() -> None:
    """Verify produced benchmark report validates strictly against benchmark_report.schema.json."""
    harness = BenchmarkHarness()
    report = harness.run_parser_benchmark(
        parser_spec=SAMPLE_KV_PARSER_SPEC,
        event_count=100,
        format_type="kv",
    )

    root = Path(__file__).resolve().parents[2]
    schema_file = root / "packages" / "contracts" / "benchmark_report.schema.json"
    schema = json.loads(schema_file.read_text(encoding="utf-8"))

    # Validate against JSON Schema engine
    validate(report, schema, schema)
