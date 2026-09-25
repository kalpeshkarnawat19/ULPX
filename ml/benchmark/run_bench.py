"""
Standalone Benchmark Runner for ULPF-X (SIH26156) - Stage 19.
Executes performance benchmarking over reference security log formats (CEF, Syslog, KV)
and reports empirical throughput, latency percentiles, and host hardware profiles.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.benchmark.hardware import get_hardware_profile
from ml.benchmark.harness import BenchmarkHarness


SAMPLE_CEF_SPEC: Dict[str, Any] = {
    "schema_version": "1.0",
    "parser": {"id": "paloalto.panos.cef", "version": "10.1.0"},
    "match": {"format": "cef"},
    "fields": {
        "src": {"map_to": "source.ip", "type": "ipv4"},
        "dst": {"map_to": "destination.ip", "type": "ipv4"},
        "spt": {"map_to": "source.port", "type": "integer"},
        "dpt": {"map_to": "destination.port", "type": "integer"},
        "act": {"map_to": "event.action", "enum": {"allow": "allowed", "block": "blocked"}},
    },
}

SAMPLE_KV_SPEC: Dict[str, Any] = {
    "schema_version": "1.0",
    "parser": {"id": "fortinet.fgt.traffic", "version": "7.0.0"},
    "match": {"format": "kv"},
    "fields": {
        "srcip": {"map_to": "source.ip", "type": "ipv4"},
        "dstip": {"map_to": "destination.ip", "type": "ipv4"},
        "srcport": {"map_to": "source.port", "type": "integer"},
        "dstport": {"map_to": "destination.port", "type": "integer"},
        "action": {"map_to": "event.action", "enum": {"deny": "blocked", "permit": "allowed"}},
    },
}


def main() -> int:
    harness = BenchmarkHarness()
    hw = get_hardware_profile()

    print("=" * 78)
    print("  ULPF-X PERFORMANCE BENCHMARK HARNESS (STAGE 19)")
    print("=" * 78)
    print(f" Reference CPU:      {hw['cpu_model']} ({hw['cpu_cores']} cores)")
    print(f" Reference Memory:   {hw['memory_total_mb']:,.1f} MB")
    print(f" Platform OS:        {hw['os_platform']}")
    print(f" Python Version:     {hw['python_version']}")
    print("-" * 78)

    specs = [
        ("CEF Parser", "cef", SAMPLE_CEF_SPEC),
        ("Key-Value Parser", "kv", SAMPLE_KV_SPEC),
    ]

    for name, fmt, spec in specs:
        print(f"\n[+] Running benchmark: {name} (1,000 events, unconstrained)...")
        report = harness.run_parser_benchmark(
            parser_spec=spec,
            event_count=1000,
            format_type=fmt,
            target_eps=5000.0,
            component_name="parser_runtime",
        )

        res = report["results"]
        lat = res["latency_ms"]
        ru = res["resource_utilization"]
        claims = report["claims"]

        print(f"    Events Processed: {res['total_events_processed']:,}")
        print(f"    Duration:         {report['workload']['duration_seconds']:.4f}s")
        print(f"    Measured EPS:     {res['measured_eps']:,.2f} EPS")
        print(f"    Latency (p50):    {lat['p50']:.4f} ms")
        print(f"    Latency (p90):    {lat['p90']:.4f} ms")
        print(f"    Latency (p99):    {lat['p99']:.4f} ms")
        print(f"    Latency (mean):   {lat['mean']:.4f} ms")
        print(f"    CPU Utilization:  {ru['cpu_percent']:.1f}%")
        print(f"    Memory Peak:      {ru['memory_peak_mb']:.1f} MB")
        print(f"    5k EPS Verified:  {claims['target_5k_eps_verified']}")
        print(f"    Evidence:         {claims['evidence']}")

    print("\n" + "=" * 78)
    print("  BENCHMARK COMPLETE - All results recorded from empirical measurement.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
