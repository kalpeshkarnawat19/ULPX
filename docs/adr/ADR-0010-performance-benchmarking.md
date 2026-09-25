# ADR-0010: Performance Benchmarking and Empirical Throughput Validation

## Status

Accepted - Stage 19.

## Context

Perimeter security telemetry ingestion requires predictable, high-throughput parsing capable of sustaining enterprise
burst rates. While performance claims such as "5,000 Events Per Second (EPS)" are common, unverified assumptions risk
production backpressure, queue exhaustion, and dropped security events.

The Build Guide and PRD establish strict requirements and a non-negotiable scope guard for Stage 19:
> **Objective**: Measure rather than guess.
> **Required test**: `make bench`
> **Exit criteria**: Benchmark report includes reference hardware and actual measured results.
> **Scope guard**: "Do not claim 5k EPS until measured."

Under repository governance rules (Rule 1 & Rule 7), performance metrics must be contractually governed and empirically
measured rather than manufactured.

## Decision

1. Author a versioned contract `packages/contracts/benchmark_report.schema.json` (v1.0) and example fixture
   `fixtures/contracts/benchmark_report.example.json` formalizing benchmark results, host hardware profiles,
   workload configurations, latency percentiles, and verified claims.
2. Implement host hardware discovery in `ml/benchmark/hardware.py` capturing:
   - CPU model and core counts (physical and logical).
   - Host total RAM and memory utilization.
   - Operating system platform and runtime environment.
3. Implement a flexible load generator in `ml/benchmark/load_generator.py` supporting:
   - Streaming of high-velocity synthetic telemetry across standard security formats (Syslog RFC5424, CEF, KV, JSON).
   - Replay of golden historical corpora.
   - Rate pacing (target EPS enforcement) and unconstrained saturation testing.
4. Implement empirical measurement tooling in `ml/benchmark/metrics.py`:
   - `LatencyTracker`: microsecond-accurate recording and calculation of p50, p90, p99, mean, min, and max latency.
   - `ResourceMonitor`: empirical CPU % and memory RSS peak tracking.
5. Implement `BenchmarkHarness` in `ml/benchmark/harness.py`:
   - Runs benchmarks across parser runtimes, shadow runners, and normalize workers.
   - Strictly enforces the 5k EPS scope guard: `target_5k_eps_verified` evaluates to `true` if and only if
     `measured_eps >= 5000.0`. Under no circumstances is a success value hardcoded.
6. Provide a `make bench` target in `Makefile` executing automated benchmark regression testing and empirical verification.

## Consequences

- Ingestion throughput and parser latencies are backed by reproducible, machine-readable validation reports.
- Claims of 5k EPS or production readiness are empirically verifiable against known reference hardware.
- Downstream operators can detect performance regressions prior to deploying parser updates.
