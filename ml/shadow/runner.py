"""
Shadow Parsing Dual Execution Runner for ULPF-X (SIH26156) - Stage 17.
Enforces the mandatory scope guard:
"No production side effects. Candidate output never reaches normal downstream bus; comparison persisted."
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

from ml.shadow.comparator import ShadowComparator, ShadowComparisonReport
from ml.source_profiler.profiler import LogFormat, UnknownSourceProfiler


class DownstreamBusProtocol(Protocol):
    """Protocol for downstream production event brokers (e.g. Kafka, Redis, in-memory bus)."""
    def publish(self, event: Dict[str, Any]) -> None:
        ...


class ShadowRunner:
    """
    Executes active and candidate parser specifications in parallel on incoming telemetry.
    Strictly isolates candidate execution: candidate outputs are captured into an ephemeral shadow
    sink and verified to never escape to the production downstream bus or external exporters.
    """

    def __init__(self, comparator: Optional[ShadowComparator] = None):
        self.comparator = comparator or ShadowComparator()
        self.profiler = UnknownSourceProfiler()

    def execute_dual(
        self,
        raw_events: List[Any],
        active_spec: Dict[str, Any],
        candidate_spec: Dict[str, Any],
        source_id: str,
        downstream_bus: Optional[List[Dict[str, Any]]] = None,
        publish_active_to_downstream: bool = True,
    ) -> ShadowComparisonReport:
        """
        Runs dual-execution across raw events for active and candidate parsers.
        Candidate events are strictly kept in the shadow sink and never emitted to downstream_bus.
        """
        start_time = datetime.now(timezone.utc)

        active_info = active_spec.get("parser", {})
        active_id = active_info.get("id", f"{source_id}.active")
        active_version = active_info.get("version", "1.0.0")

        cand_info = candidate_spec.get("parser", {})
        cand_id = cand_info.get("id", f"{source_id}.candidate")
        cand_version = cand_info.get("version", "1.1.0")

        active_outputs: List[Dict[str, Any]] = []
        candidate_outputs: List[Dict[str, Any]] = []

        active_latencies_ms: List[float] = []
        candidate_latencies_ms: List[float] = []

        initial_bus_size = len(downstream_bus) if downstream_bus is not None else 0

        for raw in raw_events:
            # 1. Parse using Active Parser (measures latency)
            t0 = time.perf_counter()
            act_event = self._parse(raw, active_spec)
            t1 = time.perf_counter()
            active_latencies_ms.append(max(0.001, (t1 - t0) * 1000.0))
            active_outputs.append(act_event)

            # Route Active Event to Downstream Bus (if enabled)
            if downstream_bus is not None and publish_active_to_downstream:
                downstream_bus.append(act_event)

            # 2. Parse using Candidate Parser (measures latency)
            t2 = time.perf_counter()
            cand_event = self._parse(raw, candidate_spec)
            t3 = time.perf_counter()
            candidate_latencies_ms.append(max(0.001, (t3 - t2) * 1000.0))

            # Tag candidate output with shadow metadata for audit
            cand_event_tagged = dict(cand_event)
            cand_event_tagged["_shadow"] = {
                "candidate_parser_id": cand_id,
                "candidate_parser_version": cand_version,
                "is_shadow": True,
            }
            # Append EXCLUSIVELY to shadow sink
            candidate_outputs.append(cand_event_tagged)

        end_time = datetime.now(timezone.utc)

        # 3. Verify downstream bus isolation (Scope Guard check)
        downstream_isolation_verified = True
        if downstream_bus is not None:
            # Inspect new events placed on downstream_bus
            new_events = downstream_bus[initial_bus_size:]
            for ev in new_events:
                if isinstance(ev, dict) and ev.get("_shadow", {}).get("is_shadow") is True:
                    # Isolation violated!
                    downstream_isolation_verified = False
                    break

        # 4. Generate comparison report
        return self.comparator.compare(
            source_id=source_id,
            active_parser_id=active_id,
            active_parser_version=active_version,
            candidate_parser_id=cand_id,
            candidate_parser_version=cand_version,
            active_events=active_outputs,
            candidate_events=candidate_outputs,
            active_latencies_ms=active_latencies_ms,
            candidate_latencies_ms=candidate_latencies_ms,
            downstream_isolation_verified=downstream_isolation_verified,
            start_time=start_time,
            end_time=end_time,
            evaluated_at=end_time,
        )

    def execute_parsed_streams(
        self,
        source_id: str,
        active_spec: Dict[str, Any],
        candidate_spec: Dict[str, Any],
        active_events: List[Dict[str, Any]],
        candidate_events: List[Dict[str, Any]],
        active_latencies_ms: Optional[List[float]] = None,
        candidate_latencies_ms: Optional[List[float]] = None,
        downstream_bus: Optional[List[Dict[str, Any]]] = None,
        downstream_isolation_verified: bool = True,
    ) -> ShadowComparisonReport:
        """
        Directly evaluates pre-parsed active and candidate streams (e.g. from historical test runs).
        """
        active_info = active_spec.get("parser", {})
        active_id = active_info.get("id", f"{source_id}.active")
        active_version = active_info.get("version", "1.0.0")

        cand_info = candidate_spec.get("parser", {})
        cand_id = cand_info.get("id", f"{source_id}.candidate")
        cand_version = cand_info.get("version", "1.1.0")

        # Verify downstream isolation if a bus is supplied
        if downstream_bus is not None:
            for ev in downstream_bus:
                if isinstance(ev, dict) and ev.get("_shadow", {}).get("is_shadow") is True:
                    downstream_isolation_verified = False
                    break

        return self.comparator.compare(
            source_id=source_id,
            active_parser_id=active_id,
            active_parser_version=active_version,
            candidate_parser_id=cand_id,
            candidate_parser_version=cand_version,
            active_events=active_events,
            candidate_events=candidate_events,
            active_latencies_ms=active_latencies_ms,
            candidate_latencies_ms=candidate_latencies_ms,
            downstream_isolation_verified=downstream_isolation_verified,
        )

    def _parse(self, raw_input: Any, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Parses a raw log line or dictionary using whitelist DSL logic."""
        if isinstance(raw_input, dict):
            # If already a structured event, apply field transformations / enums / unknown fields
            fields_spec = spec.get("fields", {})
            mapped: Dict[str, Any] = {}
            unknowns: Dict[str, Any] = dict(raw_input.get("unknown_fields", {}))

            for k, v in raw_input.items():
                if k == "unknown_fields":
                    continue
                if k in fields_spec:
                    f_def = fields_spec[k]
                    canon_k = f_def.get("map_to", k)
                    val = v
                    enum_map = f_def.get("enum", {})
                    if isinstance(val, str) and val in enum_map:
                        val = enum_map[val]
                    mapped[canon_k] = val
                else:
                    mapped[k] = v

            if unknowns:
                mapped["unknown_fields"] = unknowns
            return mapped

        # If raw_input is a string, extract fields using profiler
        raw_str = str(raw_input)
        match_info = spec.get("match", {})
        fmt_hint = None
        fmt_str = str(match_info.get("format", "")).lower()
        if "cef" in fmt_str:
            fmt_hint = LogFormat.CEF
        elif "leef" in fmt_str:
            fmt_hint = LogFormat.LEEF
        elif "syslog" in fmt_str:
            fmt_hint = LogFormat.SYSLOG_RFC5424
        elif "json" in fmt_str:
            fmt_hint = LogFormat.JSON
        elif "csv" in fmt_str:
            fmt_hint = LogFormat.CSV
        elif "kv" in fmt_str or "key_value" in fmt_str:
            fmt_hint = LogFormat.KEY_VALUE

        profiler_res, _ = self.profiler.parse_record(raw_str, format_hint=fmt_hint)
        extracted = profiler_res or {}
        fields_spec = spec.get("fields", {})
        result: Dict[str, Any] = {}
        unknowns: Dict[str, Any] = {}

        for raw_k, raw_v in extracted.items():
            if raw_k in fields_spec:
                f_def = fields_spec[raw_k]
                canon_k = f_def.get("map_to", raw_k)
                val = raw_v
                enum_map = f_def.get("enum", {})
                if isinstance(val, str) and val in enum_map:
                    val = enum_map[val]
                result[canon_k] = val
            else:
                unknowns[raw_k] = raw_v

        if unknowns:
            result["unknown_fields"] = unknowns
        return result
