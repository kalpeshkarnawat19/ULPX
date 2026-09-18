"""
High-Throughput Telemetry Load Generator for ULPF-X Benchmark Harness.
Produces standardized synthetic and golden security log streams (Syslog, CEF, KV, JSON)
with configurable batching, concurrency, and rate pacing.
"""

from __future__ import annotations

import itertools
import time
from typing import Any, Dict, Iterator, List, Optional, Sequence


CEF_TEMPLATES = [
    "CEF:0|PaloAltoNetworks|PAN-OS|10.1.0|TRAFFIC|traffic|1|src=192.168.1.{i} dst=10.0.0.{j} spt={spt} dpt=443 proto=tcp act=allow cn1=4520 cs1=corp-web",
    "CEF:0|CheckPoint|VPN-1|R81|Accept|1|src=10.10.1.{i} dst=172.16.0.{j} spt={spt} dpt=80 proto=tcp act=allow msg=connection_accepted",
    "CEF:0|CrowdStrike|Falcon|6.30|Alert|5|src=192.168.100.{i} dst=1.1.1.1 spt={spt} dpt=53 proto=udp act=block msg=DNS_Tunneling_Detected",
    "CEF:0|Fortinet|FortiGate|7.0|deny|2|src=172.20.1.{i} dst=192.168.2.{j} spt={spt} dpt=22 proto=tcp act=deny msg=SSH_BruteForce",
]

SYSLOG_TEMPLATES = [
    "<134>1 2026-09-19T00:00:{sec:02d}Z perimeter-gw-01 sshd 12401 ID47 [auth user=admin src_ip=192.168.1.{i} port={spt}] Accepted publickey for admin",
    "<14>1 2026-09-19T00:00:{sec:02d}Z core-switch-02 kernel - - [net src=10.1.1.{i} dst=10.2.2.{j} proto=UDP len=64] Packet dropped by ACL",
    "<86>1 2026-09-19T00:00:{sec:02d}Z waf-node-03 nginx 8421 - [http status=403 method=GET path=/api/v1/auth client=192.168.50.{i}] WAF signature match 941100",
]

KV_TEMPLATES = [
    "timestamp=2026-09-19T00:00:{sec:02d}Z vendor=Fortinet devname=FGT-HQ action=deny srcip=10.0.1.{i} dstip=192.168.1.{j} srcport={spt} dstport=443 proto=6 service=HTTPS duration=12 sentbyte=1400 rcvdbyte=0",
    "timestamp=2026-09-19T00:00:{sec:02d}Z vendor=PaloAlto type=THREAT subtype=vulnerability src=192.168.10.{i} dst=10.10.0.{j} sport={spt} dport=8080 proto=tcp action=reset-both threat=SQLi",
    "timestamp=2026-09-19T00:00:{sec:02d}Z vendor=CiscoASA tag=ASA-6-302013 built inbound TCP connection src=172.16.1.{i}:{spt} dst=10.0.0.{j}:443 action=permit",
]

JSON_TEMPLATES = [
    '{{"timestamp":"2026-09-19T00:00:{sec:02d}Z","source":"aws.cloudtrail","event_name":"ConsoleLogin","user_identity":{{"type":"IAMUser","user_name":"secops-{i}"}},"source_ip_address":"198.51.100.{i}","response_elements":{{"ConsoleLogin":"Success"}},"status":"ALLOW"}}',
    '{{"timestamp":"2026-09-19T00:00:{sec:02d}Z","source":"okta","action":"user.authentication.auth_via_mfa","actor":{{"alternate_id":"user{i}@corp.local"}},"client":{{"ip":"203.0.113.{i}"}},"outcome":{{"result":"SUCCESS"}}}}',
]


class LoadGenerator:
    """
    High-performance telemetry load generator for throughput and latency benchmarking.
    """

    def __init__(
        self,
        format_type: str = "cef",
        custom_corpus: Optional[Sequence[str]] = None,
    ) -> None:
        self.format_type = format_type.lower()
        self.custom_corpus = list(custom_corpus) if custom_corpus else []
        self._index = 0

    def generate_single(self, index: Optional[int] = None) -> str:
        """Generates a single log event string."""
        if self.custom_corpus:
            idx = (index if index is not None else self._index) % len(self.custom_corpus)
            self._index += 1
            return self.custom_corpus[idx]

        idx = index if index is not None else self._index
        self._index += 1

        i = (idx % 250) + 1
        j = ((idx // 250) % 250) + 1
        spt = 1024 + (idx % 60000)
        sec = idx % 60

        if self.format_type == "cef":
            tpl = CEF_TEMPLATES[idx % len(CEF_TEMPLATES)]
            return tpl.format(i=i, j=j, spt=spt)
        elif self.format_type == "syslog":
            tpl = SYSLOG_TEMPLATES[idx % len(SYSLOG_TEMPLATES)]
            return tpl.format(i=i, j=j, spt=spt, sec=sec)
        elif self.format_type in ("kv", "key_value"):
            tpl = KV_TEMPLATES[idx % len(KV_TEMPLATES)]
            return tpl.format(i=i, j=j, spt=spt, sec=sec)
        elif self.format_type == "json":
            tpl = JSON_TEMPLATES[idx % len(JSON_TEMPLATES)]
            return tpl.format(i=i, j=j, spt=spt, sec=sec)
        else:
            # Default KV format
            tpl = KV_TEMPLATES[idx % len(KV_TEMPLATES)]
            return tpl.format(i=i, j=j, spt=spt, sec=sec)

    def generate_batch(self, count: int) -> List[str]:
        """Generates a batch of `count` log events."""
        return [self.generate_single() for _ in range(count)]

    def stream_events(
        self,
        count: int,
        pacing_eps: Optional[float] = None,
    ) -> Iterator[str]:
        """
        Streams `count` events. If `pacing_eps` is specified, throttles rate to target EPS
        with zero-drift target-time compensation.
        If `pacing_eps` is None, yields unconstrained for maximum saturation testing.
        """
        if not pacing_eps or pacing_eps <= 0:
            for idx in range(count):
                yield self.generate_single(idx)
            return

        interval = 1.0 / pacing_eps
        start_time = time.perf_counter()

        for idx in range(count):
            yield self.generate_single(idx)
            target_time = start_time + ((idx + 1) * interval)
            remaining = target_time - time.perf_counter()
            if remaining > 0:
                time.sleep(remaining)

    def stream_batches(
        self,
        total_events: int,
        batch_size: int = 100,
        pacing_eps: Optional[float] = None,
    ) -> Iterator[List[str]]:
        """
        Streams batches of events with drift-compensated batch interval scheduling.
        """
        if not pacing_eps or pacing_eps <= 0:
            remaining = total_events
            while remaining > 0:
                current_batch_size = min(batch_size, remaining)
                yield [self.generate_single() for _ in range(current_batch_size)]
                remaining -= current_batch_size
            return

        batch_interval = batch_size / pacing_eps
        start_time = time.perf_counter()
        batch_idx = 0
        remaining = total_events

        while remaining > 0:
            current_batch_size = min(batch_size, remaining)
            batch = [self.generate_single() for _ in range(current_batch_size)]
            yield batch
            remaining -= current_batch_size
            batch_idx += 1

            target_time = start_time + (batch_idx * batch_interval)
            sleep_time = target_time - time.perf_counter()
            if sleep_time > 0:
                time.sleep(sleep_time)
