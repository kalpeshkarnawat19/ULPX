"""
ULPF-X (SIH26156) - STAGE 8: Semantic Mapper
Workstream: Agastya (Intelligence & Assurance Lead)

Purely deterministic semantic mapping engine.
Ranks candidate canonical mappings for fields discovered by Stage 7 UnknownSourceProfiler.
Enforces hard type checks, explicit confidence thresholds, and abstention logic:
- mapping_score >= 0.95 -> AUTO_ACCEPTED
- mapping_score 0.80 - 0.94 -> HUMAN_REVIEW
- mapping_score < 0.80 -> ABSTAIN (preserved in extensions.source.*)
No LLMs/AI used in mapping decisions. Never uses the term "probability".
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from ml.source_profiler.profiler import DataType, FieldProfile, SourceProfile


class ReviewStatus(str, Enum):
    AUTO_ACCEPTED = "AUTO_ACCEPTED"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    ABSTAIN = "ABSTAIN"


class EventFamily(str, Enum):
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    FIREWALL_POLICY = "FIREWALL_POLICY"
    AUTHENTICATION = "AUTHENTICATION"
    DNS_ACTIVITY = "DNS_ACTIVITY"
    WEB_SESSION = "WEB_SESSION"
    SECURITY_ALERT = "SECURITY_ALERT"
    GENERIC_NETWORK_EVENT = "GENERIC_NETWORK_EVENT"


@dataclass
class CanonicalFieldDefinition:
    path: str
    expected_types: Set[str]
    description: str
    is_critical: bool
    event_families: Set[str]
    aliases: Set[str]
    suggested_transform: Optional[str] = None


@dataclass
class MappingCandidate:
    raw_field: str
    canonical_path: str
    mapping_score: float
    evidence: List[str] = field(default_factory=list)
    review_status: ReviewStatus = ReviewStatus.ABSTAIN
    is_critical: bool = False
    hard_type_conflict: bool = False
    suggested_transformation: Optional[str] = None
    preserve_in_extensions: bool = False
    destination_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_field": self.raw_field,
            "canonical_path": self.canonical_path,
            "mapping_score": round(self.mapping_score, 4),
            "evidence": self.evidence,
            "review_status": self.review_status.value if isinstance(self.review_status, ReviewStatus) else str(self.review_status),
            "is_critical": self.is_critical,
            "hard_type_conflict": self.hard_type_conflict,
            "suggested_transformation": self.suggested_transformation,
            "preserve_in_extensions": self.preserve_in_extensions,
            "destination_path": self.destination_path,
        }


@dataclass
class FieldMappingResult:
    raw_field: str
    chosen_mapping: MappingCandidate
    top_candidates: List[MappingCandidate] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_field": self.raw_field,
            "chosen_mapping": self.chosen_mapping.to_dict(),
            "top_candidates": [c.to_dict() for c in self.top_candidates],
        }


@dataclass
class SourceMappingReport:
    source_id: Optional[str]
    event_family: Optional[str]
    mappings: Dict[str, FieldMappingResult] = field(default_factory=dict)
    summary: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "event_family": self.event_family,
            "summary": self.summary,
            "mappings": {k: v.to_dict() for k, v in self.mappings.items()},
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# =====================================================================
# Canonical Knowledge Base
# =====================================================================

class CanonicalKnowledgeBase:
    """Catalog of ULPF canonical fields, aliases, types, and event families."""

    def __init__(self):
        self._fields: Dict[str, CanonicalFieldDefinition] = {}
        self._alias_index: Dict[str, str] = {}
        self._load_canonical_definitions()

    def _load_canonical_definitions(self):
        definitions = [
            # 1. Critical Network/Perimeter Fields
            CanonicalFieldDefinition(
                path="src.ip",
                expected_types={"ipv4", "ipv6", "ip"},
                description="Source IP address of network event",
                is_critical=True,
                event_families={
                    EventFamily.NETWORK_CONNECTION.value,
                    EventFamily.FIREWALL_POLICY.value,
                    EventFamily.AUTHENTICATION.value,
                    EventFamily.DNS_ACTIVITY.value,
                    EventFamily.WEB_SESSION.value,
                    EventFamily.SECURITY_ALERT.value,
                    EventFamily.GENERIC_NETWORK_EVENT.value,
                },
                aliases={
                    "src", "src_ip", "source_ip", "srcip", "source_address", "s_ip",
                    "source", "client_ip", "clientip", "c_ip", "src_addr", "sourceaddress",
                    "initiator_ip", "sender_ip", "sourceipaddress"
                },
                suggested_transform="parse_ip",
            ),
            CanonicalFieldDefinition(
                path="dst.ip",
                expected_types={"ipv4", "ipv6", "ip"},
                description="Destination IP address of network event",
                is_critical=True,
                event_families={
                    EventFamily.NETWORK_CONNECTION.value,
                    EventFamily.FIREWALL_POLICY.value,
                    EventFamily.AUTHENTICATION.value,
                    EventFamily.DNS_ACTIVITY.value,
                    EventFamily.WEB_SESSION.value,
                    EventFamily.SECURITY_ALERT.value,
                    EventFamily.GENERIC_NETWORK_EVENT.value,
                },
                aliases={
                    "dst", "dst_ip", "destination_ip", "dest_ip", "destip",
                    "destination_address", "d_ip", "destination", "server_ip", "serverip",
                    "dst_addr", "destaddress", "target_ip", "responder_ip", "destinationipaddress"
                },
                suggested_transform="parse_ip",
            ),
            CanonicalFieldDefinition(
                path="src.port",
                expected_types={"integer"},
                description="Source port number",
                is_critical=True,
                event_families={
                    EventFamily.NETWORK_CONNECTION.value,
                    EventFamily.FIREWALL_POLICY.value,
                    EventFamily.WEB_SESSION.value,
                    EventFamily.GENERIC_NETWORK_EVENT.value,
                },
                aliases={
                    "spt", "src_port", "source_port", "srcport", "s_port",
                    "sport", "client_port", "sourceport"
                },
                suggested_transform="to_integer",
            ),
            CanonicalFieldDefinition(
                path="dst.port",
                expected_types={"integer"},
                description="Destination port number",
                is_critical=True,
                event_families={
                    EventFamily.NETWORK_CONNECTION.value,
                    EventFamily.FIREWALL_POLICY.value,
                    EventFamily.DNS_ACTIVITY.value,
                    EventFamily.WEB_SESSION.value,
                    EventFamily.GENERIC_NETWORK_EVENT.value,
                },
                aliases={
                    "dpt", "dst_port", "destination_port", "dest_port", "destport",
                    "d_port", "dport", "server_port", "destinationport", "service_port"
                },
                suggested_transform="to_integer",
            ),

            # 2. Critical Event Metadata
            CanonicalFieldDefinition(
                path="event.action",
                expected_types={"string"},
                description="Action taken on the event (e.g. allowed, blocked, denied)",
                is_critical=True,
                event_families={
                    EventFamily.NETWORK_CONNECTION.value,
                    EventFamily.FIREWALL_POLICY.value,
                    EventFamily.AUTHENTICATION.value,
                    EventFamily.SECURITY_ALERT.value,
                    EventFamily.GENERIC_NETWORK_EVENT.value,
                },
                aliases={
                    "act", "action", "activity", "decision", "status_action",
                    "disposition", "rule_action", "filter_action", "event_action"
                },
                suggested_transform="trim",
            ),
            CanonicalFieldDefinition(
                path="event.outcome",
                expected_types={"string", "boolean"},
                description="Result of event (e.g. success, failure, timeout)",
                is_critical=True,
                event_families={
                    EventFamily.AUTHENTICATION.value,
                    EventFamily.NETWORK_CONNECTION.value,
                    EventFamily.FIREWALL_POLICY.value,
                    EventFamily.SECURITY_ALERT.value,
                },
                aliases={
                    "outcome", "result", "status", "res", "success", "session_status",
                    "auth_result", "login_status", "status_code_name"
                },
                suggested_transform="trim",
            ),
            CanonicalFieldDefinition(
                path="event.time",
                expected_types={"timestamp", "integer", "float"},
                description="Timestamp when event occurred",
                is_critical=True,
                event_families=set(f.value for f in EventFamily),
                aliases={
                    "timestamp", "time", "ts", "event_time", "datetime", "date_time",
                    "occurred_at", "received_at", "eventtime", "generation_time",
                    "log_time", "device_time"
                },
                suggested_transform="parse_timestamp",
            ),
            CanonicalFieldDefinition(
                path="event.class",
                expected_types={"string"},
                description="Event classification taxonomy",
                is_critical=True,
                event_families=set(f.value for f in EventFamily),
                aliases={
                    "event_class", "class", "event_type", "type", "category", "cat",
                    "device_event_class_id", "event_id", "signature_id"
                },
                suggested_transform="trim",
            ),

            # 3. Network Transport & Metrics
            CanonicalFieldDefinition(
                path="network.protocol",
                expected_types={"string"},
                description="Network layer-4/7 protocol (e.g. tcp, udp, icmp)",
                is_critical=False,
                event_families={
                    EventFamily.NETWORK_CONNECTION.value,
                    EventFamily.FIREWALL_POLICY.value,
                    EventFamily.GENERIC_NETWORK_EVENT.value,
                },
                aliases={
                    "proto", "protocol", "transport", "network_proto", "app_proto",
                    "ip_protocol", "proto_name"
                },
                suggested_transform="lowercase",
            ),
            CanonicalFieldDefinition(
                path="network.bytes_in",
                expected_types={"integer"},
                description="Bytes received by source or in session",
                is_critical=False,
                event_families={
                    EventFamily.NETWORK_CONNECTION.value,
                    EventFamily.WEB_SESSION.value,
                    EventFamily.GENERIC_NETWORK_EVENT.value,
                },
                aliases={
                    "bytes_in", "in_bytes", "bytes_rcvd", "rcvd_bytes", "inbytes",
                    "bytes_received", "bytesin", "rcvdbyte", "rx_bytes"
                },
                suggested_transform="to_integer",
            ),
            CanonicalFieldDefinition(
                path="network.bytes_out",
                expected_types={"integer"},
                description="Bytes transmitted by source or in session",
                is_critical=False,
                event_families={
                    EventFamily.NETWORK_CONNECTION.value,
                    EventFamily.WEB_SESSION.value,
                    EventFamily.GENERIC_NETWORK_EVENT.value,
                },
                aliases={
                    "bytes_out", "out_bytes", "bytes_sent", "sent_bytes", "outbytes",
                    "bytes_transmitted", "bytesout", "sentbyte", "tx_bytes"
                },
                suggested_transform="to_integer",
            ),
            CanonicalFieldDefinition(
                path="network.packets",
                expected_types={"integer"},
                description="Total packets in network exchange",
                is_critical=False,
                event_families={
                    EventFamily.NETWORK_CONNECTION.value,
                    EventFamily.FIREWALL_POLICY.value,
                    EventFamily.GENERIC_NETWORK_EVENT.value,
                },
                aliases={
                    "packets", "pkts", "packet_count", "total_packets", "pkt_count"
                },
                suggested_transform="to_integer",
            ),

            # 4. Identity & User Context
            CanonicalFieldDefinition(
                path="user.name",
                expected_types={"string"},
                description="Username or user identity",
                is_critical=True,
                event_families={
                    EventFamily.AUTHENTICATION.value,
                    EventFamily.WEB_SESSION.value,
                    EventFamily.SECURITY_ALERT.value,
                },
                aliases={
                    "user", "username", "user_name", "account", "login", "usr",
                    "actor", "account_name", "src_user", "source_username",
                    "duser", "suser"
                },
                suggested_transform="trim",
            ),
            CanonicalFieldDefinition(
                path="user.id",
                expected_types={"string", "integer"},
                description="Unique identifier for user account",
                is_critical=True,
                event_families={
                    EventFamily.AUTHENTICATION.value,
                    EventFamily.WEB_SESSION.value,
                },
                aliases={
                    "uid", "user_id", "userid", "account_id", "actor_id"
                },
                suggested_transform="trim",
            ),
            CanonicalFieldDefinition(
                path="user.email",
                expected_types={"email", "string"},
                description="User email address",
                is_critical=False,
                event_families={
                    EventFamily.AUTHENTICATION.value,
                    EventFamily.WEB_SESSION.value,
                },
                aliases={
                    "email", "user_email", "mail", "user_mail", "sender_email"
                },
                suggested_transform="lowercase",
            ),
            CanonicalFieldDefinition(
                path="user.domain",
                expected_types={"string"},
                description="User domain or realm",
                is_critical=False,
                event_families={
                    EventFamily.AUTHENTICATION.value,
                },
                aliases={
                    "domain", "user_domain", "realm", "account_domain", "nt_domain"
                },
                suggested_transform="trim",
            ),

            # 5. HTTP & Web Session Context
            CanonicalFieldDefinition(
                path="http.method",
                expected_types={"string"},
                description="HTTP request verb (e.g. GET, POST)",
                is_critical=False,
                event_families={
                    EventFamily.WEB_SESSION.value,
                },
                aliases={
                    "method", "http_method", "request_method", "verb"
                },
                suggested_transform="uppercase",
            ),
            CanonicalFieldDefinition(
                path="http.status_code",
                expected_types={"integer"},
                description="HTTP response status code",
                is_critical=False,
                event_families={
                    EventFamily.WEB_SESSION.value,
                },
                aliases={
                    "status_code", "http_status", "http_code", "response_code",
                    "resp_code", "statuscode"
                },
                suggested_transform="to_integer",
            ),
            CanonicalFieldDefinition(
                path="http.url",
                expected_types={"url", "string"},
                description="HTTP target URL or request URI",
                is_critical=False,
                event_families={
                    EventFamily.WEB_SESSION.value,
                    EventFamily.SECURITY_ALERT.value,
                },
                aliases={
                    "url", "request_url", "uri", "request_uri", "path", "http_url"
                },
                suggested_transform="trim",
            ),
            CanonicalFieldDefinition(
                path="http.user_agent",
                expected_types={"string"},
                description="HTTP Client User-Agent string",
                is_critical=False,
                event_families={
                    EventFamily.WEB_SESSION.value,
                },
                aliases={
                    "user_agent", "useragent", "agent", "http_user_agent", "cs_user_agent"
                },
                suggested_transform="trim",
            ),

            # 6. DNS Activity Context
            CanonicalFieldDefinition(
                path="dns.query_name",
                expected_types={"string"},
                description="DNS queried hostname or domain name",
                is_critical=False,
                event_families={
                    EventFamily.DNS_ACTIVITY.value,
                },
                aliases={
                    "query", "qname", "query_name", "dns_query", "question"
                },
                suggested_transform="lowercase",
            ),
            CanonicalFieldDefinition(
                path="dns.query_type",
                expected_types={"string", "integer"},
                description="DNS record query type (e.g. A, AAAA, TXT)",
                is_critical=False,
                event_families={
                    EventFamily.DNS_ACTIVITY.value,
                },
                aliases={
                    "qtype", "query_type", "record_type", "dns_type"
                },
                suggested_transform="uppercase",
            ),
            CanonicalFieldDefinition(
                path="dns.response_code",
                expected_types={"string", "integer"},
                description="DNS response status / rcode (e.g. NOERROR, NXDOMAIN)",
                is_critical=False,
                event_families={
                    EventFamily.DNS_ACTIVITY.value,
                },
                aliases={
                    "rcode", "response_code", "dns_rcode"
                },
                suggested_transform="trim",
            ),

            # 7. Device / Host Context
            CanonicalFieldDefinition(
                path="device.hostname",
                expected_types={"string"},
                description="Device or appliance hostname",
                is_critical=False,
                event_families=set(f.value for f in EventFamily),
                aliases={
                    "hostname", "host", "device_name", "device_hostname",
                    "dhost", "shost", "devname", "node"
                },
                suggested_transform="lowercase",
            ),
            CanonicalFieldDefinition(
                path="device.ip",
                expected_types={"ipv4", "ipv6", "ip"},
                description="Reporting device IP address",
                is_critical=False,
                event_families=set(f.value for f in EventFamily),
                aliases={
                    "device_ip", "dev_ip", "dvc_ip", "sensor_ip", "agent_ip", "dvchost"
                },
                suggested_transform="parse_ip",
            ),
        ]

        for defn in definitions:
            self._fields[defn.path] = defn
            # Register aliases
            for alias in defn.aliases:
                norm_alias = self._normalize_name(alias)
                self._alias_index[norm_alias] = defn.path
            # Register path itself
            norm_path = self._normalize_name(defn.path)
            self._alias_index[norm_path] = defn.path

    @classmethod
    def _normalize_name(cls, name: str) -> str:
        s = name.strip().lower()
        s = re.sub(r"[^a-z0-9]", "", s)
        return s

    def get_field(self, path: str) -> Optional[CanonicalFieldDefinition]:
        return self._fields.get(path)

    def get_all_fields(self) -> List[CanonicalFieldDefinition]:
        return list(self._fields.values())

    def lookup_alias(self, name: str) -> Optional[CanonicalFieldDefinition]:
        norm = self._normalize_name(name)
        canonical_path = self._alias_index.get(norm)
        if canonical_path:
            return self._fields.get(canonical_path)
        return None


# =====================================================================
# Semantic Mapper Engine
# =====================================================================

class SemanticMapper:
    """
    Deterministic semantic mapping and confidence scoring engine.
    Computes mapping_score, enforces hard type checks, and handles abstentions.
    """

    AUTO_ACCEPT_THRESHOLD = 0.95
    HUMAN_REVIEW_THRESHOLD = 0.80

    def __init__(self, knowledge_base: Optional[CanonicalKnowledgeBase] = None):
        self.kb = knowledge_base or CanonicalKnowledgeBase()

    @classmethod
    def compute_lexical_similarity(cls, raw: str, target: str) -> float:
        """Normalized string similarity using token and character-level alignment."""
        r_norm = re.sub(r"[^a-z0-9]", "", raw.lower())
        t_norm = re.sub(r"[^a-z0-9]", "", target.lower())

        if not r_norm or not t_norm:
            return 0.0

        if r_norm == t_norm:
            return 1.0

        # Substring / token matching
        if r_norm.endswith(t_norm) or t_norm.endswith(r_norm):
            return 0.90

        # Sequence matcher ratio
        seq_ratio = difflib.SequenceMatcher(None, r_norm, t_norm).ratio()
        return round(seq_ratio, 3)

    def evaluate_type_compatibility(
        self,
        raw_type: str,
        expected_types: Set[str],
        field_profile: Optional[FieldProfile] = None,
    ) -> Tuple[bool, bool]:
        """
        Evaluates datatype compatibility.
        Returns (is_compatible: bool, is_hard_conflict: bool).
        """
        # Null values cannot form a hard conflict by themselves, but are not verified
        if raw_type == DataType.NULL.value:
            return True, False

        # If expected allows string, anything can be serialized as string,
        # UNLESS the expected type is strict (e.g. integer, IP, timestamp) and the observed type is string
        if "string" in expected_types and raw_type == DataType.STRING.value:
            return True, False

        # Direct type match
        if raw_type in expected_types:
            return True, False

        # IP aliases
        if ("ip" in expected_types or "ipv4" in expected_types or "ipv6" in expected_types) and (
            raw_type in ("ipv4", "ipv6", "ip")
        ):
            return True, False

        # Numeric conversions
        if "integer" in expected_types and raw_type == DataType.INTEGER.value:
            return True, False

        if "float" in expected_types and raw_type in (DataType.INTEGER.value, DataType.FLOAT.value):
            return True, False

        # Hard Incompatibilities:
        # 1. Expected integer (e.g. port), but received non-numeric string or IP
        if "integer" in expected_types:
            if raw_type in ("string", "ipv4", "ipv6", "timestamp", "email", "url", "json", "array"):
                # If it's string, check if sample values could be parsed as int
                if field_profile and field_profile.sample_values:
                    try:
                        all(int(str(v)) for v in field_profile.sample_values)
                        return True, False
                    except (ValueError, TypeError):
                        return False, True
                return False, True

        # 2. Expected IP, but received boolean or float
        if ("ip" in expected_types or "ipv4" in expected_types or "ipv6" in expected_types):
            if raw_type in ("boolean", "float", "array", "json"):
                return False, True
            if raw_type == "string" and field_profile and not field_profile.is_ip_candidate:
                # String that is clearly not an IP address
                return False, True

        # 3. Expected timestamp, but received boolean or array
        if "timestamp" in expected_types and raw_type in ("boolean", "array", "json", "ipv4", "ipv6"):
            return False, True

        # Default fallback: not fully compatible, but not fatal hard conflict
        return False, False

    def score_candidate(
        self,
        raw_field: str,
        field_profile: FieldProfile,
        canonical_defn: CanonicalFieldDefinition,
        event_family: Optional[str] = None,
    ) -> MappingCandidate:
        """Scores a single canonical candidate against a raw field profile."""
        evidence: List[str] = []
        raw_clean = raw_field.strip().lower()

        # 1. Lexical and Alias Matching
        norm_raw = CanonicalKnowledgeBase._normalize_name(raw_clean)
        is_exact_path = raw_clean == canonical_defn.path.lower()
        is_exact_alias = (
            raw_clean in canonical_defn.aliases
            or norm_raw in [CanonicalKnowledgeBase._normalize_name(a) for a in canonical_defn.aliases]
            or (not is_exact_path and norm_raw == CanonicalKnowledgeBase._normalize_name(canonical_defn.path))
        )

        if is_exact_path:
            base_score = 1.00
            evidence.append("exact_canonical_path_match")
        elif is_exact_alias:
            base_score = 0.98
            evidence.append("exact_alias_match")
        else:
            # Suffix or token similarity
            leaf_target = canonical_defn.path.split(".")[-1]
            leaf_sim = self.compute_lexical_similarity(raw_clean, leaf_target)
            alias_sims = [self.compute_lexical_similarity(raw_clean, a) for a in canonical_defn.aliases]
            best_alias_sim = max(alias_sims) if alias_sims else 0.0

            best_sim = max(leaf_sim, best_alias_sim)
            if best_sim >= 0.75:
                base_score = best_sim * 0.88
            elif best_sim >= 0.50:
                base_score = best_sim * 0.60
            else:
                base_score = best_sim * 0.40
            evidence.append(f"lexical_similarity:{base_score:.2f}")

        # 2. Datatype Compatibility & Hard Type Checks
        raw_type = field_profile.inferred_type
        is_compat, is_hard_conflict = self.evaluate_type_compatibility(
            raw_type, canonical_defn.expected_types, field_profile=field_profile
        )

        if is_hard_conflict:
            # Severe penalty: force abstention / human review, never auto-accept
            base_score = min(base_score - 0.35, 0.65)
            evidence.append(
                f"hard_type_conflict:expected_{sorted(list(canonical_defn.expected_types))}_got_{raw_type}"
            )
        elif is_compat:
            evidence.append(f"datatype_compatible:{raw_type}")
            # Slight boost for confirmed complex types
            if raw_type in ("ipv4", "ipv6", "timestamp", "email", "url"):
                base_score = min(1.0, base_score + 0.02)
        else:
            base_score -= 0.15
            evidence.append(f"datatype_mismatch:expected_{list(canonical_defn.expected_types)}_got_{raw_type}")

        # 3. Shape & Value Profile Heuristics
        if field_profile.is_ip_candidate and (
            "ipv4" in canonical_defn.expected_types or "ip" in canonical_defn.expected_types
        ):
            base_score = min(1.0, base_score + 0.03)
            evidence.append("is_ip_candidate_bonus")

        if field_profile.is_timestamp_candidate and "timestamp" in canonical_defn.expected_types:
            base_score = min(1.0, base_score + 0.03)
            evidence.append("is_timestamp_candidate_bonus")

        if field_profile.is_enum_candidate and canonical_defn.path in ("event.action", "event.outcome", "network.protocol"):
            base_score = min(1.0, base_score + 0.03)
            evidence.append("is_enum_candidate_bonus")

        # 4. Event Family Context
        if event_family and event_family in canonical_defn.event_families:
            base_score = min(1.0, base_score + 0.02)
            evidence.append(f"event_family_context:{event_family}")

        final_score = max(0.0, min(1.0, round(base_score, 4)))

        # 5. Threshold Decision Logic
        # Safety rule: if hard type conflict exists, NEVER auto-accept
        if is_hard_conflict:
            status = ReviewStatus.ABSTAIN if final_score < self.HUMAN_REVIEW_THRESHOLD else ReviewStatus.HUMAN_REVIEW
        elif final_score >= self.AUTO_ACCEPT_THRESHOLD:
            status = ReviewStatus.AUTO_ACCEPTED
        elif final_score >= self.HUMAN_REVIEW_THRESHOLD:
            status = ReviewStatus.HUMAN_REVIEW
        else:
            status = ReviewStatus.ABSTAIN

        preserve_ext = status == ReviewStatus.ABSTAIN
        dest_path = (
            f"extensions.source.{raw_field}" if preserve_ext else canonical_defn.path
        )

        return MappingCandidate(
            raw_field=raw_field,
            canonical_path=canonical_defn.path,
            mapping_score=final_score,
            evidence=evidence,
            review_status=status,
            is_critical=canonical_defn.is_critical,
            hard_type_conflict=is_hard_conflict,
            suggested_transformation=canonical_defn.suggested_transform,
            preserve_in_extensions=preserve_ext,
            destination_path=dest_path,
        )

    def map_field(
        self,
        field_profile: FieldProfile,
        event_family: Optional[str] = None,
        top_n: int = 3,
    ) -> FieldMappingResult:
        """
        Ranks top-N candidate mappings for a single raw field profile.
        Selects the best mapping or abstains.
        """
        raw_field = field_profile.name
        candidates: List[MappingCandidate] = []

        for defn in self.kb.get_all_fields():
            candidate = self.score_candidate(raw_field, field_profile, defn, event_family=event_family)
            candidates.append(candidate)

        # Sort descending by mapping_score
        candidates.sort(key=lambda c: c.mapping_score, reverse=True)
        top_candidates = candidates[:top_n]
        best_candidate = top_candidates[0] if top_candidates else None

        # Decision on best candidate
        if best_candidate:
            if best_candidate.mapping_score < self.HUMAN_REVIEW_THRESHOLD:
                best_candidate.review_status = ReviewStatus.ABSTAIN
                best_candidate.preserve_in_extensions = True
                best_candidate.destination_path = f"extensions.source.{raw_field}"
                if "abstain_preserve_extension" not in best_candidate.evidence:
                    best_candidate.evidence.append("abstain_preserve_extension")
            return FieldMappingResult(
                raw_field=raw_field, chosen_mapping=best_candidate, top_candidates=top_candidates
            )

        fallback = MappingCandidate(
            raw_field=raw_field,
            canonical_path=f"extensions.source.{raw_field}",
            mapping_score=0.0,
            evidence=["no_match_found", "abstain_preserve_extension"],
            review_status=ReviewStatus.ABSTAIN,
            is_critical=False,
            hard_type_conflict=False,
            suggested_transformation=None,
            preserve_in_extensions=True,
            destination_path=f"extensions.source.{raw_field}",
        )
        return FieldMappingResult(raw_field=raw_field, chosen_mapping=fallback, top_candidates=[])

    def map_source(
        self,
        source_profile: SourceProfile,
        source_id: Optional[str] = None,
        event_family: Optional[str] = None,
        top_n: int = 3,
    ) -> SourceMappingReport:
        """Maps all fields within a SourceProfile produced by Stage 7."""
        results: Dict[str, FieldMappingResult] = {}
        auto_accepted = 0
        human_review = 0
        abstained = 0
        critical_mapped = 0

        for field_name, profile in source_profile.fields.items():
            res = self.map_field(profile, event_family=event_family, top_n=top_n)
            results[field_name] = res

            chosen = res.chosen_mapping
            if chosen.review_status == ReviewStatus.AUTO_ACCEPTED:
                auto_accepted += 1
            elif chosen.review_status == ReviewStatus.HUMAN_REVIEW:
                human_review += 1
            else:
                abstained += 1

            if chosen.is_critical and chosen.review_status != ReviewStatus.ABSTAIN:
                critical_mapped += 1

        summary = {
            "total_fields": len(results),
            "auto_accepted_count": auto_accepted,
            "human_review_count": human_review,
            "abstained_count": abstained,
            "critical_fields_mapped": critical_mapped,
        }

        return SourceMappingReport(
            source_id=source_id,
            event_family=event_family,
            mappings=results,
            summary=summary,
        )

    def map_fields(
        self,
        field_profiles: Dict[str, FieldProfile],
        source_id: Optional[str] = None,
        event_family: Optional[str] = None,
        top_n: int = 3,
    ) -> SourceMappingReport:
        """Convenience method to map a dictionary of FieldProfiles."""
        dummy_source = SourceProfile(
            format="UNKNOWN",
            confidence=1.0,
            total_records=1,
            valid_records=1,
            corrupted_records=0,
            fields=field_profiles,
        )
        return self.map_source(
            dummy_source, source_id=source_id, event_family=event_family, top_n=top_n
        )
