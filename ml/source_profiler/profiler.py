"""
ULPF-X (SIH26156) - STAGE 7: Unknown-Source Profiler
Workstream: Agastya (Intelligence & Assurance Lead)

Purely deterministic (regex/parsing heuristics) unknown-source log profiler.
Detects formats (JSON, Syslog RFC5424, Syslog RFC3164, Key-Value, CSV, CEF, LEEF),
extracts fields, infers data types, captures sample values, and generates log templates.
No LLMs/AI dependencies.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union


class LogFormat(str, Enum):
    JSON = "JSON"
    CEF = "CEF"
    LEEF = "LEEF"
    SYSLOG_RFC5424 = "SYSLOG_RFC5424"
    SYSLOG_RFC3164 = "SYSLOG_RFC3164"
    KEY_VALUE = "KEY_VALUE"
    CSV = "CSV"
    TEXT = "TEXT"
    UNKNOWN = "UNKNOWN"


class DataType(str, Enum):
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MAC_ADDRESS = "mac_address"
    TIMESTAMP = "timestamp"
    EMAIL = "email"
    URL = "url"
    UUID = "uuid"
    JSON = "json"
    ARRAY = "array"
    STRING = "string"
    NULL = "null"


@dataclass
class FieldProfile:
    name: str
    inferred_type: str
    type_distribution: Dict[str, int] = field(default_factory=dict)
    nullable: bool = False
    null_count: int = 0
    total_count: int = 0
    distinct_count: int = 0
    sample_values: List[Any] = field(default_factory=list)
    min_value: Optional[Any] = None
    max_value: Optional[Any] = None
    avg_length: Optional[float] = None
    is_ip_candidate: bool = False
    is_timestamp_candidate: bool = False
    is_enum_candidate: bool = False
    enum_values: Optional[List[Any]] = None
    presence_ratio: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TemplateProfile:
    template_id: str
    template_pattern: str
    count: int
    sample_message: str
    variable_count: int
    frequency_ratio: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SourceProfile:
    format: LogFormat
    confidence: float
    total_records: int
    valid_records: int
    corrupted_records: int
    fields: Dict[str, FieldProfile] = field(default_factory=dict)
    templates: List[TemplateProfile] = field(default_factory=list)
    delimiter: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    sample_events: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format.value if isinstance(self.format, LogFormat) else str(self.format),
            "confidence": round(self.confidence, 4),
            "total_records": self.total_records,
            "valid_records": self.valid_records,
            "corrupted_records": self.corrupted_records,
            "delimiter": self.delimiter,
            "metadata": self.metadata,
            "fields": {k: v.to_dict() for k, v in self.fields.items()},
            "templates": [t.to_dict() for t in self.templates],
            "sample_events": self.sample_events,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


# =====================================================================
# Deterministic Regular Expressions & Parsing Constants
# =====================================================================

# CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
CEF_HEADER_REGEX = re.compile(
    r"^CEF:\s*(\d+)\s*\|"                      # Version
    r"([^\\|]*(?:\\.[^\\|]*)*)\|"              # Device Vendor
    r"([^\\|]*(?:\\.[^\\|]*)*)\|"              # Device Product
    r"([^\\|]*(?:\\.[^\\|]*)*)\|"              # Device Version
    r"([^\\|]*(?:\\.[^\\|]*)*)\|"              # Device Event Class ID
    r"([^\\|]*(?:\\.[^\\|]*)*)\|"              # Name
    r"([^\\|]*(?:\\.[^\\|]*)*)\|"              # Severity
    r"(.*)$",                                  # Extension
    re.DOTALL,
)

# LEEF format: LEEF:Version|Vendor|Product|Version|EventID|[Delimiter|]Extension
LEEF_HEADER_REGEX = re.compile(
    r"^LEEF:\s*([0-9.]+)\s*\|"                 # Version (1.0 or 2.0)
    r"([^\\|]*(?:\\.[^\\|]*)*)\|"              # Vendor
    r"([^\\|]*(?:\\.[^\\|]*)*)\|"              # Product
    r"([^\\|]*(?:\\.[^\\|]*)*)\|"              # Version
    r"([^\\|]*(?:\\.[^\\|]*)*)"                # Event ID
    r"(?:\|(.*))?$",                           # Remainder (Delimiter/Extension)
    re.DOTALL,
)

# Syslog RFC 5424 Header: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [REST]
SYSLOG_5424_HDR = re.compile(
    r"^<(\d{1,3})>1\s+"                         # Priority & Version 1
    r"(\S+)\s+"                                 # Timestamp (ISO 8601 or '-')
    r"(\S+)\s+"                                 # Hostname or '-'
    r"(\S+)\s+"                                 # App-Name or '-'
    r"(\S+)\s+"                                 # ProcID or '-'
    r"(\S+)"                                    # MsgID or '-'
    r"(?:\s+(.*))?$",                           # Structured Data + Message
    re.DOTALL,
)

# Syslog RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG[PID]: MSG or <PRI>TIMESTAMP HOSTNAME TAG: MSG
SYSLOG_3164_REGEX = re.compile(
    r"^<(\d{1,3})>"                             # Priority
    r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # Timestamp e.g. Oct 11 22:14:15
    r"(\S+)\s+"                                 # Hostname
    r"([^:\[\s]+)(?:\[(\d+)\])?:\s*"            # Tag and optional PID
    r"(.*)$",                                   # Message
    re.DOTALL,
)

# Key-Value Pair Scanner
KV_PAIR_REGEX = re.compile(
    r'(?P<key>[a-zA-Z0-9_\.\-\/]+)\s*=\s*'
    r'(?P<val>"[^"\\]*(?:\\.[^"\\]*)*"'
    r"|'[^'\\]*(?:\\.[^'\\]*)*'"
    r'|[^\s,;]+)',
)

# Deterministic Type Heuristics Regexes
RE_INT = re.compile(r"^[+-]?(?:0|[1-9]\d*)$")
RE_FLOAT = re.compile(r"^[+-]?(?:\d+\.\d+|\d+(?:\.\d+)?[eE][+-]?\d+)$")
RE_BOOLEAN = re.compile(r"^(?:true|false|yes|no|on|off)$", re.IGNORECASE)
RE_NULL = re.compile(r"^(?:null|none|nil|n/a|na|-)$", re.IGNORECASE)
RE_MAC = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
RE_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
RE_EMAIL = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
RE_URL = re.compile(r"^(?:https?|ftp|sftp|ws|wss):\/\/[^\s/$.?#].[^\s]*$", re.IGNORECASE)

# Timestamp Regexes
RE_ISO8601 = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$")
RE_SYSLOG_DATE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?$")
RE_HTTP_DATE = re.compile(r"^\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}$")
RE_UNIX_TIMESTAMP = re.compile(r"^1[0-9]{9}(?:\.[0-9]+)?$")
RE_UNIX_TIMESTAMP_MS = re.compile(r"^[12][0-9]{12}$")

# Template Masking Regexes
RE_MASK_ISO8601 = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
RE_MASK_SYSLOG_DATE = re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b")
RE_MASK_HTTP_DATE = re.compile(r"\b\d{2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\b")
RE_MASK_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
RE_MASK_IPV4 = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b")
RE_MASK_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}\b")
RE_MASK_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
RE_MASK_URL = re.compile(r"\b(?:https?|ftp|sftp):\/\/[^\s]+", re.IGNORECASE)
RE_MASK_EMAIL = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")
RE_MASK_WIN_PATH = re.compile(r"\b[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
RE_MASK_UNIX_PATH = re.compile(r"(?:\/[a-zA-Z0-9_.-]+){2,}")
RE_MASK_HEX = re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{16,64}\b")
RE_MASK_QUOTED = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\'')
RE_MASK_NUMBERS = re.compile(r"\b\d+\.\d+\b|\b\d+\b")


# =====================================================================
# Deterministic Type Inferencer
# =====================================================================

class TypeInferencer:
    """Deterministic type inference engine without external dependencies."""

    @classmethod
    def infer_type(cls, val: Any) -> DataType:
        if val is None:
            return DataType.NULL

        if isinstance(val, bool):
            return DataType.BOOLEAN
        if isinstance(val, int):
            return DataType.INTEGER
        if isinstance(val, float):
            return DataType.FLOAT
        if isinstance(val, dict):
            return DataType.JSON
        if isinstance(val, (list, tuple, set)):
            return DataType.ARRAY

        s = str(val).strip()
        if not s:
            return DataType.NULL

        if RE_NULL.match(s):
            return DataType.NULL

        if RE_BOOLEAN.match(s):
            return DataType.BOOLEAN

        if RE_INT.match(s):
            return DataType.INTEGER

        if RE_FLOAT.match(s):
            return DataType.FLOAT

        # Check MAC address before IP / others
        if RE_MAC.match(s):
            return DataType.MAC_ADDRESS

        # Check IP addresses
        if "." in s and RE_MASK_IPV4.fullmatch(s):
            try:
                ipaddress.IPv4Address(s)
                return DataType.IPV4
            except ValueError:
                pass

        if ":" in s:
            try:
                ipaddress.IPv6Address(s)
                return DataType.IPV6
            except ValueError:
                pass

        if RE_UUID.match(s):
            return DataType.UUID

        if RE_EMAIL.match(s):
            return DataType.EMAIL

        if RE_URL.match(s):
            return DataType.URL

        # Timestamp checks
        if RE_ISO8601.match(s) or RE_SYSLOG_DATE.match(s) or RE_HTTP_DATE.match(s):
            return DataType.TIMESTAMP

        if RE_UNIX_TIMESTAMP.match(s) or RE_UNIX_TIMESTAMP_MS.match(s):
            try:
                num = float(s)
                if (num >= 946684800 and num <= 4102444800) or (num >= 946684800000 and num <= 4102444800000):
                    return DataType.TIMESTAMP
            except ValueError:
                pass

        # Nested JSON string check
        if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, dict):
                    return DataType.JSON
                if isinstance(parsed, list):
                    return DataType.ARRAY
            except Exception:
                pass

        return DataType.STRING


# =====================================================================
# Deterministic Template Mining & Masking
# =====================================================================

class TemplateMiner:
    """Deterministic log template mining and parameter abstraction."""

    @classmethod
    def mask_message(cls, message: str) -> str:
        if not message:
            return ""

        text = message
        text = RE_MASK_URL.sub("<URL>", text)
        text = RE_MASK_EMAIL.sub("<EMAIL>", text)
        text = RE_MASK_ISO8601.sub("<TIMESTAMP>", text)
        text = RE_MASK_HTTP_DATE.sub("<TIMESTAMP>", text)
        text = RE_MASK_SYSLOG_DATE.sub("<TIMESTAMP>", text)
        text = RE_MASK_UUID.sub("<UUID>", text)
        text = RE_MASK_MAC.sub("<MAC>", text)
        text = RE_MASK_IPV4.sub("<IP>", text)
        text = RE_MASK_IPV6.sub("<IP>", text)
        text = RE_MASK_WIN_PATH.sub("<PATH>", text)
        text = RE_MASK_UNIX_PATH.sub("<PATH>", text)
        text = RE_MASK_HEX.sub("<HEX>", text)
        text = RE_MASK_QUOTED.sub('"<STR>"', text)
        text = RE_MASK_NUMBERS.sub("<NUM>", text)

        # Collapse whitespace
        text = re.sub(r"\s+", " ", text).strip()
        return text

    @classmethod
    def generate_template_id(cls, pattern: str) -> str:
        # Fast deterministic hash for template ID
        h = 0
        for char in pattern:
            h = (h * 31 + ord(char)) & 0xFFFFFFFF
        return f"tpl_{h:08x}"


# =====================================================================
# Specialized Deterministic Parsers
# =====================================================================

class CEFParser:
    """Deterministic parser for ArcSight Common Event Format (CEF)."""

    @classmethod
    def is_cef(cls, line: str) -> bool:
        s = line.strip()
        return s.startswith("CEF:") and s.count("|") >= 7

    @classmethod
    def parse(cls, line: str) -> Optional[Dict[str, Any]]:
        s = line.strip()
        match = CEF_HEADER_REGEX.match(s)
        if not match:
            return None

        cef_ver, dev_vendor, dev_prod, dev_ver, dev_class_id, name, severity, ext = match.groups()

        result: Dict[str, Any] = {
            "cef_version": cef_ver,
            "device_vendor": dev_vendor.replace(r"\|", "|").replace(r"\\", "\\"),
            "device_product": dev_prod.replace(r"\|", "|").replace(r"\\", "\\"),
            "device_version": dev_ver.replace(r"\|", "|").replace(r"\\", "\\"),
            "device_event_class_id": dev_class_id.replace(r"\|", "|").replace(r"\\", "\\"),
            "name": name.replace(r"\|", "|").replace(r"\\", "\\"),
            "severity": severity.replace(r"\|", "|").replace(r"\\", "\\"),
        }

        # Parse extension key-value pairs
        if ext:
            ext_dict = cls.parse_cef_extension(ext)
            result.update(ext_dict)

        return result

    @classmethod
    def parse_cef_extension(cls, ext: str) -> Dict[str, Any]:
        result = {}
        # Pattern captures key=value pairs up to next key= or end of string
        pattern = re.compile(r'([a-zA-Z0-9_\.\-]+)=((?:\\=|\\\||\\\\|[^=])+?)(?=\s+[a-zA-Z0-9_\.\-]+=|$)')
        for m in pattern.finditer(ext):
            k = m.group(1).strip()
            v = m.group(2).strip()
            v = v.replace(r"\=", "=").replace(r"\|", "|").replace(r"\\", "\\").replace(r"\n", "\n").replace(r"\r", "\r")
            if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                v = v[1:-1]
            result[k] = v
        return result


class LEEFParser:
    """Deterministic parser for IBM Log Event Extended Format (LEEF 1.0 & 2.0)."""

    @classmethod
    def is_leef(cls, line: str) -> bool:
        s = line.strip()
        return s.startswith("LEEF:") and s.count("|") >= 4

    @classmethod
    def parse(cls, line: str) -> Optional[Dict[str, Any]]:
        s = line.strip()
        match = LEEF_HEADER_REGEX.match(s)
        if not match:
            return None

        leef_ver, vendor, prod, version, event_id, remainder = match.groups()

        result: Dict[str, Any] = {
            "leef_version": leef_ver,
            "vendor": vendor.replace(r"\|", "|").replace(r"\\", "\\"),
            "product": prod.replace(r"\|", "|").replace(r"\\", "\\"),
            "version": version.replace(r"\|", "|").replace(r"\\", "\\"),
            "event_id": event_id.replace(r"\|", "|").replace(r"\\", "\\"),
        }

        if not remainder:
            return result

        delimiter = "\t"
        extension_str = remainder

        # In LEEF 2.0, remainder can be "delimiter|attributes"
        if leef_ver.startswith("2") and "|" in remainder:
            parts = remainder.split("|", 1)
            delimiter = cls._resolve_leef_delimiter(parts[0])
            extension_str = parts[1] if len(parts) > 1 else ""

        if extension_str:
            ext_dict = cls._parse_leef_attributes(extension_str, delimiter)
            result.update(ext_dict)

        return result

    @classmethod
    def _resolve_leef_delimiter(cls, raw: str) -> str:
        if raw.startswith("x") or raw.startswith("0x"):
            try:
                code = int(raw.replace("0x", "").replace("x", ""), 16)
                return chr(code)
            except ValueError:
                pass
        if raw == r"\t" or raw == "\t":
            return "\t"
        return raw if raw else "\t"

    @classmethod
    def _parse_leef_attributes(cls, ext: str, delimiter: str) -> Dict[str, Any]:
        result = {}
        tokens = ext.split(delimiter)
        for token in tokens:
            token = token.strip()
            if "=" in token:
                k, v = token.split("=", 1)
                k = k.strip()
                v = v.strip()
                v = v.replace(r"\=", "=").replace(r"\\", "\\")
                if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                    v = v[1:-1]
                result[k] = v
        return result


class Syslog5424Parser:
    """Deterministic parser for RFC 5424 Syslog."""

    @classmethod
    def is_syslog_5424(cls, line: str) -> bool:
        s = line.strip()
        return bool(SYSLOG_5424_HDR.match(s))

    @classmethod
    def parse(cls, line: str) -> Optional[Dict[str, Any]]:
        s = line.strip()
        match = SYSLOG_5424_HDR.match(s)
        if not match:
            return None

        prival, ts, hostname, appname, procid, msgid, rest = match.groups()
        prival_int = int(prival)

        record: Dict[str, Any] = {
            "prival": prival_int,
            "facility": prival_int >> 3,
            "severity": prival_int & 7,
            "version": 1,
            "timestamp": None if ts == "-" else ts,
            "hostname": None if hostname == "-" else hostname,
            "app_name": None if appname == "-" else appname,
            "proc_id": None if procid == "-" else procid,
            "msg_id": None if msgid == "-" else msgid,
            "message": "",
        }

        if not rest:
            return record

        rest = rest.strip()
        if rest == "-":
            return record

        if rest.startswith("- "):
            record["message"] = rest[2:].strip()
            return record

        # Extract all structured data blocks: [id param1="val1" param2="val2"]
        sd_blocks: List[str] = []
        idx = 0
        while idx < len(rest) and rest[idx] == "[":
            end_idx = rest.find("]", idx)
            if end_idx != -1:
                sd_blocks.append(rest[idx : end_idx + 1])
                idx = end_idx + 1
                while idx < len(rest) and rest[idx] == " ":
                    idx += 1
            else:
                break

        msg = rest[idx:].strip()
        record["message"] = msg

        for block in sd_blocks:
            inner = block[1:-1].strip()
            parts = inner.split(None, 1)
            sd_id = parts[0]
            record[f"sd_{sd_id}"] = parts[1] if len(parts) > 1 else ""
            if len(parts) > 1:
                for k, v in re.findall(r'(\S+?)="([^"\\]*(?:\\.[^"\\]*)*)"', parts[1]):
                    v_clean = v.replace(r"\"", '"').replace(r"\\", "\\").replace(r"\]", "]")
                    record[f"sd_{sd_id}_{k}"] = v_clean

        return record


class Syslog3164Parser:
    """Deterministic parser for RFC 3164 BSD Syslog."""

    @classmethod
    def is_syslog_3164(cls, line: str) -> bool:
        s = line.strip()
        return bool(SYSLOG_3164_REGEX.match(s))

    @classmethod
    def parse(cls, line: str) -> Optional[Dict[str, Any]]:
        s = line.strip()
        match = SYSLOG_3164_REGEX.match(s)
        if not match:
            return None

        prival, ts, hostname, tag, pid, msg = match.groups()
        prival_int = int(prival)

        return {
            "prival": prival_int,
            "facility": prival_int >> 3,
            "severity": prival_int & 7,
            "timestamp": ts,
            "hostname": hostname,
            "tag": tag,
            "proc_id": pid if pid else None,
            "message": msg.strip() if msg else "",
        }


class JSONParser:
    """Deterministic JSON log parser with flattening capabilities."""

    @classmethod
    def is_json(cls, line: str) -> bool:
        s = line.strip()
        if not (s.startswith("{") and s.endswith("}")):
            return False
        try:
            data = json.loads(s)
            return isinstance(data, dict)
        except Exception:
            return False

    @classmethod
    def parse(cls, line: str, flatten: bool = True) -> Optional[Dict[str, Any]]:
        s = line.strip()
        try:
            data = json.loads(s)
            if not isinstance(data, dict):
                return None
            return cls.flatten_dict(data) if flatten else data
        except Exception:
            return None

    @classmethod
    def flatten_dict(cls, d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
        items: List[Tuple[str, Any]] = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
            if isinstance(v, dict) and v:
                items.extend(cls.flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)


class KeyValueParser:
    """Deterministic parser for logfmt / key-value telemetry."""

    @classmethod
    def is_kv(cls, line: str, min_pairs: int = 2) -> bool:
        s = line.strip()
        if s.startswith("CEF:") or s.startswith("LEEF:") or s.startswith("<"):
            return False
        if s.startswith("{") and s.endswith("}"):
            return False
        pairs = KV_PAIR_REGEX.findall(s)
        if len(pairs) < min_pairs:
            return False

        matched_len = sum(len(m[0]) + len(m[1]) + 1 for m in pairs)
        return matched_len >= len(s) * 0.35 or len(pairs) >= 3

    @classmethod
    def parse(cls, line: str) -> Dict[str, Any]:
        return cls.parse_extension(line.strip())

    @classmethod
    def parse_extension(cls, text: str) -> Dict[str, Any]:
        result = {}
        for m in KV_PAIR_REGEX.finditer(text):
            k = m.group("key")
            v = m.group("val")
            if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                v = v[1:-1]
            v = v.replace(r"\"", '"').replace(r"\'", "'").replace(r"\\", "\\").replace(r"\=", "=")
            result[k] = v
        return result


class CSVParser:
    """Deterministic CSV and delimited log parser."""

    DELIMITERS = [",", "\t", "|", ";"]

    @classmethod
    def detect_delimiter(cls, lines: List[str]) -> Optional[str]:
        if not lines:
            return None

        for delim in cls.DELIMITERS:
            counts = []
            for line in lines[:50]:
                s = line.strip()
                if not s:
                    continue
                if s.startswith("CEF:") or s.startswith("LEEF:") or s.startswith("<"):
                    continue
                try:
                    row = next(csv.reader([s], delimiter=delim))
                    if len(row) > 1:
                        counts.append(len(row))
                except Exception:
                    pass

            if len(counts) >= 2:
                if len(set(counts)) == 1 and counts[0] >= 2:
                    return delim
                most_common_cnt, freq = Counter(counts).most_common(1)[0]
                if freq / len(counts) >= 0.85 and most_common_cnt >= 2:
                    return delim
        return None

    @classmethod
    def parse_line(cls, line: str, delimiter: str, headers: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        s = line.strip()
        try:
            row = next(csv.reader([s], delimiter=delimiter))
            if not row:
                return None
            if headers and len(headers) == len(row):
                return {headers[i]: row[i].strip() for i in range(len(row))}
            return {f"column_{i+1}": row[i].strip() for i in range(len(row))}
        except Exception:
            return None


# =====================================================================
# Main Engine: UnknownSourceProfiler
# =====================================================================

class UnknownSourceProfiler:
    """
    Purely deterministic engine for unknown-source log profiling.
    Detects formats, extracts schema/fields, infers types, and mines templates.
    """

    def __init__(self, sample_limit: int = 1000):
        self.sample_limit = sample_limit
        self.type_inferencer = TypeInferencer()
        self.template_miner = TemplateMiner()

    def detect_format(self, raw_log: str) -> Tuple[LogFormat, float, Dict[str, Any]]:
        """
        Detects the format of a single log line deterministically.
        Returns (format, confidence, metadata).
        """
        s = raw_log.strip()
        if not s:
            return LogFormat.UNKNOWN, 0.0, {}

        # 1. CEF
        if CEFParser.is_cef(s):
            return LogFormat.CEF, 1.0, {"header_type": "ArcSight CEF"}

        # 2. LEEF
        if LEEFParser.is_leef(s):
            return LogFormat.LEEF, 1.0, {"header_type": "IBM QRadar LEEF"}

        # 3. Syslog RFC 5424
        if Syslog5424Parser.is_syslog_5424(s):
            return LogFormat.SYSLOG_RFC5424, 1.0, {"rfc": "RFC5424"}

        # 4. Syslog RFC 3164
        if Syslog3164Parser.is_syslog_3164(s):
            return LogFormat.SYSLOG_RFC3164, 0.95, {"rfc": "RFC3164"}

        # 5. JSON
        if JSONParser.is_json(s):
            return LogFormat.JSON, 1.0, {"syntax": "JSON"}

        # 6. Key-Value
        if KeyValueParser.is_kv(s):
            return LogFormat.KEY_VALUE, 0.90, {"syntax": "logfmt/key-value"}

        # 7. Fallback to TEXT
        return LogFormat.TEXT, 0.5, {}

    def detect_batch_format(self, lines: List[str]) -> Tuple[LogFormat, float, Optional[str], Dict[str, Any]]:
        """
        Detects the dominant format across a batch of log lines.
        Returns (dominant_format, confidence, delimiter, metadata).
        """
        clean_lines = [line.strip() for line in lines if line.strip()]
        if not clean_lines:
            return LogFormat.UNKNOWN, 0.0, None, {}

        # Check CSV across the batch first
        csv_delim = CSVParser.detect_delimiter(clean_lines)
        if csv_delim:
            non_csv_structured = sum(
                1 for l in clean_lines
                if CEFParser.is_cef(l) or LEEFParser.is_leef(l) or Syslog5424Parser.is_syslog_5424(l) or JSONParser.is_json(l)
            )
            if non_csv_structured / len(clean_lines) < 0.2:
                return LogFormat.CSV, 0.95, csv_delim, {"delimiter": csv_delim}

        # Profile line-by-line formats
        format_votes: Counter[LogFormat] = Counter()
        for line in clean_lines:
            fmt, _, _ = self.detect_format(line)
            format_votes[fmt] += 1

        total = len(clean_lines)
        dominant_fmt, count = format_votes.most_common(1)[0]
        confidence = count / total

        metadata = {"format_distribution": {k.value: v for k, v in format_votes.items()}}
        return dominant_fmt, confidence, None, metadata

    def parse_record(
        self,
        raw_log: str,
        format_hint: Optional[LogFormat] = None,
        delimiter: Optional[str] = None,
        headers: Optional[List[str]] = None,
    ) -> Tuple[Optional[Dict[str, Any]], LogFormat]:
        """
        Deterministically parses a single log line into a dictionary of fields.
        Returns (parsed_fields, detected_format).
        """
        s = raw_log.strip()
        if not s:
            return None, LogFormat.UNKNOWN

        target_fmt = format_hint
        if target_fmt is None or target_fmt == LogFormat.UNKNOWN:
            target_fmt, _, _ = self.detect_format(s)

        if target_fmt == LogFormat.JSON:
            res = JSONParser.parse(s)
            if res is not None:
                return res, LogFormat.JSON
            if format_hint == LogFormat.JSON:
                return None, LogFormat.JSON

        elif target_fmt == LogFormat.CEF:
            res = CEFParser.parse(s)
            if res is not None:
                return res, LogFormat.CEF
            if format_hint == LogFormat.CEF:
                return None, LogFormat.CEF

        elif target_fmt == LogFormat.LEEF:
            res = LEEFParser.parse(s)
            if res is not None:
                return res, LogFormat.LEEF
            if format_hint == LogFormat.LEEF:
                return None, LogFormat.LEEF

        elif target_fmt == LogFormat.SYSLOG_RFC5424:
            res = Syslog5424Parser.parse(s)
            if res is not None:
                return res, LogFormat.SYSLOG_RFC5424
            if format_hint == LogFormat.SYSLOG_RFC5424:
                return None, LogFormat.SYSLOG_RFC5424

        elif target_fmt == LogFormat.SYSLOG_RFC3164:
            res = Syslog3164Parser.parse(s)
            if res is not None:
                return res, LogFormat.SYSLOG_RFC3164
            if format_hint == LogFormat.SYSLOG_RFC3164:
                return None, LogFormat.SYSLOG_RFC3164

        elif target_fmt == LogFormat.KEY_VALUE:
            res = KeyValueParser.parse(s)
            if res:
                return res, LogFormat.KEY_VALUE
            if format_hint == LogFormat.KEY_VALUE:
                return None, LogFormat.KEY_VALUE

        elif target_fmt == LogFormat.CSV and delimiter:
            res = CSVParser.parse_line(s, delimiter, headers=headers)
            if res is not None:
                return res, LogFormat.CSV
            if format_hint == LogFormat.CSV:
                return None, LogFormat.CSV

        # Fallback to plain text
        return {"message": s}, LogFormat.TEXT

    def profile_line(self, raw_log: str) -> SourceProfile:
        """Profiles a single log line."""
        return self.profile([raw_log])

    def profile(self, logs: Union[str, List[str], Iterable[str]]) -> SourceProfile:
        """
        Profiles a collection or stream of logs.
        Aggregates field schemas, data types, nullabilities, sample values, and templates.
        """
        if isinstance(logs, str):
            lines = [line for line in logs.splitlines() if line.strip()]
        else:
            lines = [line.strip() for line in logs if line and line.strip()]

        total_records = len(lines)
        if total_records == 0:
            return SourceProfile(
                format=LogFormat.UNKNOWN,
                confidence=0.0,
                total_records=0,
                valid_records=0,
                corrupted_records=0,
            )

        # 1. Detect dominant batch format
        sample_subset = lines[: self.sample_limit]
        dominant_fmt, confidence, delimiter, meta = self.detect_batch_format(sample_subset)

        # CSV Header detection heuristic
        headers: Optional[List[str]] = None
        start_idx = 0
        if dominant_fmt == LogFormat.CSV and delimiter and len(lines) >= 2:
            try:
                first_row = next(csv.reader([lines[0]], delimiter=delimiter))
                second_row = next(csv.reader([lines[1]], delimiter=delimiter))
                if len(first_row) == len(second_row):
                    first_types = [TypeInferencer.infer_type(col) for col in first_row]
                    second_types = [TypeInferencer.infer_type(col) for col in second_row]
                    if all(t == DataType.STRING for t in first_types) and any(
                        t != DataType.STRING for t in second_types
                    ):
                        headers = [h.strip() for h in first_row]
                        start_idx = 1
            except Exception:
                pass

        # 2. Process records
        valid_records = 0
        corrupted_records = 0
        parsed_records: List[Dict[str, Any]] = []

        field_types: Dict[str, Counter[str]] = defaultdict(Counter)
        field_null_counts: Dict[str, int] = defaultdict(int)
        field_distinct_values: Dict[str, Set[Any]] = defaultdict(set)
        field_sample_values: Dict[str, List[Any]] = defaultdict(list)
        field_min_values: Dict[str, Any] = {}
        field_max_values: Dict[str, Any] = {}
        field_lengths: Dict[str, List[int]] = defaultdict(list)

        template_counts: Counter[str] = Counter()
        template_samples: Dict[str, str] = {}
        template_var_counts: Dict[str, int] = {}

        for line in lines[start_idx:]:
            parsed, record_fmt = self.parse_record(
                line, format_hint=dominant_fmt, delimiter=delimiter, headers=headers
            )

            if parsed is None or not parsed:
                corrupted_records += 1
                continue

            valid_records += 1
            if len(parsed_records) < 10:
                parsed_records.append(parsed)

            # Field aggregation
            for k, val in parsed.items():
                inferred = TypeInferencer.infer_type(val)
                type_name = inferred.value
                field_types[k][type_name] += 1

                if inferred == DataType.NULL or val is None or val == "":
                    field_null_counts[k] += 1
                else:
                    s_val = str(val)
                    if len(field_distinct_values[k]) < 500:
                        field_distinct_values[k].add(s_val)

                    if len(field_sample_values[k]) < 5 and s_val not in field_sample_values[k]:
                        field_sample_values[k].append(val)

                    field_lengths[k].append(len(s_val))

                    if inferred in (DataType.INTEGER, DataType.FLOAT):
                        try:
                            num = float(val)
                            if k not in field_min_values or num < field_min_values[k]:
                                field_min_values[k] = num
                            if k not in field_max_values or num > field_max_values[k]:
                                field_max_values[k] = num
                        except ValueError:
                            pass
                    elif inferred == DataType.STRING:
                        if k not in field_min_values or s_val < str(field_min_values[k]):
                            field_min_values[k] = s_val
                        if k not in field_max_values or s_val > str(field_max_values[k]):
                            field_max_values[k] = s_val

            # Template mining
            message_text = parsed.get("message") or parsed.get("name") or line
            if isinstance(message_text, str) and message_text:
                tpl_pattern = TemplateMiner.mask_message(message_text)
                template_counts[tpl_pattern] += 1
                if tpl_pattern not in template_samples:
                    template_samples[tpl_pattern] = message_text
                    template_var_counts[tpl_pattern] = len(re.findall(r"<[A-Z]+>", tpl_pattern))

        # 3. Construct Field Profiles
        fields_profile: Dict[str, FieldProfile] = {}
        all_field_names = set(field_types.keys())

        for name in sorted(all_field_names):
            type_counter = field_types[name]
            non_null_types = {k: v for k, v in type_counter.items() if k != DataType.NULL.value}
            if non_null_types:
                dom_type = max(non_null_types.items(), key=lambda x: x[1])[0]
            else:
                dom_type = DataType.NULL.value

            null_cnt = field_null_counts[name]
            missing_cnt = valid_records - sum(type_counter.values())
            total_null = null_cnt + max(0, missing_cnt)
            is_nullable = total_null > 0

            distinct_cnt = len(field_distinct_values[name])
            lengths = field_lengths.get(name, [])
            avg_len = round(sum(lengths) / len(lengths), 2) if lengths else None

            is_ip = dom_type in (DataType.IPV4.value, DataType.IPV6.value)
            is_ts = dom_type == DataType.TIMESTAMP.value

            non_null_cnt = valid_records - total_null
            pres_ratio = round(non_null_cnt / max(1, valid_records), 4)

            is_enum = False
            enum_vals = None
            if (
                non_null_cnt >= 2
                and distinct_cnt <= min(25, max(2, int(non_null_cnt * 0.5)))
                and dom_type in (DataType.STRING.value, DataType.INTEGER.value, DataType.BOOLEAN.value)
            ):
                is_enum = True
                enum_vals = sorted(list(field_distinct_values[name]))[:25]

            fields_profile[name] = FieldProfile(
                name=name,
                inferred_type=dom_type,
                type_distribution=dict(type_counter),
                nullable=is_nullable,
                null_count=total_null,
                total_count=valid_records,
                distinct_count=distinct_cnt,
                sample_values=field_sample_values.get(name, []),
                min_value=field_min_values.get(name),
                max_value=field_max_values.get(name),
                avg_length=avg_len,
                is_ip_candidate=is_ip,
                is_timestamp_candidate=is_ts,
                is_enum_candidate=is_enum,
                enum_values=enum_vals,
                presence_ratio=pres_ratio,
            )

        # 4. Construct Template Profiles
        template_profiles: List[TemplateProfile] = []
        for pattern, count in template_counts.most_common(50):
            tpl_id = TemplateMiner.generate_template_id(pattern)
            template_profiles.append(
                TemplateProfile(
                    template_id=tpl_id,
                    template_pattern=pattern,
                    count=count,
                    sample_message=template_samples[pattern],
                    variable_count=template_var_counts.get(pattern, 0),
                    frequency_ratio=round(count / max(1, valid_records), 4),
                )
            )

        return SourceProfile(
            format=dominant_fmt,
            confidence=confidence,
            total_records=total_records,
            valid_records=valid_records,
            corrupted_records=corrupted_records,
            fields=fields_profile,
            templates=template_profiles,
            delimiter=delimiter,
            metadata=meta,
            sample_events=parsed_records,
        )

    def profile_file(self, filepath: str) -> SourceProfile:
        """Profiles a file containing log records."""
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return self.profile(f.readlines())

    def profile_stream(self, stream: io.TextIOBase) -> SourceProfile:
        """Profiles an open text stream."""
        return self.profile(stream.readlines())
