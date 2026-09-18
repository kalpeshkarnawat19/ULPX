"""
ULPF-X (SIH26156) - STAGE 7: Unknown-Source Profiler Test Suite
Workstream: Agastya (Intelligence & Assurance Lead)

Comprehensive test suite for purely deterministic Unknown-Source Profiler:
- Format detection (JSON, Syslog RFC5424, Syslog RFC3164, Key-Value, CSV, CEF, LEEF, TEXT)
- Field extraction and flattening
- Type inference (IPv4, IPv6, MAC, UUID, Timestamps, Email, URL, Numeric, Boolean, etc.)
- Template extraction and dynamic variable masking
- Batch aggregation, nullability, sample values, min/max statistics
- Delimiter variations (comma, tab, pipe, semicolon, hex delimiters in LEEF 2.0)
- Stream and file profiling
- Malformed log resilience and JSON serialization
"""

import io
import json
import os
import sys
import tempfile
import pytest

# Ensure repository root is on sys.path for pytest invocation
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from ml.source_profiler.profiler import (
    UnknownSourceProfiler,
    LogFormat,
    DataType,
    TypeInferencer,
    TemplateMiner,
    CEFParser,
    LEEFParser,
    Syslog5424Parser,
    Syslog3164Parser,
    JSONParser,
    KeyValueParser,
    CSVParser,
    FieldProfile,
    TemplateProfile,
    SourceProfile,
)


@pytest.fixture
def profiler():
    return UnknownSourceProfiler()


# =====================================================================
# 1. Format Detection Tests
# =====================================================================

def test_detect_json_format(profiler):
    raw = '{"timestamp": "2023-10-15T12:00:00Z", "level": "INFO", "user_id": 1042, "ip": "192.168.1.50"}'
    fmt, conf, meta = profiler.detect_format(raw)
    assert fmt == LogFormat.JSON
    assert conf == 1.0


def test_detect_cef_format(profiler):
    raw = "CEF:0|SecurityCorp|ThreatShield|2.4.1|1001|Malware Blocked|7|src=10.0.0.15 dst=172.16.0.4 spt=44122 dpt=443"
    fmt, conf, meta = profiler.detect_format(raw)
    assert fmt == LogFormat.CEF
    assert conf == 1.0


def test_detect_leef_1_format(profiler):
    raw = "LEEF:1.0|Microsoft|MSExchange|2013|AuthSuccess|src=192.168.1.1\tdst=192.168.1.2\taccount=admin"
    fmt, conf, meta = profiler.detect_format(raw)
    assert fmt == LogFormat.LEEF
    assert conf == 1.0


def test_detect_leef_2_format(profiler):
    raw = "LEEF:2.0|Trend Micro|Deep Security|9.0|2000000|^|src=10.10.10.10^dst=10.10.10.20^proto=TCP"
    fmt, conf, meta = profiler.detect_format(raw)
    assert fmt == LogFormat.LEEF
    assert conf == 1.0


def test_detect_leef_2_hex_delimiter(profiler):
    raw = "LEEF:2.0|VendorX|ProductY|1.0|EventZ|x20|src=10.0.0.1 dst=10.0.0.2"
    record, fmt = profiler.parse_record(raw)
    assert fmt == LogFormat.LEEF
    assert record["src"] == "10.0.0.1"
    assert record["dst"] == "10.0.0.2"


def test_detect_syslog_5424_format(profiler):
    raw = '<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog 47 ID47 [exampleSDID@32473 iut="3" eventSource="Application"] An application event log entry'
    fmt, conf, meta = profiler.detect_format(raw)
    assert fmt == LogFormat.SYSLOG_RFC5424
    assert conf == 1.0


def test_detect_syslog_5424_no_sd(profiler):
    raw = "<34>1 2003-10-11T22:14:15.003Z host.net myapp 100 - - Simple message without SD"
    record, fmt = profiler.parse_record(raw)
    assert fmt == LogFormat.SYSLOG_RFC5424
    assert record["prival"] == 34
    assert record["facility"] == 4
    assert record["severity"] == 2
    assert record["hostname"] == "host.net"
    assert record["message"] == "Simple message without SD"


def test_detect_syslog_3164_format(profiler):
    raw = "<34>Oct 11 22:14:15 mymachine su[1234]: 'su root' failed for lonvick on /dev/pts/8"
    fmt, conf, meta = profiler.detect_format(raw)
    assert fmt == LogFormat.SYSLOG_RFC3164
    assert conf == 0.95


def test_detect_key_value_format(profiler):
    raw = 'time="2023-10-15 14:00:00" level=info msg="authentication successful" user=alice ip=10.0.0.5 duration_ms=45.2'
    fmt, conf, meta = profiler.detect_format(raw)
    assert fmt == LogFormat.KEY_VALUE
    assert conf >= 0.9


def test_detect_csv_batch_format(profiler):
    lines = [
        "timestamp,ip,status,bytes",
        "2023-10-15T12:00:00Z,192.168.1.1,200,1024",
        "2023-10-15T12:00:01Z,192.168.1.2,404,512",
        "2023-10-15T12:00:02Z,192.168.1.3,500,256",
    ]
    fmt, conf, delim, meta = profiler.detect_batch_format(lines)
    assert fmt == LogFormat.CSV
    assert delim == ","
    assert conf >= 0.9


def test_detect_tsv_batch_format(profiler):
    lines = [
        "2023-10-15T12:00:00Z\t192.168.1.1\t200\t1024",
        "2023-10-15T12:00:01Z\t192.168.1.2\t404\t512",
        "2023-10-15T12:00:02Z\t192.168.1.3\t500\t256",
    ]
    fmt, conf, delim, meta = profiler.detect_batch_format(lines)
    assert fmt == LogFormat.CSV
    assert delim == "\t"


def test_detect_pipe_delimited_csv(profiler):
    lines = [
        "2023-10-15T12:00:00Z|192.168.1.1|200|1024",
        "2023-10-15T12:00:01Z|192.168.1.2|404|512",
        "2023-10-15T12:00:02Z|192.168.1.3|500|256",
    ]
    fmt, conf, delim, meta = profiler.detect_batch_format(lines)
    assert fmt == LogFormat.CSV
    assert delim == "|"


# =====================================================================
# 2. Field Extraction & Parsing Tests
# =====================================================================

def test_parse_json_with_nesting(profiler):
    raw = json.dumps({
        "event_id": "evt_9901",
        "actor": {
            "name": "john_doe",
            "email": "john@corp.local",
            "details": {
                "department": "Engineering",
                "active": True
            }
        },
        "response_time": 12.35,
        "attempts": 3
    })
    record, fmt = profiler.parse_record(raw)
    assert fmt == LogFormat.JSON
    assert record["event_id"] == "evt_9901"
    assert record["actor.name"] == "john_doe"
    assert record["actor.email"] == "john@corp.local"
    assert record["actor.details.department"] == "Engineering"
    assert record["actor.details.active"] is True
    assert record["response_time"] == 12.35
    assert record["attempts"] == 3


def test_parse_cef_fields(profiler):
    raw = r"CEF:0|Check Point|VPN-1 & FireWall-1|4.1|drop|drop|1|src=192.168.1.5 dst=10.0.0.1 spt=5000 dpt=80 msg=packet\=dropped"
    record, fmt = profiler.parse_record(raw)
    assert fmt == LogFormat.CEF
    assert record["cef_version"] == "0"
    assert record["device_vendor"] == "Check Point"
    assert record["device_product"] == "VPN-1 & FireWall-1"
    assert record["device_version"] == "4.1"
    assert record["device_event_class_id"] == "drop"
    assert record["name"] == "drop"
    assert record["severity"] == "1"
    assert record["src"] == "192.168.1.5"
    assert record["dst"] == "10.0.0.1"
    assert record["spt"] == "5000"
    assert record["dpt"] == "80"
    assert record["msg"] == "packet=dropped"


def test_parse_leef_1_and_2(profiler):
    # LEEF 1.0 tab-delimited
    raw_1 = "LEEF:1.0|Cisco|ASA|9.2|106015|src=10.1.1.1\tdst=10.2.2.2\tproto=icmp"
    record_1, fmt_1 = profiler.parse_record(raw_1)
    assert fmt_1 == LogFormat.LEEF
    assert record_1["vendor"] == "Cisco"
    assert record_1["product"] == "ASA"
    assert record_1["event_id"] == "106015"
    assert record_1["src"] == "10.1.1.1"
    assert record_1["proto"] == "icmp"

    # LEEF 2.0 with custom delimiter '^'
    raw_2 = "LEEF:2.0|PaloAlto|PAN-OS|8.1|threat|^|src=172.16.1.1^dst=8.8.8.8^cat=malware"
    record_2, fmt_2 = profiler.parse_record(raw_2)
    assert fmt_2 == LogFormat.LEEF
    assert record_2["vendor"] == "PaloAlto"
    assert record_2["src"] == "172.16.1.1"
    assert record_2["dst"] == "8.8.8.8"
    assert record_2["cat"] == "malware"


def test_parse_syslog_5424_structured_data(profiler):
    raw = '<165>1 2023-10-15T16:20:00.000Z host.acme.com myapp 9812 ID47 [meta@123 session="xyz123" user="bob"] [net@123 ip="192.168.0.1"] User session initiated'
    record, fmt = profiler.parse_record(raw)
    assert fmt == LogFormat.SYSLOG_RFC5424
    assert record["prival"] == 165
    assert record["facility"] == 20  # 165 >> 3
    assert record["severity"] == 5   # 165 & 7
    assert record["timestamp"] == "2023-10-15T16:20:00.000Z"
    assert record["hostname"] == "host.acme.com"
    assert record["app_name"] == "myapp"
    assert record["proc_id"] == "9812"
    assert record["msg_id"] == "ID47"
    assert record["sd_meta@123_session"] == "xyz123"
    assert record["sd_meta@123_user"] == "bob"
    assert record["sd_net@123_ip"] == "192.168.0.1"
    assert record["message"] == "User session initiated"


def test_parse_syslog_3164(profiler):
    raw = "<13>Oct 15 17:30:00 gateway kernel: [12345.678] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=192.168.1.1"
    record, fmt = profiler.parse_record(raw)
    assert fmt == LogFormat.SYSLOG_RFC3164
    assert record["prival"] == 13
    assert record["facility"] == 1
    assert record["severity"] == 5
    assert record["timestamp"] == "Oct 15 17:30:00"
    assert record["hostname"] == "gateway"
    assert record["tag"] == "kernel"


def test_parse_key_value(profiler):
    raw = 'level=warn tag=auth msg="Failed password for invalid user admin" client_ip=192.168.10.100 port=54321 attempts=5'
    record, fmt = profiler.parse_record(raw)
    assert fmt == LogFormat.KEY_VALUE
    assert record["level"] == "warn"
    assert record["tag"] == "auth"
    assert record["msg"] == "Failed password for invalid user admin"
    assert record["client_ip"] == "192.168.10.100"
    assert record["port"] == "54321"
    assert record["attempts"] == "5"


# =====================================================================
# 3. Deterministic Type Inference Tests
# =====================================================================

@pytest.mark.parametrize("value,expected_type", [
    (1234, DataType.INTEGER),
    ("5678", DataType.INTEGER),
    ("-999", DataType.INTEGER),
    (3.14159, DataType.FLOAT),
    ("0.0052", DataType.FLOAT),
    ("-1.5e-4", DataType.FLOAT),
    (True, DataType.BOOLEAN),
    ("true", DataType.BOOLEAN),
    ("FALSE", DataType.BOOLEAN),
    ("yes", DataType.BOOLEAN),
    (None, DataType.NULL),
    ("", DataType.NULL),
    ("null", DataType.NULL),
    ("-", DataType.NULL),
    ("192.168.1.100", DataType.IPV4),
    ("10.0.0.1", DataType.IPV4),
    ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", DataType.IPV6),
    ("fe80::1", DataType.IPV6),
    ("00:1A:2B:3C:4D:5E", DataType.MAC_ADDRESS),
    ("00-1A-2B-3C-4D-5E", DataType.MAC_ADDRESS),
    ("c0a80101-1234-4567-89ab-cdef01234567", DataType.UUID),
    ("admin@enterprise.internal", DataType.EMAIL),
    ("https://api.cloud.corp/v1/metrics?id=5", DataType.URL),
    ("2023-10-15T12:30:45.123Z", DataType.TIMESTAMP),
    ("Oct 15 12:30:45", DataType.TIMESTAMP),
    ("15/Oct/2023:12:30:45 +0000", DataType.TIMESTAMP),
    ('{"nested": "val", "num": 1}', DataType.JSON),
    ('[1, 2, 3]', DataType.ARRAY),
    ("unstructured message string", DataType.STRING),
])
def test_type_inferencer(value, expected_type):
    assert TypeInferencer.infer_type(value) == expected_type


# =====================================================================
# 4. Template Mining & Masking Tests
# =====================================================================

def test_template_miner_masking():
    raw_msg = (
        "User 1042 failed login from 192.168.1.50 at 2023-10-15T14:22:10Z "
        "using session c0a80101-1234-4567-89ab-cdef01234567 on /var/log/auth.log with MAC 00:1A:2B:3C:4D:5E"
    )
    masked = TemplateMiner.mask_message(raw_msg)
    assert "<IP>" in masked
    assert "<TIMESTAMP>" in masked
    assert "<UUID>" in masked
    assert "<PATH>" in masked
    assert "<MAC>" in masked
    assert "<NUM>" in masked
    assert "192.168.1.50" not in masked
    assert "2023-10-15T14:22:10Z" not in masked


def test_template_id_generation():
    pattern = "User <NUM> failed login from <IP>"
    tpl_id = TemplateMiner.generate_template_id(pattern)
    assert tpl_id.startswith("tpl_")
    assert tpl_id == TemplateMiner.generate_template_id(pattern)


# =====================================================================
# 5. Full Source Profiling & Aggregation Tests
# =====================================================================

def test_profile_json_batch(profiler):
    batch = [
        json.dumps({"ts": "2023-10-15T10:00:00Z", "ip": "10.0.0.1", "status": 200, "duration": 15.4, "tag": "prod"}),
        json.dumps({"ts": "2023-10-15T10:00:01Z", "ip": "10.0.0.2", "status": 200, "duration": 22.1, "tag": "prod"}),
        json.dumps({"ts": "2023-10-15T10:00:02Z", "ip": "10.0.0.3", "status": 500, "duration": 105.0, "tag": "stage"}),
        json.dumps({"ts": "2023-10-15T10:00:03Z", "ip": "10.0.0.4", "status": 200, "duration": None, "tag": "prod"}),
    ]

    profile = profiler.profile(batch)

    assert profile.format == LogFormat.JSON
    assert profile.confidence == 1.0
    assert profile.total_records == 4
    assert profile.valid_records == 4
    assert profile.corrupted_records == 0

    # Fields checks
    fields = profile.fields
    assert "ts" in fields
    assert fields["ts"].inferred_type == DataType.TIMESTAMP.value
    assert fields["ts"].is_timestamp_candidate is True
    assert not fields["ts"].nullable
    assert fields["ts"].presence_ratio == 1.0

    assert "ip" in fields
    assert fields["ip"].inferred_type == DataType.IPV4.value
    assert fields["ip"].is_ip_candidate is True
    assert len(fields["ip"].sample_values) == 4

    assert "tag" in fields
    assert fields["tag"].is_enum_candidate is True
    assert sorted(fields["tag"].enum_values) == ["prod", "stage"]

    assert "status" in fields
    assert fields["status"].inferred_type == DataType.INTEGER.value
    assert fields["status"].min_value == 200
    assert fields["status"].max_value == 500

    assert "duration" in fields
    assert fields["duration"].inferred_type == DataType.FLOAT.value
    assert fields["duration"].nullable is True
    assert fields["duration"].presence_ratio == 0.75

    # Serialization test
    doc = profile.to_dict()
    assert doc["format"] == "JSON"
    assert len(doc["fields"]) == 5
    json_str = profile.to_json()
    assert '"format": "JSON"' in json_str


def test_profile_cef_batch(profiler):
    batch = [
        "CEF:0|FirewallVendor|AppDefense|1.0|101|Connection Allowed|3|src=10.0.0.1 dst=192.168.1.1 spt=1024 dpt=80 proto=TCP",
        "CEF:0|FirewallVendor|AppDefense|1.0|102|Connection Denied|8|src=10.0.0.2 dst=192.168.1.1 spt=1025 dpt=443 proto=TCP",
        "CEF:0|FirewallVendor|AppDefense|1.0|101|Connection Allowed|3|src=10.0.0.3 dst=192.168.1.1 spt=1026 dpt=80 proto=TCP",
    ]

    profile = profiler.profile(batch)

    assert profile.format == LogFormat.CEF
    assert profile.confidence == 1.0
    assert profile.valid_records == 3
    assert "device_vendor" in profile.fields
    assert profile.fields["device_vendor"].sample_values == ["FirewallVendor"]
    assert profile.fields["src"].inferred_type == DataType.IPV4.value
    assert len(profile.templates) > 0


def test_profile_csv_with_headers(profiler):
    csv_data = [
        "timestamp,client_ip,request_path,status_code,latency",
        "2023-10-15T01:00:00Z,10.0.0.1,/api/v1/auth,200,0.12",
        "2023-10-15T01:00:01Z,10.0.0.2,/api/v1/users,200,0.45",
        "2023-10-15T01:00:02Z,10.0.0.3,/api/v1/checkout,500,1.20",
    ]

    profile = profiler.profile(csv_data)

    assert profile.format == LogFormat.CSV
    assert profile.delimiter == ","
    assert "client_ip" in profile.fields
    assert profile.fields["client_ip"].inferred_type == DataType.IPV4.value
    assert profile.fields["status_code"].inferred_type == DataType.INTEGER.value
    assert profile.fields["latency"].inferred_type == DataType.FLOAT.value


def test_profile_empty_and_corrupted_lines(profiler):
    mixed_batch = [
        '{"id": 1, "msg": "ok"}',
        "",
        "   ",
        '{"id": 2, "msg": "ok"}',
        "INVALID RAW CORRUPTED NOT JSON {{{",
    ]

    profile = profiler.profile(mixed_batch)

    assert profile.format == LogFormat.JSON
    assert profile.total_records == 3
    assert profile.valid_records == 2
    assert profile.corrupted_records == 1


def test_profile_stream(profiler):
    data = "time=2023-10-15 status=200 action=login\ntime=2023-10-15 status=403 action=denied\n"
    stream = io.StringIO(data)
    profile = profiler.profile_stream(stream)
    assert profile.format == LogFormat.KEY_VALUE
    assert profile.valid_records == 2


def test_profile_file(profiler):
    content = '{"user": "alice", "action": "read"}\n{"user": "bob", "action": "write"}\n'
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".log") as f:
        f.write(content)
        temp_path = f.name

    try:
        profile = profiler.profile_file(temp_path)
        assert profile.format == LogFormat.JSON
        assert profile.valid_records == 2
        assert "user" in profile.fields
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_profile_line_single(profiler):
    raw = '{"host": "srv1", "load": 0.75}'
    profile = profiler.profile_line(raw)
    assert profile.format == LogFormat.JSON
    assert profile.total_records == 1
    assert profile.valid_records == 1
    assert profile.fields["load"].inferred_type == DataType.FLOAT.value


def test_profile_mixed_format_fallback(profiler):
    # Dominant JSON batch with a CEF log line interleaved
    logs = [
        '{"event": "login", "user": "alice"}',
        '{"event": "logout", "user": "alice"}',
        '{"event": "login", "user": "bob"}',
        'CEF:0|SecurityCorp|ThreatShield|2.4.1|1001|Malware Blocked|7|src=10.0.0.15 dst=172.16.0.4',
    ]
    profile = profiler.profile(logs)
    assert profile.total_records == 4
    # All 4 should be validly parsed because of multi-format fallback!
    assert profile.valid_records == 4
    assert profile.corrupted_records == 0
    assert "format_distribution" in profile.metadata
    assert profile.metadata["format_distribution"][LogFormat.JSON.value] == 3
    assert profile.metadata["format_distribution"][LogFormat.CEF.value] == 1

