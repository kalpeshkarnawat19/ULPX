package parser_runtime

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestDSLValidation_Valid(t *testing.T) {
	specJSON := `{
		"dsl_version": "1.0",
		"parser": {"id": "demo.firewall.kv", "version": "1.0.0"},
		"match": {"format": "syslog", "body_contains": ["src=", "dst="]},
		"body_parser": {"type": "key_value", "pair_separator": " ", "key_value_separator": "="},
		"fields": {
			"src": {"type": "ip", "map_to": "src.ip", "transformations": ["trim", "ip"]},
			"dst": {"type": "ip", "map_to": "dst.ip"},
			"spt": {"type": "integer", "map_to": "src.port"},
			"dpt": {"type": "integer", "map_to": "dst.port"},
			"action": {"type": "string", "map_to": "event.action", "enum": {"deny": "blocked", "allow": "allowed"}}
		},
		"unknown_fields": {"policy": "preserve"},
		"raw": {"preserve": true}
	}`

	spec, err := LoadParserSpecJSON([]byte(specJSON))
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if spec.Parser.ID != "demo.firewall.kv" {
		t.Errorf("expected parser id demo.firewall.kv, got %s", spec.Parser.ID)
	}
}

func TestDSLValidation_Invalid(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{
			name: "bad dsl version",
			json: `{"dsl_version":"2.0","parser":{"id":"test","version":"1.0.0"},"match":{"format":"json"},"body_parser":{"type":"json"},"fields":{"f":{"type":"string","map_to":"f"}},"unknown_fields":{"policy":"preserve"},"raw":{"preserve":true}}`,
		},
		{
			name: "unwhitelisted operation",
			json: `{"dsl_version":"1.0","parser":{"id":"test","version":"1.0.0"},"match":{"format":"json"},"body_parser":{"type":"json"},"fields":{"f":{"type":"string","map_to":"f","transformations":["eval_arbitrary_code"]}},"unknown_fields":{"policy":"preserve"},"raw":{"preserve":true}}`,
		},
		{
			name: "raw preserve false",
			json: `{"dsl_version":"1.0","parser":{"id":"test","version":"1.0.0"},"match":{"format":"json"},"body_parser":{"type":"json"},"fields":{"f":{"type":"string","map_to":"f"}},"unknown_fields":{"policy":"preserve"},"raw":{"preserve":false}}`,
		},
		{
			name: "invalid semver",
			json: `{"dsl_version":"1.0","parser":{"id":"test","version":"beta1"},"match":{"format":"json"},"body_parser":{"type":"json"},"fields":{"f":{"type":"string","map_to":"f"}},"unknown_fields":{"policy":"preserve"},"raw":{"preserve":true}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadParserSpecJSON([]byte(tc.json))
			if err == nil {
				t.Fatalf("expected error for case %q, but got nil", tc.name)
			}
		})
	}
}

func TestFormat_Syslog_RFC5424_and_KeyValue(t *testing.T) {
	runtime := NewParserRuntime()
	spec := &ParserSpec{
		DSLVersion: "1.0",
		Parser:     ParserInfo{ID: "syslog.kv", Version: "1.0.0"},
		Match:      MatchConfig{Format: "syslog", BodyContains: []string{"src=", "dst="}},
		BodyParser: BodyParserConfig{Type: "key_value", PairSeparator: " ", KeyValueSeparator: "="},
		Fields: map[string]FieldSpec{
			"src":      {Type: "ip", MapTo: "src.ip"},
			"dst":      {Type: "ip", MapTo: "dst.ip"},
			"spt":      {Type: "integer", MapTo: "src.port"},
			"dpt":      {Type: "integer", MapTo: "dst.port"},
			"action":   {Type: "string", MapTo: "event.action", Enum: map[string]string{"deny": "blocked", "allow": "allowed"}},
			"hostname": {Type: "string", MapTo: "host.name"},
		},
		UnknownFields: UnknownFieldsConfig{Policy: "preserve"},
		Raw:           RawConfig{Preserve: true},
	}

	raw := []byte(`<134>1 2026-09-16T15:00:00Z fw-01 firewall - - - src=10.0.0.1 dst=192.168.1.1 spt=44321 dpt=443 action=deny policy_id=9942`)

	if !runtime.CanHandle(raw, spec) {
		t.Fatalf("runtime should be able to handle syslog event")
	}

	res, err := runtime.Parse(raw, spec)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if res.Extracted["src.ip"] != "10.0.0.1" {
		t.Errorf("expected src.ip 10.0.0.1, got %v", res.Extracted["src.ip"])
	}
	if res.Extracted["dst.ip"] != "192.168.1.1" {
		t.Errorf("expected dst.ip 192.168.1.1, got %v", res.Extracted["dst.ip"])
	}
	if res.Extracted["src.port"] != int64(44321) {
		t.Errorf("expected src.port 44321, got %v", res.Extracted["src.port"])
	}
	if res.Extracted["event.action"] != "blocked" {
		t.Errorf("expected event.action blocked, got %v", res.Extracted["event.action"])
	}
	if res.Extracted["host.name"] != "fw-01" {
		t.Errorf("expected host.name fw-01, got %v", res.Extracted["host.name"])
	}

	// Unknown field policy
	if res.UnknownFields["policy_id"] != "9942" {
		t.Errorf("expected policy_id in unknown_fields, got %v", res.UnknownFields["policy_id"])
	}

	// Raw retention
	if res.Raw != string(raw) {
		t.Errorf("raw byte retention failed")
	}
}

func TestFormat_CEF(t *testing.T) {
	runtime := NewParserRuntime()
	spec := &ParserSpec{
		DSLVersion: "1.0",
		Parser:     ParserInfo{ID: "arcsight.cef", Version: "1.0.0"},
		Match:      MatchConfig{Format: "cef"},
		BodyParser: BodyParserConfig{Type: "cef"},
		Fields: map[string]FieldSpec{
			"src":            {Type: "ip", MapTo: "src.ip"},
			"dst":            {Type: "ip", MapTo: "dst.ip"},
			"spt":            {Type: "integer", MapTo: "src.port"},
			"device_vendor":  {Type: "string", MapTo: "observer.vendor"},
			"device_product": {Type: "string", MapTo: "observer.product"},
		},
		UnknownFields: UnknownFieldsConfig{Policy: "preserve"},
		Raw:           RawConfig{Preserve: true},
	}

	raw := []byte("CEF:0|SecurityCorp|ThreatShield|2.4.1|1001|Malware Blocked|7|src=10.0.0.15 dst=172.16.0.4 spt=44122 dpt=443 msg=TrojanDetected")

	if !runtime.CanHandle(raw, spec) {
		t.Fatalf("runtime should be able to handle CEF event")
	}

	res, err := runtime.Parse(raw, spec)
	if err != nil {
		t.Fatalf("CEF parse failed: %v", err)
	}

	if res.Extracted["src.ip"] != "10.0.0.15" {
		t.Errorf("expected src.ip 10.0.0.15, got %v", res.Extracted["src.ip"])
	}
	if res.Extracted["observer.vendor"] != "SecurityCorp" {
		t.Errorf("expected observer.vendor SecurityCorp, got %v", res.Extracted["observer.vendor"])
	}
	if res.UnknownFields["msg"] != "TrojanDetected" {
		t.Errorf("expected unknown msg field, got %v", res.UnknownFields["msg"])
	}
}

func TestFormat_LEEF_2(t *testing.T) {
	runtime := NewParserRuntime()
	spec := &ParserSpec{
		DSLVersion: "1.0",
		Parser:     ParserInfo{ID: "qradar.leef", Version: "1.0.0"},
		Match:      MatchConfig{Format: "leef"},
		BodyParser: BodyParserConfig{Type: "leef"},
		Fields: map[string]FieldSpec{
			"src":    {Type: "ip", MapTo: "src.ip"},
			"dst":    {Type: "ip", MapTo: "dst.ip"},
			"vendor": {Type: "string", MapTo: "observer.vendor"},
			"proto":  {Type: "string", MapTo: "network.transport"},
		},
		UnknownFields: UnknownFieldsConfig{Policy: "preserve"},
		Raw:           RawConfig{Preserve: true},
	}

	raw := []byte("LEEF:2.0|Trend Micro|Deep Security|9.0|2000000|^|src=10.10.10.10^dst=10.10.10.20^proto=TCP^severity=High")

	if !runtime.CanHandle(raw, spec) {
		t.Fatalf("runtime should be able to handle LEEF event")
	}

	res, err := runtime.Parse(raw, spec)
	if err != nil {
		t.Fatalf("LEEF parse failed: %v", err)
	}

	if res.Extracted["src.ip"] != "10.10.10.10" {
		t.Errorf("expected src.ip 10.10.10.10, got %v", res.Extracted["src.ip"])
	}
	if res.Extracted["network.transport"] != "TCP" {
		t.Errorf("expected network.transport TCP, got %v", res.Extracted["network.transport"])
	}
	if res.UnknownFields["severity"] != "High" {
		t.Errorf("expected severity in unknown fields, got %v", res.UnknownFields["severity"])
	}
}

func TestFormat_JSON(t *testing.T) {
	runtime := NewParserRuntime()
	spec := &ParserSpec{
		DSLVersion: "1.0",
		Parser:     ParserInfo{ID: "aws.cloudtrail", Version: "1.0.0"},
		Match:      MatchConfig{Format: "json"},
		BodyParser: BodyParserConfig{Type: "json"},
		Fields: map[string]FieldSpec{
			"userIdentity.userName": {Type: "string", MapTo: "user.name"},
			"sourceIPAddress":       {Type: "ip", MapTo: "src.ip"},
			"eventName":             {Type: "string", MapTo: "event.action"},
		},
		UnknownFields: UnknownFieldsConfig{Policy: "preserve"},
		Raw:           RawConfig{Preserve: true},
	}

	raw := []byte(`{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"alice"},"sourceIPAddress":"203.0.113.19","eventName":"ConsoleLogin","responseElements":{"ConsoleLogin":"Success"}}`)

	res, err := runtime.Parse(raw, spec)
	if err != nil {
		t.Fatalf("JSON parse failed: %v", err)
	}

	if res.Extracted["user.name"] != "alice" {
		t.Errorf("expected user.name alice, got %v", res.Extracted["user.name"])
	}
	if res.Extracted["src.ip"] != "203.0.113.19" {
		t.Errorf("expected src.ip 203.0.113.19, got %v", res.Extracted["src.ip"])
	}
	if res.Extracted["event.action"] != "ConsoleLogin" {
		t.Errorf("expected event.action ConsoleLogin, got %v", res.Extracted["event.action"])
	}
}

func TestFormat_CSV(t *testing.T) {
	runtime := NewParserRuntime()
	spec := &ParserSpec{
		DSLVersion: "1.0",
		Parser:     ParserInfo{ID: "web.proxy.csv", Version: "1.0.0"},
		Match:      MatchConfig{Format: "csv"},
		BodyParser: BodyParserConfig{Type: "csv", Delimiter: ",", Headers: []string{"timestamp", "src_ip", "dst_ip", "status", "method", "uri"}},
		Fields: map[string]FieldSpec{
			"src_ip": {Type: "ip", MapTo: "src.ip"},
			"dst_ip": {Type: "ip", MapTo: "dst.ip"},
			"status": {Type: "integer", MapTo: "http.response.status_code"},
			"method": {Type: "string", MapTo: "http.request.method", Transformations: []string{"uppercase"}},
		},
		UnknownFields: UnknownFieldsConfig{Policy: "preserve"},
		Raw:           RawConfig{Preserve: true},
	}

	raw := []byte(`2026-09-16T14:00:00Z,10.0.0.50,192.168.1.100,200,get,/api/v1/status`)

	res, err := runtime.Parse(raw, spec)
	if err != nil {
		t.Fatalf("CSV parse failed: %v", err)
	}

	if res.Extracted["src.ip"] != "10.0.0.50" {
		t.Errorf("expected src.ip 10.0.0.50, got %v", res.Extracted["src.ip"])
	}
	if res.Extracted["http.response.status_code"] != int64(200) {
		t.Errorf("expected http.response.status_code 200, got %v", res.Extracted["http.response.status_code"])
	}
	if res.Extracted["http.request.method"] != "GET" {
		t.Errorf("expected uppercase GET, got %v", res.Extracted["http.request.method"])
	}
	if res.UnknownFields["uri"] != "/api/v1/status" {
		t.Errorf("expected uri in unknown fields, got %v", res.UnknownFields["uri"])
	}
}

func TestScopeGuard_NoDynamicCode(t *testing.T) {
	files := []string{"dsl.go", "runtime.go", "whitelist.go"}
	forbiddenPatterns := []string{
		"eval(",
		"eval ",
		"exec.Command",
		"plugin.Open",
		"/bin/sh",
		"/bin/bash",
		"http.Get",
		"http.Post",
	}

	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		s := string(content)
		for _, forbidden := range forbiddenPatterns {
			if strings.Contains(s, forbidden) {
				t.Fatalf("scope guard violation in %s: found %q", f, forbidden)
			}
		}
	}
}

// TestParser_Adversarial_EscapedDelimitersAndQuotes verifies that Key-Value parsing
// correctly handles inner escaped quotes (\"), embedded delimiters, and spaces without premature key splitting.
func TestParser_Adversarial_EscapedDelimitersAndQuotes(t *testing.T) {
	raw := `cmd="sh -c \"echo name=admin\"" status="ok" count=42 reason="timeout while connecting"`
	kv := ParseKeyValue(raw, " ", "=")

	// Verify escaped quotes did not prematurely close the string
	if !strings.Contains(fmt.Sprintf("%v", kv["cmd"]), "name=admin") {
		t.Errorf("expected cmd to contain 'name=admin', got %q", kv["cmd"])
	}
	// Crucial security invariant: 'name' must NOT be extracted as a separate top-level key
	if _, exists := kv["name"]; exists {
		t.Errorf("escaped delimiter inside quote leaked into top-level key: %v", kv["name"])
	}
	if kv["status"] != "ok" {
		t.Errorf("expected status 'ok', got %q", kv["status"])
	}
	if kv["count"] != "42" {
		t.Errorf("expected count '42', got %q", kv["count"])
	}
	if kv["reason"] != "timeout while connecting" {
		t.Errorf("expected reason with spaces, got %q", kv["reason"])
	}
}

// TestParser_Adversarial_ReDoSRefusal verifies that unwhitelisted operations and
// dangerous dynamic code operations are rejected during parser spec validation.
func TestParser_Adversarial_ReDoSRefusal(t *testing.T) {
	maliciousSpecs := []string{
		`{"dsl_version":"1.0","parser":{"id":"redos.1","version":"1.0.0"},"match":{"format":"syslog"},"body_parser":{"type":"key_value"},"fields":{"f":{"type":"string","map_to":"f","transformations":["regex_eval_unbounded"]}},"unknown_fields":{"policy":"preserve"},"raw":{"preserve":true}}`,
		`{"dsl_version":"1.0","parser":{"id":"redos.2","version":"1.0.0"},"match":{"format":"syslog"},"body_parser":{"type":"key_value"},"fields":{"f":{"type":"string","map_to":"f","transformations":["exec_shell"]}},"unknown_fields":{"policy":"preserve"},"raw":{"preserve":true}}`,
	}

	for _, specJSON := range maliciousSpecs {
		_, err := LoadParserSpecJSON([]byte(specJSON))
		if err == nil {
			t.Errorf("expected rejection of unwhitelisted operation, got nil error")
		}
	}
}

// TestParser_Adversarial_MalformedAndEdgeTimestamps tests timestamp normalization across
// nanoseconds, milliseconds, seconds, negative offsets, and unparseable garbage.
func TestParser_Adversarial_MalformedAndEdgeTimestamps(t *testing.T) {
	// Nanoseconds (> 1e18)
	tsNano, err := TransformTimestamp(int64(1700000000123456789))
	if err != nil {
		t.Errorf("failed to parse nanosecond epoch: %v", err)
	}
	if !strings.HasPrefix(tsNano, "2023-11-14T") {
		t.Errorf("expected 2023-11-14T..., got %s", tsNano)
	}

	// Milliseconds (> 1e11)
	tsMilli, err := TransformTimestamp(int64(1700000000123))
	if err != nil {
		t.Errorf("failed to parse millisecond epoch: %v", err)
	}
	if !strings.HasPrefix(tsMilli, "2023-11-14T") {
		t.Errorf("expected 2023-11-14T..., got %s", tsMilli)
	}

	// Negative timezone offset (-08:00) should normalize to UTC RFC3339
	tsOffset, err := TransformTimestamp("2026-09-16T15:00:00-08:00")
	if err != nil {
		t.Errorf("failed to parse offset timestamp: %v", err)
	}
	if tsOffset != "2026-09-16T23:00:00Z" {
		t.Errorf("expected UTC 2026-09-16T23:00:00Z, got %s", tsOffset)
	}

	// Invalid garbage timestamp: must return clean error without panic
	_, errGarbage := TransformTimestamp("9999-99-99T99:99:99Z")
	if errGarbage == nil {
		t.Errorf("expected error parsing invalid timestamp, got nil")
	}
}

// TestParser_Adversarial_IPv6FormVariationsAndBypass verifies that TransformIP standardizes
// valid IPv6 forms and strictly rejects spoofed/malicious IP representations.
func TestParser_Adversarial_IPv6FormVariationsAndBypass(t *testing.T) {
	// Compressed IPv6
	ipLoopback, err := TransformIP("::1")
	if err != nil || ipLoopback != "::1" {
		t.Errorf("expected ::1, got %s (err: %v)", ipLoopback, err)
	}

	// IPv4-mapped IPv6 normalizes to canonical IPv4
	ipMapped, err := TransformIP("::ffff:192.0.2.1")
	if err != nil || ipMapped != "192.0.2.1" {
		t.Errorf("expected 192.0.2.1 for IPv4-mapped IPv6, got %s (err: %v)", ipMapped, err)
	}

	// Hostile/malformed IP strings: must return error without panic
	hostileIPs := []string{
		"127.0.0.1.attacker.com",
		"999.999.999.999",
		"10.0.0.1\x00bypass",
		"0x7f000001",
		"",
		"   ",
	}
	for _, hostile := range hostileIPs {
		_, err := TransformIP(hostile)
		if err == nil {
			t.Errorf("expected error for hostile IP %q, got nil", hostile)
		}
	}
}

// TestParser_Adversarial_TypeMismatchAndNullInjections tests that JSON payloads with null values
// and type mismatches are handled gracefully with error records and zero runtime panics.
func TestParser_Adversarial_TypeMismatchAndNullInjections(t *testing.T) {
	runtime := NewParserRuntime()
	spec := &ParserSpec{
		DSLVersion: "1.0",
		Parser:     ParserInfo{ID: "adversarial.json", Version: "1.0.0"},
		Match:      MatchConfig{Format: "json"},
		BodyParser: BodyParserConfig{Type: "json"},
		Fields: map[string]FieldSpec{
			"src":  {Type: "ip", MapTo: "src.ip"},
			"port": {Type: "integer", MapTo: "src.port"},
		},
		UnknownFields: UnknownFieldsConfig{Policy: "preserve"},
		Raw:           RawConfig{Preserve: true},
	}

	// Payload with null port and invalid string IP
	raw := []byte(`{"src": "not_an_ip", "port": null, "extra": "unmapped"}`)
	res, err := runtime.Parse(raw, spec)
	if err != nil {
		t.Fatalf("runtime.Parse must not fail catastrophically: %v", err)
	}

	// Verify error diagnostics collected for mismatched fields
	if len(res.Errors) == 0 {
		t.Errorf("expected conversion errors for invalid src/port, got zero errors")
	}

	// Verify unknown fields preserved
	if res.UnknownFields["extra"] != "unmapped" {
		t.Errorf("expected unknown field 'extra' to be preserved, got %v", res.UnknownFields["extra"])
	}
}

// TestParser_Adversarial_ZeroByteAndWhitespacePayloads verifies that empty or whitespace-only
// payloads produce clean errors without index out-of-range or nil pointer dereferences.
func TestParser_Adversarial_ZeroByteAndWhitespacePayloads(t *testing.T) {
	runtime := NewParserRuntime()
	spec := &ParserSpec{
		DSLVersion: "1.0",
		Parser:     ParserInfo{ID: "empty.test", Version: "1.0.0"},
		Match:      MatchConfig{Format: "json"},
		BodyParser: BodyParserConfig{Type: "json"},
		Fields:     map[string]FieldSpec{"src": {Type: "string", MapTo: "src.ip"}},
		UnknownFields: UnknownFieldsConfig{Policy: "preserve"},
		Raw:           RawConfig{Preserve: true},
	}

	// Empty payload
	_, errEmpty := runtime.Parse([]byte{}, spec)
	if errEmpty == nil {
		t.Errorf("expected error parsing empty payload, got nil")
	}

	// Whitespace payload
	_, errSpace := runtime.Parse([]byte("   \t\r\n   "), spec)
	if errSpace == nil {
		t.Errorf("expected error parsing whitespace payload, got nil")
	}
}

// TestParser_Adversarial_CEFMalformedPipesAndEscapes verifies that CEF parsing handles
// escaped pipes \| in headers and safely reports errors on truncated pipe headers.
func TestParser_Adversarial_CEFMalformedPipesAndEscapes(t *testing.T) {
	// Missing 7th header pipe: must return clean error
	truncatedCEF := "CEF:0|Vendor|Product|1.0|100|EventName"
	_, errTrunc := ParseCEF(truncatedCEF)
	if errTrunc == nil {
		t.Errorf("expected error for truncated CEF header, got nil")
	}

	// Escaped pipes \| inside header fields
	escapedCEF := `CEF:0|Vendor\|Corp|Product\|Pro|1.0|100|Event\|Name|5|src=10.0.0.1`
	fields, errEsc := ParseCEF(escapedCEF)
	if errEsc != nil {
		t.Fatalf("failed to parse CEF with escaped pipes: %v", errEsc)
	}

	if fields["device_vendor"] != "Vendor|Corp" {
		t.Errorf("expected device_vendor 'Vendor|Corp', got %q", fields["device_vendor"])
	}
	if fields["device_product"] != "Product|Pro" {
		t.Errorf("expected device_product 'Product|Pro', got %q", fields["device_product"])
	}
	if fields["name"] != "Event|Name" {
		t.Errorf("expected name 'Event|Name', got %q", fields["name"])
	}
	if fields["src"] != "10.0.0.1" {
		t.Errorf("expected src 10.0.0.1, got %q", fields["src"])
	}
}

