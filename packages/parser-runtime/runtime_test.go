package parser_runtime

import (
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
