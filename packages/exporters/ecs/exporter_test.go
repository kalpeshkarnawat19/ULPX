package ecs

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/kalpeshkarnawat19/SIH-PS-2/packages/exporters"
)

func sampleNormalizedEvent() *exporters.NormalizedEvent {
	return &exporters.NormalizedEvent{
		SchemaVersion: "1.0",
		EventID:       "01J9A0K0P0Z3R3M5WQ6F7H8J9K",
		Event: exporters.EventInfo{
			Class:   "NETWORK_CONNECTION",
			Action:  "blocked",
			Outcome: "failure",
			Time:    "2026-09-16T09:30:00Z",
		},
		Source: exporters.SourceInfo{
			Vendor:   "paloalto",
			Product:  "panos",
			DeviceID: "pa-3200-core",
		},
		Src: &exporters.Endpoint{
			IP:   "192.168.1.100",
			Port: 54321,
		},
		Dst: &exporters.Endpoint{
			IP:   "10.0.0.1",
			Port: 443,
		},
		Network: &exporters.NetworkInfo{
			Protocol: "TCP",
		},
		User: &exporters.UserInfo{
			Name:   "alice",
			ID:     "U12345",
			Domain: "CORP",
		},
		Device: &exporters.DeviceInfo{
			Hostname: "alice-laptop",
			IP:       "192.168.1.100",
			MAC:      "00:11:22:33:44:55",
		},
		HTTP: &exporters.HTTPInfo{
			Method:     "POST",
			StatusCode: 403,
			URL:        "https://10.0.0.1/api/login",
		},
		DNS: &exporters.DNSInfo{
			QueryName:    "corp.internal",
			QueryType:    "A",
			ResponseCode: "NOERROR",
		},
		Alert: &exporters.AlertInfo{
			Severity: "high",
			Name:     "Unauthorized Admin Access",
			Category: "lateral_movement",
		},
		Parser: exporters.ParserMetadata{
			ID:      "panos.traffic.kv",
			Version: "1.0.0",
		},
		Raw: exporters.RawProvenance{
			Ref:    "raw/2026/09/16/src_pa/01J9A0K0P0Z3R3M5WQ6F7H8J9K",
			SHA256: "4a0a19218e082a343393b8bd810de8a39c8f7ff733e3ce81d89b3e056c1003fe",
		},
		Quality: exporters.QualityReport{
			MappingScore: 1.0,
			Status:       "VERIFIED",
		},
		Extensions: map[string]interface{}{
			"rule_name": "Block-Admin-Access",
		},
	}
}

func TestECSExporter_ValidExport(t *testing.T) {
	exp := NewExporter()
	ir := sampleNormalizedEvent()

	out, err := exp.Export(ir)
	if err != nil {
		t.Fatalf("unexpected export error: %v", err)
	}

	if out.Timestamp != "2026-09-16T09:30:00Z" {
		t.Errorf("expected @timestamp 2026-09-16T09:30:00Z, got %s", out.Timestamp)
	}
	if out.ECS.Version != ECSVersion {
		t.Errorf("expected ecs.version %s, got %s", ECSVersion, out.ECS.Version)
	}
	if out.Event.ID != ir.EventID {
		t.Errorf("expected event.id %s, got %s", ir.EventID, out.Event.ID)
	}
	if len(out.Event.Category) != 1 || out.Event.Category[0] != "network" {
		t.Errorf("expected event.category ['network'], got %v", out.Event.Category)
	}
	if len(out.Event.Type) != 1 || out.Event.Type[0] != "denied" {
		t.Errorf("expected event.type ['denied'], got %v", out.Event.Type)
	}
	if out.Event.Outcome != "failure" {
		t.Errorf("expected event.outcome failure, got %s", out.Event.Outcome)
	}
	if out.Source == nil || out.Source.IP != "192.168.1.100" || out.Source.Port != 54321 {
		t.Errorf("unexpected source endpoint: %+v", out.Source)
	}
	if out.Destination == nil || out.Destination.IP != "10.0.0.1" || out.Destination.Port != 443 {
		t.Errorf("unexpected destination endpoint: %+v", out.Destination)
	}
	if out.Network == nil || out.Network.Transport != "tcp" {
		t.Errorf("expected network.transport tcp, got %+v", out.Network)
	}
	if out.User == nil || out.User.Name != "alice" {
		t.Errorf("expected user alice, got %+v", out.User)
	}
	if out.Host == nil || out.Host.Name != "alice-laptop" {
		t.Errorf("expected host alice-laptop, got %+v", out.Host)
	}
	if out.HTTP == nil || out.HTTP.Request.Method != "POST" || out.HTTP.Response.StatusCode != 403 {
		t.Errorf("unexpected HTTP fields: %+v", out.HTTP)
	}
	if out.URL == nil || out.URL.Original != "https://10.0.0.1/api/login" {
		t.Errorf("unexpected URL: %+v", out.URL)
	}
	if out.DNS == nil || out.DNS.Question.Name != "corp.internal" {
		t.Errorf("unexpected DNS: %+v", out.DNS)
	}
	if out.Observer == nil || out.Observer.Vendor != "paloalto" {
		t.Errorf("unexpected observer: %+v", out.Observer)
	}
	if out.Labels["rule_name"] != "Block-Admin-Access" {
		t.Errorf("missing rule_name in labels: %v", out.Labels)
	}
	if out.Labels["raw_sha256"] != ir.Raw.SHA256 {
		t.Errorf("missing raw_sha256 in labels: %v", out.Labels)
	}

	// Verify JSON serialization
	jsonBytes, err := exp.ExportJSON(ir)
	if err != nil {
		t.Fatalf("failed to serialize ECS event to JSON: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("invalid json produced: %v", err)
	}
}

func TestECSExporter_ScopeGuard_ZeroMutation(t *testing.T) {
	exp := NewExporter()
	ir := sampleNormalizedEvent()

	// Clone original state before export
	beforeJSON, err := json.Marshal(ir)
	if err != nil {
		t.Fatalf("failed to marshal initial state: %v", err)
	}

	_, err = exp.Export(ir)
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	// Capture state after export
	afterJSON, err := json.Marshal(ir)
	if err != nil {
		t.Fatalf("failed to marshal state after export: %v", err)
	}

	if string(beforeJSON) != string(afterJSON) {
		t.Fatalf("SCOPE GUARD VIOLATION: Source NormalizedEvent was mutated during export!\nBefore: %s\nAfter:  %s", string(beforeJSON), string(afterJSON))
	}

	// Also perform reflect.DeepEqual check
	var cloned exporters.NormalizedEvent
	_ = json.Unmarshal(beforeJSON, &cloned)
	if !reflect.DeepEqual(*ir, cloned) {
		t.Fatalf("SCOPE GUARD VIOLATION: DeepEqual failed on Canonical IR event after export")
	}
}

func TestECSExporter_RejectsNilAndInvalid(t *testing.T) {
	exp := NewExporter()

	if _, err := exp.Export(nil); err == nil {
		t.Errorf("expected error exporting nil canonical event")
	}

	invalid := sampleNormalizedEvent()
	invalid.SchemaVersion = "2.0" // Invalid schema version
	if _, err := exp.Export(invalid); err == nil {
		t.Errorf("expected error exporting event with invalid schema_version")
	}

	invalid2 := sampleNormalizedEvent()
	invalid2.Event.Outcome = "pending" // Invalid outcome
	if _, err := exp.Export(invalid2); err == nil {
		t.Errorf("expected error exporting event with invalid outcome")
	}
}
