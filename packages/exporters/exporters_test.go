package exporters_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kalpeshkarnawat19/SIH-PS-2/packages/exporters"
	"github.com/kalpeshkarnawat19/SIH-PS-2/packages/exporters/ecs"
	"github.com/kalpeshkarnawat19/SIH-PS-2/packages/exporters/ocsf"
)

func goldenCanonicalEvents() map[string]*exporters.NormalizedEvent {
	return map[string]*exporters.NormalizedEvent{
		"cef_edr": {
			SchemaVersion: "1.0",
			EventID:       "01J9A0K0P0Z3R3M5WQ6F7H8J91",
			Event: exporters.EventInfo{
				Class:   "SECURITY_ALERT",
				Action:  "blocked",
				Outcome: "failure",
				Time:    "2026-09-17T08:00:00Z",
			},
			Source: exporters.SourceInfo{
				Vendor:   "CrowdStrike",
				Product:  "Falcon",
				DeviceID: "sensor-edr-01",
			},
			Src: &exporters.Endpoint{
				IP:   "10.0.1.50",
				Port: 49152,
			},
			Dst: &exporters.Endpoint{
				IP:   "198.51.100.25",
				Port: 443,
			},
			Network: &exporters.NetworkInfo{
				Protocol: "tcp",
			},
			User: &exporters.UserInfo{
				Name: "malicious_user",
			},
			Device: &exporters.DeviceInfo{
				Hostname: "workstation-09",
				IP:       "10.0.1.50",
			},
			Alert: &exporters.AlertInfo{
				Severity: "high",
				Name:     "Suspicious Process Injection",
				Category: "malware",
			},
			Parser: exporters.ParserMetadata{
				ID:      "cef_edr.parser",
				Version: "1.0.0",
			},
			Raw: exporters.RawProvenance{
				Ref:    "raw/2026/09/17/cef_edr/01J9A0K0P0Z3R3M5WQ6F7H8J91",
				SHA256: "4a0a19218e082a343393b8bd810de8a39c8f7ff733e3ce81d89b3e056c1003fe",
			},
			Quality: exporters.QualityReport{
				MappingScore: 1.0,
				Status:       "VERIFIED",
			},
			Extensions: map[string]interface{}{
				"cs1": "powershell.exe",
			},
		},
		"csv_access": {
			SchemaVersion: "1.0",
			EventID:       "01J9A0K0P0Z3R3M5WQ6F7H8J92",
			Event: exporters.EventInfo{
				Class:   "WEB_ACCESS",
				Action:  "get",
				Outcome: "success",
				Time:    "2026-09-17T08:05:00Z",
			},
			Source: exporters.SourceInfo{
				Vendor:   "Apache",
				Product:  "HTTP Server",
				DeviceID: "web-srv-01",
			},
			Src: &exporters.Endpoint{
				IP: "203.0.113.195",
			},
			Dst: &exporters.Endpoint{
				IP:   "10.0.0.80",
				Port: 80,
			},
			Network: &exporters.NetworkInfo{
				Protocol: "tcp",
			},
			HTTP: &exporters.HTTPInfo{
				Method:     "GET",
				StatusCode: 200,
				URL:        "/index.html",
			},
			Parser: exporters.ParserMetadata{
				ID:      "csv_access.parser",
				Version: "1.0.0",
			},
			Raw: exporters.RawProvenance{
				Ref:    "raw/2026/09/17/csv_access/01J9A0K0P0Z3R3M5WQ6F7H8J92",
				SHA256: "4a0a19218e082a343393b8bd810de8a39c8f7ff733e3ce81d89b3e056c1003fe",
			},
			Quality: exporters.QualityReport{
				MappingScore: 1.0,
				Status:       "VERIFIED",
			},
			Extensions: map[string]interface{}{
				"user_agent": "Mozilla/5.0",
			},
		},
		"json_cloudtrail": {
			SchemaVersion: "1.0",
			EventID:       "01J9A0K0P0Z3R3M5WQ6F7H8J93",
			Event: exporters.EventInfo{
				Class:   "AUTHENTICATION",
				Action:  "ConsoleLogin",
				Outcome: "success",
				Time:    "2026-09-17T08:10:00Z",
			},
			Source: exporters.SourceInfo{
				Vendor:   "AWS",
				Product:  "CloudTrail",
				DeviceID: "us-east-1",
			},
			Src: &exporters.Endpoint{
				IP: "198.51.100.42",
			},
			User: &exporters.UserInfo{
				Name: "admin_user",
				ID:   "AIDACKCEVSQ6C2EXAMPLE",
			},
			Parser: exporters.ParserMetadata{
				ID:      "json_cloudtrail.parser",
				Version: "1.0.0",
			},
			Raw: exporters.RawProvenance{
				Ref:    "raw/2026/09/17/json_cloudtrail/01J9A0K0P0Z3R3M5WQ6F7H8J93",
				SHA256: "4a0a19218e082a343393b8bd810de8a39c8f7ff733e3ce81d89b3e056c1003fe",
			},
			Quality: exporters.QualityReport{
				MappingScore: 1.0,
				Status:       "VERIFIED",
			},
			Extensions: map[string]interface{}{
				"awsRegion": "us-east-1",
			},
		},
		"key_value_server": {
			SchemaVersion: "1.0",
			EventID:       "01J9A0K0P0Z3R3M5WQ6F7H8J94",
			Event: exporters.EventInfo{
				Class:   "NETWORK_FLOW",
				Action:  "ACCEPT",
				Outcome: "success",
				Time:    "2026-09-17T08:15:00Z",
			},
			Source: exporters.SourceInfo{
				Vendor:   "Linux",
				Product:  "iptables",
				DeviceID: "fw-internal-01",
			},
			Src: &exporters.Endpoint{
				IP:   "172.16.0.4",
				Port: 43210,
			},
			Dst: &exporters.Endpoint{
				IP:   "10.0.0.15",
				Port: 22,
			},
			Network: &exporters.NetworkInfo{
				Protocol: "tcp",
			},
			Parser: exporters.ParserMetadata{
				ID:      "key_value_server.parser",
				Version: "1.0.0",
			},
			Raw: exporters.RawProvenance{
				Ref:    "raw/2026/09/17/key_value_server/01J9A0K0P0Z3R3M5WQ6F7H8J94",
				SHA256: "4a0a19218e082a343393b8bd810de8a39c8f7ff733e3ce81d89b3e056c1003fe",
			},
			Quality: exporters.QualityReport{
				MappingScore: 1.0,
				Status:       "VERIFIED",
			},
			Extensions: map[string]interface{}{
				"ttl": 64,
			},
		},
		"leef_auth": {
			SchemaVersion: "1.0",
			EventID:       "01J9A0K0P0Z3R3M5WQ6F7H8J95",
			Event: exporters.EventInfo{
				Class:   "AUTHENTICATION",
				Action:  "FailedLogin",
				Outcome: "failure",
				Time:    "2026-09-17T08:20:00Z",
			},
			Source: exporters.SourceInfo{
				Vendor:   "Microsoft",
				Product:  "Active Directory",
				DeviceID: "dc-01.corp",
			},
			Src: &exporters.Endpoint{
				IP: "192.168.10.5",
			},
			User: &exporters.UserInfo{
				Name:   "service_account",
				Domain: "CORP",
			},
			Device: &exporters.DeviceInfo{
				Hostname: "dc-01",
			},
			Parser: exporters.ParserMetadata{
				ID:      "leef_auth.parser",
				Version: "1.0.0",
			},
			Raw: exporters.RawProvenance{
				Ref:    "raw/2026/09/17/leef_auth/01J9A0K0P0Z3R3M5WQ6F7H8J95",
				SHA256: "4a0a19218e082a343393b8bd810de8a39c8f7ff733e3ce81d89b3e056c1003fe",
			},
			Quality: exporters.QualityReport{
				MappingScore: 1.0,
				Status:       "VERIFIED",
			},
			Extensions: map[string]interface{}{
				"status": "bad_password",
			},
		},
		"syslog_firewall": {
			SchemaVersion: "1.0",
			EventID:       "01J9A0K0P0Z3R3M5WQ6F7H8J96",
			Event: exporters.EventInfo{
				Class:   "NETWORK_CONNECTION",
				Action:  "DROP",
				Outcome: "failure",
				Time:    "2026-09-17T08:25:00Z",
			},
			Source: exporters.SourceInfo{
				Vendor:   "Cisco",
				Product:  "ASA",
				DeviceID: "edge-asa-01",
			},
			Src: &exporters.Endpoint{
				IP:   "203.0.113.88",
				Port: 55432,
			},
			Dst: &exporters.Endpoint{
				IP:   "10.0.0.1",
				Port: 445,
			},
			Network: &exporters.NetworkInfo{
				Protocol: "tcp",
			},
			Device: &exporters.DeviceInfo{
				Hostname: "edge-asa-01",
			},
			Parser: exporters.ParserMetadata{
				ID:      "syslog_firewall.parser",
				Version: "1.0.0",
			},
			Raw: exporters.RawProvenance{
				Ref:    "raw/2026/09/17/syslog_firewall/01J9A0K0P0Z3R3M5WQ6F7H8J96",
				SHA256: "4a0a19218e082a343393b8bd810de8a39c8f7ff733e3ce81d89b3e056c1003fe",
			},
			Quality: exporters.QualityReport{
				MappingScore: 1.0,
				Status:       "VERIFIED",
			},
			Extensions: map[string]interface{}{
				"interface": "outside",
			},
		},
	}
}

func TestExporters_GoldenCorpora_ECS(t *testing.T) {
	ecsExp := ecs.NewExporter()
	goldenMap := goldenCanonicalEvents()

	if len(goldenMap) != 6 {
		t.Fatalf("expected 6 golden corpora, got %d", len(goldenMap))
	}

	for name, ir := range goldenMap {
		t.Run(name, func(t *testing.T) {
			// Validate Canonical IR first
			if err := ir.Validate(); err != nil {
				t.Fatalf("golden IR event %s is invalid: %v", name, err)
			}

			// Snapshot original state
			beforeJSON, err := json.Marshal(ir)
			if err != nil {
				t.Fatalf("failed to serialize initial state: %v", err)
			}

			// 1. Export to ECS
			ecsEvent, err := ecsExp.Export(ir)
			if err != nil {
				t.Fatalf("ECS export failed for %s: %v", name, err)
			}

			// 2. Validate essential ECS fields
			if ecsEvent.Timestamp != ir.Event.Time {
				t.Errorf("expected @timestamp %s, got %s", ir.Event.Time, ecsEvent.Timestamp)
			}
			if ecsEvent.ECS.Version != ecs.ECSVersion {
				t.Errorf("expected ecs.version %s, got %s", ecs.ECSVersion, ecsEvent.ECS.Version)
			}
			if ecsEvent.Event.ID != ir.EventID {
				t.Errorf("expected event.id %s, got %s", ir.EventID, ecsEvent.Event.ID)
			}
			if ecsEvent.Event.Outcome != ir.Event.Outcome {
				t.Errorf("expected event.outcome %s, got %s", ir.Event.Outcome, ecsEvent.Event.Outcome)
			}

			// 3. Serialize to JSON bytes
			jsonBytes, err := ecsExp.ExportJSON(ir)
			if err != nil {
				t.Fatalf("failed to export ECS JSON: %v", err)
			}
			if len(jsonBytes) == 0 {
				t.Fatalf("produced empty JSON bytes for %s", name)
			}

			// 4. Scope guard: verify zero mutation of source IR
			afterJSON, err := json.Marshal(ir)
			if err != nil {
				t.Fatalf("failed to serialize state after export: %v", err)
			}
			if !bytes.Equal(beforeJSON, afterJSON) {
				t.Fatalf("SCOPE GUARD VIOLATION: Source IR event was mutated during ECS export for %s", name)
			}
		})
	}
}

func TestExporters_GoldenCorpora_OCSF(t *testing.T) {
	ocsfExp := ocsf.NewExporter()
	goldenMap := goldenCanonicalEvents()

	if len(goldenMap) != 6 {
		t.Fatalf("expected 6 golden corpora, got %d", len(goldenMap))
	}

	for name, ir := range goldenMap {
		t.Run(name, func(t *testing.T) {
			if err := ir.Validate(); err != nil {
				t.Fatalf("golden IR event %s is invalid: %v", name, err)
			}

			beforeJSON, err := json.Marshal(ir)
			if err != nil {
				t.Fatalf("failed to serialize initial state: %v", err)
			}

			// 1. Export to OCSF
			ocsfEvent, err := ocsfExp.Export(ir)
			if err != nil {
				t.Fatalf("OCSF export failed for %s: %v", name, err)
			}

			// 2. Validate essential OCSF fields
			if ocsfEvent.ClassUID <= 0 {
				t.Errorf("expected positive class_uid, got %d", ocsfEvent.ClassUID)
			}
			if ocsfEvent.CategoryUID <= 0 {
				t.Errorf("expected positive category_uid, got %d", ocsfEvent.CategoryUID)
			}
			if ocsfEvent.Time <= 0 {
				t.Errorf("expected valid epoch milliseconds, got %d", ocsfEvent.Time)
			}
			if ocsfEvent.TimeDT != ir.Event.Time {
				t.Errorf("expected time_dt %s, got %s", ir.Event.Time, ocsfEvent.TimeDT)
			}
			if ocsfEvent.Metadata.UID != ir.EventID {
				t.Errorf("expected metadata.uid %s, got %s", ir.EventID, ocsfEvent.Metadata.UID)
			}
			if ocsfEvent.Metadata.Version != ocsf.OCSFVersion {
				t.Errorf("expected metadata.version %s, got %s", ocsf.OCSFVersion, ocsfEvent.Metadata.Version)
			}

			// 3. Serialize to JSON bytes
			jsonBytes, err := ocsfExp.ExportJSON(ir)
			if err != nil {
				t.Fatalf("failed to export OCSF JSON: %v", err)
			}
			if len(jsonBytes) == 0 {
				t.Fatalf("produced empty JSON bytes for %s", name)
			}

			// 4. Scope guard: verify zero mutation of source IR
			afterJSON, err := json.Marshal(ir)
			if err != nil {
				t.Fatalf("failed to serialize state after export: %v", err)
			}
			if !bytes.Equal(beforeJSON, afterJSON) {
				t.Fatalf("SCOPE GUARD VIOLATION: Source IR event was mutated during OCSF export for %s", name)
			}
		})
	}
}

func TestExporters_DeterminismAcrossRepeatedExports(t *testing.T) {
	ecsExp := ecs.NewExporter()
	ocsfExp := ocsf.NewExporter()
	goldenMap := goldenCanonicalEvents()

	for name, ir := range goldenMap {
		t.Run(name, func(t *testing.T) {
			// Test ECS determinism across 5 iterations
			baseECS, err := ecsExp.ExportJSON(ir)
			if err != nil {
				t.Fatalf("initial ECS export failed: %v", err)
			}
			for i := 0; i < 5; i++ {
				repECS, err := ecsExp.ExportJSON(ir)
				if err != nil {
					t.Fatalf("iteration %d ECS export failed: %v", i, err)
				}
				if !bytes.Equal(baseECS, repECS) {
					t.Fatalf("ECS export non-deterministic on %s at iteration %d", name, i)
				}
			}

			// Test OCSF determinism across 5 iterations
			baseOCSF, err := ocsfExp.ExportJSON(ir)
			if err != nil {
				t.Fatalf("initial OCSF export failed: %v", err)
			}
			for i := 0; i < 5; i++ {
				repOCSF, err := ocsfExp.ExportJSON(ir)
				if err != nil {
					t.Fatalf("iteration %d OCSF export failed: %v", i, err)
				}
				if !bytes.Equal(baseOCSF, repOCSF) {
					t.Fatalf("OCSF export non-deterministic on %s at iteration %d", name, i)
				}
			}
		})
	}
}

func TestExporters_ContractExampleEvent(t *testing.T) {
	contractPath := filepath.Join("..", "..", "fixtures", "contracts", "normalized_event.example.json")
	data, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("reading contract example: %v", err)
	}

	ir, err := exporters.FromJSON(data)
	if err != nil {
		t.Fatalf("parsing contract example: %v", err)
	}

	clone := ir.DeepCopy()
	if !reflect.DeepEqual(ir, clone) {
		t.Fatalf("DeepCopy failed on contract example event")
	}

	ecsExp := ecs.NewExporter()
	ecsOut, err := ecsExp.Export(ir)
	if err != nil {
		t.Fatalf("ECS export of contract example failed: %v", err)
	}
	if ecsOut.Event.ID != "01J9A0K0P0Z3R3M5WQ6F7H8J9K" {
		t.Errorf("unexpected event.id in ECS: %s", ecsOut.Event.ID)
	}

	ocsfExp := ocsf.NewExporter()
	ocsfOut, err := ocsfExp.Export(ir)
	if err != nil {
		t.Fatalf("OCSF export of contract example failed: %v", err)
	}
	if ocsfOut.ClassUID != ocsf.ClassNetworkActivity {
		t.Errorf("expected ClassNetworkActivity in OCSF, got %d", ocsfOut.ClassUID)
	}

	// Verify source IR is completely unmutated
	if !reflect.DeepEqual(ir, clone) {
		t.Fatalf("SCOPE GUARD VIOLATION: Contract example event was mutated during export")
	}
}
