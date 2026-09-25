package ocsf

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

func TestOCSFExporter_ValidExport(t *testing.T) {
	exp := NewExporter()
	ir := sampleNormalizedEvent()

	out, err := exp.Export(ir)
	if err != nil {
		t.Fatalf("unexpected export error: %v", err)
	}

	if out.ClassUID != ClassNetworkActivity {
		t.Errorf("expected class_uid %d, got %d", ClassNetworkActivity, out.ClassUID)
	}
	if out.CategoryUID != CategoryNetworkActivity {
		t.Errorf("expected category_uid %d, got %d", CategoryNetworkActivity, out.CategoryUID)
	}
	if out.ActivityID != 6 { // Deny for blocked
		t.Errorf("expected activity_id 6, got %d", out.ActivityID)
	}
	if out.TypeUID != ClassNetworkActivity*100+6 {
		t.Errorf("expected type_uid %d, got %d", ClassNetworkActivity*100+6, out.TypeUID)
	}
	if out.Time <= 0 {
		t.Errorf("expected positive millisecond epoch time, got %d", out.Time)
	}
	if out.TimeDT != "2026-09-16T09:30:00Z" {
		t.Errorf("expected time_dt 2026-09-16T09:30:00Z, got %s", out.TimeDT)
	}
	if out.Status != "Failure" || out.StatusID != 2 {
		t.Errorf("expected Failure/2 status, got %s/%d", out.Status, out.StatusID)
	}
	if out.Metadata.Version != OCSFVersion {
		t.Errorf("expected metadata.version %s, got %s", OCSFVersion, out.Metadata.Version)
	}
	if out.Metadata.UID != ir.EventID {
		t.Errorf("expected metadata.uid %s, got %s", ir.EventID, out.Metadata.UID)
	}
	if out.Metadata.Product.VendorName != "paloalto" {
		t.Errorf("unexpected product vendor: %s", out.Metadata.Product.VendorName)
	}
	if out.SrcEndpoint == nil || out.SrcEndpoint.IP != "192.168.1.100" || out.SrcEndpoint.Port != 54321 {
		t.Errorf("unexpected src_endpoint: %+v", out.SrcEndpoint)
	}
	if out.DstEndpoint == nil || out.DstEndpoint.IP != "10.0.0.1" || out.DstEndpoint.Port != 443 {
		t.Errorf("unexpected dst_endpoint: %+v", out.DstEndpoint)
	}
	if out.ConnectionInfo == nil || out.ConnectionInfo.ProtocolName != "TCP" {
		t.Errorf("expected connection_info TCP, got %+v", out.ConnectionInfo)
	}
	if out.Actor == nil || out.Actor.User == nil || out.Actor.User.Name != "alice" {
		t.Errorf("expected user alice, got %+v", out.Actor)
	}
	if out.Device == nil || out.Device.Hostname != "alice-laptop" {
		t.Errorf("expected device alice-laptop, got %+v", out.Device)
	}
	if out.HTTPRequest == nil || out.HTTPRequest.HTTPMethod != "POST" || out.HTTPRequest.URL == nil || out.HTTPRequest.URL.URLString != "https://10.0.0.1/api/login" {
		t.Errorf("unexpected HTTP request: %+v", out.HTTPRequest)
	}
	if out.Finding == nil || out.Finding.Title != "Unauthorized Admin Access" {
		t.Errorf("unexpected finding: %+v", out.Finding)
	}
	if out.Unmapped["rule_name"] != "Block-Admin-Access" {
		t.Errorf("missing rule_name in unmapped: %v", out.Unmapped)
	}

	// Verify JSON serialization
	jsonBytes, err := exp.ExportJSON(ir)
	if err != nil {
		t.Fatalf("failed to serialize OCSF event to JSON: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("invalid json produced: %v", err)
	}
}

func TestOCSFExporter_ClassResolution(t *testing.T) {
	exp := NewExporter()

	tests := []struct {
		class       string
		action      string
		wantClass   int
		wantCat     int
		wantActID   int
	}{
		{"AUTHENTICATION", "login", ClassAuthentication, CategoryIdentityAndAccessMgmt, 1},
		{"IDENTITY_EVENT", "logout", ClassAuthentication, CategoryIdentityAndAccessMgmt, 2},
		{"HTTP_REQUEST", "get", ClassHTTPActivity, CategoryApplicationActivity, 1},
		{"SECURITY_ALERT", "alert_fired", ClassSecurityFinding, CategoryFindings, 1},
		{"SYSTEM_PROCESS", "start", ClassSystemActivity, CategorySystemActivity, 99},
	}

	for _, tt := range tests {
		ir := sampleNormalizedEvent()
		ir.Event.Class = tt.class
		ir.Event.Action = tt.action

		out, err := exp.Export(ir)
		if err != nil {
			t.Fatalf("export error for %s: %v", tt.class, err)
		}
		if out.ClassUID != tt.wantClass {
			t.Errorf("for class %s: expected class_uid %d, got %d", tt.class, tt.wantClass, out.ClassUID)
		}
		if out.CategoryUID != tt.wantCat {
			t.Errorf("for class %s: expected category_uid %d, got %d", tt.class, tt.wantCat, out.CategoryUID)
		}
		if out.ActivityID != tt.wantActID {
			t.Errorf("for class %s/action %s: expected activity_id %d, got %d", tt.class, tt.action, tt.wantActID, out.ActivityID)
		}
	}
}

func TestOCSFExporter_ScopeGuard_ZeroMutation(t *testing.T) {
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

	var cloned exporters.NormalizedEvent
	_ = json.Unmarshal(beforeJSON, &cloned)
	if !reflect.DeepEqual(*ir, cloned) {
		t.Fatalf("SCOPE GUARD VIOLATION: DeepEqual failed on Canonical IR event after export")
	}
}

func TestOCSFExporter_RejectsNilAndInvalid(t *testing.T) {
	exp := NewExporter()

	if _, err := exp.Export(nil); err == nil {
		t.Errorf("expected error exporting nil canonical event")
	}

	invalid := sampleNormalizedEvent()
	invalid.SchemaVersion = "0.9"
	if _, err := exp.Export(invalid); err == nil {
		t.Errorf("expected error exporting event with invalid schema_version")
	}
}

func TestOCSFExporter_ClassIDAutoResolution(t *testing.T) {
	exp := NewExporter()

	tests := []struct {
		classInput   string
		expectedUID  int
		expectedName string
	}{
		{"AUTHENTICATION", ClassAuthentication, "Authentication"},
		{"HTTP_REQUEST", ClassHTTPActivity, "HTTP Activity"},
		{"SECURITY_FINDING", ClassSecurityFinding, "Security Finding"},
		{"FILE_SYSTEM", ClassSystemActivity, "System Activity"},
	}

	for _, tc := range tests {
		event := sampleNormalizedEvent()
		event.Event.Class = tc.classInput
		ocsfEvent, err := exp.Export(event)
		if err != nil {
			t.Fatalf("export failed for %s: %v", tc.classInput, err)
		}
		if ocsfEvent.ClassUID != tc.expectedUID {
			t.Errorf("for %s, expected class_uid = %d, got %d", tc.classInput, tc.expectedUID, ocsfEvent.ClassUID)
		}
		if ocsfEvent.ClassName != tc.expectedName {
			t.Errorf("for %s, expected class_name = %s, got %s", tc.classInput, tc.expectedName, ocsfEvent.ClassName)
		}
	}
}

func TestOCSFExporter_SeverityAndStatusMapping(t *testing.T) {
	exp := NewExporter()

	// Test Success
	evSuccess := sampleNormalizedEvent()
	evSuccess.Event.Outcome = "success"
	ocsfSuccess, err := exp.Export(evSuccess)
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if ocsfSuccess.Status != "Success" || ocsfSuccess.StatusID != 1 {
		t.Errorf("expected Status=Success (ID 1), got %s (%d)", ocsfSuccess.Status, ocsfSuccess.StatusID)
	}

	// Test Failure & Finding Severity
	evFailure := sampleNormalizedEvent()
	evFailure.Event.Outcome = "failure"
	evFailure.Alert.Severity = "critical"
	ocsfFailure, err := exp.Export(evFailure)
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if ocsfFailure.Status != "Failure" || ocsfFailure.StatusID != 2 {
		t.Errorf("expected Status=Failure (ID 2), got %s (%d)", ocsfFailure.Status, ocsfFailure.StatusID)
	}
	if ocsfFailure.Finding == nil || ocsfFailure.Finding.Severity != "critical" {
		t.Errorf("expected Finding.Severity = 'critical', got %v", ocsfFailure.Finding)
	}
}

func TestOCSFExporter_ObservablesAndUnmappedPreservation(t *testing.T) {
	exp := NewExporter()
	event := sampleNormalizedEvent()
	event.Extensions = map[string]interface{}{
		"edr_threat_score": 98.5,
		"c2_channel":       "dns_beacon",
	}

	ocsfEvent, err := exp.Export(event)
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if ocsfEvent.Unmapped == nil {
		t.Fatalf("expected Unmapped dictionary to be populated")
	}
	if val, ok := ocsfEvent.Unmapped["edr_threat_score"]; !ok || val != 98.5 {
		t.Errorf("expected Unmapped[edr_threat_score] = 98.5, got %v", val)
	}
	if val, ok := ocsfEvent.Unmapped["c2_channel"]; !ok || val != "dns_beacon" {
		t.Errorf("expected Unmapped[c2_channel] = 'dns_beacon', got %v", val)
	}
	if ocsfEvent.Unmapped["raw_sha256"] == "" {
		t.Errorf("expected raw_sha256 preserved in Unmapped")
	}
}

func TestOCSFExporter_CategoryFallbackSafety(t *testing.T) {
	exp := NewExporter()
	event := sampleNormalizedEvent()
	event.Event.Class = "CUSTOM_SENSOR_TELEMETRY"

	ocsfEvent, err := exp.Export(event)
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if ocsfEvent.ClassUID != ClassSystemActivity {
		t.Errorf("expected fallback to ClassSystemActivity (%d), got %d", ClassSystemActivity, ocsfEvent.ClassUID)
	}
	if ocsfEvent.CategoryUID != CategorySystemActivity {
		t.Errorf("expected fallback to CategorySystemActivity (%d), got %d", CategorySystemActivity, ocsfEvent.CategoryUID)
	}
}
