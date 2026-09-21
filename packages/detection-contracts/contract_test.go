package detectioncontracts

import (
	"testing"
)

func sampleNormalizedEvent(action, outcome, user, srcIP, dstIP string) map[string]interface{} {
	return map[string]interface{}{
		"schema_version": "1.0",
		"event_id":       "01HZY8X9ABCD1234EFGH567890",
		"event": map[string]interface{}{
			"class":   "network",
			"action":  action,
			"outcome": outcome,
			"time":    "2026-09-18T12:00:00Z",
		},
		"source": map[string]interface{}{
			"vendor":    "CheckPoint",
			"product":   "Firewall-1",
			"device_id": "fw-edge-01",
		},
		"src": map[string]interface{}{
			"ip":   srcIP,
			"port": 44321,
		},
		"dst": map[string]interface{}{
			"ip":   dstIP,
			"port": 443,
		},
		"user": map[string]interface{}{
			"name": user,
		},
	}
}

func TestEngineRuleEvaluation(t *testing.T) {
	engine := NewEngine()

	// 1. Test DET-001 (Auth Failure)
	authFailEvent := sampleNormalizedEvent("authentication", "failure", "admin", "192.168.1.100", "10.0.0.1")
	res, err := engine.EvaluateRule("DET-001", authFailEvent, true)
	if err != nil {
		t.Fatalf("unexpected error evaluating DET-001: %v", err)
	}
	if !res.Matched || !res.Preserved {
		t.Errorf("expected DET-001 to match and be preserved, got %+v", res)
	}

	// 2. Test DET-002 (Blocked Connection)
	blockEvent := sampleNormalizedEvent("drop", "failure", "", "10.0.0.50", "172.16.0.10")
	res, err = engine.EvaluateRule("DET-002", blockEvent, true)
	if err != nil {
		t.Fatalf("unexpected error evaluating DET-002: %v", err)
	}
	if !res.Matched || !res.Preserved {
		t.Errorf("expected DET-002 to match, got %+v", res)
	}

	// 3. Test DET-003 (Successful Authentication)
	authSuccessEvent := sampleNormalizedEvent("login", "success", "alice", "192.168.1.20", "10.0.0.2")
	res, err = engine.EvaluateRule("DET-003", authSuccessEvent, true)
	if err != nil {
		t.Fatalf("unexpected error evaluating DET-003: %v", err)
	}
	if !res.Matched || !res.Preserved {
		t.Errorf("expected DET-003 to match, got %+v", res)
	}

	// 4. Negative test: non-matching event with expected=false should be preserved
	res, err = engine.EvaluateRule("DET-001", authSuccessEvent, false)
	if err != nil {
		t.Fatalf("unexpected error evaluating DET-001 negative: %v", err)
	}
	if res.Matched {
		t.Errorf("expected DET-001 NOT to match auth success, got matched=true")
	}
	if !res.Preserved {
		t.Errorf("expected negative evaluation to be preserved (expected false, matched false)")
	}
}

func TestDPSCalculationAllPreserved(t *testing.T) {
	calc := NewDPSCalculator()
	results := []EvaluationResult{
		{RuleID: "DET-001", IsMandatory: true, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-002", IsMandatory: true, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-003", IsMandatory: true, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-004", IsMandatory: true, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-005", IsMandatory: false, Matched: true, Expected: true, Preserved: true},
	}

	report, err := calc.Calculate(results)
	if err != nil {
		t.Fatalf("unexpected error calculating DPS: %v", err)
	}
	if report.DPS != 1.0 {
		t.Errorf("expected DPS 1.0, got %f", report.DPS)
	}
	if !report.MandatoryPassed {
		t.Errorf("expected MandatoryPassed=true")
	}
	if !report.Certified {
		t.Errorf("expected Certified=true")
	}
	if len(report.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(report.Violations))
	}
}

func TestDPSMandatoryFailureBlocksCertification(t *testing.T) {
	calc := NewDPSCalculator()
	// 9 out of 10 rules pass (DPS = 0.90), but 1 mandatory rule fails!
	results := []EvaluationResult{
		{RuleID: "DET-001", IsMandatory: true, Matched: false, Expected: true, Preserved: false}, // Critical mandatory failure!
		{RuleID: "DET-002", IsMandatory: true, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-003", IsMandatory: true, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-004", IsMandatory: true, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-005", IsMandatory: false, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-006", IsMandatory: false, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-007", IsMandatory: false, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-008", IsMandatory: false, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-009", IsMandatory: false, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-010", IsMandatory: false, Matched: true, Expected: true, Preserved: true},
	}

	report, err := calc.Calculate(results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mandatory failure must block certification even if DPS was high!
	if report.MandatoryPassed {
		t.Errorf("expected MandatoryPassed=false due to mandatory violation")
	}
	if report.Certified {
		t.Errorf("SCOPE GUARD VIOLATION: A critical mandatory failure must NOT be averaged away!")
	}
	if len(report.Violations) != 1 || report.Violations[0].RuleID != "DET-001" {
		t.Errorf("expected violation on DET-001, got %+v", report.Violations)
	}
}

func TestDPSEmptyResults(t *testing.T) {
	calc := NewDPSCalculator()
	_, err := calc.Calculate(nil)
	if err == nil {
		t.Errorf("expected error calculating DPS on empty results, got nil")
	}
}

func TestEngine_DET007_LateralMovement(t *testing.T) {
	engine := NewEngine()

	// Internal SMB connection (port 445)
	smbEvent := map[string]interface{}{
		"event": map[string]interface{}{"action": "allow", "outcome": "success"},
		"src":   map[string]interface{}{"ip": "10.0.1.10", "port": 49201},
		"dst":   map[string]interface{}{"ip": "10.0.2.20", "port": 445},
	}
	res, err := engine.EvaluateRule("DET-007", smbEvent, true)
	if err != nil {
		t.Fatalf("unexpected error evaluating DET-007: %v", err)
	}
	if !res.Matched || !res.Preserved {
		t.Errorf("expected DET-007 to match SMB lateral movement, got %+v", res)
	}

	// External connection (not lateral port)
	webEvent := map[string]interface{}{
		"event": map[string]interface{}{"action": "allow"},
		"src":   map[string]interface{}{"ip": "10.0.1.10"},
		"dst":   map[string]interface{}{"ip": "8.8.8.8", "port": 53},
	}
	resNeg, _ := engine.EvaluateRule("DET-007", webEvent, false)
	if resNeg.Matched {
		t.Errorf("expected DET-007 NOT to match non-lateral port")
	}
}

func TestEngine_DET008_PrivilegeEscalation(t *testing.T) {
	engine := NewEngine()

	privEvent := map[string]interface{}{
		"event": map[string]interface{}{"action": "sudo_elevation", "class": "privilege_activity"},
		"user":  map[string]interface{}{"name": "root"},
	}
	res, err := engine.EvaluateRule("DET-008", privEvent, true)
	if err != nil {
		t.Fatalf("unexpected error evaluating DET-008: %v", err)
	}
	if !res.Matched || !res.Preserved {
		t.Errorf("expected DET-008 to match privilege escalation, got %+v", res)
	}

	// Standard unprivileged user action
	unprivEvent := map[string]interface{}{
		"event": map[string]interface{}{"action": "read"},
		"user":  map[string]interface{}{"name": "guest"},
	}
	resNeg, _ := engine.EvaluateRule("DET-008", unprivEvent, false)
	if resNeg.Matched {
		t.Errorf("expected DET-008 NOT to match unprivileged user read")
	}
}

func TestEngine_DET009_DataExfiltration(t *testing.T) {
	engine := NewEngine()

	// High egress volume: 25 MB transfer
	exfilEvent := map[string]interface{}{
		"event":   map[string]interface{}{"class": "network"},
		"network": map[string]interface{}{"bytes_out": 26214400},
		"dst":     map[string]interface{}{"ip": "203.0.113.50"},
	}
	res, err := engine.EvaluateRule("DET-009", exfilEvent, true)
	if err != nil {
		t.Fatalf("unexpected error evaluating DET-009: %v", err)
	}
	if !res.Matched || !res.Preserved {
		t.Errorf("expected DET-009 to match high egress volume, got %+v", res)
	}

	// Normal small HTTP response: 15 KB
	normalEvent := map[string]interface{}{
		"event":   map[string]interface{}{"class": "network"},
		"network": map[string]interface{}{"bytes_out": 15360},
		"dst":     map[string]interface{}{"ip": "203.0.113.50"},
	}
	resNeg, _ := engine.EvaluateRule("DET-009", normalEvent, false)
	if resNeg.Matched {
		t.Errorf("expected DET-009 NOT to match normal traffic volume")
	}
}

func TestEngine_DET010_RansomwareFileModification(t *testing.T) {
	engine := NewEngine()

	ransomEvent := map[string]interface{}{
		"event": map[string]interface{}{"class": "file", "action": "bulk_encrypt", "outcome": "success"},
		"file":  map[string]interface{}{"path": "/data/confidential.docx.locked"},
	}
	res, err := engine.EvaluateRule("DET-010", ransomEvent, true)
	if err != nil {
		t.Fatalf("unexpected error evaluating DET-010: %v", err)
	}
	if !res.Matched || !res.Preserved {
		t.Errorf("expected DET-010 to match ransomware file encryption, got %+v", res)
	}
}

func TestEngine_CaseInsensitiveSemanticPreservation(t *testing.T) {
	engine := NewEngine()

	// Uppercase action and mixed case outcome
	event := sampleNormalizedEvent("AUTHENTICATION", "FAILURE", "ADMIN", "10.0.0.1", "10.0.0.2")
	res, err := engine.EvaluateRule("DET-001", event, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Matched || !res.Preserved {
		t.Errorf("expected case-insensitive matching on DET-001, got %+v", res)
	}
}

func TestEngine_MultiStageAttackChain(t *testing.T) {
	engine := NewEngine()

	// Step 1: Initial failed auth
	e1 := sampleNormalizedEvent("authentication", "failure", "attacker", "192.168.1.50", "10.0.0.5")
	// Step 2: Lateral movement via RDP
	e2 := map[string]interface{}{
		"event": map[string]interface{}{"action": "allow", "outcome": "success"},
		"src":   map[string]interface{}{"ip": "10.0.0.5", "port": 50123},
		"dst":   map[string]interface{}{"ip": "10.0.0.10", "port": 3389},
	}
	// Step 3: Privilege escalation
	e3 := map[string]interface{}{
		"event": map[string]interface{}{"action": "sudo_elevation"},
		"user":  map[string]interface{}{"name": "root"},
	}
	// Step 4: Data exfiltration
	e4 := map[string]interface{}{
		"event":   map[string]interface{}{"class": "network"},
		"network": map[string]interface{}{"bytes_out": 50000000},
		"dst":     map[string]interface{}{"ip": "198.51.100.22"},
	}

	r1, _ := engine.EvaluateRule("DET-001", e1, true)
	r2, _ := engine.EvaluateRule("DET-007", e2, true)
	r3, _ := engine.EvaluateRule("DET-008", e3, true)
	r4, _ := engine.EvaluateRule("DET-009", e4, true)

	calc := NewDPSCalculator()
	report, err := calc.Calculate([]EvaluationResult{r1, r2, r3, r4})
	if err != nil {
		t.Fatalf("DPS calculation failed on attack chain: %v", err)
	}
	if report.DPS != 1.0 || !report.Certified {
		t.Errorf("expected 100%% DPS across multi-stage attack chain, got %f (certified: %v)",
			report.DPS, report.Certified)
	}
}

func TestEngine_MissingIdentityAbstention(t *testing.T) {
	engine := NewEngine()

	// Auth failure event but completely missing user identity AND src IP
	incompleteEvent := map[string]interface{}{
		"event": map[string]interface{}{"action": "authentication", "outcome": "failure"},
	}
	res, err := engine.EvaluateRule("DET-001", incompleteEvent, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Matched {
		t.Errorf("expected rule to abstain from matching when identity is absent")
	}
}

func TestDPS_PartialPreservationMetricScoring(t *testing.T) {
	calc := NewDPSCalculator()

	// 7 preserved, 3 unpreserved non-mandatory rules
	results := []EvaluationResult{
		{RuleID: "DET-001", IsMandatory: true, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-002", IsMandatory: true, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-003", IsMandatory: true, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-004", IsMandatory: true, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-005", IsMandatory: false, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-006", IsMandatory: false, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-007", IsMandatory: true, Matched: true, Expected: true, Preserved: true},
		{RuleID: "DET-008", IsMandatory: false, Matched: false, Expected: true, Preserved: false},
		{RuleID: "DET-009", IsMandatory: false, Matched: false, Expected: true, Preserved: false},
		{RuleID: "DET-010", IsMandatory: false, Matched: false, Expected: true, Preserved: false},
	}

	report, err := calc.Calculate(results)
	if err != nil {
		t.Fatalf("DPS calculation error: %v", err)
	}

	expectedDPS := 0.70
	if report.DPS != expectedDPS {
		t.Errorf("expected DPS %f, got %f", expectedDPS, report.DPS)
	}
	if !report.MandatoryPassed {
		t.Errorf("expected MandatoryPassed=true because all mandatory rules were preserved")
	}
}
