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
