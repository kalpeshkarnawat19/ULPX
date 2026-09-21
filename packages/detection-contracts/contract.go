package detectioncontracts

import (
	"fmt"
	"strings"
)

// Severity defines the priority of a detection rule contract.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// DetectionRule defines a semantic regression contract for normalized events.
// It verifies that normalization preserves detection-relevant semantics
// without implementing full SIEM threat detection.
type DetectionRule struct {
	ID          string                                  `json:"id"`
	Name        string                                  `json:"name"`
	Description string                                  `json:"description"`
	Severity    Severity                                `json:"severity"`
	IsMandatory bool                                    `json:"is_mandatory"` // Critical mandatory rules require DPS=100%
	Predicate   func(event map[string]interface{}) bool `json:"-"`
}

// EvaluationResult represents the execution outcome of a rule against an event.
type EvaluationResult struct {
	RuleID      string   `json:"rule_id"`
	RuleName    string   `json:"rule_name"`
	IsMandatory bool     `json:"is_mandatory"`
	Severity    Severity `json:"severity"`
	Matched     bool     `json:"matched"`
	Expected    bool     `json:"expected"`
	Preserved   bool     `json:"preserved"` // Matched == Expected
}

// Engine evaluates semantic detection contracts against normalized events.
type Engine struct {
	rules map[string]DetectionRule
}

// NewEngine constructs an Engine with standard synthetic regression contracts.
func NewEngine() *Engine {
	e := &Engine{
		rules: make(map[string]DetectionRule),
	}
	e.registerDefaultRules()
	return e
}

// RegisterRule registers a custom detection rule contract.
func (e *Engine) RegisterRule(rule DetectionRule) {
	e.rules[rule.ID] = rule
}

// GetRule returns a registered rule by ID.
func (e *Engine) GetRule(id string) (DetectionRule, bool) {
	r, exists := e.rules[id]
	return r, exists
}

// Rules returns all registered detection rules.
func (e *Engine) Rules() []DetectionRule {
	result := make([]DetectionRule, 0, len(e.rules))
	for _, r := range e.rules {
		result = append(result, r)
	}
	return result
}

// EvaluateRule evaluates a specific rule against a normalized event map.
func (e *Engine) EvaluateRule(ruleID string, event map[string]interface{}, expected bool) (EvaluationResult, error) {
	rule, exists := e.rules[ruleID]
	if !exists {
		return EvaluationResult{}, fmt.Errorf("detection rule %s not found", ruleID)
	}
	matched := rule.Predicate(event)
	return EvaluationResult{
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		IsMandatory: rule.IsMandatory,
		Severity:    rule.Severity,
		Matched:     matched,
		Expected:    expected,
		Preserved:   matched == expected,
	}, nil
}

// Helper functions for nested map inspection
func getNestedString(m map[string]interface{}, path ...string) string {
	var current interface{} = m
	for _, key := range path {
		currMap, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current, ok = currMap[key]
		if !ok {
			return ""
		}
	}
	if s, ok := current.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func getNestedInt(m map[string]interface{}, path ...string) (int, bool) {
	var current interface{} = m
	for _, key := range path {
		currMap, ok := current.(map[string]interface{})
		if !ok {
			return 0, false
		}
		current, ok = currMap[key]
		if !ok {
			return 0, false
		}
	}
	switch v := current.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}

// registerDefaultRules registers standard regression scenarios defined in PRD Section 8.
func (e *Engine) registerDefaultRules() {
	// 1. Repeated Authentication Failures (Mandatory)
	e.RegisterRule(DetectionRule{
		ID:          "DET-001",
		Name:        "Authentication Failure Detection Contract",
		Description: "Preserves failed authentication semantics (action=authentication, outcome=failure, user/src identity).",
		Severity:    SeverityCritical,
		IsMandatory: true,
		Predicate: func(event map[string]interface{}) bool {
			action := strings.ToLower(getNestedString(event, "event", "action"))
			outcome := strings.ToLower(getNestedString(event, "event", "outcome"))
			user := getNestedString(event, "user", "name")
			srcIP := getNestedString(event, "src", "ip")

			isAuthAction := strings.Contains(action, "auth") || strings.Contains(action, "login") || strings.Contains(action, "logon")
			isFailureOutcome := outcome == "failure" || outcome == "fail" || outcome == "denied"

			return isAuthAction && isFailureOutcome && (user != "" || srcIP != "")
		},
	})

	// 2. Blocked Connection Sequences (Mandatory)
	e.RegisterRule(DetectionRule{
		ID:          "DET-002",
		Name:        "Blocked Connection Detection Contract",
		Description: "Preserves network block/drop semantics (action/outcome=block/drop/deny with src/dst endpoints).",
		Severity:    SeverityCritical,
		IsMandatory: true,
		Predicate: func(event map[string]interface{}) bool {
			action := strings.ToLower(getNestedString(event, "event", "action"))
			outcome := strings.ToLower(getNestedString(event, "event", "outcome"))
			srcIP := getNestedString(event, "src", "ip")
			dstIP := getNestedString(event, "dst", "ip")

			isBlocked := strings.Contains(action, "block") || strings.Contains(action, "drop") ||
				strings.Contains(action, "deny") || outcome == "failure" || outcome == "deny" || outcome == "drop"
			hasEndpoints := srcIP != "" || dstIP != ""

			return isBlocked && hasEndpoints
		},
	})

	// 3. Successful Authentication (Mandatory)
	e.RegisterRule(DetectionRule{
		ID:          "DET-003",
		Name:        "Successful Authentication Detection Contract",
		Description: "Preserves successful authentication semantics (action=authentication, outcome=success, user identity).",
		Severity:    SeverityHigh,
		IsMandatory: true,
		Predicate: func(event map[string]interface{}) bool {
			action := strings.ToLower(getNestedString(event, "event", "action"))
			outcome := strings.ToLower(getNestedString(event, "event", "outcome"))
			user := getNestedString(event, "user", "name")

			isAuthAction := strings.Contains(action, "auth") || strings.Contains(action, "login") || strings.Contains(action, "logon")
			isSuccessOutcome := outcome == "success"

			return isAuthAction && isSuccessOutcome && user != ""
		},
	})

	// 4. Policy Deny Events (Mandatory)
	e.RegisterRule(DetectionRule{
		ID:          "DET-004",
		Name:        "Policy Deny Detection Contract",
		Description: "Preserves security policy denial semantics across firewalls and endpoint controls.",
		Severity:    SeverityCritical,
		IsMandatory: true,
		Predicate: func(event map[string]interface{}) bool {
			action := strings.ToLower(getNestedString(event, "event", "action"))
			outcome := strings.ToLower(getNestedString(event, "event", "outcome"))
			cls := strings.ToLower(getNestedString(event, "event", "class"))

			isDeny := strings.Contains(action, "deny") || strings.Contains(action, "reject") ||
				outcome == "failure" || strings.Contains(cls, "security") || strings.Contains(cls, "policy")

			return isDeny
		},
	})

	// 5. DNS Lookup Sequences
	e.RegisterRule(DetectionRule{
		ID:          "DET-005",
		Name:        "DNS Lookup Query Contract",
		Description: "Preserves DNS query name and query type semantics for anomaly tracking.",
		Severity:    SeverityMedium,
		IsMandatory: false,
		Predicate: func(event map[string]interface{}) bool {
			qname := getNestedString(event, "dns", "query_name")
			qtype := getNestedString(event, "dns", "query_type")
			cls := strings.ToLower(getNestedString(event, "event", "class"))

			return qname != "" || (qtype != "" && (cls == "dns" || strings.Contains(cls, "network")))
		},
	})

	// 6. Web Proxy Deny Events
	e.RegisterRule(DetectionRule{
		ID:          "DET-006",
		Name:        "Web Proxy Deny Contract",
		Description: "Preserves HTTP proxy block/deny status codes (e.g. 403) and requested URL.",
		Severity:    SeverityMedium,
		IsMandatory: false,
		Predicate: func(event map[string]interface{}) bool {
			statusCode, hasCode := getNestedInt(event, "http", "status_code")
			outcome := strings.ToLower(getNestedString(event, "event", "outcome"))
			url := getNestedString(event, "http", "url")

			isProxyDeny := (hasCode && (statusCode == 403 || statusCode == 401)) ||
				outcome == "failure" || outcome == "denied"

			return isProxyDeny && url != ""
		},
	})

	// 7. Lateral Movement Sequences (MITRE T1021)
	e.RegisterRule(DetectionRule{
		ID:          "DET-007",
		Name:        "Lateral Movement Detection Contract",
		Description: "Preserves internal lateral connection semantics (ports 445, 3389, 22, 5985 with internal src and dst endpoints).",
		Severity:    SeverityHigh,
		IsMandatory: true,
		Predicate: func(event map[string]interface{}) bool {
			dstPort, hasPort := getNestedInt(event, "dst", "port")
			srcIP := getNestedString(event, "src", "ip")
			dstIP := getNestedString(event, "dst", "ip")
			action := strings.ToLower(getNestedString(event, "event", "action"))
			outcome := strings.ToLower(getNestedString(event, "event", "outcome"))

			isLateralPort := hasPort && (dstPort == 445 || dstPort == 3389 || dstPort == 22 || dstPort == 5985 || dstPort == 135)
			hasEndpoints := srcIP != "" && dstIP != ""
			isAllowed := strings.Contains(action, "allow") || strings.Contains(action, "accept") ||
				strings.Contains(action, "connect") || outcome == "success"

			return isLateralPort && hasEndpoints && isAllowed
		},
	})

	// 8. Privilege Escalation Events (MITRE T1548 / T1078)
	e.RegisterRule(DetectionRule{
		ID:          "DET-008",
		Name:        "Privilege Escalation Detection Contract",
		Description: "Preserves user elevation and privileged credential access semantics (target user root/admin, elevation actions).",
		Severity:    SeverityCritical,
		IsMandatory: true,
		Predicate: func(event map[string]interface{}) bool {
			user := strings.ToLower(getNestedString(event, "user", "name"))
			action := strings.ToLower(getNestedString(event, "event", "action"))
			cls := strings.ToLower(getNestedString(event, "event", "class"))

			isPrivilegedUser := user == "root" || user == "administrator" || user == "system" || strings.Contains(user, "admin")
			isElevation := strings.Contains(action, "elevat") || strings.Contains(action, "sudo") ||
				strings.Contains(action, "runas") || strings.Contains(cls, "privilege")

			return isPrivilegedUser && isElevation
		},
	})

	// 9. Data Exfiltration Volume Spike (MITRE T1048 / T1041)
	e.RegisterRule(DetectionRule{
		ID:          "DET-009",
		Name:        "Data Exfiltration Spike Contract",
		Description: "Preserves high outbound transfer bytes and egress network activity semantics.",
		Severity:    SeverityHigh,
		IsMandatory: false,
		Predicate: func(event map[string]interface{}) bool {
			bytesOut, hasBytes := getNestedInt(event, "network", "bytes_out")
			if !hasBytes {
				bytesOut, hasBytes = getNestedInt(event, "network", "bytes")
			}
			cls := strings.ToLower(getNestedString(event, "event", "class"))
			dstIP := getNestedString(event, "dst", "ip")

			isHighEgress := hasBytes && bytesOut >= 10000000 // >= 10 MB egress
			isNetwork := cls == "network" || dstIP != ""

			return isHighEgress && isNetwork
		},
	})

	// 10. Ransomware Rapid File Modification (MITRE T1486)
	e.RegisterRule(DetectionRule{
		ID:          "DET-010",
		Name:        "Ransomware File Modification Contract",
		Description: "Preserves mass file encryption, modification, and bulk deletion semantics.",
		Severity:    SeverityCritical,
		IsMandatory: true,
		Predicate: func(event map[string]interface{}) bool {
			action := strings.ToLower(getNestedString(event, "event", "action"))
			cls := strings.ToLower(getNestedString(event, "event", "class"))
			outcome := strings.ToLower(getNestedString(event, "event", "outcome"))

			isFileClass := cls == "file" || cls == "filesystem" || strings.Contains(cls, "storage")
			isDestructiveAction := strings.Contains(action, "encrypt") || strings.Contains(action, "ransom") ||
				strings.Contains(action, "delete") || strings.Contains(action, "bulk_modify")
			isSuccess := outcome == "success" || outcome == ""

			return isFileClass && isDestructiveAction && isSuccess
		},
	})
}
