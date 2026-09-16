// Package main implements the ULPF-X ingest gateway and telemetry firewall.
//
// Stage 2: Telemetry Firewall
// Provides deterministic untrusted-input safety gates:
// - Max raw event size (default: 64 KiB)
// - Valid UTF-8 encoding verification
// - Max parsed fields (default: 512)
// - Max key length (default: 256 chars)
// - Max structural nesting depth (default: 32 levels)
// - Per-event inspection timeout
// - Explicit quarantine status assignment (nothing silently dropped)
// - Safe rendering rules (neutralize script injection, HTML, and ANSI escapes)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// IngestStatus represents the classification status assigned by the firewall.
type IngestStatus string

const (
	StatusAccepted    IngestStatus = "ACCEPTED"
	StatusQuarantined IngestStatus = "QUARANTINED"
	StatusRejected    IngestStatus = "REJECTED"
)

// ViolationCode classifies the exact firewall rule triggered.
type ViolationCode string

const (
	ViolationNone               ViolationCode = ""
	ViolationOversized          ViolationCode = "ERR_OVERSIZED"
	ViolationInvalidEncoding    ViolationCode = "ERR_INVALID_ENCODING"
	ViolationNestingExceeded    ViolationCode = "ERR_NESTING_EXCEEDED"
	ViolationFieldLimitExceeded ViolationCode = "ERR_FIELD_LIMIT_EXCEEDED"
	ViolationKeyTooLong         ViolationCode = "ERR_KEY_TOO_LONG"
	ViolationTimeout            ViolationCode = "ERR_TIMEOUT"
)

// FirewallDecision holds the result of inspecting a raw event.
type FirewallDecision struct {
	Status        IngestStatus   `json:"status"`
	ViolationCode ViolationCode  `json:"violation_code,omitempty"`
	Reason        string         `json:"reason,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
}

// FirewallConfig defines limits per PRD Section 12.
type FirewallConfig struct {
	MaxRawSizeBytes      int           `json:"max_raw_size_bytes"`
	MaxParsedFields      int           `json:"max_parsed_fields"`
	MaxKeyLength         int           `json:"max_key_length"`
	MaxStructuralNesting int           `json:"max_structural_nesting"`
	PerEventTimeout      time.Duration `json:"per_event_timeout"`
	EnforceUTF8          bool          `json:"enforce_utf8"`
}

// DefaultFirewallConfig returns the default limits per PRD §12.
func DefaultFirewallConfig() FirewallConfig {
	return FirewallConfig{
		MaxRawSizeBytes:      64 * 1024, // 64 KiB = 65,536 bytes
		MaxParsedFields:      512,
		MaxKeyLength:         256,
		MaxStructuralNesting: 32,
		PerEventTimeout:      50 * time.Millisecond,
		EnforceUTF8:          true,
	}
}

// TelemetryFirewall inspects untrusted payloads deterministically.
type TelemetryFirewall struct {
	config FirewallConfig
}

// NewTelemetryFirewall creates a firewall with the given configuration.
func NewTelemetryFirewall(cfg FirewallConfig) *TelemetryFirewall {
	return &TelemetryFirewall{config: cfg}
}

// Inspect evaluates raw bytes against deterministic safety rules.
// Nothing is silently dropped: any malformed input produces a QUARANTINED
// or REJECTED decision with full violation diagnostics.
func (f *TelemetryFirewall) Inspect(ctx context.Context, raw []byte) FirewallDecision {
	// 0. Timeout & cancellation check
	select {
	case <-ctx.Done():
		return FirewallDecision{
			Status:        StatusQuarantined,
			ViolationCode: ViolationTimeout,
			Reason:        fmt.Sprintf("inspection aborted: %v", ctx.Err()),
		}
	default:
	}

	// 1. Size limit check (PRD: Max raw event size 64 KiB)
	if len(raw) > f.config.MaxRawSizeBytes {
		return FirewallDecision{
			Status:        StatusQuarantined,
			ViolationCode: ViolationOversized,
			Reason: fmt.Sprintf("payload size %d bytes exceeds maximum allowed limit of %d bytes (64 KiB)",
				len(raw), f.config.MaxRawSizeBytes),
			Details: map[string]any{
				"measured_bytes": len(raw),
				"max_allowed":    f.config.MaxRawSizeBytes,
			},
		}
	}

	// 2. Encoding verification (Valid UTF-8)
	if f.config.EnforceUTF8 && !utf8.Valid(raw) {
		return FirewallDecision{
			Status:        StatusQuarantined,
			ViolationCode: ViolationInvalidEncoding,
			Reason:        "payload contains invalid UTF-8 byte sequences",
			Details: map[string]any{
				"encoding": "utf-8",
			},
		}
	}

	// 3. Structural inspection (Nesting depth, field count, key length)
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		if decision, ok := f.inspectJSONStructure(trimmed); !ok {
			return decision
		}
	} else if len(trimmed) > 0 {
		// Key-Value style inspection (e.g. CEF, LEEF, Syslog KV)
		if decision, ok := f.inspectKVStructure(trimmed); !ok {
			return decision
		}
	}

	return FirewallDecision{
		Status: StatusAccepted,
	}
}

// inspectJSONStructure checks structural nesting depth, total fields, and key length.
func (f *TelemetryFirewall) inspectJSONStructure(raw []byte) (FirewallDecision, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	depth := 0
	fieldCount := 0

	type containerType int
	const (
		containerObject containerType = iota
		containerArray
	)
	var stack []containerType
	expectKey := false

	for {
		token, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			// Malformed JSON syntax
			return FirewallDecision{
				Status:        StatusQuarantined,
				ViolationCode: ViolationInvalidEncoding,
				Reason:        fmt.Sprintf("malformed JSON syntax: %v", err),
			}, false
		}

		switch t := token.(type) {
		case json.Delim:
			switch t {
			case '{':
				depth++
				if depth > f.config.MaxStructuralNesting {
					return FirewallDecision{
						Status:        StatusQuarantined,
						ViolationCode: ViolationNestingExceeded,
						Reason: fmt.Sprintf("structural nesting depth %d exceeds maximum limit of %d",
							depth, f.config.MaxStructuralNesting),
						Details: map[string]any{
							"measured_depth": depth,
							"max_allowed":    f.config.MaxStructuralNesting,
						},
					}, false
				}
				stack = append(stack, containerObject)
				expectKey = true
			case '[':
				depth++
				if depth > f.config.MaxStructuralNesting {
					return FirewallDecision{
						Status:        StatusQuarantined,
						ViolationCode: ViolationNestingExceeded,
						Reason: fmt.Sprintf("structural nesting depth %d exceeds maximum limit of %d",
							depth, f.config.MaxStructuralNesting),
						Details: map[string]any{
							"measured_depth": depth,
							"max_allowed":    f.config.MaxStructuralNesting,
						},
					}, false
				}
				stack = append(stack, containerArray)
				expectKey = false
			case '}', ']':
				depth--
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				if len(stack) > 0 && stack[len(stack)-1] == containerObject {
					expectKey = true
				} else {
					expectKey = false
				}
			}
		case string:
			inObject := len(stack) > 0 && stack[len(stack)-1] == containerObject
			if inObject && expectKey {
				// This string is an object key
				runeLen := utf8.RuneCountInString(t)
				if runeLen > f.config.MaxKeyLength {
					return FirewallDecision{
						Status:        StatusQuarantined,
						ViolationCode: ViolationKeyTooLong,
						Reason: fmt.Sprintf("JSON key length %d characters exceeds maximum limit of %d",
							runeLen, f.config.MaxKeyLength),
						Details: map[string]any{
							"measured_length": runeLen,
							"max_allowed":     f.config.MaxKeyLength,
						},
					}, false
				}
				fieldCount++
				if fieldCount > f.config.MaxParsedFields {
					return FirewallDecision{
						Status:        StatusQuarantined,
						ViolationCode: ViolationFieldLimitExceeded,
						Reason: fmt.Sprintf("total field count %d exceeds maximum limit of %d",
							fieldCount, f.config.MaxParsedFields),
						Details: map[string]any{
							"measured_fields": fieldCount,
							"max_allowed":     f.config.MaxParsedFields,
						},
					}, false
				}
				expectKey = false // next token is the value
			} else if inObject {
				// This string is an object value
				expectKey = true // next token is the next key
			}
		default:
			// scalar value (float64, bool, nil)
			if len(stack) > 0 && stack[len(stack)-1] == containerObject {
				expectKey = true
			}
		}
	}

	return FirewallDecision{Status: StatusAccepted}, true
}

// inspectKVStructure checks key-value pairs for key length and field counts.
func (f *TelemetryFirewall) inspectKVStructure(raw []byte) (FirewallDecision, bool) {
	str := string(raw)
	pairs := strings.Fields(str)
	fieldCount := 0

	for _, pair := range pairs {
		idx := strings.IndexByte(pair, '=')
		if idx == -1 {
			idx = strings.IndexByte(pair, ':')
		}
		if idx > 0 {
			fieldCount++
			key := pair[:idx]
			keyLen := utf8.RuneCountInString(key)
			if keyLen > f.config.MaxKeyLength {
				return FirewallDecision{
					Status:        StatusQuarantined,
					ViolationCode: ViolationKeyTooLong,
					Reason: fmt.Sprintf("KV key length %d characters exceeds maximum limit of %d",
						keyLen, f.config.MaxKeyLength),
					Details: map[string]any{
						"measured_length": keyLen,
						"max_allowed":     f.config.MaxKeyLength,
					},
				}, false
			}
			if fieldCount > f.config.MaxParsedFields {
				return FirewallDecision{
					Status:        StatusQuarantined,
					ViolationCode: ViolationFieldLimitExceeded,
					Reason: fmt.Sprintf("KV field count %d exceeds maximum limit of %d",
						fieldCount, f.config.MaxParsedFields),
					Details: map[string]any{
						"measured_fields": fieldCount,
						"max_allowed":     f.config.MaxParsedFields,
					},
				}, false
			}
		}
	}

	return FirewallDecision{Status: StatusAccepted}, true
}

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// SafeRender implements safe rendering rules per PRD §12:
// - Escapes HTML tags (<, >, &, ", ') to prevent XSS.
// - Strips ANSI terminal escape sequences to prevent terminal injection.
// - Neutralizes dangerous ASCII control characters while preserving tabs and newlines.
func SafeRender(untrusted string) string {
	// 1. Strip ANSI escape sequences
	cleaned := ansiRegex.ReplaceAllString(untrusted, "")

	// 2. Neutralize non-printable control characters (except \t, \n, \r)
	var b strings.Builder
	b.Grow(len(cleaned))
	for _, r := range cleaned {
		if r == '\t' || r == '\n' || r == '\r' || r >= 32 && r != 127 {
			b.WriteRune(r)
		} else {
			b.WriteString(fmt.Sprintf("\\x%02x", r))
		}
	}

	// 3. Escape HTML entities
	return html.EscapeString(b.String())
}
