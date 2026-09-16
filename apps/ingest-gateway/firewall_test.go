package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFirewall_MalformedFixtures verifies that all malformed fixtures in
// fixtures/malformed/ are explicitly quarantined or rejected, and NEVER silently dropped.
func TestFirewall_MalformedFixtures(t *testing.T) {
	fw := NewTelemetryFirewall(DefaultFirewallConfig())
	fixturesDir := filepath.Join("..", "..", "fixtures", "malformed")

	tests := []struct {
		filename         string
		expectedStatus   IngestStatus
		expectedCode     ViolationCode
		description      string
	}{
		{
			filename:       "oversized.raw",
			expectedStatus: StatusQuarantined,
			expectedCode:   ViolationOversized,
			description:    "Payload exceeding 64 KiB limit",
		},
		{
			filename:       "invalid_utf8.raw",
			expectedStatus: StatusQuarantined,
			expectedCode:   ViolationInvalidEncoding,
			description:    "Payload with corrupted non-UTF8 byte sequences",
		},
		{
			filename:       "deep_nesting.json",
			expectedStatus: StatusQuarantined,
			expectedCode:   ViolationNestingExceeded,
			description:    "JSON object nested 36 levels deep (> 32 limit)",
		},
		{
			filename:       "huge_keys.json",
			expectedStatus: StatusQuarantined,
			expectedCode:   ViolationKeyTooLong,
			description:    "JSON object with key length 300 characters (> 256 limit)",
		},
		{
			filename:       "excessive_fields.json",
			expectedStatus: StatusQuarantined,
			expectedCode:   ViolationFieldLimitExceeded,
			description:    "JSON object with 600 fields (> 512 limit)",
		},
		{
			filename:       "valid_syslog.raw",
			expectedStatus: StatusAccepted,
			expectedCode:   ViolationNone,
			description:    "Clean baseline syslog event",
		},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			path := filepath.Join(fixturesDir, tt.filename)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read fixture %s: %v", path, err)
			}

			decision := fw.Inspect(context.Background(), raw)

			if decision.Status != tt.expectedStatus {
				t.Errorf("%s: expected status %s, got %s (reason: %s)",
					tt.filename, tt.expectedStatus, decision.Status, decision.Reason)
			}

			if tt.expectedCode != "" && decision.ViolationCode != tt.expectedCode {
				t.Errorf("%s: expected violation code %s, got %s",
					tt.filename, tt.expectedCode, decision.ViolationCode)
			}
		})
	}
}

// TestFirewall_SizeBoundary verifies exact 64 KiB boundary enforcement.
func TestFirewall_SizeBoundary(t *testing.T) {
	fw := NewTelemetryFirewall(DefaultFirewallConfig())

	// Exactly 64 KiB (65536 bytes) of valid UTF-8 spaces
	exact64K := bytes.Repeat([]byte(" "), 64*1024)
	decision := fw.Inspect(context.Background(), exact64K)
	if decision.Status != StatusAccepted {
		t.Errorf("expected 64 KiB to be ACCEPTED, got %s: %s", decision.Status, decision.Reason)
	}

	// 64 KiB + 1 byte
	over64K := append(exact64K, '!')
	decisionOver := fw.Inspect(context.Background(), over64K)
	if decisionOver.Status != StatusQuarantined || decisionOver.ViolationCode != ViolationOversized {
		t.Errorf("expected 64 KiB + 1 to be QUARANTINED with ERR_OVERSIZED, got %s: %s",
			decisionOver.Status, decisionOver.ViolationCode)
	}
}

// TestFirewall_NestingDepthBoundary verifies exact 32 nesting levels limit.
func TestFirewall_NestingDepthBoundary(t *testing.T) {
	fw := NewTelemetryFirewall(DefaultFirewallConfig())

	// Exactly 32 levels deep: {"l1":{"l2": ... {"l32":"ok"}...}}
	var b strings.Builder
	for i := 1; i <= 32; i++ {
		b.WriteString(fmt.Sprintf(`{"l%d":`, i))
	}
	b.WriteString(`"val"`)
	b.WriteString(strings.Repeat("}", 32))

	dec32 := fw.Inspect(context.Background(), []byte(b.String()))
	if dec32.Status != StatusAccepted {
		t.Errorf("expected 32 levels to be ACCEPTED, got %s: %s", dec32.Status, dec32.Reason)
	}

	// 33 levels deep
	var b33 strings.Builder
	for i := 1; i <= 33; i++ {
		b33.WriteString(fmt.Sprintf(`{"l%d":`, i))
	}
	b33.WriteString(`"val"`)
	b33.WriteString(strings.Repeat("}", 33))

	dec33 := fw.Inspect(context.Background(), []byte(b33.String()))
	if dec33.Status != StatusQuarantined || dec33.ViolationCode != ViolationNestingExceeded {
		t.Errorf("expected 33 levels to be QUARANTINED with ERR_NESTING_EXCEEDED, got %s: %s",
			dec33.Status, dec33.ViolationCode)
	}
}

// TestFirewall_FieldCountBoundary verifies exact 512 fields limit.
func TestFirewall_FieldCountBoundary(t *testing.T) {
	fw := NewTelemetryFirewall(DefaultFirewallConfig())

	// 512 fields: {"f1":"v", "f2":"v", ...}
	fields512 := make(map[string]string)
	for i := 1; i <= 512; i++ {
		fields512[fmt.Sprintf("f%d", i)] = "v"
	}
	raw512, _ := json.Marshal(fields512)
	dec512 := fw.Inspect(context.Background(), raw512)
	if dec512.Status != StatusAccepted {
		t.Errorf("expected 512 fields to be ACCEPTED, got %s: %s", dec512.Status, dec512.Reason)
	}

	// 513 fields
	fields513 := make(map[string]string)
	for i := 1; i <= 513; i++ {
		fields513[fmt.Sprintf("f%d", i)] = "v"
	}
	raw513, _ := json.Marshal(fields513)
	dec513 := fw.Inspect(context.Background(), raw513)
	if dec513.Status != StatusQuarantined || dec513.ViolationCode != ViolationFieldLimitExceeded {
		t.Errorf("expected 513 fields to be QUARANTINED with ERR_FIELD_LIMIT_EXCEEDED, got %s: %s",
			dec513.Status, dec513.ViolationCode)
	}
}

// TestFirewall_KeyLengthBoundary verifies exact 256 characters key length limit.
func TestFirewall_KeyLengthBoundary(t *testing.T) {
	fw := NewTelemetryFirewall(DefaultFirewallConfig())

	// 256 chars key
	key256 := strings.Repeat("k", 256)
	raw256 := []byte(fmt.Sprintf(`{"%s":"value"}`, key256))
	dec256 := fw.Inspect(context.Background(), raw256)
	if dec256.Status != StatusAccepted {
		t.Errorf("expected 256 char key to be ACCEPTED, got %s: %s", dec256.Status, dec256.Reason)
	}

	// 257 chars key
	key257 := strings.Repeat("k", 257)
	raw257 := []byte(fmt.Sprintf(`{"%s":"value"}`, key257))
	dec257 := fw.Inspect(context.Background(), raw257)
	if dec257.Status != StatusQuarantined || dec257.ViolationCode != ViolationKeyTooLong {
		t.Errorf("expected 257 char key to be QUARANTINED with ERR_KEY_TOO_LONG, got %s: %s",
			dec257.Status, dec257.ViolationCode)
	}
}

// TestFirewall_SafeRender tests XSS and escape sequence neutralization.
func TestFirewall_SafeRender(t *testing.T) {
	input := `<script>alert('XSS')</script><b onmouseover=evil()>bold</b> \x1b[31;1mALERT\x1b[0m`
	rendered := SafeRender(input)

	if strings.Contains(rendered, "<script>") {
		t.Errorf("SafeRender failed to escape <script>: %s", rendered)
	}
	if strings.Contains(rendered, "\x1b[31;1m") {
		t.Errorf("SafeRender failed to strip ANSI escapes: %s", rendered)
	}
	if !strings.Contains(rendered, "&lt;script&gt;") {
		t.Errorf("SafeRender did not produce HTML escaped tags: %s", rendered)
	}
}

// TestFirewall_Timeout verifies context cancellation triggers ERR_TIMEOUT.
func TestFirewall_Timeout(t *testing.T) {
	fw := NewTelemetryFirewall(DefaultFirewallConfig())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled immediately

	decision := fw.Inspect(ctx, []byte("some raw log"))
	if decision.Status != StatusQuarantined || decision.ViolationCode != ViolationTimeout {
		t.Errorf("expected ERR_TIMEOUT on canceled context, got %s: %s",
			decision.Status, decision.ViolationCode)
	}
}

// TestFirewall_QuarantinePreservesRawBytes verifies the non-negotiable rule:
// Even when quarantined, raw bytes are persisted immutably and nothing is silently dropped.
func TestFirewall_QuarantinePreservesRawBytes(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "firewall_test_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store := NewLocalFSStore(tmpDir)
	bus := NewInMemoryBus()
	svc := NewIngestService(store, bus)

	// Subscribe to quarantine topic
	qChan, unsub := bus.Subscribe(TopicQuarantinedEvents)
	defer unsub()

	// Malformed payload (invalid UTF-8)
	malformedBytes := []byte("malformed_log=\xff\xfe\x80\xbf")
	sourceID := "src_adversarial_test"

	envelope, decision, err := svc.IngestWithContext(context.Background(), sourceID, "http", malformedBytes)
	if err != nil {
		t.Fatalf("IngestWithContext failed: %v", err)
	}

	// 1. Verify decision
	if decision.Status != StatusQuarantined {
		t.Errorf("expected QUARANTINED, got %s", decision.Status)
	}

	// 2. Verify envelope status
	if envelope.IngestStatus != "QUARANTINED" {
		t.Errorf("expected envelope.IngestStatus == QUARANTINED, got %s", envelope.IngestStatus)
	}

	// 3. Verify raw bytes preserved on disk exactly
	loadedBytes, err := store.Load(envelope.RawRef)
	if err != nil {
		t.Fatalf("failed to load quarantined raw bytes: %v", err)
	}
	if !bytes.Equal(loadedBytes, malformedBytes) {
		t.Errorf("stored bytes do not match malformed input bytes")
	}

	// 4. Verify message arrived on quarantine bus topic
	select {
	case receivedEnv := <-qChan:
		if receivedEnv.EventID != envelope.EventID {
			t.Errorf("bus received event %s, expected %s", receivedEnv.EventID, envelope.EventID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("timed out waiting for quarantine event on bus")
	}
}
