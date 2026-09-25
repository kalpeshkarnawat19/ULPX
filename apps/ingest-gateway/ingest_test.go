package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ulidPattern matches a canonical ULID (26 chars, Crockford base32).
var ulidPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// rawRefPattern matches the expected storage path format.
var rawRefPattern = regexp.MustCompile(`^raw/\d{4}/\d{2}/\d{2}/[^/]+/[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

func tempStore(t *testing.T) *LocalFSStore {
	t.Helper()
	dir := t.TempDir()
	return NewLocalFSStore(dir)
}

// --- Envelope Tests ---

func TestNewRawEventEnvelope_Valid(t *testing.T) {
	raw := []byte(`<14>Sep 16 09:30:00 fw-01 src=10.0.0.5 dst=10.0.0.10 action=deny`)
	env, err := NewRawEventEnvelope("src_demo_firewall", "syslog_tcp", raw, "raw/2026/09/16/src_demo_firewall/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if env.SchemaVersion != "1.0" {
		t.Errorf("schema_version = %q, want %q", env.SchemaVersion, "1.0")
	}
	if !ulidPattern.MatchString(env.EventID) {
		t.Errorf("event_id %q is not a valid ULID", env.EventID)
	}
	if env.SourceID != "src_demo_firewall" {
		t.Errorf("source_id = %q, want %q", env.SourceID, "src_demo_firewall")
	}
	if env.Transport != "syslog_tcp" {
		t.Errorf("transport = %q, want %q", env.Transport, "syslog_tcp")
	}
	if env.IngestStatus != "ACCEPTED" {
		t.Errorf("ingest_status = %q, want %q", env.IngestStatus, "ACCEPTED")
	}
	if env.RawLengthBytes != len(raw) {
		t.Errorf("raw_length_bytes = %d, want %d", env.RawLengthBytes, len(raw))
	}

	// Verify SHA-256.
	expectedHash := sha256.Sum256(raw)
	expectedHex := hex.EncodeToString(expectedHash[:])
	if env.RawSHA256 != expectedHex {
		t.Errorf("raw_sha256 = %q, want %q", env.RawSHA256, expectedHex)
	}
}

func TestNewRawEventEnvelope_EmptySourceID(t *testing.T) {
	_, err := NewRawEventEnvelope("", "http", []byte("data"), "ref")
	if err == nil {
		t.Fatal("expected error for empty source_id")
	}
}

func TestNewRawEventEnvelope_InvalidTransport(t *testing.T) {
	_, err := NewRawEventEnvelope("src", "invalid_transport", []byte("data"), "ref")
	if err == nil {
		t.Fatal("expected error for invalid transport")
	}
}

func TestNewRawEventEnvelope_EmptyBody(t *testing.T) {
	_, err := NewRawEventEnvelope("src", "http", []byte{}, "ref")
	if err == nil {
		t.Fatal("expected error for empty body")
	}
}

// --- Raw Store Tests ---

func TestLocalFSStore_StoreAndLoad(t *testing.T) {
	store := tempStore(t)
	raw := []byte(`<14>Sep 16 09:30:00 fw-01 src=10.0.0.5 dst=10.0.0.10 action=deny`)

	rawRef, err := store.Store("01TESTID0000000000000000AB", "src_demo_firewall", raw)
	if err != nil {
		t.Fatalf("Store error: %v", err)
	}

	// Verify raw_ref format.
	if !strings.HasPrefix(rawRef, "raw/") {
		t.Errorf("rawRef %q does not start with raw/", rawRef)
	}
	if !strings.HasSuffix(rawRef, "/01TESTID0000000000000000AB") {
		t.Errorf("rawRef %q does not end with event ID", rawRef)
	}

	// Byte-exact preservation: re-read and compare.
	loaded, err := store.Load(rawRef)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if !bytes.Equal(raw, loaded) {
		t.Errorf("loaded bytes differ from stored bytes")
	}
}

func TestLocalFSStore_Immutability(t *testing.T) {
	store := tempStore(t)
	raw := []byte("event data")

	_, err := store.Store("01TESTID0000000000000000AB", "src_test", raw)
	if err != nil {
		t.Fatalf("first Store: %v", err)
	}

	// Second store with same event_id must fail.
	_, err = store.Store("01TESTID0000000000000000AB", "src_test", raw)
	if err == nil {
		t.Fatal("expected error on duplicate store (immutability violation)")
	}
}

func TestLocalFSStore_ByteExactPreservation(t *testing.T) {
	store := tempStore(t)

	// Test with binary-like content including special characters.
	raw := []byte{0x00, 0x01, 0xFF, 0xFE, '\n', '\r', '\t', 0x80}
	rawRef, err := store.Store("01TESTID0000000000000000CD", "binary_src", raw)
	if err != nil {
		t.Fatalf("Store error: %v", err)
	}

	loaded, err := store.Load(rawRef)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if !bytes.Equal(raw, loaded) {
		t.Errorf("binary content not preserved byte-exact")
	}
}

func TestLocalFSStore_IdenticalBytesDistinctEvents(t *testing.T) {
	store := tempStore(t)
	raw := []byte("identical content")

	ref1, err := store.Store("01TESTID0000000000000000EF", "src_a", raw)
	if err != nil {
		t.Fatalf("Store 1: %v", err)
	}

	ref2, err := store.Store("01TESTID0000000000000000GH", "src_a", raw)
	if err != nil {
		t.Fatalf("Store 2: %v", err)
	}

	if ref1 == ref2 {
		t.Error("identical content with different event IDs should have different rawRefs")
	}

	// Both should produce the same SHA-256.
	hash := sha256.Sum256(raw)
	expectedHex := hex.EncodeToString(hash[:])

	env1, _ := NewRawEventEnvelope("src_a", "http", raw, ref1)
	env2, _ := NewRawEventEnvelope("src_a", "http", raw, ref2)

	if env1.RawSHA256 != expectedHex || env2.RawSHA256 != expectedHex {
		t.Error("identical raw bytes should produce the same SHA-256")
	}
}

// --- IngestService Tests ---

func TestIngestService_EndToEnd(t *testing.T) {
	store := tempStore(t)
	bus := NewInMemoryBus()
	svc := NewIngestService(store, bus)

	// Subscribe before ingesting.
	ch, unsub := bus.Subscribe(TopicRawEvents)
	defer unsub()

	raw := []byte(`<14>Sep 16 09:30:00 fw-01 src=10.0.0.5 dst=10.0.0.10 spt=51022 dpt=443 action=deny`)
	env, err := svc.Ingest("src_demo_firewall", "syslog_tcp", raw)
	if err != nil {
		t.Fatalf("Ingest error: %v", err)
	}

	// Validate envelope fields.
	if env.SchemaVersion != "1.0" {
		t.Errorf("schema_version = %q", env.SchemaVersion)
	}
	if !ulidPattern.MatchString(env.EventID) {
		t.Errorf("event_id %q is not a valid ULID", env.EventID)
	}
	if env.IngestStatus != "ACCEPTED" {
		t.Errorf("ingest_status = %q", env.IngestStatus)
	}
	if !rawRefPattern.MatchString(env.RawRef) {
		t.Errorf("raw_ref %q doesn't match expected pattern", env.RawRef)
	}

	// Verify raw bytes were stored correctly.
	loaded, err := store.Load(env.RawRef)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if !bytes.Equal(raw, loaded) {
		t.Error("stored bytes differ from input")
	}

	// Verify SHA-256.
	hash := sha256.Sum256(raw)
	if env.RawSHA256 != hex.EncodeToString(hash[:]) {
		t.Error("SHA-256 mismatch")
	}

	// Verify event bus received the envelope.
	select {
	case received := <-ch:
		if received.EventID != env.EventID {
			t.Errorf("bus envelope event_id = %q, want %q", received.EventID, env.EventID)
		}
	default:
		t.Error("event bus did not receive the envelope")
	}
}

func TestIngestService_EmptySourceID(t *testing.T) {
	store := tempStore(t)
	svc := NewIngestService(store, nil)

	_, err := svc.Ingest("", "http", []byte("data"))
	if err == nil {
		t.Fatal("expected error for empty source_id")
	}
}

func TestIngestService_EmptyBody(t *testing.T) {
	store := tempStore(t)
	svc := NewIngestService(store, nil)

	_, err := svc.Ingest("src", "http", []byte{})
	if err == nil {
		t.Fatal("expected error for empty body")
	}
}

// --- Contract Compliance Test ---

func TestEnvelope_MatchesContractSchema(t *testing.T) {
	// Load the golden fixture and validate that a produced envelope
	// has the same structure and types.
	store := tempStore(t)
	bus := NewInMemoryBus()
	svc := NewIngestService(store, bus)

	raw := []byte(`<14>Sep 16 09:30:00 fw-01 src=10.0.0.5 dst=10.0.0.10 action=deny`)
	env, err := svc.Ingest("src_demo_firewall", "syslog_tcp", raw)
	if err != nil {
		t.Fatalf("Ingest error: %v", err)
	}

	// Serialize to JSON and re-parse to verify field names.
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("JSON marshal error: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	// Required fields per raw_event_envelope.schema.json.
	requiredFields := []string{
		"schema_version", "event_id", "source_id", "received_at",
		"transport", "raw_ref", "raw_sha256", "raw_length_bytes",
		"ingest_status",
	}
	for _, field := range requiredFields {
		if _, ok := m[field]; !ok {
			t.Errorf("missing required contract field: %s", field)
		}
	}

	// No extra fields allowed (additionalProperties: false).
	contractFields := map[string]bool{
		"schema_version": true, "event_id": true, "source_id": true,
		"received_at": true, "transport": true, "raw_ref": true,
		"raw_sha256": true, "raw_length_bytes": true, "ingest_status": true,
	}
	for key := range m {
		if !contractFields[key] {
			t.Errorf("unexpected field in envelope: %q (additionalProperties: false)", key)
		}
	}

	// Validate enum values.
	if m["schema_version"] != "1.0" {
		t.Errorf("schema_version must be 1.0")
	}
	validStatuses := map[string]bool{"ACCEPTED": true, "QUARANTINED": true, "REJECTED": true}
	if !validStatuses[m["ingest_status"].(string)] {
		t.Errorf("invalid ingest_status: %v", m["ingest_status"])
	}

	// Validate SHA-256 pattern.
	sha256Pattern := regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
	if !sha256Pattern.MatchString(m["raw_sha256"].(string)) {
		t.Errorf("raw_sha256 does not match pattern")
	}
}

// --- Golden Fixture Validation ---

func TestGoldenFixtureContract(t *testing.T) {
	// Find the repo root by walking up from the test binary location.
	// In Go tests, the working directory is the package directory.
	goldenPath := filepath.Join("..", "..", "fixtures", "contracts", "raw_event_envelope.example.json")
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Skipf("golden fixture not found at %s: %v (run from repo root)", goldenPath, err)
	}

	var fixture map[string]interface{}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("invalid JSON in golden fixture: %v", err)
	}

	// Verify fixture has all required contract fields (minus $schema).
	requiredFields := []string{
		"schema_version", "event_id", "source_id", "received_at",
		"transport", "raw_ref", "raw_sha256", "raw_length_bytes",
		"ingest_status",
	}
	for _, field := range requiredFields {
		if _, ok := fixture[field]; !ok {
			t.Errorf("golden fixture missing required field: %s", field)
		}
	}
}
