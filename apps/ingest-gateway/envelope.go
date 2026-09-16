// Package main implements the ULPF-X ingest gateway.
//
// Stage 1: Ingest / Raw Preservation
// Receives raw security-log events, computes SHA-256 identity,
// preserves raw bytes immutably, and emits a RawEventEnvelope
// conforming to the Stage 0 contract.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// RawEventEnvelope matches the packages/contracts/raw_event_envelope.schema.json
// contract (version 1.0). Field names use JSON tags matching the contract exactly.
type RawEventEnvelope struct {
	SchemaVersion  string `json:"schema_version"`
	EventID        string `json:"event_id"`
	SourceID       string `json:"source_id"`
	ReceivedAt     string `json:"received_at"`
	Transport      string `json:"transport"`
	RawRef         string `json:"raw_ref"`
	RawSHA256      string `json:"raw_sha256"`
	RawLengthBytes int    `json:"raw_length_bytes"`
	IngestStatus   string `json:"ingest_status"`
}

// validTransports is the enum defined in the contract.
var validTransports = map[string]bool{
	"syslog_tcp": true,
	"syslog_udp": true,
	"http":       true,
	"file":       true,
	"agent":      true,
	"unknown":    true,
}

// NewRawEventEnvelope constructs a RawEventEnvelope from raw event bytes.
// It generates a ULID, computes SHA-256, records byte length, and builds
// the raw_ref storage path. The ingest_status is always ACCEPTED at this
// stage (Telemetry Firewall is Stage 2).
func NewRawEventEnvelope(sourceID, transport string, rawBytes []byte, rawRef string) (*RawEventEnvelope, error) {
	if sourceID == "" {
		return nil, fmt.Errorf("source_id must not be empty")
	}
	if !validTransports[transport] {
		return nil, fmt.Errorf("invalid transport %q", transport)
	}
	if len(rawBytes) == 0 {
		return nil, fmt.Errorf("raw event bytes must not be empty")
	}

	eventID, err := generateULID()
	if err != nil {
		return nil, fmt.Errorf("generating event ID: %w", err)
	}

	hash := sha256.Sum256(rawBytes)

	return &RawEventEnvelope{
		SchemaVersion:  "1.0",
		EventID:        eventID,
		SourceID:       sourceID,
		ReceivedAt:     time.Now().UTC().Format(time.RFC3339),
		Transport:      transport,
		RawRef:         rawRef,
		RawSHA256:      hex.EncodeToString(hash[:]),
		RawLengthBytes: len(rawBytes),
		IngestStatus:   "ACCEPTED",
	}, nil
}

// generateULID creates a new ULID using crypto/rand for entropy.
func generateULID() (string, error) {
	id, err := ulid.New(ulid.Timestamp(time.Now()), rand.Reader)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// ToJSON serializes the envelope to indented JSON.
func (e *RawEventEnvelope) ToJSON() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}
