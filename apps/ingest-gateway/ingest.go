package main

import (
	"fmt"
)

// IngestService orchestrates the raw event ingest pipeline:
//
//  1. Receive raw bytes + metadata (source_id, transport).
//  2. Store raw bytes immutably via RawStore.
//  3. Build a RawEventEnvelope (SHA-256, ULID, byte length).
//  4. Publish the envelope to the EventBus.
//
// No telemetry firewall (Stage 2) or parsing (Stage 3) is applied.
// All events receive ingest_status = ACCEPTED.
type IngestService struct {
	store RawStore
	bus   EventBus
}

// NewIngestService creates a new IngestService.
func NewIngestService(store RawStore, bus EventBus) *IngestService {
	return &IngestService{store: store, bus: bus}
}

// Ingest processes a raw event: store → envelope → publish.
// Returns the constructed RawEventEnvelope for the HTTP response.
func (s *IngestService) Ingest(sourceID, transport string, rawBytes []byte) (*RawEventEnvelope, error) {
	if sourceID == "" {
		return nil, fmt.Errorf("source_id is required")
	}
	if len(rawBytes) == 0 {
		return nil, fmt.Errorf("raw event body is required")
	}

	// Build a temporary envelope to get the event ID and raw_ref.
	// We need the event ID before we can compute the storage path.
	envelope, err := NewRawEventEnvelope(sourceID, transport, rawBytes, "" /* rawRef set below */)
	if err != nil {
		return nil, fmt.Errorf("building envelope: %w", err)
	}

	// Store raw bytes immutably.
	rawRef, err := s.store.Store(envelope.EventID, sourceID, rawBytes)
	if err != nil {
		return nil, fmt.Errorf("storing raw event: %w", err)
	}
	envelope.RawRef = rawRef

	// Publish to event bus.
	if s.bus != nil {
		if err := s.bus.Publish(TopicRawEvents, *envelope); err != nil {
			// Log but don't fail the ingest — raw bytes are already safely stored.
			// Future: add structured logging.
			fmt.Printf("WARN: failed to publish envelope %s: %v\n", envelope.EventID, err)
		}
	}

	return envelope, nil
}
