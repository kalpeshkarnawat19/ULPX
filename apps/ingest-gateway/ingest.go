package main

import (
	"context"
	"fmt"
)

// IngestService orchestrates the raw event ingest pipeline:
//
//  1. Receive raw bytes + metadata (source_id, transport).
//  2. Evaluate deterministic Telemetry Firewall safety gates (Stage 2).
//  3. Store raw bytes immutably via RawStore (never lose raw evidence).
//  4. Build a RawEventEnvelope (SHA-256, ULID, byte length, IngestStatus).
//  5. Publish the envelope to the EventBus (TopicRawEvents or TopicQuarantinedEvents).
type IngestService struct {
	store    RawStore
	bus      EventBus
	firewall *TelemetryFirewall
}

// NewIngestService creates a new IngestService with the default Telemetry Firewall.
func NewIngestService(store RawStore, bus EventBus) *IngestService {
	return NewIngestServiceWithFirewall(store, bus, NewTelemetryFirewall(DefaultFirewallConfig()))
}

// NewIngestServiceWithFirewall creates an IngestService with a custom Telemetry Firewall.
func NewIngestServiceWithFirewall(store RawStore, bus EventBus, fw *TelemetryFirewall) *IngestService {
	if fw == nil {
		fw = NewTelemetryFirewall(DefaultFirewallConfig())
	}
	return &IngestService{
		store:    store,
		bus:      bus,
		firewall: fw,
	}
}

// Ingest processes a raw event: firewall → store → envelope → publish.
// Returns the constructed RawEventEnvelope.
func (s *IngestService) Ingest(sourceID, transport string, rawBytes []byte) (*RawEventEnvelope, error) {
	envelope, _, err := s.IngestWithContext(context.Background(), sourceID, transport, rawBytes)
	return envelope, err
}

// IngestWithContext processes a raw event with contextual timeout and returns both
// the envelope and the detailed FirewallDecision.
func (s *IngestService) IngestWithContext(ctx context.Context, sourceID, transport string, rawBytes []byte) (*RawEventEnvelope, FirewallDecision, error) {
	if sourceID == "" {
		return nil, FirewallDecision{}, fmt.Errorf("source_id is required")
	}
	if len(rawBytes) == 0 {
		return nil, FirewallDecision{}, fmt.Errorf("raw event body is required")
	}

	// 1. Evaluate untrusted input through Telemetry Firewall
	decision := s.firewall.Inspect(ctx, rawBytes)

	// 2. Build envelope with assigned IngestStatus (ACCEPTED or QUARANTINED)
	envelope, err := NewRawEventEnvelopeWithStatus(sourceID, transport, rawBytes, "", decision.Status)
	if err != nil {
		return nil, decision, fmt.Errorf("building envelope: %w", err)
	}

	// 3. Store raw bytes immutably — raw bytes are NEVER discarded, even if quarantined
	rawRef, err := s.store.Store(envelope.EventID, sourceID, rawBytes)
	if err != nil {
		return nil, decision, fmt.Errorf("storing raw event: %w", err)
	}
	envelope.RawRef = rawRef

	// 4. Publish to event bus on appropriate topic
	if s.bus != nil {
		topic := TopicRawEvents
		switch decision.Status {
		case StatusQuarantined:
			topic = TopicQuarantinedEvents
		case StatusRejected:
			topic = TopicRejectedEvents
		}

		if err := s.bus.Publish(topic, *envelope); err != nil {
			fmt.Printf("WARN: failed to publish envelope %s to %s: %v\n", envelope.EventID, topic, err)
		}
	}

	return envelope, decision, nil
}
