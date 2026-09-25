package main

import (
	"fmt"
	"sync"
)

// EventBus defines a publish/subscribe interface for RawEventEnvelopes.
// Stage 1 uses InMemoryBus; future stages may swap in Kafka/Redpanda.
type EventBus interface {
	// Publish sends an envelope to all subscribers of the given topic.
	Publish(topic string, envelope RawEventEnvelope) error

	// Subscribe registers a channel to receive envelopes for a topic.
	// Returns an unsubscribe function.
	Subscribe(topic string) (<-chan RawEventEnvelope, func())
}

// InMemoryBus implements EventBus using Go channels.
// Suitable for development and testing.
type InMemoryBus struct {
	mu          sync.RWMutex
	subscribers map[string]map[int]chan RawEventEnvelope
	nextID      int
}

// NewInMemoryBus creates a new InMemoryBus.
func NewInMemoryBus() *InMemoryBus {
	return &InMemoryBus{
		subscribers: make(map[string]map[int]chan RawEventEnvelope),
	}
}

// Publish sends the envelope to all subscribers of the topic.
// Non-blocking: if a subscriber's channel buffer is full, the
// message is dropped for that subscriber (prevents slow consumers
// from blocking the hot path).
func (b *InMemoryBus) Publish(topic string, envelope RawEventEnvelope) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	subs, ok := b.subscribers[topic]
	if !ok {
		return nil // no subscribers — valid, just nothing to do
	}

	for _, ch := range subs {
		select {
		case ch <- envelope:
		default:
			// Drop message for slow consumer rather than blocking hot path.
		}
	}
	return nil
}

// Subscribe returns a channel that receives envelopes for the topic
// and an unsubscribe function. The channel is buffered (capacity 64).
func (b *InMemoryBus) Subscribe(topic string) (<-chan RawEventEnvelope, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.subscribers[topic] == nil {
		b.subscribers[topic] = make(map[int]chan RawEventEnvelope)
	}

	id := b.nextID
	b.nextID++
	ch := make(chan RawEventEnvelope, 64)
	b.subscribers[topic][id] = ch

	unsub := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		delete(b.subscribers[topic], id)
		close(ch)
	}

	return ch, unsub
}

// TopicRawEvents is the canonical topic name for accepted raw event envelopes.
const TopicRawEvents = "raw_events"

// TopicQuarantinedEvents is the topic name for quarantined event envelopes.
const TopicQuarantinedEvents = "quarantined_events"

// TopicRejectedEvents is the topic name for rejected event envelopes.
const TopicRejectedEvents = "rejected_events"

// MustPublish is a convenience wrapper that panics on error.
// Only for use in contexts where publish failure is unrecoverable.
func MustPublish(bus EventBus, envelope RawEventEnvelope) {
	if err := bus.Publish(TopicRawEvents, envelope); err != nil {
		panic(fmt.Sprintf("failed to publish raw event: %v", err))
	}
}
