package main

import (
	"sync"
	"testing"
	"time"
)

func TestInMemoryBus_PublishSubscribe(t *testing.T) {
	bus := NewInMemoryBus()
	ch, unsub := bus.Subscribe(TopicRawEvents)
	defer unsub()

	env := RawEventEnvelope{
		SchemaVersion:  "1.0",
		EventID:        "01TESTID0000000000000000AB",
		SourceID:       "test_source",
		ReceivedAt:     "2026-09-16T09:30:00Z",
		Transport:      "http",
		RawRef:         "raw/2026/09/16/test_source/01TESTID0000000000000000AB",
		RawSHA256:      "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		RawLengthBytes: 42,
		IngestStatus:   "ACCEPTED",
	}

	if err := bus.Publish(TopicRawEvents, env); err != nil {
		t.Fatalf("Publish error: %v", err)
	}

	select {
	case received := <-ch:
		if received.EventID != env.EventID {
			t.Errorf("received event_id = %q, want %q", received.EventID, env.EventID)
		}
		if received.SourceID != env.SourceID {
			t.Errorf("received source_id = %q, want %q", received.SourceID, env.SourceID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for message")
	}
}

func TestInMemoryBus_MultipleSubscribers(t *testing.T) {
	bus := NewInMemoryBus()

	ch1, unsub1 := bus.Subscribe(TopicRawEvents)
	defer unsub1()
	ch2, unsub2 := bus.Subscribe(TopicRawEvents)
	defer unsub2()

	env := RawEventEnvelope{
		SchemaVersion: "1.0",
		EventID:       "01TESTID0000000000000000CD",
		IngestStatus:  "ACCEPTED",
	}

	if err := bus.Publish(TopicRawEvents, env); err != nil {
		t.Fatalf("Publish error: %v", err)
	}

	// Both subscribers should receive the message.
	for i, ch := range []<-chan RawEventEnvelope{ch1, ch2} {
		select {
		case received := <-ch:
			if received.EventID != env.EventID {
				t.Errorf("subscriber %d: event_id = %q, want %q", i, received.EventID, env.EventID)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timed out waiting for message", i)
		}
	}
}

func TestInMemoryBus_Unsubscribe(t *testing.T) {
	bus := NewInMemoryBus()
	ch, unsub := bus.Subscribe(TopicRawEvents)

	// Unsubscribe before publish.
	unsub()

	env := RawEventEnvelope{EventID: "01TESTID0000000000000000EF"}
	bus.Publish(TopicRawEvents, env)

	// Channel should be closed, not receive the message.
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("received message after unsubscribe")
		}
	default:
		// Channel is closed — correct behavior.
	}
}

func TestInMemoryBus_NoSubscribers(t *testing.T) {
	bus := NewInMemoryBus()

	// Publishing with no subscribers should not error.
	env := RawEventEnvelope{EventID: "01TESTID0000000000000000GH"}
	if err := bus.Publish(TopicRawEvents, env); err != nil {
		t.Fatalf("Publish with no subscribers should not error: %v", err)
	}
}

func TestInMemoryBus_ConcurrentPublish(t *testing.T) {
	bus := NewInMemoryBus()
	ch, unsub := bus.Subscribe(TopicRawEvents)
	defer unsub()

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			env := RawEventEnvelope{
				SchemaVersion: "1.0",
				EventID:       "01TESTID0000000000000000AB",
				IngestStatus:  "ACCEPTED",
			}
			bus.Publish(TopicRawEvents, env)
		}(i)
	}

	wg.Wait()

	// Drain and count received messages.
	received := 0
	for {
		select {
		case <-ch:
			received++
		default:
			goto done
		}
	}
done:
	if received == 0 {
		t.Error("expected at least some messages from concurrent publish")
	}
}
