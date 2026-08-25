package router

import (
	"context"
	"sync"
	"testing"

	clientapi "gosuda.org/ivnp/contracts/destination"
	streamtunnel "gosuda.org/ivnp/networking/internal/streaming/tunnel"
)

type testByteBudget struct {
	mu    sync.Mutex
	limit int
	used  int
}

func (b *testByteBudget) TryReserve(size int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if size < 0 || b.used > b.limit-size {
		return false
	}
	b.used += size
	return true
}
func (b *testByteBudget) Release(size int) {
	b.mu.Lock()
	b.used -= size
	b.mu.Unlock()
}

func TestDestinationRoutesEnforcePerSessionAndSharedByteBudgets(t *testing.T) {
	shared := &testByteBudget{limit: 4}
	first := &destinationSubscription{route: clientapi.DestinationRoute{Protocol: 18}, messages: make(chan *clientapi.ReceivedMessage, 2), done: make(chan struct{}), maxBytes: 3, shared: shared}
	second := &destinationSubscription{route: clientapi.DestinationRoute{Protocol: 18}, messages: make(chan *clientapi.ReceivedMessage, 2), done: make(chan struct{}), maxBytes: 3, shared: shared}
	if err := first.enqueue(streamtunnel.Delivery{Payload: []byte("abc")}); err != nil {
		t.Fatal(err)
	}
	if err := first.enqueue(streamtunnel.Delivery{Payload: []byte("d")}); err != ErrDestinationBackpressure {
		t.Fatalf("per-route budget = %v", err)
	}
	if err := second.enqueue(streamtunnel.Delivery{Payload: []byte("xy")}); err != ErrDestinationBackpressure {
		t.Fatalf("shared budget = %v", err)
	}
	message, err := first.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	message.Release()
	if err = second.enqueue(streamtunnel.Delivery{Payload: []byte("xy")}); err != nil {
		t.Fatal(err)
	}
	second.close(false)
	shared.mu.Lock()
	used := shared.used
	shared.mu.Unlock()
	if used != 0 {
		t.Fatalf("close retained %d shared queued bytes", used)
	}
}
