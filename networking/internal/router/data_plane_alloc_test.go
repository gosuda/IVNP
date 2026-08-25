package router

import (
	"testing"

	"gosuda.org/ivnp/foundation"
	streamingtunnel "gosuda.org/ivnp/networking/internal/streaming/tunnel"
)

func TestStreamingDestinationFramingHasZeroAllocations(t *testing.T) {
	var nextID uint32
	sender := &StreamingTunnelSender{nextID: func() (uint32, error) {
		nextID++
		return nextID, nil
	}}
	delivery := streamingtunnel.Delivery{
		From: foundation.Hash{1}, To: foundation.Hash{2}, Protocol: streamingtunnel.ProtocolStreaming,
		FromPort: 1234, ToPort: 4321, Payload: []byte("prewarmed streaming frame"),
	}
	set := make([]byte, 1024)
	data := make([]byte, 1024)
	if _, err := sender.destinationCloveSetTo(set, data, delivery, 10_000); err != nil {
		t.Fatal(err)
	}
	var frameErr error
	allocations := testing.AllocsPerRun(1000, func() {
		_, frameErr = sender.destinationCloveSetTo(set, data, delivery, 10_000)
	})
	if frameErr != nil {
		t.Fatal(frameErr)
	}
	if allocations != 0 {
		t.Fatalf("destination framing allocations = %v, want 0", allocations)
	}
}
