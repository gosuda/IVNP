package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func replayTestMessage(t *testing.T, tunnelID uint32) foundation.I2NPMessage {
	t.Helper()
	sender := new(captureTunnelSender)
	gateway := NewGateway(bytes.NewReader(bytes.Repeat([]byte{7}, foundation.I2NPTunnelDataMessageLen)))
	producer := NewRuntime(RuntimeConfig{Sender: sender, Gateway: gateway, Now: func() uint64 { return 100 }})
	if _, err := producer.RegisterOutbound(OutboundCircuit{ID: 1, NextTunnelID: tunnelID}); err != nil {
		t.Fatal(err)
	}
	if err := producer.SendBlock(context.Background(), 1, Block{Delivery: DeliveryLocal, Last: true, Data: deliveryStatusFrame(t, 9)}); err != nil {
		t.Fatal(err)
	}
	messages := sender.take()
	if len(messages) != 1 {
		t.Fatalf("produced %d tunnel cells, want 1", len(messages))
	}
	return messages[0].message
}

func TestRuntimeRejectsRewrappedTunnelCell(t *testing.T) {
	for _, test := range []struct {
		name    string
		transit bool
	}{
		{name: "transit", transit: true},
		{name: "endpoint"},
	} {
		t.Run(test.name, func(t *testing.T) {
			incoming := replayTestMessage(t, 77)
			sender := new(captureTunnelSender)
			runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return 100 }})
			var delivered int
			circuit := InboundCircuit{ID: 77}
			if test.transit {
				circuit.Forward = &Forward{Peer: foundation.Hash{2}, TunnelID: 78}
			} else {
				circuit.Endpoint = NewEndpoint(8, 4096)
				circuit.Local = func(foundation.I2NPMessage) error { delivered++; return nil }
			}
			if _, err := runtime.RegisterInbound(circuit); err != nil {
				t.Fatal(err)
			}
			if err := runtime.Handle(incoming); err != nil {
				t.Fatalf("first cell = %v", err)
			}
			for index := range 3 {
				replay := incoming
				replay.Header.ID += uint32(index + 1)
				replay.Header.Expiration += uint64(index + 1)
				if err := runtime.Handle(replay); !errors.Is(err, ErrTunnelReplay) {
					t.Fatalf("rewrapped cell %d = %v, want ErrTunnelReplay", index, err)
				}
			}
			forwarded := len(sender.take())
			if test.transit {
				if forwarded != 1 {
					t.Fatalf("forwarded %d cells, want 1", forwarded)
				}
			} else if delivered != 1 || forwarded != 0 {
				t.Fatalf("endpoint delivered %d cells and forwarded %d, want 1 and 0", delivered, forwarded)
			}
		})
	}
}

func TestRuntimeReplayStateScopedToCircuitGeneration(t *testing.T) {
	incoming := replayTestMessage(t, 77)
	runtime := NewRuntime(RuntimeConfig{Now: func() uint64 { return 100 }})
	var firstDelivered, nextDelivered, otherDelivered int
	firstToken, err := runtime.RegisterInbound(InboundCircuit{
		ID: 77, Endpoint: NewEndpoint(8, 4096),
		Local: func(foundation.I2NPMessage) error { firstDelivered++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RegisterInbound(InboundCircuit{
		ID: 78, Endpoint: NewEndpoint(8, 4096),
		Local: func(foundation.I2NPMessage) error { otherDelivered++; return nil },
	}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Handle(incoming); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Handle(incoming); !errors.Is(err, ErrTunnelReplay) {
		t.Fatalf("repeated cell = %v", err)
	}

	// Identical ciphertext belongs to an independent replay domain on ID 78.
	other := incoming
	other.Payload = append([]byte(nil), incoming.Payload...)
	binary.BigEndian.PutUint32(other.Payload[:4], 78)
	if err := runtime.Handle(other); err != nil {
		t.Fatalf("different circuit = %v", err)
	}

	// Replacing ID 77 creates a fresh generation, not a reopened replay window
	// in the previous generation.
	nextToken, err := runtime.ReplaceInbound(firstToken, InboundCircuit{
		ID: 77, Endpoint: NewEndpoint(8, 4096),
		Local: func(foundation.I2NPMessage) error { nextDelivered++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.RemoveCircuit(firstToken) {
		t.Fatal("stale circuit token removed the new generation")
	}
	if err := runtime.Handle(incoming); err != nil {
		t.Fatalf("new circuit generation = %v", err)
	}
	if err := runtime.Handle(incoming); !errors.Is(err, ErrTunnelReplay) {
		t.Fatalf("new generation replay = %v", err)
	}
	if firstDelivered != 1 || otherDelivered != 1 || nextDelivered != 1 {
		t.Fatalf("deliveries across generations: original=%d other=%d replacement=%d", firstDelivered, otherDelivered, nextDelivered)
	}
	if !runtime.RemoveCircuit(nextToken) {
		t.Fatal("failed to remove live replacement")
	}
}

func TestRuntimeConcurrentRewrappedTunnelCell(t *testing.T) {
	incoming := replayTestMessage(t, 77)
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return 100 }})
	if _, err := runtime.RegisterInbound(InboundCircuit{ID: 77, Forward: &Forward{Peer: foundation.Hash{2}, TunnelID: 78}}); err != nil {
		t.Fatal(err)
	}
	const workers = 64
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for index := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			replay := incoming
			replay.Header.ID += uint32(index)
			results <- runtime.Handle(replay)
		}()
	}
	wg.Wait()
	close(results)
	var admitted, rejected int
	for err := range results {
		switch {
		case err == nil:
			admitted++
		case errors.Is(err, ErrTunnelReplay):
			rejected++
		default:
			t.Fatalf("unexpected concurrent receive error: %v", err)
		}
	}
	if admitted != 1 || rejected != workers-1 || len(sender.take()) != 1 {
		t.Fatalf("concurrent cells: admitted=%d rejected=%d", admitted, rejected)
	}
}

func TestCellReplayFilterFailsClosedWhenFull(t *testing.T) {
	var filter cellReplayFilter
	if filter.seen([]byte("initial cell")) || !filter.seen([]byte("initial cell")) {
		t.Fatal("first cell should be admitted exactly once")
	}
	if len(filter.words) != cellReplayWords || cap(filter.words) != cellReplayWords {
		t.Fatalf("filter storage length %d, capacity %d", len(filter.words), cap(filter.words))
	}
	// Exhaust every bit; the filter must never evict entries or grow.
	for index := range filter.words {
		filter.words[index] = ^uint64(0)
	}
	if !filter.seen([]byte("new cell after saturation")) {
		t.Fatal("full replay filter admitted a new cell")
	}
	if len(filter.words) != cellReplayWords || cap(filter.words) != cellReplayWords {
		t.Fatalf("full filter changed size: length %d, capacity %d", len(filter.words), cap(filter.words))
	}
}
