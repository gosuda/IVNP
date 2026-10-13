package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func tunnelReplayMessage(tunnelID uint32) foundation.I2NPMessage {
	payload := make([]byte, foundation.I2NPTunnelDataMessageLen)
	binary.BigEndian.PutUint32(payload[:4], tunnelID)
	for index := range 32 {
		payload[4+index] = byte(index + 1)
	}
	return foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPTunnelData, ID: 1, Expiration: 1000},
		Payload: payload,
	}
}

func TestRuntimeRejectsTransitReplayInFreshI2NPEnvelope(t *testing.T) {
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return 100 }})
	if _, err := runtime.RegisterInbound(InboundCircuit{ID: 33, Forward: &Forward{TunnelID: 34}}); err != nil {
		t.Fatal(err)
	}
	message := tunnelReplayMessage(33)
	if err := runtime.Handle(message); err != nil {
		t.Fatal(err)
	}
	message.Header.ID++
	message.Header.Expiration++
	if err := runtime.Handle(message); !errors.Is(err, ErrTunnelReplay) {
		t.Fatalf("replay with fresh header = %v, want ErrTunnelReplay", err)
	}
	if sent := sender.take(); len(sent) != 1 {
		t.Fatalf("forwarded cells = %d, want 1", len(sent))
	}
}

func TestRuntimeRejectsEndpointReplayInFreshI2NPEnvelope(t *testing.T) {
	producerSender := new(captureTunnelSender)
	producer := NewRuntime(RuntimeConfig{Sender: producerSender, Now: func() uint64 { return 100 }})
	if _, err := producer.RegisterOutbound(OutboundCircuit{ID: 1, NextTunnelID: 77}); err != nil {
		t.Fatal(err)
	}
	if err := producer.SendBlock(context.Background(), 1, Block{Delivery: DeliveryLocal, Last: true, Data: deliveryStatusFrame(t, 9)}); err != nil {
		t.Fatal(err)
	}
	produced := producerSender.take()
	if len(produced) != 1 {
		t.Fatalf("produced cells = %d, want 1", len(produced))
	}

	deliveries := 0
	runtime := NewRuntime(RuntimeConfig{Now: func() uint64 { return 100 }})
	if _, err := runtime.RegisterInbound(InboundCircuit{
		ID: 77, Endpoint: NewEndpoint(8, 4096),
		Local: func(foundation.I2NPMessage) error { deliveries++; return nil },
	}); err != nil {
		t.Fatal(err)
	}
	message := produced[0].message
	if err := runtime.Handle(message); err != nil {
		t.Fatal(err)
	}
	message.Header.ID++
	message.Header.Expiration++
	if err := runtime.Handle(message); !errors.Is(err, ErrTunnelReplay) {
		t.Fatalf("endpoint replay = %v, want ErrTunnelReplay", err)
	}
	if deliveries != 1 {
		t.Fatalf("local deliveries = %d, want 1", deliveries)
	}
}

func TestRuntimeTunnelReplayScopedToCircuitAndGeneration(t *testing.T) {
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender})
	first, err := runtime.RegisterInbound(InboundCircuit{ID: 40, Forward: &Forward{TunnelID: 42}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RegisterInbound(InboundCircuit{ID: 41, Forward: &Forward{TunnelID: 43}}); err != nil {
		t.Fatal(err)
	}
	message := tunnelReplayMessage(40)
	if err := runtime.Handle(message); err != nil {
		t.Fatal(err)
	}
	other := tunnelReplayMessage(41)
	copy(other.Payload[4:], message.Payload[4:])
	if err := runtime.Handle(other); err != nil {
		t.Fatalf("same ciphertext in other circuit = %v", err)
	}
	if _, err := runtime.ReplaceInbound(first, InboundCircuit{ID: 40, Forward: &Forward{TunnelID: 42}}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Handle(message); err != nil {
		t.Fatalf("same ciphertext in new generation = %v", err)
	}
	if sent := sender.take(); len(sent) != 3 {
		t.Fatalf("forwarded cells = %d, want 3", len(sent))
	}
}

func TestRuntimeConcurrentReplayAdmitsOnlyOneCell(t *testing.T) {
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender})
	if _, err := runtime.RegisterInbound(InboundCircuit{ID: 55, Forward: &Forward{TunnelID: 56}}); err != nil {
		t.Fatal(err)
	}
	message := tunnelReplayMessage(55)
	const copies = 32
	var workers sync.WaitGroup
	results := make(chan error, copies)
	for i := range copies {
		workers.Add(1)
		go func() {
			defer workers.Done()
			copy := message
			copy.Header.ID += uint32(i)
			results <- runtime.Handle(copy)
		}()
	}
	workers.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrTunnelReplay) {
			t.Fatalf("unexpected concurrent replay error: %v", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted cells = %d, want 1", accepted)
	}
	if sent := sender.take(); len(sent) != 1 {
		t.Fatalf("forwarded cells = %d, want 1", len(sent))
	}
}
