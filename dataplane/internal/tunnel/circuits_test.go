package tunnel

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"gosuda.org/ivnp/foundation"
)

type gatedCircuitSender struct {
	captureTunnelSender
	once    sync.Once
	entered chan struct{}
	resume  chan struct{}
}

func (s *gatedCircuitSender) Send(ctx context.Context, peer foundation.Hash, message foundation.I2NPMessage) error {
	s.once.Do(func() {
		close(s.entered)
		<-s.resume
	})
	return s.captureTunnelSender.Send(ctx, peer, message)
}

func TestCircuitRetirementPinsFragmentedGeneration(t *testing.T) {
	for _, operation := range []string{"replace", "remove", "owner", "expire"} {
		t.Run(operation, func(t *testing.T) {
			var now atomic.Uint64
			now.Store(100)
			sender := &gatedCircuitSender{entered: make(chan struct{}), resume: make(chan struct{})}
			runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: now.Load})
			owner := foundation.Hash{7}
			layer, iv := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
			encryptor, err := NewLayerEncryptor(layer, iv)
			if err != nil {
				t.Fatal(err)
			}
			decryptor, err := NewLayerDecryptor(layer, iv)
			if err != nil {
				t.Fatal(err)
			}
			original := OutboundCircuit{ID: 1, Owner: owner, FirstHop: foundation.Hash{8}, NextTunnelID: 2, Transforms: []LayerCipher{encryptor}, ExpiresAt: 200}
			token, err := runtime.RegisterOutbound(original)
			if err != nil {
				t.Fatal(err)
			}
			message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPData, ID: 9, Expiration: 1000}, Payload: bytes.Repeat([]byte{42}, 5000)}
			frame := make([]byte, message.EncodedLen())
			if _, err := message.MarshalTo(frame); err != nil {
				t.Fatal(err)
			}
			block := Block{Delivery: DeliveryLocal, Last: true, Data: frame}
			finished := make(chan error, 1)
			var unblock sync.Once
			var join sync.Once
			var sendErr error
			wait := func() { join.Do(func() { sendErr = <-finished }) }
			t.Cleanup(func() { unblock.Do(func() { close(sender.resume) }); wait() })
			go func() { finished <- runtime.SendBlockPrepared(context.Background(), token, block) }()
			<-sender.entered
			replacement := OutboundCircuit{ID: 1, Owner: owner, FirstHop: foundation.Hash{9}, NextTunnelID: 3, ExpiresAt: 300}
			var current CircuitToken
			switch operation {
			case "replace":
				current, err = runtime.ReplaceOutbound(token, replacement)
			case "remove":
				if !runtime.RemoveCircuit(token) {
					t.Fatal("live token did not retire circuit")
				}
			case "owner":
				runtime.RemoveOwner(owner)
			case "expire":
				now.Store(200)
				if err := runtime.SendBlockPrepared(context.Background(), token, block); !errors.Is(err, ErrCircuitExpired) {
					t.Fatalf("deadline send = %v, want expired", err)
				}
				if removed := runtime.Expire(200); removed != 1 {
					t.Fatalf("expired = %d, want 1", removed)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if operation != "replace" {
				current, err = runtime.RegisterOutbound(replacement)
				if err != nil {
					t.Fatal(err)
				}
			}
			if runtime.RemoveCircuit(token) {
				t.Fatal("stale token removed replacement")
			}
			if err := runtime.SendBlockPrepared(context.Background(), token, block); !errors.Is(err, ErrCircuitNotFound) {
				t.Fatalf("stale prepared send = %v, want not found", err)
			}
			unblock.Do(func() { close(sender.resume) })
			wait()
			if sendErr != nil {
				t.Fatalf("pinned send failed: %v", sendErr)
			}
			var delivered []byte
			endpoint := NewRuntime(RuntimeConfig{Now: now.Load})
			if _, err := endpoint.RegisterInbound(InboundCircuit{ID: 2, Transforms: []LayerCipher{decryptor}, Endpoint: NewEndpoint(8, 8192), Local: func(got foundation.I2NPMessage) error { delivered = append([]byte(nil), got.Payload...); return nil }}); err != nil {
				t.Fatal(err)
			}
			for _, sent := range sender.take() {
				if sent.peer != original.FirstHop {
					t.Fatalf("retired flight changed peer to %x", sent.peer)
				}
				if err := endpoint.Handle(sent.message); err != nil {
					t.Fatalf("retired flight corrupted: %v", err)
				}
			}
			if !bytes.Equal(delivered, message.Payload) {
				t.Fatal("retirement interrupted fragmented delivery")
			}
			if err := runtime.SendBlockPrepared(context.Background(), current, Block{Delivery: DeliveryLocal, Last: true, Data: deliveryStatusFrame(t, 1)}); err != nil {
				t.Fatal(err)
			}
			sent := sender.take()
			if len(sent) != 1 || sent[0].peer != replacement.FirstHop {
				t.Fatalf("replacement route = %#v", sent)
			}
		})
	}
}

func TestInboundOwnerRemovalKeepsAdmittedCallbackIsolated(t *testing.T) {
	producerSender := new(captureTunnelSender)
	producer := NewRuntime(RuntimeConfig{Sender: producerSender})
	if _, err := producer.RegisterOutbound(OutboundCircuit{ID: 1, NextTunnelID: 2}); err != nil {
		t.Fatal(err)
	}
	if err := producer.SendBlock(context.Background(), 1, Block{Delivery: DeliveryLocal, Last: true, Data: deliveryStatusFrame(t, 5)}); err != nil {
		t.Fatal(err)
	}
	packet := producerSender.take()[0].message
	runtime := NewRuntime(RuntimeConfig{})
	entered, resume := make(chan struct{}), make(chan struct{})
	oldEndpoint := NewEndpoint(8, 4096)
	token, err := runtime.RegisterInbound(InboundCircuit{ID: 2, Owner: foundation.Hash{1}, Endpoint: oldEndpoint, Local: func(foundation.I2NPMessage) error { close(entered); <-resume; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	var unblock, join sync.Once
	var receiveErr error
	wait := func() { join.Do(func() { receiveErr = <-finished }) }
	t.Cleanup(func() { unblock.Do(func() { close(resume) }); wait() })
	go func() { finished <- runtime.Handle(packet) }()
	<-entered
	runtime.RemoveOwner(foundation.Hash{1})
	if err := runtime.Handle(packet); !errors.Is(err, ErrCircuitNotFound) {
		t.Fatalf("removed receive = %v", err)
	}
	if _, err := runtime.RegisterInbound(InboundCircuit{ID: 2, Owner: foundation.Hash{2}, Endpoint: oldEndpoint}); !errors.Is(err, ErrCircuitExists) {
		t.Fatalf("reused endpoint = %v", err)
	}
	var delivered int
	if _, err := runtime.RegisterInbound(InboundCircuit{ID: 2, Owner: foundation.Hash{2}, Endpoint: NewEndpoint(8, 4096), Local: func(foundation.I2NPMessage) error { delivered++; return nil }}); err != nil {
		t.Fatal(err)
	}
	if runtime.RemoveCircuit(token) {
		t.Fatal("retired owner token removed new owner's circuit")
	}
	runtime.RemoveOwner(foundation.Hash{1})
	if err := runtime.Handle(packet); err != nil {
		t.Fatal(err)
	}
	if delivered != 1 {
		t.Fatalf("new owner's deliveries = %d, want 1", delivered)
	}
	unblock.Do(func() { close(resume) })
	wait()
	if receiveErr != nil {
		t.Fatalf("admitted receive failed after retirement: %v", receiveErr)
	}
}

func TestCircuitReplacementRejectsOwnerAndRuntimeMismatch(t *testing.T) {
	runtime := NewRuntime(RuntimeConfig{})
	circuit := OutboundCircuit{ID: 1, Owner: foundation.Hash{1}, NextTunnelID: 2}
	token, err := runtime.RegisterOutbound(circuit)
	if err != nil {
		t.Fatal(err)
	}
	other := NewRuntime(RuntimeConfig{})
	if _, err := other.RegisterOutbound(circuit); err != nil {
		t.Fatal(err)
	}
	if other.RemoveCircuit(token) {
		t.Fatal("token crossed runtime boundary")
	}
	circuit.Owner = foundation.Hash{2}
	if _, err := runtime.ReplaceOutbound(token, circuit); !errors.Is(err, ErrCircuitOwner) {
		t.Fatalf("owner-changing replacement = %v", err)
	}
	if _, err := runtime.RegisterOutbound(circuit); !errors.Is(err, ErrCircuitExists) {
		t.Fatalf("duplicate registration = %v", err)
	}
	if !runtime.RemoveCircuit(token) {
		t.Fatal("failed replacement retired original")
	}
}
