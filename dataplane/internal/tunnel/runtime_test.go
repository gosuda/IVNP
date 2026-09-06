package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/observability"
)

type capturedTunnelMessage struct {
	peer    foundation.Hash
	message foundation.I2NPMessage
}

type captureTunnelSender struct {
	mu       sync.Mutex
	messages []capturedTunnelMessage
}

func (s *captureTunnelSender) Send(_ context.Context, peer foundation.Hash, message foundation.I2NPMessage) error {
	copy := message
	copy.Payload = append([]byte(nil), message.Payload...)
	s.mu.Lock()
	s.messages = append(s.messages, capturedTunnelMessage{peer: peer, message: copy})
	s.mu.Unlock()
	return nil
}

func (s *captureTunnelSender) take() []capturedTunnelMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	messages := s.messages
	s.messages = nil
	return messages
}

type discardTunnelSender struct{}

func (discardTunnelSender) Send(context.Context, foundation.Hash, foundation.I2NPMessage) error {
	return nil
}

func deliveryStatusFrame(t testing.TB, id uint32) []byte {
	t.Helper()
	payload := make([]byte, 12)
	binary.BigEndian.PutUint32(payload[:4], id)
	binary.BigEndian.PutUint64(payload[4:], 1234)
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: id, Expiration: 1_000_000}, Payload: payload}
	frame := make([]byte, message.EncodedLen())
	if _, err := message.MarshalTo(frame); err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestRuntimeTunnelRoundTrip(t *testing.T) {
	var layer, iv [32]byte
	for index := range layer {
		layer[index] = byte(index + 1)
		iv[index] = byte(255 - index)
	}
	encrypt, err := NewLayerEncryptor(layer[:], iv[:])
	if err != nil {
		t.Fatal(err)
	}
	decrypt, err := NewLayerDecryptor(layer[:], iv[:])
	if err != nil {
		t.Fatal(err)
	}

	var firstHop foundation.Hash
	firstHop[0] = 1
	outboundSender := new(captureTunnelSender)
	outbound := NewRuntime(RuntimeConfig{Sender: outboundSender, Now: func() uint64 { return 100 }})
	if _, err := outbound.RegisterOutbound(OutboundCircuit{
		ID: 1, FirstHop: firstHop, NextTunnelID: 77, Transforms: []LayerCipher{encrypt},
	}); err != nil {
		t.Fatal(err)
	}
	frame := deliveryStatusFrame(t, 9)
	if err := outbound.SendBlock(context.Background(), 1, Block{Delivery: DeliveryLocal, Last: true, Data: frame}); err != nil {
		t.Fatal(err)
	}
	sent := outboundSender.take()
	if len(sent) != 1 || sent[0].peer != firstHop || sent[0].message.Header.Type != foundation.I2NPTunnelData {
		t.Fatalf("outbound message = %#v", sent)
	}

	var received foundation.I2NPMessage
	inbound := NewRuntime(RuntimeConfig{Now: func() uint64 { return 100 }})
	if _, err := inbound.RegisterInbound(InboundCircuit{
		ID: 77, Transforms: []LayerCipher{decrypt}, Endpoint: NewEndpoint(8, 4096),
		Local: func(message foundation.I2NPMessage) error { received = message; return nil },
	}); err != nil {
		t.Fatal(err)
	}
	if err := inbound.Handle(sent[0].message); err != nil {
		t.Fatal(err)
	}
	if received.Header.Type != foundation.I2NPDeliveryStatus || !bytes.Equal(received.Payload, frame[foundation.I2NPStandardHeaderLen:]) {
		t.Fatalf("local delivery = %#v", received)
	}
}

func TestRuntimeTransitForwarding(t *testing.T) {
	var layer, iv [32]byte
	layer[0], iv[0] = 1, 2
	encrypt, err := NewLayerEncryptor(layer[:], iv[:])
	if err != nil {
		t.Fatal(err)
	}
	decrypt, err := NewLayerDecryptor(layer[:], iv[:])
	if err != nil {
		t.Fatal(err)
	}
	frame := deliveryStatusFrame(t, 5)
	plain := NewGateway(bytes.NewReader(bytes.Repeat([]byte{7}, foundation.I2NPTunnelDataMessageLen)))
	buffer := make([]byte, foundation.I2NPTunnelDataMessageLen)
	// Use a pooled buffer through an outbound circuit to make a valid payload.
	producerSender := new(captureTunnelSender)
	producer := NewRuntime(RuntimeConfig{Sender: producerSender, Gateway: plain, Now: func() uint64 { return 100 }})
	if _, err := producer.RegisterOutbound(OutboundCircuit{ID: 1, NextTunnelID: 44}); err != nil {
		t.Fatal(err)
	}
	if err := producer.SendBlock(context.Background(), 1, Block{Delivery: DeliveryLocal, Last: true, Data: frame}); err != nil {
		t.Fatal(err)
	}
	produced := producerSender.take()
	if len(produced) != 1 || len(buffer) != foundation.I2NPTunnelDataMessageLen {
		t.Fatal("producer failed")
	}

	var nextPeer foundation.Hash
	nextPeer[0] = 99
	transitSender := new(captureTunnelSender)
	transit := NewRuntime(RuntimeConfig{Sender: transitSender, Now: func() uint64 { return 100 }})
	if _, err := transit.RegisterInbound(InboundCircuit{ID: 44, Transforms: []LayerCipher{encrypt}, Forward: &Forward{Peer: nextPeer, TunnelID: 45}}); err != nil {
		t.Fatal(err)
	}
	if err := transit.Handle(produced[0].message); err != nil {
		t.Fatal(err)
	}
	forwarded := transitSender.take()
	if len(forwarded) != 1 || forwarded[0].peer != nextPeer {
		t.Fatalf("forwarded = %#v", forwarded)
	}
	data, err := foundation.I2NPParseTunnelData(forwarded[0].message.Payload)
	if err != nil || data.TunnelID != 45 {
		t.Fatalf("forwarded tunnel data = %#v, %v", data, err)
	}
	if err := decrypt.Transform(data.Data, data.Data); err != nil {
		t.Fatal(err)
	}
	decoded := make([]byte, foundation.I2NPTunnelDataMessageLen)
	binary.BigEndian.PutUint32(decoded[:4], data.TunnelID)
	copy(decoded[4:], data.Data)
	blocks := make([]Block, 1)
	count, err := NewEndpoint(1, 4096).Parse(decoded, blocks, 0)
	if err != nil || count != 1 || !bytes.Equal(blocks[0].Data, frame) {
		t.Fatalf("transit result = %d, %#v, %v", count, blocks[0], err)
	}
}

func TestRuntimeRejectsInvalidCircuitDirections(t *testing.T) {
	runtime := NewRuntime(RuntimeConfig{})
	if _, err := runtime.RegisterInbound(InboundCircuit{ID: 1}); err != ErrCircuitDirection {
		t.Fatalf("missing endpoint/forward error = %v", err)
	}
	if _, err := runtime.RegisterInbound(InboundCircuit{ID: 1, Endpoint: NewEndpoint(1, 1), Forward: &Forward{TunnelID: 2}}); err != ErrCircuitDirection {
		t.Fatalf("dual endpoint/forward error = %v", err)
	}
	if _, err := runtime.RegisterOutbound(OutboundCircuit{ID: 1}); err != ErrCircuitID {
		t.Fatalf("missing next tunnel ID error = %v", err)
	}
}

func TestRuntimeExpiresCircuitLifecycle(t *testing.T) {
	now := uint64(100)
	runtime := NewRuntime(RuntimeConfig{Now: func() uint64 { return now }})
	if _, err := runtime.RegisterOutbound(OutboundCircuit{ID: 1, NextTunnelID: 2, ExpiresAt: 101}); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RegisterInbound(InboundCircuit{ID: 3, Endpoint: NewEndpoint(1, 1), ExpiresAt: 101}); err != nil {
		t.Fatal(err)
	}
	now = 101
	block := Block{Delivery: DeliveryLocal, Last: true, Data: deliveryStatusFrame(t, 1)}
	if err := runtime.SendBlock(context.Background(), 1, block); err != ErrCircuitExpired {
		t.Fatalf("expired send = %v", err)
	}
	if removed := runtime.Expire(now); removed != 2 {
		t.Fatalf("Expire() = %d, want 2", removed)
	}
	if err := runtime.SendBlock(context.Background(), 1, block); err != ErrCircuitNotFound {
		t.Fatalf("removed send = %v", err)
	}
	if _, err := runtime.RegisterOutbound(OutboundCircuit{ID: 5, NextTunnelID: 6, ExpiresAt: now}); err != ErrCircuitExpired {
		t.Fatalf("register expired circuit = %v", err)
	}
}

func TestRuntimeExpiresIncompleteEndpointReassemblies(t *testing.T) {
	const started = uint64(1_000)
	lifetime := uint64(fragmentReassemblyLifetime / time.Millisecond)
	now := started
	endpoint := NewEndpoint(2, 64)
	if _, _, err := endpoint.reasm.Add(Fragment{MessageID: 7, Data: []byte("partial")}, now); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.remember(Block{MessageID: 7}, now); err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(RuntimeConfig{Now: func() uint64 { return now }})
	if _, err := runtime.RegisterInbound(InboundCircuit{ID: 3, Endpoint: endpoint, ExpiresAt: started + 2*lifetime}); err != nil {
		t.Fatal(err)
	}

	now = started + lifetime - 1
	if removed := runtime.Expire(now); removed != 0 || len(endpoint.reasm.entries) != 1 || len(endpoint.meta) != 1 {
		t.Fatalf("early expiry removed circuits=%d reassemblies=%d metadata=%d", removed, len(endpoint.reasm.entries), len(endpoint.meta))
	}
	now++
	if removed := runtime.Expire(now); removed != 0 || len(endpoint.reasm.entries) != 0 || len(endpoint.meta) != 0 {
		t.Fatalf("deadline expiry removed circuits=%d reassemblies=%d metadata=%d", removed, len(endpoint.reasm.entries), len(endpoint.meta))
	}
	if _, exists := runtime.InspectCircuit(3); !exists {
		t.Fatal("endpoint cleanup removed the live circuit")
	}
}

func TestRuntimeActiveTunnelCountsSeparateOwnersAndTransit(t *testing.T) {
	now := uint64(100)
	metrics := observability.NewRegistry()
	runtime := NewRuntime(RuntimeConfig{Now: func() uint64 { return now }, Metrics: metrics})
	var client foundation.Hash
	client[0] = 1
	for _, circuit := range []InboundCircuit{
		{ID: 1, Endpoint: NewEndpoint(1, 1), ExpiresAt: 200},
		{ID: 2, Owner: client, Endpoint: NewEndpoint(1, 1), ExpiresAt: 200},
		{ID: 3, Forward: &Forward{TunnelID: 30}, ExpiresAt: 200},
	} {
		if _, err := runtime.RegisterInbound(circuit); err != nil {
			t.Fatal(err)
		}
	}
	for _, circuit := range []OutboundCircuit{
		{ID: 4, NextTunnelID: 40, ExpiresAt: 200},
		{ID: 5, Owner: client, NextTunnelID: 50, ExpiresAt: 200},
	} {
		if _, err := runtime.RegisterOutbound(circuit); err != nil {
			t.Fatal(err)
		}
	}
	if in, out, clientIn, clientOut := runtime.ActiveTunnelCounts(); in != 1 || out != 1 || clientIn != 1 || clientOut != 1 {
		t.Fatalf("active counts = (%d, %d, %d, %d)", in, out, clientIn, clientOut)
	}
	snapshot := metrics.Snapshot().Tunnel
	if snapshot.ExploratoryInboundActive != 1 || snapshot.ExploratoryOutboundActive != 1 || snapshot.ClientInboundActive != 1 || snapshot.ClientOutboundActive != 1 {
		t.Fatalf("published active counts = %+v", snapshot)
	}
	now = 200
	if in, out, clientIn, clientOut := runtime.ActiveTunnelCounts(); in != 0 || out != 0 || clientIn != 0 || clientOut != 0 {
		t.Fatalf("expired active counts = (%d, %d, %d, %d)", in, out, clientIn, clientOut)
	}
	if removed := runtime.Expire(now); removed != 5 {
		t.Fatalf("expired circuits = %d, want 5", removed)
	}
	snapshot = metrics.Snapshot().Tunnel
	if snapshot.ExploratoryInboundActive != 0 || snapshot.ExploratoryOutboundActive != 0 || snapshot.ClientInboundActive != 0 || snapshot.ClientOutboundActive != 0 {
		t.Fatalf("published expired counts = %+v", snapshot)
	}
}

func TestRuntimeHandlesHundredsOfConcurrentCircuits(t *testing.T) {
	const circuits = 512
	runtime := NewRuntime(RuntimeConfig{Sender: discardTunnelSender{}})
	for id := uint32(1); id <= circuits; id++ {
		if _, err := runtime.RegisterOutbound(OutboundCircuit{ID: id, NextTunnelID: id + circuits}); err != nil {
			t.Fatal(err)
		}
	}
	block := Block{Delivery: DeliveryLocal, Last: true, Data: deliveryStatusFrame(t, 1)}
	start := make(chan struct{})
	errs := make(chan error, circuits)
	var workers sync.WaitGroup
	for id := uint32(1); id <= circuits; id++ {
		workers.Add(1)
		go func(circuitID uint32) {
			defer workers.Done()
			<-start
			for range 32 {
				if err := runtime.SendBlock(context.Background(), circuitID, block); err != nil {
					errs <- err
					return
				}
			}
		}(id)
	}
	close(start)
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func BenchmarkRuntimeSendBlockParallel(b *testing.B) {
	frame := deliveryStatusFrame(b, 1)
	runtime := NewRuntime(RuntimeConfig{Sender: discardTunnelSender{}})
	if _, err := runtime.RegisterOutbound(OutboundCircuit{ID: 1, NextTunnelID: 2}); err != nil {
		b.Fatal(err)
	}
	block := Block{Delivery: DeliveryLocal, Last: true, Data: frame}
	b.ReportAllocs()
	b.RunParallel(func(parallel *testing.PB) {
		for parallel.Next() {
			if err := runtime.SendBlock(context.Background(), 1, block); err != nil {
				b.Fatal(err)
			}
		}
	})
}
