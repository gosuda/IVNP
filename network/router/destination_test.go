package router

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp"
	streamtunnel "gosuda.org/ivnp/protocol/streaming/tunnel"
	"gosuda.org/ivnp/service/clientapi"
)

var _ StreamBackend = (*DestinationManager)(nil)

func TestDestinationManagerOwnsStreamSessions(t *testing.T) {
	fabric := &destinationFabric{targets: make(map[ivnp.Hash]*DestinationManager)}
	left := NewDestinationManager()
	right := NewDestinationManager()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})

	leftDestination, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	rightDestination, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	leftSession, err := left.Create(DestinationSessionConfig{Default: true, Streaming: streamtunnel.TunnelNetworkConfig{Destination: leftDestination, Sender: fabric}})
	if err != nil {
		t.Fatal(err)
	}
	rightSession, err := right.Create(DestinationSessionConfig{Default: true, Streaming: streamtunnel.TunnelNetworkConfig{Destination: rightDestination, Sender: fabric}})
	if err != nil {
		t.Fatal(err)
	}
	fabric.mu.Lock()
	fabric.targets[leftSession.Hash()] = left
	fabric.targets[rightSession.Hash()] = right
	fabric.mu.Unlock()

	listener, err := right.ListenI2P(context.Background(), ":80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	outbound, err := left.DialI2P(ctx, rightSession.B32()+":80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbound.Close() })
	var inbound net.Conn
	select {
	case inbound = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("destination listener did not receive tunnel stream")
	}
	t.Cleanup(func() { _ = inbound.Close() })
	if _, err := outbound.Write([]byte("session")); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len("session"))
	if _, err := io.ReadFull(inbound, received); err != nil || string(received) != "session" {
		t.Fatalf("inbound data = %q, %v", received, err)
	}

	if err := right.Destroy(rightSession.Hash()); err != nil {
		t.Fatal(err)
	}
	if _, ok := right.Session(rightSession.Hash()); ok {
		t.Fatal("destroyed destination remained registered")
	}
	if err := right.HandleStreaming(context.Background(), streamtunnel.Delivery{To: rightSession.Hash(), Protocol: streamtunnel.ProtocolStreaming}); err != ErrDestinationNotFound {
		t.Fatalf("delivery to destroyed destination = %v", err)
	}
}

func TestDestinationSessionDeliversSelfMessagesLocally(t *testing.T) {
	manager := NewDestinationManager()
	t.Cleanup(func() { _ = manager.Close() })
	destination, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.Create(DestinationSessionConfig{
		Default: true,
		Streaming: streamtunnel.TunnelNetworkConfig{
			Destination: destination,
			Sender:      &destinationFabric{targets: make(map[ivnp.Hash]*DestinationManager)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []uint8{17, 18} {
		route := clientapi.DestinationRoute{Protocol: protocol, ToPort: 4444}
		subscription, subscribeErr := session.Subscribe(route, 1)
		if subscribeErr != nil {
			t.Fatal(subscribeErr)
		}
		for sequence := range 4 {
			payload := []byte{protocol, byte(sequence), 0x49, 0x32, 0x50}
			if sendErr := session.SendMessage(context.Background(), streamtunnel.Delivery{
				To: session.Hash(), Protocol: protocol, FromPort: 3333, ToPort: route.ToPort, Payload: payload,
			}); sendErr != nil {
				t.Fatalf("protocol %d self message %d: %v", protocol, sequence, sendErr)
			}
			receiveCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			message, receiveErr := subscription.Receive(receiveCtx)
			cancel()
			if receiveErr != nil {
				t.Fatalf("protocol %d self message %d receive: %v", protocol, sequence, receiveErr)
			}
			if message.Delivery.From != session.Hash() || message.Delivery.To != session.Hash() ||
				message.Delivery.Protocol != protocol || message.Delivery.FromPort != 3333 ||
				message.Delivery.ToPort != route.ToPort || string(message.Delivery.Payload) != string(payload) {
				t.Fatalf("protocol %d self message %d = %#v", protocol, sequence, message.Delivery)
			}
			message.Release()
		}
		if closeErr := subscription.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}
}

func TestDestinationSessionRejectsStaleSelfDeliveryAfterRecreate(t *testing.T) {
	manager := NewDestinationManager()
	t.Cleanup(func() { _ = manager.Close() })
	original, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	recreated, err := original.Clone()
	if err != nil {
		t.Fatal(err)
	}
	fabric := &destinationFabric{targets: make(map[ivnp.Hash]*DestinationManager)}
	stale, err := manager.Create(DestinationSessionConfig{
		Default: true,
		Streaming: streamtunnel.TunnelNetworkConfig{
			Destination: original,
			Sender:      fabric,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Destroy(stale.Hash()); err != nil {
		t.Fatal(err)
	}
	replacement, err := manager.Create(DestinationSessionConfig{
		Default: true,
		Streaming: streamtunnel.TunnelNetworkConfig{
			Destination: recreated,
			Sender:      fabric,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	route := clientapi.DestinationRoute{Protocol: 17, ToPort: 4444}
	subscription, err := replacement.Subscribe(route, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	delivery := streamtunnel.Delivery{
		To: replacement.Hash(), Protocol: route.Protocol,
		FromPort: 3333, ToPort: route.ToPort, Payload: []byte("replacement"),
	}
	if err = stale.SendMessage(context.Background(), delivery); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("stale self delivery = %v", err)
	}
	if err = replacement.SendMessage(context.Background(), delivery); err != nil {
		t.Fatal(err)
	}
	receiveCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	message, err := subscription.Receive(receiveCtx)
	if err != nil {
		t.Fatal(err)
	}
	if string(message.Delivery.Payload) != string(delivery.Payload) {
		t.Fatalf("replacement payload = %q", message.Delivery.Payload)
	}
	message.Release()
}

type destinationFabric struct {
	mu      sync.Mutex
	targets map[ivnp.Hash]*DestinationManager
}

func (f *destinationFabric) SendTunnel(ctx context.Context, delivery streamtunnel.Delivery) error {
	f.mu.Lock()
	target := f.targets[delivery.To]
	f.mu.Unlock()
	if target == nil {
		return ErrDestinationNotFound
	}
	return target.HandleStreaming(ctx, delivery)
}
