package streamingtunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/stream"
)

func TestStreamPortOwnershipAndSetupContexts(t *testing.T) {
	fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
	client, server := newTunnelNetworkPair(t, fabric, DefaultRetransmitAfter)
	ctx, cancel := context.WithCancel(context.Background())
	listener, err := server.ListenStream(ctx, ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	port := listener.Addr().(tunnelAddr).port
	if port < 49152 {
		t.Fatalf("ephemeral port = %d", port)
	}
	outbound, err := client.DialStream(ctx, listener.Addr().String(), 4242)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbound.Close() })
	cancel()
	inbound, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inbound.Close() })
	if _, err := client.ListenStream(context.Background(), ":4242"); !errors.Is(err, stream.ErrAddressInUse) {
		t.Fatalf("live dial port bind = %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	returnListener, err := client.ListenStream(context.Background(), ":9000")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = returnListener.Close() })
	if dialed, err := server.DialStream(context.Background(), returnListener.Addr().String(), port); !errors.Is(err, stream.ErrAddressInUse) {
		if dialed != nil {
			_ = dialed.Close()
		}
		t.Fatalf("dial claimed port retained by accepted stream: %v", err)
	}
	replacement, err := server.ListenStream(context.Background(), listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replacement.Close() })
	if _, err := outbound.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	var data [2]byte
	if _, err := io.ReadFull(inbound, data[:]); err != nil || string(data[:]) != "ok" {
		t.Fatalf("read after setup cancellation/listener close = %q, %v", data, err)
	}
	if err := inbound.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := server.ListenStream(context.Background(), replacement.Addr().String()); !errors.Is(err, stream.ErrAddressInUse) {
		t.Fatalf("accepted close released replacement = %v", err)
	}
	if err := outbound.Close(); err != nil {
		t.Fatal(err)
	}
	reused, err := client.ListenStream(context.Background(), ":4242")
	if err != nil {
		t.Fatal(err)
	}
	_ = reused.Close()
	if _, err := outbound.Read(data[:]); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after Close = %v", err)
	}
}

func TestStreamPendingReadObservesDeadlineChanges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
		client, server := newTunnelNetworkPair(t, fabric, DefaultRetransmitAfter)
		listener, err := server.ListenStream(context.Background(), ":80")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		outbound, err := client.DialStream(context.Background(), listener.Addr().String(), 0)
		if err != nil {
			t.Fatal(err)
		}
		defer outbound.Close()
		inbound, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer inbound.Close()
		result := make(chan error, 1)
		go func() { var b [1]byte; _, err := inbound.Read(b[:]); result <- err }()
		synctest.Wait()
		if err := inbound.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := inbound.SetReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		observation := time.NewTimer(time.Hour)
		defer observation.Stop()
		<-observation.C
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("cleared deadline woke read: %v", err)
		default:
		}
		if err := inbound.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("pending read timeout = %v", err)
		}
		if err := inbound.SetReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		if _, err := outbound.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		var b [1]byte
		if _, err := inbound.Read(b[:]); err != nil || b[0] != 'x' {
			t.Fatalf("read after clearing expired deadline = %q, %v", b, err)
		}
	})
}

func TestStreamPendingWriteObservesDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		identity, err := foundation.GenerateLegacyLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		defer identity.ReleaseSensitive()
		sender := &blockingTunnelSender{started: make(chan struct{})}
		network, err := NewTunnelNetwork(TunnelNetworkConfig{Destination: identity, Sender: sender})
		if err != nil {
			t.Fatal(err)
		}
		defer network.Close()
		connection := network.newConn(1, 2, foundation.Hash{1}, foundation.Identity{}, 4242, 80, true)
		if err := network.register(connection); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { _, err := connection.Write([]byte("data")); result <- err }()
		<-sender.started
		if err := connection.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("pending write timeout = %v", err)
		}
	})
}

func TestStreamDrainsReceivedBytesAfterProtocolClose(t *testing.T) {
	fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
	client, server := newTunnelNetworkPair(t, fabric, DefaultRetransmitAfter)
	listener, err := server.ListenStream(t.Context(), ":80")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	outbound, err := client.DialStream(t.Context(), listener.Addr().String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.Close()
	inbound, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer inbound.Close()
	if _, err := inbound.Write([]byte("final response")); err != nil {
		t.Fatal(err)
	}
	if err := inbound.(*tunnelConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := outbound.(*tunnelConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-outbound.(*tunnelConn).done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not finish protocol close")
	}
	data, err := io.ReadAll(outbound)
	if err != nil || string(data) != "final response" {
		t.Fatalf("final buffered response = %q, %v", data, err)
	}
}
