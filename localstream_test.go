package ivnp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
)

func TestLocalStreamNetworkDialListen(t *testing.T) {
	network := NewLocalStreamNetwork()
	listener, err := ListenerConfig{Network: network}.Listen(context.Background(), "service.i2p")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		_, err = conn.Read(buf)
		if err == nil && !bytes.Equal(buf, []byte("hello")) {
			err = ErrAddressInvalid
		}
		accepted <- err
	}()
	conn, err := Dialer{Network: network}.Dial("i2p", "service.i2p")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestLocalStreamNetworkRejectsCanceledListen(t *testing.T) {
	network := NewLocalStreamNetwork()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	listener, err := network.ListenI2P(ctx, "canceled.i2p")
	if listener != nil {
		_ = listener.Close()
		t.Fatal("ListenI2P returned a listener for a canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ListenI2P error = %v, want context.Canceled", err)
	}
}

func TestLocalStreamNetworkCancellationClosesAndReleasesAddress(t *testing.T) {
	network := NewLocalStreamNetwork()
	ctx, cancel := context.WithCancel(context.Background())
	listener, err := network.ListenI2P(ctx, "reusable.i2p")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err = listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after cancellation error = %v, want net.ErrClosed", err)
	}

	replacement, err := network.ListenI2P(context.Background(), "reusable.i2p")
	if err != nil {
		t.Fatalf("ListenI2P after cancellation: %v", err)
	}
	if err = replacement.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLocalStreamNetworkCloseRejectsBlockedDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		network := NewLocalStreamNetwork().(*localStreamNetwork)
		rawListener, err := network.ListenI2P(context.Background(), "closing.i2p")
		if err != nil {
			t.Fatal(err)
		}
		listener := rawListener.(*localListener)
		clients := make([]net.Conn, 0, cap(listener.incoming))
		for range cap(listener.incoming) {
			client, dialErr := network.DialI2P(context.Background(), "closing.i2p")
			if dialErr != nil {
				t.Fatal(dialErr)
			}
			clients = append(clients, client)
		}
		defer func() {
			for _, client := range clients {
				_ = client.Close()
			}
		}()

		type dialResult struct {
			connection net.Conn
			err        error
		}
		result := make(chan dialResult, 1)
		go func() {
			connection, dialErr := network.DialI2P(context.Background(), "closing.i2p")
			result <- dialResult{connection: connection, err: dialErr}
		}()
		synctest.Wait()
		if err = listener.Close(); err != nil {
			t.Fatal(err)
		}
		dialed := <-result
		if dialed.connection != nil {
			_ = dialed.connection.Close()
			t.Fatal("blocked DialI2P succeeded after listener close")
		}
		if !errors.Is(dialed.err, net.ErrClosed) {
			t.Fatalf("blocked DialI2P error = %v, want net.ErrClosed", dialed.err)
		}
	})
}

func TestLocalListenerAcceptRejectsConnectionAfterCloseStarts(t *testing.T) {
	listener := &localListener{incoming: make(chan net.Conn, 1), closed: make(chan struct{})}
	client, server := net.Pipe()
	defer client.Close()
	listener.incoming <- server
	listener.mu.Lock()
	listener.closing = true
	listener.mu.Unlock()

	connection, err := listener.Accept()
	if connection != nil {
		_ = connection.Close()
		t.Fatal("Accept returned a connection after listener close started")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept error = %v, want net.ErrClosed", err)
	}
}
