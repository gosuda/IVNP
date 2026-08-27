package ivnp

import (
	"context"
	"errors"
	"net"
	"testing"
)

type mockStreamNetwork struct {
	dial   func(context.Context, string) (net.Conn, error)
	listen func(context.Context, string) (net.Listener, error)
}

func (m mockStreamNetwork) DialI2P(ctx context.Context, address string) (net.Conn, error) {
	return m.dial(ctx, address)
}

func (m mockStreamNetwork) ListenI2P(ctx context.Context, address string) (net.Listener, error) {
	return m.listen(ctx, address)
}

type mockListener struct{}

func (mockListener) Accept() (net.Conn, error) { return nil, errors.New("accept not implemented") }
func (mockListener) Close() error              { return nil }
func (mockListener) Addr() net.Addr            { return mockAddr("i2p") }

type mockAddr string

func (a mockAddr) Network() string { return "i2p" }
func (a mockAddr) String() string  { return string(a) }

func TestDialerDialContextDelegates(t *testing.T) {
	ctx := context.WithValue(context.Background(), "test", "value")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var gotContext context.Context
	var gotAddress string
	dialer := Dialer{Network: mockStreamNetwork{
		dial: func(ctx context.Context, address string) (net.Conn, error) {
			gotContext = ctx
			gotAddress = address
			return client, nil
		},
	}}

	conn, err := dialer.DialContext(ctx, "i2p", "destination.i2p:1234")
	if err != nil {
		t.Fatal(err)
	}
	if conn != client {
		t.Fatal("DialContext() connection did not come from StreamNetwork")
	}
	if gotContext != ctx {
		t.Fatal("DialContext() did not pass its context to StreamNetwork")
	}
	if gotAddress != "destination.i2p:1234" {
		t.Fatalf("DialContext() address = %q, want %q", gotAddress, "destination.i2p:1234")
	}
}

func TestDialerDialUsesBackgroundContext(t *testing.T) {
	var gotContext context.Context
	dialer := Dialer{Network: mockStreamNetwork{
		dial: func(ctx context.Context, address string) (net.Conn, error) {
			gotContext = ctx
			return nil, nil
		},
	}}

	if _, err := dialer.Dial("i2p", "destination.i2p"); err != nil {
		t.Fatal(err)
	}
	if gotContext != context.Background() {
		t.Fatal("Dial() context is not context.Background()")
	}
}

func TestDialerRejectsUnsupportedNetwork(t *testing.T) {
	called := false
	dialer := Dialer{Network: mockStreamNetwork{
		dial: func(context.Context, string) (net.Conn, error) {
			called = true
			return nil, nil
		},
	}}

	for _, network := range []string{"", "tcp", "udp", "I2P"} {
		if _, err := dialer.DialContext(context.Background(), network, "destination.i2p"); !errors.Is(err, ErrUnsupportedNetwork) {
			t.Fatalf("DialContext(%q) error = %v, want ErrUnsupportedNetwork", network, err)
		}
	}
	if called {
		t.Fatal("DialContext() called StreamNetwork for an unsupported network")
	}
}

func TestDialerAcceptsI2PStreamNetwork(t *testing.T) {
	called := false
	dialer := Dialer{Network: mockStreamNetwork{
		dial: func(context.Context, string) (net.Conn, error) {
			called = true
			return nil, nil
		},
	}}

	if _, err := dialer.DialContext(context.Background(), "i2p-stream", "destination.i2p"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("DialContext() did not call StreamNetwork for i2p-stream")
	}
}

func TestDialerErrorsWithoutStreamNetwork(t *testing.T) {
	for _, dial := range []func() error{
		func() error {
			_, err := (Dialer{}).DialContext(context.Background(), "i2p", "destination.i2p")
			return err
		},
		func() error {
			_, err := (Dialer{}).Dial("i2p", "destination.i2p")
			return err
		},
	} {
		err := dial()
		if !errors.Is(err, ErrStreamNetworkRequired) {
			t.Fatalf("dial error = %v, want ErrStreamNetworkRequired", err)
		}
	}
}

func TestListenerConfigDelegates(t *testing.T) {
	ctx := context.WithValue(context.Background(), "test", "value")
	listener := mockListener{}
	var gotContext context.Context
	var gotAddress string
	config := ListenerConfig{Network: mockStreamNetwork{
		listen: func(ctx context.Context, address string) (net.Listener, error) {
			gotContext = ctx
			gotAddress = address
			return listener, nil
		},
	}}

	got, err := config.Listen(ctx, "service.i2p:8080")
	if err != nil {
		t.Fatal(err)
	}
	if got != listener {
		t.Fatal("Listen() listener did not come from StreamNetwork")
	}
	if gotContext != ctx {
		t.Fatal("Listen() did not pass its context to StreamNetwork")
	}
	if gotAddress != "service.i2p:8080" {
		t.Fatalf("Listen() address = %q, want %q", gotAddress, "service.i2p:8080")
	}
}

func TestDelegatesStreamNetworkErrors(t *testing.T) {
	want := errors.New("stream network failed")
	network := mockStreamNetwork{
		dial:   func(context.Context, string) (net.Conn, error) { return nil, want },
		listen: func(context.Context, string) (net.Listener, error) { return nil, want },
	}

	if _, err := (Dialer{Network: network}).DialContext(context.Background(), "i2p", "destination.i2p"); !errors.Is(err, want) {
		t.Fatalf("DialContext() error = %v, want %v", err, want)
	}
	if _, err := (ListenerConfig{Network: network}).Listen(context.Background(), "destination.i2p"); !errors.Is(err, want) {
		t.Fatalf("Listen() error = %v, want %v", err, want)
	}
}

func TestListenerConfigErrorsWithoutStreamNetwork(t *testing.T) {
	if _, err := (ListenerConfig{}).Listen(context.Background(), "service.i2p"); !errors.Is(err, ErrStreamNetworkRequired) {
		t.Fatalf("Listen() error = %v, want ErrStreamNetworkRequired", err)
	}
}
