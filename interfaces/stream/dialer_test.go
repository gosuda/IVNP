package stream

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

func TestListenerConfigErrorsWithoutStreamNetwork(t *testing.T) {
	if _, err := (ListenerConfig{}).Listen(context.Background(), "service.i2p"); !errors.Is(err, ErrStreamNetworkRequired) {
		t.Fatalf("Listen() error = %v, want ErrStreamNetworkRequired", err)
	}
}
