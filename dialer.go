package ivnp

import (
	"context"
	"errors"
	"net"
)

var (
	ErrUnsupportedNetwork    = errors.New("i2p: unsupported network")
	errStreamNetworkRequired = errors.New("i2p: StreamNetwork is required")
)

// StreamNetwork provides I2P stream dialing and listening.
//
// Implementations are responsible for routing streams through an I2P runtime.
type StreamNetwork interface {
	DialI2P(context.Context, string) (net.Conn, error)
	ListenI2P(context.Context, string) (net.Listener, error)
}

// Dialer dials I2P stream addresses through Network.
type Dialer struct {
	Network StreamNetwork
}

// DialContext dials address through the configured I2P stream network.
// network must be "i2p" or "i2p-stream".
func (d Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "i2p" && network != "i2p-stream" {
		return nil, ErrUnsupportedNetwork
	}
	if d.Network == nil {
		return nil, errStreamNetworkRequired
	}
	return d.Network.DialI2P(ctx, address)
}

// Dial dials address through the configured I2P stream network.
func (d Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// ListenerConfig listens for I2P streams through Network.
type ListenerConfig struct {
	Network StreamNetwork
}

// Listen listens on address through the configured I2P stream network.
func (c ListenerConfig) Listen(ctx context.Context, address string) (net.Listener, error) {
	if c.Network == nil {
		return nil, errStreamNetworkRequired
	}
	return c.Network.ListenI2P(ctx, address)
}
