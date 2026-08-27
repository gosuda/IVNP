package stream

import (
	"context"
	"errors"
	"net"
)

var (
	ErrUnsupportedNetwork    = errors.New("i2p: unsupported network")
	ErrAddressInUse          = errors.New("i2p: address already listening")
	ErrAddressUnavailable    = errors.New("i2p: address is not listening")
	ErrAddressInvalid        = errors.New("i2p: invalid address")
	ErrStreamNetworkRequired = errors.New("i2p: StreamNetwork is required")
)

// StreamNetwork dials and listens for streaming connections over I2P.
type StreamNetwork interface {
	DialI2P(context.Context, string) (net.Conn, error)
	ListenI2P(context.Context, string) (net.Listener, error)
}

// Dialer establishes outbound I2P streaming connections.
type Dialer struct {
	Network StreamNetwork
}

// DialContext connects to the target I2P address. network must be "i2p" or "i2p-stream".
func (d Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "i2p" && network != "i2p-stream" {
		return nil, ErrUnsupportedNetwork
	}
	if d.Network == nil {
		return nil, ErrStreamNetworkRequired
	}
	return d.Network.DialI2P(ctx, address)
}

// Dial connects to the target I2P address using a background context.
func (d Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// ListenerConfig creates stream listeners on an I2P network.
type ListenerConfig struct {
	Network StreamNetwork
}

// Listen starts listening for incoming connections on the given address.
func (c ListenerConfig) Listen(ctx context.Context, address string) (net.Listener, error) {
	if c.Network == nil {
		return nil, ErrStreamNetworkRequired
	}
	return c.Network.ListenI2P(ctx, address)
}
