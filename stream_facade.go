package ivnp

import (
	"gosuda.org/ivnp/interfaces/stream"
)

var (
	ErrUnsupportedNetwork    = stream.ErrUnsupportedNetwork
	ErrAddressInUse          = stream.ErrAddressInUse
	ErrAddressUnavailable    = stream.ErrAddressUnavailable
	ErrAddressInvalid        = stream.ErrAddressInvalid
	ErrStreamNetworkRequired = stream.ErrStreamNetworkRequired
)

type (
	// StreamNetwork is explicit: adapters never substitute a native TCP connection.
	StreamNetwork = stream.StreamNetwork
	// Dialer requires Network and accepts only "i2p" or "i2p-stream".
	Dialer = stream.Dialer
	// ListenerConfig binds through its supplied Network, not the host's TCP stack.
	ListenerConfig = stream.ListenerConfig
)
