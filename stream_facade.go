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
	StreamNetwork  = stream.StreamNetwork
	Dialer         = stream.Dialer
	ListenerConfig = stream.ListenerConfig
)
