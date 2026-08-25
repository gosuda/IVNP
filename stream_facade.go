package ivnp

import streamapi "gosuda.org/ivnp/contracts/stream"

var (
	ErrUnsupportedNetwork    = streamapi.ErrUnsupportedNetwork
	ErrAddressInUse          = streamapi.ErrAddressInUse
	ErrAddressUnavailable    = streamapi.ErrAddressUnavailable
	ErrAddressInvalid        = streamapi.ErrAddressInvalid
	ErrStreamNetworkRequired = streamapi.ErrStreamNetworkRequired
	errStreamNetworkRequired = ErrStreamNetworkRequired
)

type (
	StreamNetwork  = streamapi.StreamNetwork
	Dialer         = streamapi.Dialer
	ListenerConfig = streamapi.ListenerConfig
)
