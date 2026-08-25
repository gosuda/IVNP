// Package client is the only public entry point for IVNP client implementations.
package client

import (
	addressbookinternal "gosuda.org/ivnp/client/internal/addressbook"
	frontendinternal "gosuda.org/ivnp/client/internal/frontend"
	saminternal "gosuda.org/ivnp/client/internal/sam"
)

type (
	AddressBookConfig                        = addressbookinternal.Config
	AddressBookService                       = addressbookinternal.Service
	ClientByteBudget                         = frontendinternal.ByteBudget
	ClientControl                            = frontendinternal.Control
	ClientControlConfig                      = frontendinternal.ControlConfig
	ClientDestination                        = frontendinternal.Destination
	ClientDestinationCatalog                 = frontendinternal.DestinationCatalog
	ClientDestinationController              = frontendinternal.DestinationController
	ClientDestinationEndpoint                = frontendinternal.DestinationEndpoint
	ClientDestinationRoute                   = frontendinternal.DestinationRoute
	ClientDestinationSpec                    = frontendinternal.DestinationSpec
	ClientHTTPProxy                          = frontendinternal.HTTPProxy
	ClientHTTPProxyConfig                    = frontendinternal.HTTPProxyConfig
	ClientLeaseSetPolicy                     = frontendinternal.LeaseSetPolicy
	ClientMessageSubscription                = frontendinternal.MessageSubscription
	ClientReadinessDetails                   = frontendinternal.ReadinessDetails
	ClientSOCKS5Config                       = frontendinternal.SOCKS5Config
	ClientSOCKS5Proxy                        = frontendinternal.SOCKS5Proxy
	ClientStatus                             = frontendinternal.Status
	ClientStatusProvider                     = frontendinternal.StatusProvider
	SimpleAnonymousMessagingConfig           = saminternal.Config
	SimpleAnonymousMessagingListenFunc       = saminternal.ListenFunc
	SimpleAnonymousMessagingListenPacketFunc = saminternal.ListenPacketFunc
	SimpleAnonymousMessagingNetwork          = saminternal.Network
	SimpleAnonymousMessagingServer           = saminternal.Server
	SimpleAnonymousMessagingServerConfig     = saminternal.ServerConfig
)

const ()

var (
	AddressBookNewService              = addressbookinternal.NewService
	ClientErrInvalidConfig             = frontendinternal.ErrInvalidConfig
	ClientNewConnectionLimitedListener = frontendinternal.NewConnectionLimitedListener
	ClientNewControl                   = frontendinternal.NewControl
	ClientNewHTTPProxy                 = frontendinternal.NewHTTPProxy
	ClientNewSOCKS5Proxy               = frontendinternal.NewSOCKS5Proxy
	SimpleAnonymousMessagingNew        = saminternal.New
	SimpleAnonymousMessagingNewServer  = saminternal.NewServer
)
