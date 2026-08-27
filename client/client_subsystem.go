// Package client provides client-facing services including SAM v3.3 bridge, HTTP/SOCKS5 proxies, and AddressBook.
package client

import (
	"gosuda.org/ivnp/client/internal/addressbook"
	"gosuda.org/ivnp/client/internal/frontend"
	"gosuda.org/ivnp/client/internal/registration"
	"gosuda.org/ivnp/client/internal/sam"
)

type (
	AddressBookConfig                        = addressbook.Config
	AddressBookService                       = addressbook.Service
	ClientByteBudget                         = frontend.ByteBudget
	ClientControl                            = frontend.Control
	ClientControlConfig                      = frontend.ControlConfig
	ClientDestination                        = frontend.Destination
	ClientDestinationCatalog                 = frontend.DestinationCatalog
	ClientDestinationController              = frontend.DestinationController
	ClientDestinationEndpoint                = frontend.DestinationEndpoint
	ClientDestinationRoute                   = frontend.DestinationRoute
	ClientDestinationSpec                    = frontend.DestinationSpec
	ClientHTTPProxy                          = frontend.HTTPProxy
	ClientHTTPProxyConfig                    = frontend.HTTPProxyConfig
	ClientLeaseSetPolicy                     = frontend.LeaseSetPolicy
	ClientMessageSubscription                = frontend.MessageSubscription
	ClientReadinessDetails                   = frontend.ReadinessDetails
	ClientSOCKS5Config                       = frontend.SOCKS5Config
	ClientSOCKS5Proxy                        = frontend.SOCKS5Proxy
	ClientStatus                             = frontend.Status
	ClientStatusProvider                     = frontend.StatusProvider
	RegistrationSigner                       = registration.Signer
	SimpleAnonymousMessagingConfig           = sam.Config
	SimpleAnonymousMessagingListenFunc       = sam.ListenFunc
	SimpleAnonymousMessagingListenPacketFunc = sam.ListenPacketFunc
	SimpleAnonymousMessagingNetwork          = sam.Network
	SimpleAnonymousMessagingServer           = sam.Server
	SimpleAnonymousMessagingServerConfig     = sam.ServerConfig
)

const ()

var (
	AddressBookNewService              = addressbook.NewService
	ClientErrInvalidConfig             = frontend.ErrInvalidConfig
	ClientNewConnectionLimitedListener = frontend.NewConnectionLimitedListener
	ClientNewControl                   = frontend.NewControl
	ClientNewHTTPProxy                 = frontend.NewHTTPProxy
	ClientNewSOCKS5Proxy               = frontend.NewSOCKS5Proxy
	RegistrationAuthentication         = registration.Authentication
	RegistrationEd25519Signer          = registration.Ed25519Signer
	RegistrationErrDomain              = registration.ErrDomain
	SimpleAnonymousMessagingNew        = sam.New
	SimpleAnonymousMessagingNewServer  = sam.NewServer
)
