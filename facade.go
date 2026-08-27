package ivnp

import (
	"gosuda.org/ivnp/client"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/networking"
	"gosuda.org/ivnp/node"
	"gosuda.org/ivnp/state"
)

// Config is the complete embedded-node operating configuration.
type Config = state.ConfigurationOperating

type LogConfig = state.ConfigurationLog

func LoadConfig(path string) (Config, error) { return state.ConfigurationLoadOperating(path) }

func LoadOrCreateConfig(path string) (Config, error) {
	return state.ConfigurationLoadOrCreateOperating(path)
}

func ParseConfig(text, path string) (Config, error) {
	return state.ConfigurationParseOperating(text, path)
}

// Node owns one complete embedded router and its local services.
type Node = node.Subsystem

type (
	Options           = node.Options
	Status            = node.Status
	Destination       = client.ClientDestination
	DestinationStatus = client.ClientStatus
	DestinationPolicy = node.DestinationPolicy
	DestinationKind   = node.DestinationPolicyKind
)

const (
	DestinationPublicLS2     = node.DestinationPublicLeaseSet2
	DestinationEncryptedNone = node.DestinationEncryptedWithoutAuth
	DestinationEncryptedDH   = node.DestinationEncryptedWithDiffieHellman
	DestinationEncryptedPSK  = node.DestinationEncryptedWithPreSharedKey
)

// New constructs a complete embedded IVNP node without starting network I/O.
func New(cfg Config, options Options) (*Node, error) { return node.NewSubsystem(cfg, options) }

type (
	DestinationResolver           = destination.DestinationResolver
	LeaseSetPolicy                = destination.LeaseSetPolicy
	DestinationSpec               = destination.DestinationSpec
	DestinationRoute              = destination.DestinationRoute
	ReceivedMessage               = destination.ReceivedMessage
	MessageSubscription           = destination.MessageSubscription
	DestinationEndpoint           = destination.DestinationEndpoint
	DestinationController         = destination.DestinationController
	ReadyDestinationEndpoint      = destination.ReadyDestinationEndpoint
	BoundedDestinationEndpoint    = destination.BoundedDestinationEndpoint
	SourcePortDestinationEndpoint = destination.SourcePortDestinationEndpoint
	ByteBudget                    = destination.ByteBudget
)

type (
	Router             = networking.Router
	RouterConfig       = networking.RouterConfig
	RouterDependencies = networking.RouterDependencies
	RouterStatus       = networking.RouterStatus
	RouterEndpoint     = networking.RouterEndpoint
	RouterState        = networking.RouterState
	Reachability       = networking.RouterReachability
)

func NewRouter(cfg RouterConfig, dependencies RouterDependencies) (*Router, error) {
	return networking.RouterNew(cfg, dependencies)
}

type (
	Database          = networking.NetworkDatabase
	RouterInfo        = networking.NetworkDatabaseRouterInfo
	RouterAddress     = networking.NetworkDatabaseRouterAddress
	Lease             = networking.NetworkDatabaseLease
	LeaseSet          = networking.NetworkDatabaseLeaseSet
	LeaseSet2         = networking.NetworkDatabaseLeaseSet2
	EncryptedLeaseSet = networking.NetworkDatabaseEncryptedLeaseSet
	MetaLeaseSet      = networking.NetworkDatabaseMetaLeaseSet
	RouterRef         = networking.NetworkDatabaseRouterRef
)

func NewDatabase(local Hash, bucketCapacity int) *Database {
	return networking.NetworkDatabaseNewDatabase(local, bucketCapacity)
}

func ParseRouterInfo(src []byte) (RouterInfo, error) {
	return networking.NetworkDatabaseParseRouterInfo(src)
}

func ParseRouterAddress(src []byte) (RouterAddress, int, error) {
	return networking.NetworkDatabaseParseRouterAddress(src)
}

func ParseLeaseSet(src []byte) (LeaseSet, error) { return networking.NetworkDatabaseParseLeaseSet(src) }

func ParseLeaseSet2(src []byte) (LeaseSet2, error) {
	return networking.NetworkDatabaseParseLeaseSet2(src)
}

func ParseEncryptedLeaseSet(src []byte) (EncryptedLeaseSet, error) {
	return networking.NetworkDatabaseParseEncryptedLeaseSet(src)
}

func ParseMetaLeaseSet(src []byte) (MetaLeaseSet, error) {
	return networking.NetworkDatabaseParseMetaLeaseSet(src)
}

type (
	I2NPMessage              = networking.I2NPMessage
	I2NPHeader               = networking.I2NPHeader
	I2NPShortHeader          = networking.I2NPShortHeader
	I2NPTransportHeader      = networking.I2NPTransportHeader
	I2NPMessageType          = networking.I2NPMessageType
	I2NPStoreType            = networking.I2NPStoreType
	I2NPDataMessage          = networking.I2NPDataMessage
	I2NPGarlicMessage        = networking.I2NPGarlicMessage
	I2NPDatabaseStoreMessage = networking.I2NPDatabaseStoreMessage
	I2NPDatabaseLookup       = networking.I2NPDatabaseLookupMessage
	I2NPTunnelDataMessage    = networking.I2NPTunnelDataMessage
	I2NPTunnelGatewayMessage = networking.I2NPTunnelGatewayMessage
)

func ParseI2NP(src []byte) (I2NPMessage, int, error) { return networking.I2NPParse(src) }

func ParseI2NPWire(src []byte) (I2NPMessage, int, error) { return networking.I2NPParseWire(src) }

func ParseI2NPData(payload []byte) (I2NPDataMessage, error) { return networking.I2NPParseData(payload) }

func ParseI2NPGarlic(payload []byte) (I2NPGarlicMessage, error) {
	return networking.I2NPParseGarlic(payload)
}

func ParseI2NPDatabaseStore(payload []byte) (I2NPDatabaseStoreMessage, error) {
	return networking.I2NPParseDatabaseStore(payload)
}

func ParseI2NPDatabaseLookup(payload []byte) (I2NPDatabaseLookup, error) {
	return networking.I2NPParseDatabaseLookup(payload)
}

func ParseI2NPTunnelData(payload []byte) (I2NPTunnelDataMessage, error) {
	return networking.I2NPParseTunnelData(payload)
}

func ParseI2NPTunnelGateway(payload []byte) (I2NPTunnelGatewayMessage, error) {
	return networking.I2NPParseTunnelGateway(payload)
}

type (
	TunnelRuntime       = networking.TunnelRuntime
	TunnelRuntimeConfig = networking.TunnelRuntimeConfig
	TunnelPool          = networking.TunnelPool
	TunnelEntry         = networking.TunnelEntry
	TunnelDirection     = networking.TunnelDirection
	TunnelSender        = networking.TunnelSender
	GarlicReplyKey      = networking.GarlicReplyKey
	GarlicReplyKeys     = networking.GarlicReplyKeyRegistryContract
	StreamingDelivery   = destination.Delivery
)

const (
	TunnelInbound  = networking.TunnelInbound
	TunnelOutbound = networking.TunnelOutbound
)

func NewTunnelRuntime(cfg TunnelRuntimeConfig) *TunnelRuntime {
	return networking.TunnelNewRuntime(cfg)
}

func NewTunnelPool(maximum int) *TunnelPool { return networking.TunnelNewPool(maximum) }

func NewOwnedTunnelPool(owner Hash, maximum int) *TunnelPool {
	return networking.TunnelNewOwnedPool(owner, maximum)
}

func NewGarlicReplyKeyRegistry(maximum int) *networking.GarlicReplyKeyRegistry {
	return networking.GarlicNewReplyKeyRegistry(maximum)
}

type (
	SAMNetwork         = client.SimpleAnonymousMessagingNetwork
	SAMConfig          = client.SimpleAnonymousMessagingConfig
	SAMServer          = client.SimpleAnonymousMessagingServer
	SAMServerConfig    = client.SimpleAnonymousMessagingServerConfig
	HTTPProxy          = client.ClientHTTPProxy
	HTTPProxyConfig    = client.ClientHTTPProxyConfig
	SOCKS5Proxy        = client.ClientSOCKS5Proxy
	SOCKS5Config       = client.ClientSOCKS5Config
	ControlServer      = client.ClientControl
	ControlConfig      = client.ClientControlConfig
	RegistrationSigner = client.RegistrationSigner
)

var (
	ErrRegistrationDomain      = client.RegistrationErrDomain
	RegistrationAuthentication = client.RegistrationAuthentication
	RegistrationEd25519Signer  = client.RegistrationEd25519Signer
)

func NewSAMNetwork(cfg SAMConfig) (*SAMNetwork, error) {
	return client.SimpleAnonymousMessagingNew(cfg)
}

func NewSAMServer(cfg SAMServerConfig) (*SAMServer, error) {
	return client.SimpleAnonymousMessagingNewServer(cfg)
}

func NewHTTPProxy(cfg HTTPProxyConfig) (*HTTPProxy, error) { return client.ClientNewHTTPProxy(cfg) }

func NewSOCKS5Proxy(cfg SOCKS5Config) (*SOCKS5Proxy, error) {
	return client.ClientNewSOCKS5Proxy(cfg)
}

func NewControlServer(cfg ControlConfig) (*ControlServer, error) {
	return client.ClientNewControl(cfg)
}
