package ivnp

import (
	"gosuda.org/ivnp/api/destination"
	"gosuda.org/ivnp/network/router"
	"gosuda.org/ivnp/network/tunnel"
	"gosuda.org/ivnp/protocol/garlic"
	"gosuda.org/ivnp/protocol/i2np"
	"gosuda.org/ivnp/protocol/netdb"
	streamtunnel "gosuda.org/ivnp/protocol/streaming/tunnel"
	"gosuda.org/ivnp/service/clientapi"
	"gosuda.org/ivnp/service/daemon"
	"gosuda.org/ivnp/service/sam"
	"gosuda.org/ivnp/support/config"
)

// Config is the complete embedded-node operating configuration.
type Config = config.Operating

type LogConfig = config.Log

func LoadConfig(path string) (Config, error) { return config.LoadOperating(path) }

func LoadOrCreateConfig(path string) (Config, error) {
	return config.LoadOrCreateOperating(path)
}

func ParseConfig(text, path string) (Config, error) {
	return config.ParseOperating(text, path)
}

// Node owns one complete embedded router and its local services.
type Node = daemon.Daemon

type (
	Options           = daemon.Options
	Status            = daemon.Status
	Destination       = clientapi.Destination
	DestinationStatus = clientapi.Status
	DestinationPolicy = daemon.DestinationPolicy
	DestinationKind   = daemon.DestinationPolicyKind
)

const (
	DestinationPublicLS2     = daemon.DestinationPublicLS2
	DestinationEncryptedNone = daemon.DestinationEncryptedNone
	DestinationEncryptedDH   = daemon.DestinationEncryptedDH
	DestinationEncryptedPSK  = daemon.DestinationEncryptedPSK
)

// New constructs a complete embedded IVNP node without starting network I/O.
func New(cfg Config, options Options) (*Node, error) { return daemon.New(cfg, options) }

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
	Router             = router.Router
	RouterConfig       = router.Config
	RouterDependencies = router.Dependencies
	RouterStatus       = router.Status
	RouterEndpoint     = router.Endpoint
	RouterState        = router.State
	Reachability       = router.Reachability
)

func NewRouter(cfg RouterConfig, dependencies RouterDependencies) (*Router, error) {
	return router.New(cfg, dependencies)
}

type (
	Database          = netdb.Database
	RouterInfo        = netdb.RouterInfo
	RouterAddress     = netdb.RouterAddress
	Lease             = netdb.Lease
	LeaseSet          = netdb.LeaseSet
	LeaseSet2         = netdb.LeaseSet2
	EncryptedLeaseSet = netdb.EncryptedLeaseSet
	MetaLeaseSet      = netdb.MetaLeaseSet
	RouterRef         = netdb.RouterRef
)

func NewDatabase(local Hash, bucketCapacity int) *Database {
	return netdb.NewDatabase(local, bucketCapacity)
}

func ParseRouterInfo(src []byte) (RouterInfo, error) { return netdb.ParseRouterInfo(src) }

func ParseRouterAddress(src []byte) (RouterAddress, int, error) {
	return netdb.ParseRouterAddress(src)
}

func ParseLeaseSet(src []byte) (LeaseSet, error) { return netdb.ParseLeaseSet(src) }

func ParseLeaseSet2(src []byte) (LeaseSet2, error) { return netdb.ParseLeaseSet2(src) }

func ParseEncryptedLeaseSet(src []byte) (EncryptedLeaseSet, error) {
	return netdb.ParseEncryptedLeaseSet(src)
}

func ParseMetaLeaseSet(src []byte) (MetaLeaseSet, error) { return netdb.ParseMetaLeaseSet(src) }

type (
	I2NPMessage              = i2np.Message
	I2NPHeader               = i2np.Header
	I2NPShortHeader          = i2np.ShortHeader
	I2NPTransportHeader      = i2np.TransportHeader
	I2NPMessageType          = i2np.MessageType
	I2NPStoreType            = i2np.StoreType
	I2NPDataMessage          = i2np.DataMessage
	I2NPGarlicMessage        = i2np.GarlicMessage
	I2NPDatabaseStoreMessage = i2np.DatabaseStoreMessage
	I2NPDatabaseLookup       = i2np.DatabaseLookupMessage
	I2NPTunnelDataMessage    = i2np.TunnelDataMessage
	I2NPTunnelGatewayMessage = i2np.TunnelGatewayMessage
)

func ParseI2NP(src []byte) (I2NPMessage, int, error) { return i2np.Parse(src) }

func ParseI2NPWire(src []byte) (I2NPMessage, int, error) { return i2np.ParseWire(src) }

func ParseI2NPData(payload []byte) (I2NPDataMessage, error) { return i2np.ParseData(payload) }

func ParseI2NPGarlic(payload []byte) (I2NPGarlicMessage, error) {
	return i2np.ParseGarlic(payload)
}

func ParseI2NPDatabaseStore(payload []byte) (I2NPDatabaseStoreMessage, error) {
	return i2np.ParseDatabaseStore(payload)
}

func ParseI2NPDatabaseLookup(payload []byte) (I2NPDatabaseLookup, error) {
	return i2np.ParseDatabaseLookup(payload)
}

func ParseI2NPTunnelData(payload []byte) (I2NPTunnelDataMessage, error) {
	return i2np.ParseTunnelData(payload)
}

func ParseI2NPTunnelGateway(payload []byte) (I2NPTunnelGatewayMessage, error) {
	return i2np.ParseTunnelGateway(payload)
}

type (
	TunnelRuntime       = tunnel.Runtime
	TunnelRuntimeConfig = tunnel.RuntimeConfig
	TunnelPool          = tunnel.Pool
	TunnelEntry         = tunnel.Entry
	TunnelDirection     = tunnel.Direction
	TunnelSender        = tunnel.Sender
	GarlicReplyKey      = garlic.GarlicReplyKey
	GarlicReplyKeys     = garlic.GarlicReplyKeyRegistry
	StreamingDelivery   = streamtunnel.Delivery
)

const (
	TunnelInbound  = tunnel.Inbound
	TunnelOutbound = tunnel.Outbound
)

func NewTunnelRuntime(cfg TunnelRuntimeConfig) *TunnelRuntime { return tunnel.NewRuntime(cfg) }

func NewTunnelPool(maximum int) *TunnelPool { return tunnel.NewPool(maximum) }

func NewOwnedTunnelPool(owner Hash, maximum int) *TunnelPool {
	return tunnel.NewOwnedPool(owner, maximum)
}

func NewGarlicReplyKeyRegistry(maximum int) *garlic.ReplyKeyRegistry {
	return garlic.NewReplyKeyRegistry(maximum)
}

type (
	SAMNetwork      = sam.Network
	SAMConfig       = sam.Config
	SAMServer       = sam.Server
	SAMServerConfig = sam.ServerConfig
	HTTPProxy       = clientapi.HTTPProxy
	HTTPProxyConfig = clientapi.HTTPProxyConfig
	SOCKS5Proxy     = clientapi.SOCKS5Proxy
	SOCKS5Config    = clientapi.SOCKS5Config
	ControlServer   = clientapi.Control
	ControlConfig   = clientapi.ControlConfig
)

func NewSAMNetwork(cfg SAMConfig) (*SAMNetwork, error) { return sam.New(cfg) }

func NewSAMServer(cfg SAMServerConfig) (*SAMServer, error) { return sam.NewServer(cfg) }

func NewHTTPProxy(cfg HTTPProxyConfig) (*HTTPProxy, error) { return clientapi.NewHTTPProxy(cfg) }

func NewSOCKS5Proxy(cfg SOCKS5Config) (*SOCKS5Proxy, error) {
	return clientapi.NewSOCKS5Proxy(cfg)
}

func NewControlServer(cfg ControlConfig) (*ControlServer, error) {
	return clientapi.NewControl(cfg)
}
