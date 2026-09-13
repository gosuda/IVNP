package ivnp

import (
	"cmp"
	"crypto/sha256"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"gosuda.org/ivnp/node"
	"gosuda.org/ivnp/overlay"
)

// Domain aliases keep the facade self-contained: applications configure
// networks, realms, and services without a second import.
type (
	RealmID             = overlay.RealmID
	FabricID            = overlay.FabricID
	EndpointID          = overlay.EndpointID
	FabricDescriptor    = overlay.FabricDescriptor
	AdmissionMode       = overlay.AdmissionMode
	DiscoveryMode       = overlay.DiscoveryMode
	PrivacyClass        = overlay.PrivacyClass
	DataRouting         = overlay.DataRouting
	PublicationMode     = overlay.PublicationMode
	PublicationCursor   = overlay.PublicationCursor
	PrefixPolicy        = overlay.PrefixPolicy
	PublicParticipation = overlay.PublicParticipation
	RouteClass          = overlay.RouteClass
	EndpointProtocol    = overlay.EndpointProtocol
	ProtocolFallback    = overlay.ProtocolFallback
	SessionFailover     = overlay.SessionFailover
	EndpointRef         = overlay.EndpointRef
	// StaticPeer is one statically configured fabric member.
	StaticPeer = node.OverlayPeer

	OverlayAddr         = overlay.Addr
	OverlayHost         = overlay.Host
	OverlayRealm        = overlay.Realm
	OverlayService      = overlay.Service
	OverlayConnection   = overlay.Connection
	OverlayListener     = overlay.Listener
	OverlayTarget       = overlay.ServiceTarget
	OverlayDialPolicy   = overlay.DialPolicy
	OverlayListenPolicy = overlay.ListenPolicy

	TransportProvider     = overlay.TransportProvider
	InboundProvider       = overlay.InboundProvider
	Channel               = overlay.Channel
	MembershipChannel     = overlay.MembershipChannel
	ChannelScope          = overlay.ChannelScope
	TransportCapabilities = overlay.TransportCapabilities
	RouteCandidate        = overlay.RouteCandidate
	AdmissionRequest      = overlay.AdmissionRequest
	AuthorizationProvider = overlay.AuthorizationProvider
	BootstrapProvider     = overlay.BootstrapProvider
	Signer                = overlay.Signer
	CustomProvider        = any
)

const (
	AdmissionOpen = overlay.AdmissionOpen
	AdmissionPSK  = overlay.AdmissionPSK

	DiscoveryLocalOnly      = overlay.DiscoveryLocalOnly
	DiscoveryPublicPrimary  = overlay.DiscoveryPublicPrimary
	DiscoveryHedged         = overlay.DiscoveryHedged
	DiscoveryPublicFallback = overlay.DiscoveryPublicFallback

	PrivacyI2PCompatible   = overlay.PrivacyI2PCompatible
	PrivacyExplicitDirect  = overlay.PrivacyExplicitDirect
	PrivacyPrivateConfined = overlay.PrivacyPrivateConfined

	RoutingNativeI2P     = overlay.RoutingNativeI2P
	RoutingOverlayDirect = overlay.RoutingOverlayDirect
	RoutingOverlayRouted = overlay.RoutingOverlayRouted
	RoutingOpportunistic = overlay.RoutingOpportunistic

	PublicationNone         = overlay.PublicationNone
	PublicationNativeRI     = overlay.PublicationNativeRI
	PublicationLS2          = overlay.PublicationLS2
	PublicationEncryptedLS2 = overlay.PublicationEncryptedLS2

	PrefixStrict     = overlay.PrefixStrict
	PrefixBestEffort = overlay.PrefixBestEffort
	PrefixDisabled   = overlay.PrefixDisabled

	ParticipationOnDemand    = overlay.ParticipationOnDemand
	ParticipationWarm        = overlay.ParticipationWarm
	ParticipationContributor = overlay.ParticipationContributor

	RouteNativeI2P = overlay.RouteNativeI2P
	RouteDirect    = overlay.RouteDirect
	RouteRouted    = overlay.RouteRouted

	EndpointProtocolLegacyStream = overlay.EndpointProtocolLegacyStream
	EndpointProtocolIVNPStream   = overlay.EndpointProtocolIVNPStream

	ProtocolIVNPOnly      = overlay.ProtocolIVNPOnly
	ProtocolIVNPPreferred = overlay.ProtocolIVNPPreferred
	ProtocolLegacyOnly    = overlay.ProtocolLegacyOnly

	FailoverReconnect        = overlay.FailoverReconnect
	FailoverNegotiatedResume = overlay.FailoverNegotiatedResume
)

// NetworkIDPublicI2P is the fixed official I2P network number. IVNP fabrics
// must choose 16..254.
const NetworkIDPublicI2P = 2

// networkNativeName is the canonical handle of the netId=2 entry.
const networkNativeName = "i2p"

// NetworkKind distinguishes the wire-level network implementations.
type NetworkKind uint8

const (
	// NetworkNativeI2P is the public garlic routing context (defaulting to netId=2).
	NetworkNativeI2P NetworkKind = iota + 1
	// NetworkIVNPFabric is a direct 1-hop routing context with its own netId,
	// listeners, and peer table.
	NetworkIVNPFabric
)

// RoutingStrategy describes the data-routing topology of a network.
type RoutingStrategy uint8

const (
	// RoutingGarlic routes traffic through multi-hop garlic-encrypted tunnel pools.
	RoutingGarlic RoutingStrategy = iota + 1
	// RoutingDirect routes traffic directly between peers (1-hop).
	RoutingDirect
)

// DiscoveryStrategy describes how peers and destinations are discovered in a network.
type DiscoveryStrategy uint8

const (
	// DiscoveryNetDB discovers peers and published LeaseSets via the distributed NetDB.
	DiscoveryNetDB DiscoveryStrategy = iota + 1
	// DiscoveryStatic discovers peers via a statically configured membership directory.
	DiscoveryStatic
)

// NetworkConfig describes one network the router operates.
type NetworkConfig struct {
	Name      string
	Kind      NetworkKind
	NetworkID uint32
	// Default marks this network as the target for generic "tcp", "udp",
	// and unqualified "stream"/"packet" operations.
	Default bool

	// Composable routing and discovery strategies
	Routing   RoutingStrategy
	Discovery DiscoveryStrategy

	// Garlic / Multi-hop components
	NTCP2       TransportConfig
	SSU2        TransportConfig
	Bootstrap   BootstrapConfig
	Exploratory TunnelPoolConfig
	// Participation selects native network contribution. ParticipationOnDemand
	// runs client-only: RouterInfo is still published but carries the 'H'
	// (hidden) and forced 'K' bandwidth capabilities so peers do not select it
	// for tunnel hops, and transit build requests are rejected. ParticipationWarm
	// (the default) also accepts transit tunnels. ParticipationContributor
	// additionally serves as a floodfill NetDB participant.
	Participation PublicParticipation

	// Direct Overlay components
	Fabric    *FabricDescriptor
	Listeners []string
	// Advertise lists operator-declared public contact endpoints
	// ("ivnp-tls@ip:port") the fabric's presence projection may carry —
	// required when Listeners bind unspecified or translated addresses.
	Advertise []string
	Peers     []StaticPeer
}

// RealmProfile is the single realm over the configured networks. Fabrics
// selects which IVNP entries join; IncludeNative adds the netId=2 context.
type RealmProfile = overlay.RealmProfile

// OverlayPolicy aliases RealmProfile, providing a clear domain concept for
// multi-network routing, discovery, and admission policy.
type OverlayPolicy = RealmProfile

// ServiceProfile describes the overlay service a destination owns when
// DestinationConfig.Overlay is set.
type ServiceProfile struct {
	// Port is the logical service selector bound into channel scopes.
	// If 0 or omitted, the port is bound dynamically when Listen is called
	// (allocating an ephemeral port if ":0" is requested).
	Port uint16
	// Networks names the RouterConfig.Networks entries this destination's
	// overlay service may use; empty allows every realm-bound network.
	Networks []string
	// Protocols are the endpoint protocols this service accepts; empty
	// accepts both stream protocols.
	Protocols []EndpointProtocol
	// Publication selects the native-record projection; PublicationNone
	// keeps the service off the public netDB.
	Publication PublicationMode
	// Privacy and Routing zero values inherit the realm's classes.
	Privacy PrivacyClass
	Routing DataRouting
	// DualPresence authorizes an x-ivnp.* projection of the service's
	// contact address inside its native record.
	DualPresence bool
	// Floor carries the durable publication position from a previous run.
	Floor PublicationCursor
}

// DefaultI2PNetwork returns the official I2P network entry carrying safe production defaults.
func DefaultI2PNetwork() NetworkConfig {
	return NewNativeI2PNetwork()
}

// IVNPFabricNetwork returns a private fabric entry: the descriptor derives
// its identity from the name and never claims public reachability.
func IVNPFabricNetwork(name string, networkID uint32, maxPeers int, listeners []string, peers []StaticPeer) NetworkConfig {
	return NetworkConfig{
		Name: name, Kind: NetworkIVNPFabric, NetworkID: networkID,
		Fabric: &FabricDescriptor{
			ID: FabricIDFor(name), NetworkID: overlay.WireNetworkID(networkID), MaxPeers: maxPeers,
		},
		Listeners: append([]string(nil), listeners...), Peers: append([]StaticPeer(nil), peers...),
	}
}

// NetworkOption configures a NetworkConfig component.
type NetworkOption func(*NetworkConfig)

// NativeI2POption is an alias for NetworkOption for native I2P configuration.
type NativeI2POption = NetworkOption

// FabricOption is an alias for NetworkOption for private fabric configuration.
type FabricOption = NetworkOption

// WithDefaultNetwork marks this network as the default target for generic operations ("tcp", "udp").
func WithDefaultNetwork() NetworkOption {
	return func(c *NetworkConfig) {
		c.Default = true
	}
}

// WithFloodfill configures whether the router contributes as a floodfill NetDB participant.
func WithFloodfill(floodfill bool) NetworkOption {
	return func(c *NetworkConfig) {
		if floodfill {
			c.Participation = ParticipationContributor
		} else {
			c.Participation = ParticipationWarm
		}
	}
}

// WithPublicParticipation sets explicit participation level for the native network.
func WithPublicParticipation(p PublicParticipation) NetworkOption {
	return func(c *NetworkConfig) {
		c.Participation = p
	}
}

// WithReseedURLs configures the standard reseed URLs.
func WithReseedURLs(urls []string) NetworkOption {
	return func(c *NetworkConfig) {
		c.Bootstrap.ReseedURLs = append([]string(nil), urls...)
	}
}

// WithPriorityReseedURLs configures high-priority reseed URLs.
func WithPriorityReseedURLs(urls []string) NetworkOption {
	return func(c *NetworkConfig) {
		c.Bootstrap.PriorityReseedURLs = append([]string(nil), urls...)
	}
}

// WithExploratoryPool configures the exploratory tunnel pool for NetDB routing.
func WithExploratoryPool(pool TunnelPoolConfig) NetworkOption {
	return func(c *NetworkConfig) {
		c.Exploratory = pool
	}
}

// WithTransportNTCP2 configures the NTCP2 transport.
func WithTransportNTCP2(cfg TransportConfig) NetworkOption {
	return func(c *NetworkConfig) {
		c.NTCP2 = cfg
	}
}

// WithTransportSSU2 configures the SSU2 transport.
func WithTransportSSU2(cfg TransportConfig) NetworkOption {
	return func(c *NetworkConfig) {
		c.SSU2 = cfg
	}
}

// WithStaticPeers registers static peer entries on a fabric.
func WithStaticPeers(peers ...StaticPeer) NetworkOption {
	return func(c *NetworkConfig) {
		c.Peers = append(c.Peers, peers...)
	}
}

// WithFabricNetworkID configures the wire network ID for a fabric.
func WithFabricNetworkID(id uint32) NetworkOption {
	return func(c *NetworkConfig) {
		c.NetworkID = id
		if c.Fabric != nil {
			c.Fabric.NetworkID = overlay.WireNetworkID(id)
		} else {
			c.Fabric = &FabricDescriptor{
				ID: FabricIDFor(c.Name), NetworkID: overlay.WireNetworkID(id), MaxPeers: 256,
			}
		}
	}
}

// WithFabricMaxPeers configures the maximum peer capacity of a fabric.
func WithFabricMaxPeers(maxPeers int) NetworkOption {
	return func(c *NetworkConfig) {
		if c.Fabric != nil {
			c.Fabric.MaxPeers = maxPeers
		} else {
			c.Fabric = &FabricDescriptor{
				ID: FabricIDFor(c.Name), NetworkID: overlay.WireNetworkID(c.NetworkID), MaxPeers: maxPeers,
			}
		}
	}
}

// WithFabricListeners adds listen addresses to a fabric.
func WithFabricListeners(listeners ...string) NetworkOption {
	return func(c *NetworkConfig) {
		c.Listeners = append(c.Listeners, listeners...)
	}
}

// WithFabricDescriptor sets an explicit fabric descriptor.
func WithFabricDescriptor(d *FabricDescriptor) NetworkOption {
	return func(c *NetworkConfig) {
		c.Fabric = d
		if d != nil && d.NetworkID != 0 {
			c.NetworkID = uint32(d.NetworkID)
		}
	}
}

// WithNetworkName sets the network handle name.
func WithNetworkName(name string) NetworkOption {
	return func(c *NetworkConfig) {
		c.Name = name
	}
}

// WithNetworkID sets the wire network identifier.
func WithNetworkID(id uint32) NetworkOption {
	return func(c *NetworkConfig) {
		c.NetworkID = id
		if c.Fabric != nil {
			c.Fabric.NetworkID = overlay.WireNetworkID(id)
		}
	}
}

// WithGarlicRouting configures the network to use multi-hop garlic tunnel routing.
func WithGarlicRouting() NetworkOption {
	return func(c *NetworkConfig) {
		c.Routing = RoutingGarlic
		c.Kind = NetworkNativeI2P
	}
}

// WithDirectRouting configures the network to use direct 1-hop link routing.
func WithDirectRouting() NetworkOption {
	return func(c *NetworkConfig) {
		c.Routing = RoutingDirect
		c.Kind = NetworkIVNPFabric
	}
}

// WithNetDBDiscovery configures distributed NetDB discovery with optional reseed URLs.
func WithNetDBDiscovery(reseedURLs ...string) NetworkOption {
	return func(c *NetworkConfig) {
		c.Discovery = DiscoveryNetDB
		if len(reseedURLs) > 0 {
			c.Bootstrap.ReseedURLs = append([]string(nil), reseedURLs...)
		}
	}
}

// WithBootstrap sets the complete bootstrap configuration.
func WithBootstrap(b BootstrapConfig) NetworkOption {
	return func(c *NetworkConfig) {
		c.Bootstrap = b
	}
}

// WithStaticDiscovery configures static peer discovery with optional initial members.
func WithStaticDiscovery(peers ...StaticPeer) NetworkOption {
	return func(c *NetworkConfig) {
		c.Discovery = DiscoveryStatic
		if len(peers) > 0 {
			c.Peers = append(c.Peers, peers...)
		}
	}
}

// WithListeners adds listener bind addresses to the network.
func WithListeners(listeners ...string) NetworkOption {
	return func(c *NetworkConfig) {
		c.Listeners = append(c.Listeners, listeners...)
	}
}

// NewNetwork constructs a generic composable NetworkConfig with the given name and options.
func NewNetwork(name string, opts ...NetworkOption) NetworkConfig {
	cfg := NetworkConfig{
		Name: name,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.Kind == 0 {
		if isGarlicNetwork(cfg) {
			cfg.Kind = NetworkNativeI2P
		} else {
			cfg.Kind = NetworkIVNPFabric
		}
	}
	if cfg.Kind == NetworkIVNPFabric && cfg.Fabric == nil {
		netID := cfg.NetworkID
		if netID == 0 {
			netID = 77
			cfg.NetworkID = 77
		}
		cfg.Fabric = &FabricDescriptor{
			ID: FabricIDFor(name), NetworkID: overlay.WireNetworkID(netID), MaxPeers: 256,
		}
	}
	return cfg
}

func isGarlicNetwork(c NetworkConfig) bool {
	if c.Routing == RoutingGarlic || c.Discovery == DiscoveryNetDB {
		return true
	}
	if c.NTCP2 != (TransportConfig{}) || c.SSU2 != (TransportConfig{}) {
		return true
	}
	return c.Exploratory != (TunnelPoolConfig{}) || c.NetworkID == NetworkIDPublicI2P
}

// NewNativeI2PNetwork creates a composable official I2P network entry (netId=2)
// using the canonical composition of universal components:
// - Network ID: 2 (NetworkIDPublicI2P)
// - Routing: Garlic multi-hop tunnel pools (Exploratory + warm pools)
// - Discovery: Public NetDB with standard I2P reseed bootstrap
// - Transports: NTCP2 + SSU2
// - Participation: Warm (embedded router)
func NewNativeI2PNetwork(opts ...NetworkOption) NetworkConfig {
	defaults := DefaultRouterConfig()
	baseOpts := []NetworkOption{
		WithNetworkID(NetworkIDPublicI2P),
		WithGarlicRouting(),
		WithExploratoryPool(defaults.Exploratory),
		WithBootstrap(defaults.Bootstrap),
		WithNetDBDiscovery(),
		WithTransportNTCP2(defaults.NTCP2),
		WithTransportSSU2(defaults.SSU2),
		WithPublicParticipation(ParticipationWarm),
	}
	return NewNetwork(networkNativeName, append(baseOpts, opts...)...)
}

// NewDirectNetwork creates a composable direct 1-hop network entry.
func NewDirectNetwork(name string, opts ...NetworkOption) NetworkConfig {
	baseCfg := IVNPFabricNetwork(name, 77, 256, nil, nil)
	baseCfg.Routing = RoutingDirect
	baseCfg.Discovery = DiscoveryStatic
	for _, opt := range opts {
		if opt != nil {
			opt(&baseCfg)
		}
	}
	return baseCfg
}

// NewFabricNetwork creates a composable direct network entry for backward compatibility.
func NewFabricNetwork(name, listenAddr string, opts ...NetworkOption) NetworkConfig {
	var options []NetworkOption
	if listenAddr != "" {
		options = append(options, WithListeners(listenAddr))
	}
	options = append(options, opts...)
	return NewDirectNetwork(name, options...)
}

// RealmIDFor derives a stable realm identity from a name. Two deployments
// choosing the same name address the same realm — names are capability-free
// labels, not secrets.
func RealmIDFor(name string) RealmID { return overlay.RealmIDFor(name) }

// FabricIDFor derives a stable fabric identity from a name.
func FabricIDFor(name string) FabricID { return FabricID(sha256.Sum256([]byte("ivnp-fabric/" + name))) }

// SetNetworks configures the router for multi-network or overlay operation,
// clearing legacy single-network fields so they do not conflict with Networks.
func (c *RouterConfig) SetNetworks(realm *RealmProfile, entries ...NetworkConfig) {
	c.NetworkID = 0
	c.NTCP2 = TransportConfig{}
	c.SSU2 = TransportConfig{}
	c.Bootstrap = BootstrapConfig{}
	c.Exploratory = TunnelPoolConfig{}
	c.Networks = append([]NetworkConfig(nil), entries...)
	c.Realm = realm
}

// RegisterTransport adds a custom transport provider to the router configuration.
func (c *RouterConfig) RegisterTransport(t TransportProvider) {
	if t != nil {
		c.Transports = append(c.Transports, t)
	}
}

// RegisterProvider adds a custom provider (e.g. CredentialVerifier,
// IdentityProvider, TrustProvider) to the router configuration.
func (c *RouterConfig) RegisterProvider(p any) {
	if p != nil {
		c.CustomProviders = append(c.CustomProviders, p)
	}
}

// NewOverlayTarget constructs an OverlayTarget for the given endpoint and port.
func NewOverlayTarget(endpoint EndpointID, port uint16) OverlayTarget {
	return OverlayTarget{
		Endpoint: EndpointRef{ID: endpoint},
		Port:     port,
	}
}

// ParseOverlayTarget parses an address string into an OverlayTarget.
// Supported formats:
// - "ivnp://<52-char-b32>:<port>"
// - "<52-char-b32>:<port>"
// - "<52-char-b32>.b32.i2p:<port>"
// - "ivnp://<52-char-b32>" (port 0)
// - "<52-char-b32>" (port 0)
func ParseOverlayTarget(address string) (OverlayTarget, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return OverlayTarget{}, ErrAddressInvalid
	}
	var host string
	var port uint16
	if strings.Contains(address, ":") {
		trimmed := strings.TrimPrefix(address, "ivnp://")
		if h, pStr, err := net.SplitHostPort(trimmed); err == nil {
			host = h
			p, err := strconv.ParseUint(pStr, 10, 16)
			if err != nil {
				return OverlayTarget{}, ErrAddressInvalid
			}
			port = uint16(p)
		} else if strings.HasPrefix(address, "ivnp://") && !strings.Contains(trimmed, ":") {
			host = trimmed
		} else {
			return OverlayTarget{}, ErrAddressInvalid
		}
	} else {
		host = strings.TrimPrefix(address, "ivnp://")
	}
	host = strings.TrimSuffix(host, ".b32.i2p")
	id, err := overlay.ParseEndpointID(host)
	if err != nil {
		return OverlayTarget{}, err
	}
	return OverlayTarget{
		Endpoint: EndpointRef{ID: id},
		Port:     port,
	}, nil
}

// NewStaticPeer creates a StaticPeer entry from raw destination bytes and contact address.
// If contactAddr does not contain a carrier transport prefix ("carrier@..."), "ivnp-tls@"
// is automatically added as the default carrier.
func NewStaticPeer(destination []byte, contactAddr string) StaticPeer {
	contact := strings.TrimSpace(contactAddr)
	if !strings.Contains(contact, "@") {
		contact = "ivnp-tls@" + contact
	}
	return StaticPeer{
		Destination: append([]byte(nil), destination...),
		Contact:     contact,
	}
}

// NewCustomStaticPeer creates a static peer entry with a custom carrier transport format.
// e.g. NewCustomStaticPeer(destBytes, "quic", "1.2.3.4:4433") -> contact "quic@1.2.3.4:4433".
func NewCustomStaticPeer(destination []byte, carrier, contactAddr string) StaticPeer {
	carrier = strings.TrimSpace(carrier)
	contact := strings.TrimSpace(contactAddr)
	prefix := carrier + "@"
	if !strings.HasPrefix(contact, prefix) {
		contact = prefix + contact
	}
	return StaticPeer{
		Destination: append([]byte(nil), destination...),
		Contact:     contact,
	}
}

// NewChannel wraps an established net.Conn with the authenticated scope and peer contact key.
// It satisfies overlay.Channel for custom TransportProviders.
func NewChannel(conn net.Conn, scope ChannelScope, peerContactKey [32]byte) Channel {
	return &basicChannel{
		Conn:  conn,
		scope: scope,
		key:   peerContactKey,
	}
}

type basicChannel struct {
	net.Conn
	scope ChannelScope
	key   [32]byte
}

func (c *basicChannel) Binding() (ChannelScope, [32]byte) {
	return c.scope, c.key
}

// NewDualStackRealmProfile returns a realm profile configured for dual-stack operation:
// official I2P network for Sybil-resistant NetDB discovery and backup, plus
// the named fabrics for high-speed direct transport.
func NewDualStackRealmProfile(name string, fabrics ...string) *RealmProfile {
	return &RealmProfile{
		ID:                  RealmIDFor(name),
		Admission:           AdmissionOpen,
		AcknowledgeOpen:     true,
		AcknowledgeExposure: true,
		Discovery:           DiscoveryHedged,
		Privacy:             PrivacyExplicitDirect,
		Routing:             RoutingOpportunistic,
		Publication:         PublicationLS2,
		Prefix:              PrefixPolicy{Mode: PrefixBestEffort, IPv4Prefix: 16, IPv6Prefix: 48, MaxPerPrefix: 2},
		Fabrics:             append([]string(nil), fabrics...),
		IncludeNative:       true,
	}
}

// NewDualStackRealm is an alias for NewDualStackRealmProfile.
func NewDualStackRealm(name string, fabrics ...string) *RealmProfile {
	return NewDualStackRealmProfile(name, fabrics...)
}

// NewPrivateRealmProfile returns a realm profile configured for an isolated private network:
// strictly confined to private fabrics, no public I2P access, local discovery, and PSK admission.
func NewPrivateRealmProfile(name string, psk []byte, fabrics ...string) *RealmProfile {
	return &RealmProfile{
		ID:            RealmIDFor(name),
		Admission:     AdmissionPSK,
		PSK:           append([]byte(nil), psk...),
		Discovery:     DiscoveryLocalOnly,
		Privacy:       PrivacyPrivateConfined,
		Routing:       RoutingOverlayDirect,
		Publication:   PublicationNone,
		Fabrics:       append([]string(nil), fabrics...),
		IncludeNative: false,
	}
}

// NewPrivateRealm is an alias for NewPrivateRealmProfile.
func NewPrivateRealm(name string, psk []byte, fabrics ...string) *RealmProfile {
	return NewPrivateRealmProfile(name, psk, fabrics...)
}

// NewOpenRealmProfile returns a realm profile configured for open admission across the named fabrics.
func NewOpenRealmProfile(name string, fabrics ...string) *RealmProfile {
	return &RealmProfile{
		ID:                  RealmIDFor(name),
		Admission:           AdmissionOpen,
		AcknowledgeOpen:     true,
		AcknowledgeExposure: true,
		Discovery:           DiscoveryLocalOnly,
		Privacy:             PrivacyExplicitDirect,
		Routing:             RoutingOverlayDirect,
		Publication:         PublicationNone,
		Fabrics:             append([]string(nil), fabrics...),
		IncludeNative:       true,
	}
}

// NewPSKRealmProfile returns a realm profile configured for PSK admission across the named fabrics.
func NewPSKRealmProfile(name string, psk []byte, fabrics ...string) *RealmProfile {
	return &RealmProfile{
		ID:            RealmIDFor(name),
		Admission:     AdmissionPSK,
		PSK:           append([]byte(nil), psk...),
		Discovery:     DiscoveryLocalOnly,
		Privacy:       PrivacyExplicitDirect,
		Routing:       RoutingOverlayDirect,
		Publication:   PublicationNone,
		Fabrics:       append([]string(nil), fabrics...),
		IncludeNative: true,
	}
}

// DefaultRouterConfigWithNetworks returns a router configuration composing the given
// networks and realm, with legacy single-network fields already cleared and ready for use.
func DefaultRouterConfigWithNetworks(realm *RealmProfile, networks ...NetworkConfig) RouterConfig {
	cfg := DefaultRouterConfig()
	cfg.SetNetworks(realm, networks...)
	return cfg
}

// DefaultDualStackRouterConfig returns a router configuration composing the official
// I2P network (netId=2) for Sybil resistance and discovery alongside a private IVNP fabric
// for high-speed direct transport.
func DefaultDualStackRouterConfig(fabricName string, netID uint32, listenAddr string) RouterConfig {
	cfg := DefaultRouterConfig()
	native := DefaultI2PNetwork()
	var listeners []string
	if listenAddr != "" {
		listeners = []string{listenAddr}
	}
	fabric := IVNPFabricNetwork(fabricName, netID, 256, listeners, nil)
	realm := NewDualStackRealm(fabricName, fabricName)
	cfg.SetNetworks(realm, native, fabric)
	return cfg
}

// networkPlan resolves the effective native network and optional overlay spec
// from the configuration. Networks empty is the legacy path: the legacy fields
// are the native network, and Realm alone enables the bridge over it.
// Networks non-empty requires Realm and forbids every legacy network field —
// the official I2P network becomes the "i2p" entry instead.
func networkPlan(cfg RouterConfig) (native NetworkConfig, spec *node.OverlaySpec, err error) {
	if _, err := resolveDefaultNetwork(cfg); err != nil {
		return native, nil, err
	}
	if len(cfg.Networks) == 0 {
		native = NetworkConfig{
			Name: networkNativeName, Kind: NetworkNativeI2P, NetworkID: cfg.NetworkID,
			NTCP2: cfg.NTCP2, SSU2: cfg.SSU2, Bootstrap: cfg.Bootstrap, Exploratory: cfg.Exploratory,
		}
		if cfg.Realm == nil {
			return native, nil, nil
		}
		realm, err := realmSpec(cfg.Realm, nil)
		if err != nil {
			return native, nil, err
		}
		// The legacy path configures only the native network; a realm that
		// declines it binds nothing.
		if !cfg.Realm.IncludeNative {
			return native, nil, &ConfigError{Field: "Realm.IncludeNative", Err: ErrInvalidConfig}
		}
		return native, &node.OverlaySpec{
			Native: true, NativeID: "native", NativeParticipation: ParticipationWarm,
			Realm:      realm,
			Transports: append([]overlay.TransportProvider(nil), cfg.Transports...),
			Providers:  append([]any(nil), cfg.CustomProviders...),
		}, nil
	}
	if cfg.Realm == nil && cfg.Policy != nil {
		cfg.Realm = cfg.Policy
	}
	if cfg.Realm == nil {
		return native, nil, &ConfigError{Field: "Realm", Err: ErrInvalidConfig}
	}
	if legacyNetworkSet(cfg) {
		return native, nil, &ConfigError{Field: "Networks", Err: errLegacyNetworkFields}
	}
	var fabrics []node.OverlayFabric
	names := make(map[string]struct{}, len(cfg.Networks))
	fabricNames := make(map[string]struct{}, len(cfg.Networks))
	nativeSeen := false
	for i := range cfg.Networks {
		nc := cfg.Networks[i]
		field := "Networks[" + strconv.Itoa(i) + "]"
		if nc.Name == "" {
			return native, nil, invalidConfig(field + ".Name")
		}
		if _, dup := names[nc.Name]; dup {
			return native, nil, invalidConfig(field + ".Name")
		}
		names[nc.Name] = struct{}{}
		switch nc.Kind {
		case NetworkNativeI2P:
			if nativeSeen {
				return native, nil, invalidConfig(field + ".Kind")
			}
			nativeSeen = true
			if nc.NetworkID != NetworkIDPublicI2P {
				return native, nil, invalidConfig(field + ".NetworkID")
			}
			if nc.Fabric != nil || len(nc.Listeners) > 0 || len(nc.Advertise) > 0 || len(nc.Peers) > 0 {
				return native, nil, invalidConfig(field + ".Fabric")
			}
			if nc.Participation != 0 && (nc.Participation < ParticipationOnDemand || nc.Participation > ParticipationContributor) {
				return native, nil, invalidConfig(field + ".Participation")
			}
			native = nc
		case NetworkIVNPFabric:
			if nc.Fabric == nil {
				return native, nil, invalidConfig(field + ".Fabric")
			}
			if err := nc.Fabric.Validate(); err != nil {
				return native, nil, &ConfigError{Field: field + ".Fabric", Err: err}
			}
			if nc.NetworkID != 0 && nc.NetworkID != uint32(nc.Fabric.NetworkID) {
				return native, nil, invalidConfig(field + ".NetworkID")
			}
			if nc.NTCP2 != (TransportConfig{}) || nc.SSU2 != (TransportConfig{}) ||
				!bootstrapEmpty(nc.Bootstrap) || nc.Exploratory != (TunnelPoolConfig{}) ||
				nc.Participation != 0 {
				return native, nil, invalidConfig(field)
			}
			for _, listen := range nc.Listeners {
				if _, err := netip.ParseAddrPort(listen); err != nil {
					return native, nil, invalidConfig(field + ".Listeners")
				}
			}
			for _, advertise := range nc.Advertise {
				if _, err := overlay.ParseEndpoint(advertise); err != nil {
					return native, nil, invalidConfig(field + ".Advertise")
				}
			}
			fabricNames[nc.Name] = struct{}{}
			fabrics = append(fabrics, node.OverlayFabric{
				Name: nc.Name, Descriptor: *nc.Fabric, IdentityRef: "fabric/" + nc.Name,
				Listeners: append([]string(nil), nc.Listeners...),
				Advertise: append([]string(nil), nc.Advertise...),
				Peers:     append([]node.OverlayPeer(nil), nc.Peers...),
			})
		default:
			return native, nil, invalidConfig(field + ".Kind")
		}
	}
	if !nativeSeen {
		return native, nil, &ConfigError{Field: "Networks", Err: errNativeRequired}
	}
	realm, err := realmSpec(cfg.Realm, fabricNames)
	if err != nil {
		return native, nil, err
	}
	return native, &node.OverlaySpec{
		Native: true, NativeID: "native", NativeName: native.Name, NativeParticipation: nativeParticipation(native),
		Fabrics:    fabrics,
		Realm:      realm,
		Transports: append([]overlay.TransportProvider(nil), cfg.Transports...),
		Providers:  append([]any(nil), cfg.CustomProviders...),
	}, nil
}

// legacyNetworkSet reports whether any legacy single-network field carries a
// value; combined with Networks it is always an error rather than a merge.
func legacyNetworkSet(cfg RouterConfig) bool {
	return cfg.NetworkID != 0 || cfg.NTCP2 != (TransportConfig{}) || cfg.SSU2 != (TransportConfig{}) ||
		!bootstrapEmpty(cfg.Bootstrap) || cfg.Exploratory != (TunnelPoolConfig{})
}

// bootstrapEmpty reports whether a bootstrap section carries no values;
// RouterInfos makes the struct incomparable so the check is explicit.
func bootstrapEmpty(b BootstrapConfig) bool {
	return len(b.ReseedURLs) == 0 && len(b.PriorityReseedURLs) == 0 && len(b.RouterInfos) == 0 &&
		b.ReseedTimeout == 0 && b.PriorityReseedTimeout == 0
}

// nativeParticipation maps the entry's declared mode; zero selects the warm
// default matching an embedded router's tunnel pools.
func nativeParticipation(nc NetworkConfig) overlay.PublicParticipation {
	if nc.Participation == 0 {
		return ParticipationWarm
	}
	return nc.Participation
}

// realmSpec validates the realm profile against the configured fabric names
// and converts it to the node-level spec.
func realmSpec(profile *RealmProfile, fabricNames map[string]struct{}) (node.OverlayRealm, error) {
	var realm node.OverlayRealm
	if profile == nil {
		return realm, invalidConfig("Realm")
	}
	if profile.ID == (RealmID{}) {
		return realm, invalidConfig("Realm.ID")
	}
	switch profile.Admission {
	case AdmissionPSK, overlay.AdmissionCredentialPSK:
		if len(profile.PSK) == 0 {
			return realm, invalidConfig("Realm.PSK")
		}
	default:
		if len(profile.PSK) != 0 {
			return realm, invalidConfig("Realm.PSK")
		}
	}
	for _, name := range profile.Fabrics {
		if _, ok := fabricNames[name]; !ok {
			return realm, &ConfigError{Field: "Realm.Fabrics", Err: ErrInvalidConfig}
		}
	}
	realm = node.OverlayRealm{
		ID: profile.ID, Admission: profile.Admission, Discovery: profile.Discovery,
		Privacy: profile.Privacy, Routing: profile.Routing, Publication: profile.Publication,
		Prefix: profile.Prefix, Fabrics: append([]string(nil), profile.Fabrics...),
		IncludeNative: profile.IncludeNative, PSK: append([]byte(nil), profile.PSK...),
		AcknowledgeOpen: profile.AcknowledgeOpen, AcknowledgeExposure: profile.AcknowledgeExposure,
	}
	return realm, nil
}

// resolveDefaultNetwork determines which network handles generic "tcp", "udp",
// and unqualified operations.
func resolveDefaultNetwork(cfg RouterConfig) (string, error) {
	var explicitDefault string
	for i, nc := range cfg.Networks {
		if nc.Default {
			if explicitDefault != "" {
				return "", &ConfigError{Field: "Networks[" + strconv.Itoa(i) + "].Default", Err: ErrInvalidConfig}
			}
			explicitDefault = nc.Name
		}
	}
	if explicitDefault != "" && cfg.DefaultNetwork != "" && cfg.DefaultNetwork != explicitDefault {
		return "", &ConfigError{Field: "DefaultNetwork", Err: ErrInvalidConfig}
	}
	target := cmp.Or(explicitDefault, cfg.DefaultNetwork)
	if target == "" {
		if cfg.Realm != nil && !cfg.Realm.IncludeNative && len(cfg.Networks) > 0 {
			for _, nc := range cfg.Networks {
				if nc.Kind == NetworkIVNPFabric {
					target = nc.Name
					break
				}
			}
		}
		nativeName := networkNativeName
		for _, nc := range cfg.Networks {
			if nc.Kind == NetworkNativeI2P {
				nativeName = nc.Name
				break
			}
		}
		target = cmp.Or(target, nativeName)
	}
	if len(cfg.Networks) == 0 {
		if target != networkNativeName && target != "ivnp" {
			return "", &ConfigError{Field: "DefaultNetwork", Err: ErrInvalidConfig}
		}
		return target, nil
	}
	if target == "ivnp" {
		return target, nil
	}
	for _, nc := range cfg.Networks {
		if nc.Name == target {
			return target, nil
		}
	}
	return "", &ConfigError{Field: "DefaultNetwork", Err: ErrInvalidConfig}
}
