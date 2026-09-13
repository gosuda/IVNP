package ivnp

import (
	"cmp"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/node"
	"gosuda.org/ivnp/state"
)

// NetworkIDPublicI2P is the netId of the official I2P network. Dedicated
// networks choose any other value in 1..255.
const NetworkIDPublicI2P = 2

// networkNativeName is the canonical handle of the netId=2 entry.
const networkNativeName = "i2p"

// PublicParticipation selects how much a network context contributes to peers.
type PublicParticipation uint8

const (
	// ParticipationOnDemand runs client-only: the RouterInfo is published but
	// carries the 'H' (hidden) and forced 'K' bandwidth capabilities so peers
	// do not select the router for tunnel hops, and transit build requests are
	// rejected.
	ParticipationOnDemand PublicParticipation = iota + 1
	// ParticipationWarm additionally accepts transit tunnels.
	ParticipationWarm
	// ParticipationContributor additionally serves as a floodfill NetDB
	// participant.
	ParticipationContributor
)

// NetworkConfig describes one I2P protocol context: the transports, bootstrap,
// and tunnel policy serving one netId. Every entry has the same shape — the
// official I2P network is simply the netId=2 configuration produced by
// DefaultI2PNetwork, and a dedicated network differs only in field values:
// its own netId, its own listeners, and its own seed set, which yields an
// isolated NetDB rather than a different protocol.
type NetworkConfig struct {
	// Name is the local handle used in Dial/Listen network strings and
	// DestinationConfig.Networks. Names match [a-zA-Z0-9_]+ so the
	// "-stream"/"-datagram2" suffix grammar stays unambiguous.
	Name      string
	NetworkID uint32
	NTCP2     TransportConfig
	SSU2      TransportConfig
	// Bootstrap seeds this context's NetDB — reseed URLs or literal
	// RouterInfos for the dedicated network.
	Bootstrap   BootstrapConfig
	Exploratory TunnelPoolConfig
	// Participation selects this context's contribution; zero selects
	// ParticipationWarm.
	Participation PublicParticipation
}

// NetworkOption configures a NetworkConfig component.
type NetworkOption func(*NetworkConfig)

// WithPublicParticipation sets the explicit participation level.
func WithPublicParticipation(p PublicParticipation) NetworkOption {
	return func(c *NetworkConfig) { c.Participation = p }
}

// WithReseedURLs configures the standard reseed URLs.
func WithReseedURLs(urls []string) NetworkOption {
	return func(c *NetworkConfig) { c.Bootstrap.ReseedURLs = append([]string(nil), urls...) }
}

// WithPriorityReseedURLs configures high-priority reseed URLs.
func WithPriorityReseedURLs(urls []string) NetworkOption {
	return func(c *NetworkConfig) { c.Bootstrap.PriorityReseedURLs = append([]string(nil), urls...) }
}

// WithBootstrap sets the complete bootstrap configuration.
func WithBootstrap(b BootstrapConfig) NetworkOption {
	return func(c *NetworkConfig) { c.Bootstrap = b }
}

// WithBootstrapRouterInfos seeds the context's NetDB with literal signed
// RouterInfos — the static membership of a dedicated network.
func WithBootstrapRouterInfos(infos ...[]byte) NetworkOption {
	return func(c *NetworkConfig) {
		c.Bootstrap.RouterInfos = append(c.Bootstrap.RouterInfos, infos...)
	}
}

// WithExploratoryPool configures the exploratory tunnel pool for NetDB routing.
func WithExploratoryPool(pool TunnelPoolConfig) NetworkOption {
	return func(c *NetworkConfig) { c.Exploratory = pool }
}

// WithTransportNTCP2 configures the NTCP2 transport.
func WithTransportNTCP2(cfg TransportConfig) NetworkOption {
	return func(c *NetworkConfig) { c.NTCP2 = cfg }
}

// WithTransportSSU2 configures the SSU2 transport.
func WithTransportSSU2(cfg TransportConfig) NetworkOption {
	return func(c *NetworkConfig) { c.SSU2 = cfg }
}

// DefaultI2PNetwork returns the official I2P network entry: netId 2, NTCP2 and
// SSU2 enabled, standard reseed endpoints, a warm exploratory pool, and
// ParticipationWarm.
func DefaultI2PNetwork() NetworkConfig {
	defaults := DefaultRouterConfig()
	return NetworkConfig{
		Name:          networkNativeName,
		NetworkID:     NetworkIDPublicI2P,
		NTCP2:         defaults.NTCP2,
		SSU2:          defaults.SSU2,
		Bootstrap:     defaults.Bootstrap,
		Exploratory:   defaults.Exploratory,
		Participation: ParticipationWarm,
	}
}

// NewNetwork builds a dedicated-network entry: the same I2P context shape with
// a different netId. NTCP2 and SSU2 come enabled by default; the caller
// supplies bootstrap seeds (WithBootstrapRouterInfos or WithReseedURLs) unless
// the network is expected to learn peers exclusively through other means.
func NewNetwork(name string, netID uint32, opts ...NetworkOption) NetworkConfig {
	defaults := DefaultRouterConfig()
	cfg := NetworkConfig{
		Name:          name,
		NetworkID:     netID,
		NTCP2:         defaults.NTCP2,
		SSU2:          defaults.SSU2,
		Exploratory:   defaults.Exploratory,
		Participation: ParticipationWarm,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// SetNetworks selects the multi-network form, clearing the legacy
// single-network fields so they cannot conflict with Networks.
func (c *RouterConfig) SetNetworks(entries ...NetworkConfig) {
	c.NetworkID = 0
	c.NTCP2 = TransportConfig{}
	c.SSU2 = TransportConfig{}
	c.Bootstrap = BootstrapConfig{}
	c.Exploratory = TunnelPoolConfig{}
	c.Networks = append([]NetworkConfig(nil), entries...)
}

// networkPlan validates the configured networks and resolves which entry
// serves unqualified dials. Networks empty is the legacy path: the top-level
// fields are the single "i2p" entry.
func networkPlan(cfg RouterConfig) ([]NetworkConfig, string, error) {
	networks := cfg.Networks
	if len(networks) == 0 {
		networks = []NetworkConfig{{
			Name: networkNativeName, NetworkID: cfg.NetworkID,
			NTCP2: cfg.NTCP2, SSU2: cfg.SSU2, Bootstrap: cfg.Bootstrap,
			Exploratory: cfg.Exploratory,
		}}
	} else if legacyNetworkSet(cfg) {
		return nil, "", &ConfigError{Field: "Networks", Err: errLegacyNetworkFields}
	}
	names := make(map[string]struct{}, len(networks))
	netIDs := make(map[uint32]struct{}, len(networks))
	for i := range networks {
		field := "Networks[" + strconv.Itoa(i) + "]"
		if !validNetworkName(networks[i].Name) {
			return nil, "", invalidConfig(field + ".Name")
		}
		if _, dup := names[networks[i].Name]; dup {
			return nil, "", invalidConfig(field + ".Name")
		}
		names[networks[i].Name] = struct{}{}
		if networks[i].NetworkID == 0 || networks[i].NetworkID > 255 {
			return nil, "", invalidConfig(field + ".NetworkID")
		}
		if _, dup := netIDs[networks[i].NetworkID]; dup {
			return nil, "", invalidConfig(field + ".NetworkID")
		}
		netIDs[networks[i].NetworkID] = struct{}{}
		if !networks[i].NTCP2.Enabled && !networks[i].SSU2.Enabled {
			return nil, "", invalidConfig(field + ".NTCP2.Enabled")
		}
		if err := validateTransport(field+".NTCP2", networks[i].NTCP2); err != nil {
			return nil, "", err
		}
		if err := validateTransport(field+".SSU2", networks[i].SSU2); err != nil {
			return nil, "", err
		}
		if err := validateTunnelPool(field+".Exploratory", networks[i].Exploratory); err != nil {
			return nil, "", err
		}
		if networks[i].Participation > ParticipationContributor {
			return nil, "", invalidConfig(field + ".Participation")
		}
		if err := validateBootstrap(field+".Bootstrap", networks[i].Bootstrap, networks[i].NetworkID); err != nil {
			return nil, "", err
		}
	}
	def, err := resolveDefaultNetwork(cfg, networks)
	if err != nil {
		return nil, "", err
	}
	return networks, def, nil
}

// validNetworkName accepts ASCII alphanumerics and underscore so a name never
// collides with the "-stream"/"-datagramN" protocol suffix grammar.
func validNetworkName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		alpha := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		if !alpha && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
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

// resolveDefaultNetwork determines which network handles generic "tcp", "udp",
// and unqualified operations: the configured DefaultNetwork when set, the
// netId=2 entry when present, and the first entry otherwise.
func resolveDefaultNetwork(cfg RouterConfig, networks []NetworkConfig) (string, error) {
	if cfg.DefaultNetwork != "" {
		for _, nc := range networks {
			if nc.Name == cfg.DefaultNetwork {
				return nc.Name, nil
			}
		}
		return "", &ConfigError{Field: "DefaultNetwork", Err: ErrInvalidConfig}
	}
	for _, nc := range networks {
		if nc.NetworkID == NetworkIDPublicI2P {
			return nc.Name, nil
		}
	}
	return networks[0].Name, nil
}

// validateBootstrap checks one context's reseed configuration; reseed URLs
// must carry the context's netId so a dedicated network cannot be seeded from
// an incompatible directory.
func validateBootstrap(field string, b BootstrapConfig, netID uint32) error {
	if b.ReseedTimeout < 0 || (len(b.ReseedURLs) > 0 && b.ReseedTimeout == 0) {
		return invalidConfig(field + ".ReseedTimeout")
	}
	if b.PriorityReseedTimeout < 0 || (len(b.PriorityReseedURLs) > 0 && b.PriorityReseedTimeout == 0) {
		return invalidConfig(field + ".PriorityReseedTimeout")
	}
	if len(b.ReseedURLs) > 32 {
		return invalidConfig(field + ".ReseedURLs")
	}
	if len(b.PriorityReseedURLs) > 32 {
		return invalidConfig(field + ".PriorityReseedURLs")
	}
	requiredQuery := "netid=" + strconv.FormatUint(uint64(netID), 10)
	for i, text := range append(append([]string(nil), b.ReseedURLs...), b.PriorityReseedURLs...) {
		u, err := url.Parse(text)
		if err != nil {
			return invalidConfig(field + ".ReseedURLs[" + strconv.Itoa(i) + "]")
		}
		validEndpoint := len(text) <= 512 && u.Scheme == "https" && u.Hostname() != ""
		forbiddenParts := u.User != nil || u.Fragment != "" || u.ForceQuery
		if !validEndpoint || forbiddenParts || u.RawQuery != requiredQuery {
			return invalidConfig(field + ".ReseedURLs[" + strconv.Itoa(i) + "]")
		}
	}
	return nil
}

// networkSpecs lowers the validated network entries to per-context specs. Each
// context gets its own operating configuration — including an isolated state
// directory under the persistence root named after the network — and its own
// controller options so tests can inject transports per context.
func networkSpecs(cfg RouterConfig) ([]node.NetworkSpec, string, error) {
	networks, def, err := networkPlan(cfg)
	if err != nil {
		return nil, "", err
	}
	if cfg.Limits.MaxDestinations < 1 {
		return nil, "", invalidConfig("Limits.MaxDestinations")
	}
	if cfg.Limits.PacketQueueBytes <= 0 {
		return nil, "", invalidConfig("Limits.PacketQueueBytes")
	}
	if cfg.Limits.MaxPendingPacketWrites <= 0 {
		return nil, "", invalidConfig("Limits.MaxPendingPacketWrites")
	}
	var baseDir string
	if cfg.Persistence != nil {
		if cfg.Persistence.Directory == "" || strings.IndexByte(cfg.Persistence.Directory, 0) >= 0 {
			return nil, "", invalidConfig("Persistence.Directory")
		}
		baseDir, err = filepath.Abs(cfg.Persistence.Directory)
		if err != nil {
			return nil, "", &ConfigError{Field: "Persistence.Directory", Err: err}
		}
	}
	multi := len(cfg.Networks) != 0
	specs := make([]node.NetworkSpec, 0, len(networks))
	for i := range networks {
		nc := networks[i]
		operating := state.ConfigurationDefaultOperating()
		operating.DataDir, operating.StateDir, operating.StatePath, operating.KeyPath = "", "", "", ""
		var options controlplane.ControllerOptions
		if cfg.Persistence != nil {
			directory := baseDir
			if multi {
				directory = filepath.Join(baseDir, nc.Name)
			}
			operating.DataDir, operating.StateDir = directory, directory
			operating.StatePath, operating.KeyPath = filepath.Join(directory, "router.state"), filepath.Join(directory, "router.keys")
			if cfg.Persistence.TempDir != "" {
				if strings.IndexByte(cfg.Persistence.TempDir, 0) >= 0 {
					return nil, "", invalidConfig("Persistence.TempDir")
				}
				tempDir, err := filepath.Abs(cfg.Persistence.TempDir)
				if err != nil {
					return nil, "", &ConfigError{Field: "Persistence.TempDir", Err: err}
				}
				operating.TempDir = tempDir
			}
			taintedCopy := !cfg.Persistence.DisableTaintedCopy || cfg.Persistence.TaintedCopy
			operating.State.TaintedCopy = taintedCopy
			options.TaintedCopy = cfg.Persistence.TaintedCopy
			promoteToMaster := true
			if cfg.Persistence.PromoteToMaster != nil {
				promoteToMaster = *cfg.Persistence.PromoteToMaster
			}
			operating.State.PromoteToMaster = promoteToMaster
			options.PromoteToMaster = &promoteToMaster
			lockRetry := cfg.Persistence.LockRetryInterval
			if lockRetry <= 0 {
				lockRetry = 15 * time.Second
			}
			operating.State.LockRetryInterval = lockRetry
			options.LockRetryInterval = lockRetry
		}
		operating.Network = state.ConfigurationNetwork{ID: nc.NetworkID}
		for _, transport := range []TransportConfig{nc.NTCP2, nc.SSU2} {
			if transport.Enabled {
				operating.Network.IPv4 = operating.Network.IPv4 || transport.Bind.Addr().Is4()
				operating.Network.IPv6 = operating.Network.IPv6 || transport.Bind.Addr().Is6()
			}
		}
		operating.NTCP2, operating.SSU2 = runtimeTransport(nc.NTCP2), runtimeTransport(nc.SSU2)
		operating.Reseed.Enabled = len(nc.Bootstrap.ReseedURLs) != 0 || len(nc.Bootstrap.PriorityReseedURLs) != 0
		operating.Reseed.PriorityEndpoints = append([]string(nil), nc.Bootstrap.PriorityReseedURLs...)
		operating.Reseed.PriorityTimeout = nc.Bootstrap.PriorityReseedTimeout
		operating.Reseed.Endpoints = append([]string(nil), nc.Bootstrap.ReseedURLs...)
		operating.Reseed.Timeout = nc.Bootstrap.ReseedTimeout
		operating.NetDB.BootstrapRouterInfoPaths = nil
		operating.Control, operating.SOCKS5, operating.Metrics, operating.SAM = state.ConfigurationListener{}, state.ConfigurationListener{}, state.ConfigurationListener{}, state.ConfigurationListener{}
		operating.HTTPProxy = state.ConfigurationHTTPProxy{}
		operating.AddressBook = state.ConfigurationAddressBook{}
		operating.NAT.NATPMPEndpoint, operating.NAT.UPnPEndpoint = netip.AddrPort{}, ""
		operating.State.MaxDestinations = cfg.Limits.MaxDestinations
		participation := cmp.Or(nc.Participation, ParticipationWarm)
		operating.Router.Transit = participation >= ParticipationWarm
		operating.Router.Floodfill = participation == ParticipationContributor
		pool := nc.Exploratory
		options.Embedded, options.Exploratory, options.Logger = true, &pool, cfg.Logger
		options.BootstrapRouterInfos = make([][]byte, len(nc.Bootstrap.RouterInfos))
		for j, raw := range nc.Bootstrap.RouterInfos {
			options.BootstrapRouterInfos[j] = append([]byte(nil), raw...)
		}
		specs = append(specs, node.NetworkSpec{Name: nc.Name, Operating: operating, Options: options})
	}
	return specs, def, nil
}
