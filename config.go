package ivnp

import (
	"bytes"
	"crypto/ecdh"
	"log/slog"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/node"
	"gosuda.org/ivnp/state"
)

type RouterConfig struct {
	Persistence *PersistenceConfig
	// NetworkID through Exploratory configure the official I2P network. When
	// Networks is non-empty they must all be zero — the "i2p" entry carries
	// them instead.
	NetworkID   uint32
	NTCP2       TransportConfig
	SSU2        TransportConfig
	Bootstrap   BootstrapConfig
	Exploratory TunnelPoolConfig
	Limits      RouterLimits
	Resolver    NameResolver
	Logger      *slog.Logger
	// DefaultNetwork specifies which network handles generic "tcp", "udp",
	// and unqualified "stream"/"packet" operations. If empty, defaults to "i2p".
	DefaultNetwork string
	// Networks is the multi-network list: exactly one NetworkNativeI2P entry
	// named "i2p" plus any number of NetworkIVNPFabric entries. Non-empty
	// requires Realm.
	Networks []NetworkConfig
	// Realm enables the overlay host over the configured networks.
	Realm *RealmProfile
	// Policy is an alias for Realm, configuring multi-network routing and discovery policies.
	Policy *OverlayPolicy
	// Transports registers custom TransportProviders with the overlay host.
	Transports []TransportProvider
	// CustomProviders registers custom overlay providers (e.g. CredentialVerifier,
	// IdentityProvider, TrustProvider, etc.) with the overlay host.
	CustomProviders []any
}

type PersistenceConfig struct {
	Directory          string
	TempDir            string
	DisableTaintedCopy bool
	TaintedCopy        bool
	PromoteToMaster    *bool
	LockRetryInterval  time.Duration
}

// DefaultPersistenceConfig returns persistence configuration with tmp-based
// optimistic locking and master lock escalation enabled.
func DefaultPersistenceConfig(directory string) *PersistenceConfig {
	promote := true
	return &PersistenceConfig{
		Directory:         directory,
		PromoteToMaster:   &promote,
		LockRetryInterval: 15 * time.Second,
	}
}

type TransportConfig struct {
	Enabled     bool
	Bind        netip.AddrPort
	Advertised  netip.AddrPort
	MaxSessions int
	IdleTimeout time.Duration
}

type BootstrapConfig struct {
	RouterInfos           [][]byte
	PriorityReseedURLs    []string
	PriorityReseedTimeout time.Duration
	ReseedURLs            []string
	ReseedTimeout         time.Duration
}

type TunnelPoolConfig = destination.TunnelPoolConfig
type TunnelDirectionConfig = destination.TunnelDirectionConfig
type RemoteAuthKind = destination.RemoteAuthKind
type RemoteLeaseSetAccess = destination.RemoteLeaseSetAccess

const (
	RemoteAuthNone = destination.RemoteAuthNone
	RemoteAuthDH   = destination.RemoteAuthDH
	RemoteAuthPSK  = destination.RemoteAuthPSK
)

type RouterLimits struct {
	MaxDestinations        int
	PacketQueueBytes       int64
	MaxPendingPacketWrites int
}

type DestinationConfig struct {
	Identity     *foundation.LocalDestination
	Policy       DestinationPolicy
	Tunnels      TunnelPoolConfig
	PacketQueue  PacketQueueConfig
	RemoteAccess []RemoteLeaseSetAccess
	// Networks names the RouterConfig.Networks entries this destination's
	// overlay service may use; empty allows every realm-bound network.
	Networks []string
	// Overlay opens a realm service for this destination. Its EndpointID is
	// the destination hash, so b32 and ivnp:// names identify the same peer.
	Overlay *ServiceProfile
}

type PacketQueueConfig struct {
	MaxPackets int
	MaxBytes   int64
}

func DefaultRouterConfig() RouterConfig {
	defaults := state.ConfigurationDefaultOperating()
	transport := TransportConfig{Enabled: true, Bind: netip.AddrPortFrom(netip.IPv4Unspecified(), 0), MaxSessions: 256, IdleTimeout: 10 * time.Minute}
	return RouterConfig{
		NetworkID: 2, NTCP2: transport, SSU2: transport,
		Bootstrap: BootstrapConfig{
			PriorityReseedURLs:    append([]string(nil), defaults.Reseed.PriorityEndpoints...),
			PriorityReseedTimeout: defaults.Reseed.PriorityTimeout,
			ReseedURLs:            append([]string(nil), defaults.Reseed.Endpoints...),
			ReseedTimeout:         defaults.Reseed.Timeout,
		},
		Exploratory: defaultExploratoryTunnelPool(4),
		Limits:      RouterLimits{MaxDestinations: 64, PacketQueueBytes: 64 << 20, MaxPendingPacketWrites: 64},
	}
}

func DefaultDestinationConfig() DestinationConfig {
	return DestinationConfig{Policy: DestinationPolicy{Kind: DestinationPublicLS2}, Tunnels: defaultTunnelPool(2), PacketQueue: PacketQueueConfig{MaxPackets: 64, MaxBytes: 1 << 20}}
}

func defaultExploratoryTunnelPool(count int) TunnelPoolConfig {
	direction := TunnelDirectionConfig{Hops: 2, Count: count}
	return TunnelPoolConfig{Inbound: direction, Outbound: direction, RenewBefore: 210 * time.Second}
}

func defaultTunnelPool(count int) TunnelPoolConfig {
	direction := TunnelDirectionConfig{Hops: 3, Count: count}
	return TunnelPoolConfig{Inbound: direction, Outbound: direction, RenewBefore: 210 * time.Second}
}

func validateTunnelPool(field string, pool TunnelPoolConfig) error {
	for _, direction := range []struct {
		name   string
		config TunnelDirectionConfig
	}{{"Inbound", pool.Inbound}, {"Outbound", pool.Outbound}} {
		prefix := field + "." + direction.name
		if direction.config.Hops < 1 || direction.config.Hops > 7 {
			return invalidConfig(prefix + ".Hops")
		}
		if direction.config.Count < 1 || direction.config.Count > 16 {
			return invalidConfig(prefix + ".Count")
		}
		if direction.config.Backup < 0 || direction.config.Backup > 15 || direction.config.Backup > 16-direction.config.Count {
			return invalidConfig(prefix + ".Backup")
		}
	}
	if pool.RenewBefore < time.Second || pool.RenewBefore >= 10*time.Minute {
		return invalidConfig(field + ".RenewBefore")
	}
	if pool.BuildPendingCapacity < 0 || pool.BuildPendingCapacity > 256 {
		return invalidConfig(field + ".BuildPendingCapacity")
	}
	return nil
}

func validateTransport(field string, transport TransportConfig) error {
	if !transport.Enabled {
		if transport != (TransportConfig{}) {
			return invalidConfig(field)
		}
		return nil
	}
	bind := transport.Bind.Addr()
	if !transport.Bind.IsValid() || bind.Is4In6() || bind.IsMulticast() || bind.Zone() != "" {
		return invalidConfig(field + ".Bind")
	}
	if transport.Advertised != (netip.AddrPort{}) {
		advertised := transport.Advertised.Addr()
		validEndpoint := transport.Advertised.IsValid() && transport.Advertised.Port() != 0
		validAddress := !advertised.Is4In6() && advertised.IsGlobalUnicast() && advertised.Zone() == ""
		if !validEndpoint || !validAddress || advertised.Is4() != bind.Is4() {
			return invalidConfig(field + ".Advertised")
		}
	}
	if transport.MaxSessions <= 0 {
		return invalidConfig(field + ".MaxSessions")
	}
	if transport.IdleTimeout <= 0 {
		return invalidConfig(field + ".IdleTimeout")
	}
	return nil
}

func routerSettings(cfg RouterConfig) (state.ConfigurationOperating, controlplane.ControllerOptions, *node.OverlaySpec, error) {
	var empty state.ConfigurationOperating
	var options controlplane.ControllerOptions
	native, spec, err := networkPlan(cfg)
	if err != nil {
		return empty, options, nil, err
	}
	if native.NetworkID > 255 {
		return empty, options, nil, invalidConfig("NetworkID")
	}
	if !native.NTCP2.Enabled && !native.SSU2.Enabled {
		return empty, options, nil, invalidConfig("NTCP2.Enabled")
	}
	if err := validateTransport("NTCP2", native.NTCP2); err != nil {
		return empty, options, nil, err
	}
	if err := validateTransport("SSU2", native.SSU2); err != nil {
		return empty, options, nil, err
	}
	if err := validateTunnelPool("Exploratory", native.Exploratory); err != nil {
		return empty, options, nil, err
	}
	if cfg.Limits.MaxDestinations < 1 {
		return empty, options, nil, invalidConfig("Limits.MaxDestinations")
	}
	if cfg.Limits.PacketQueueBytes <= 0 {
		return empty, options, nil, invalidConfig("Limits.PacketQueueBytes")
	}
	if cfg.Limits.MaxPendingPacketWrites <= 0 {
		return empty, options, nil, invalidConfig("Limits.MaxPendingPacketWrites")
	}
	if native.Bootstrap.ReseedTimeout < 0 || (len(native.Bootstrap.ReseedURLs) > 0 && native.Bootstrap.ReseedTimeout == 0) {
		return empty, options, nil, invalidConfig("Bootstrap.ReseedTimeout")
	}
	if native.Bootstrap.PriorityReseedTimeout < 0 || (len(native.Bootstrap.PriorityReseedURLs) > 0 && native.Bootstrap.PriorityReseedTimeout == 0) {
		return empty, options, nil, invalidConfig("Bootstrap.PriorityReseedTimeout")
	}
	if len(native.Bootstrap.ReseedURLs) > 32 {
		return empty, options, nil, invalidConfig("Bootstrap.ReseedURLs")
	}
	if len(native.Bootstrap.PriorityReseedURLs) > 32 {
		return empty, options, nil, invalidConfig("Bootstrap.PriorityReseedURLs")
	}
	requiredQuery := "netid=" + strconv.FormatUint(uint64(native.NetworkID), 10)
	for i, text := range native.Bootstrap.ReseedURLs {
		u, err := url.Parse(text)
		if err != nil {
			return empty, options, nil, invalidConfig("Bootstrap.ReseedURLs[" + strconv.Itoa(i) + "]")
		}
		validEndpoint := len(text) <= 512 && u.Scheme == "https" && u.Hostname() != ""
		forbiddenParts := u.User != nil || u.Fragment != "" || u.ForceQuery
		if !validEndpoint || forbiddenParts || u.RawQuery != requiredQuery {
			return empty, options, nil, invalidConfig("Bootstrap.ReseedURLs[" + strconv.Itoa(i) + "]")
		}
	}
	for i, text := range native.Bootstrap.PriorityReseedURLs {
		u, err := url.Parse(text)
		if err != nil {
			return empty, options, nil, invalidConfig("Bootstrap.PriorityReseedURLs[" + strconv.Itoa(i) + "]")
		}
		validEndpoint := len(text) <= 512 && u.Scheme == "https" && u.Hostname() != ""
		forbiddenParts := u.User != nil || u.Fragment != "" || u.ForceQuery
		if !validEndpoint || forbiddenParts || u.RawQuery != requiredQuery {
			return empty, options, nil, invalidConfig("Bootstrap.PriorityReseedURLs[" + strconv.Itoa(i) + "]")
		}
	}
	operating := state.ConfigurationDefaultOperating()
	operating.DataDir, operating.StateDir, operating.StatePath, operating.KeyPath = "", "", "", ""
	if cfg.Persistence != nil {
		if cfg.Persistence.Directory == "" || strings.IndexByte(cfg.Persistence.Directory, 0) >= 0 {
			return empty, options, nil, invalidConfig("Persistence.Directory")
		}
		directory, err := filepath.Abs(cfg.Persistence.Directory)
		if err != nil {
			return empty, options, nil, &ConfigError{Field: "Persistence.Directory", Err: err}
		}
		operating.DataDir, operating.StateDir = directory, directory
		operating.StatePath, operating.KeyPath = filepath.Join(directory, "router.state"), filepath.Join(directory, "router.keys")
		if cfg.Persistence.TempDir != "" {
			if strings.IndexByte(cfg.Persistence.TempDir, 0) >= 0 {
				return empty, options, nil, invalidConfig("Persistence.TempDir")
			}
			tempDir, err := filepath.Abs(cfg.Persistence.TempDir)
			if err != nil {
				return empty, options, nil, &ConfigError{Field: "Persistence.TempDir", Err: err}
			}
			operating.TempDir = tempDir
		}
		taintedCopy := !cfg.Persistence.DisableTaintedCopy
		if cfg.Persistence.TaintedCopy {
			taintedCopy = true
		}
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
	operating.Network = state.ConfigurationNetwork{ID: native.NetworkID}
	for _, transport := range []TransportConfig{native.NTCP2, native.SSU2} {
		if transport.Enabled {
			operating.Network.IPv4 = operating.Network.IPv4 || transport.Bind.Addr().Is4()
			operating.Network.IPv6 = operating.Network.IPv6 || transport.Bind.Addr().Is6()
		}
	}
	operating.NTCP2, operating.SSU2 = runtimeTransport(native.NTCP2), runtimeTransport(native.SSU2)
	operating.Reseed.Enabled = len(native.Bootstrap.ReseedURLs) != 0 || len(native.Bootstrap.PriorityReseedURLs) != 0
	operating.Reseed.Required = false
	operating.Reseed.PriorityEndpoints = append([]string(nil), native.Bootstrap.PriorityReseedURLs...)
	operating.Reseed.PriorityTimeout = native.Bootstrap.PriorityReseedTimeout
	operating.Reseed.Endpoints = append([]string(nil), native.Bootstrap.ReseedURLs...)
	operating.Reseed.Timeout = native.Bootstrap.ReseedTimeout
	operating.NetDB.BootstrapRouterInfoPaths = nil
	operating.Control, operating.SOCKS5, operating.Metrics, operating.SAM = state.ConfigurationListener{}, state.ConfigurationListener{}, state.ConfigurationListener{}, state.ConfigurationListener{}
	operating.HTTPProxy = state.ConfigurationHTTPProxy{}
	operating.AddressBook = state.ConfigurationAddressBook{}
	operating.NAT.NATPMPEndpoint, operating.NAT.UPnPEndpoint = netip.AddrPort{}, ""
	operating.State.MaxDestinations = cfg.Limits.MaxDestinations
	participation := nativeParticipation(native)
	operating.Router.Transit = participation >= ParticipationWarm
	operating.Router.Floodfill = participation == ParticipationContributor
	pool := native.Exploratory
	options.Embedded, options.Exploratory, options.Logger = true, &pool, cfg.Logger
	options.BootstrapRouterInfos = make([][]byte, len(native.Bootstrap.RouterInfos))
	for i, raw := range native.Bootstrap.RouterInfos {
		options.BootstrapRouterInfos[i] = append([]byte(nil), raw...)
	}
	if spec != nil {
		spec.NativeStateDir = operating.StateDir
	}
	return operating, options, spec, nil
}

func runtimeTransport(cfg TransportConfig) state.ConfigurationTransport {
	if !cfg.Enabled {
		return state.ConfigurationTransport{}
	}
	transport := state.ConfigurationTransport{Enabled: true, Bind: state.ConfigurationEndpoint{Host: cfg.Bind.Addr().String(), Port: cfg.Bind.Port()}, MaxSessions: cfg.MaxSessions, IdleTimeout: cfg.IdleTimeout}
	if cfg.Advertised.IsValid() {
		transport.Advertised = state.ConfigurationEndpoint{Host: cfg.Advertised.Addr().String(), Port: cfg.Advertised.Port()}
	}
	return transport
}

func destinationSpec(cfg DestinationConfig) (destination.DestinationSpec, error) {
	if err := validateTunnelPool("Tunnels", cfg.Tunnels); err != nil {
		return destination.DestinationSpec{}, err
	}
	if cfg.PacketQueue.MaxPackets <= 0 {
		return destination.DestinationSpec{}, invalidConfig("PacketQueue.MaxPackets")
	}
	if cfg.PacketQueue.MaxBytes < MaxReceiveDatagramSize {
		return destination.DestinationSpec{}, invalidConfig("PacketQueue.MaxBytes")
	}
	if err := cfg.Policy.Validate(); err != nil {
		return destination.DestinationSpec{}, &ConfigError{Field: "Policy", Err: err}
	}
	if cfg.Identity != nil {
		identity, err := cfg.Identity.Identity()
		if err != nil {
			return destination.DestinationSpec{}, &ConfigError{Field: "Identity", Err: err}
		}
		supportedCrypto := identity.CryptoKeyType() == foundation.CryptoX25519 || identity.CryptoKeyType() == foundation.CryptoElGamal
		supportedSigning := identity.SigningKeyType() == foundation.SigningEdDSASHA512Ed25519 || identity.SigningKeyType() == foundation.SigningRedDSASHA512Ed25519
		if !supportedCrypto || !supportedSigning {
			return destination.DestinationSpec{}, &ConfigError{Field: "Identity", Err: ErrUnsupportedIdentity}
		}
		if _, offline := cfg.Identity.OfflineSignature(); offline && cfg.Policy.Kind != DestinationPublicLS2 {
			return destination.DestinationSpec{}, &ConfigError{Field: "Identity", Err: ErrUnsupportedIdentity}
		}
	}
	seen := make(map[Hash]struct{}, len(cfg.RemoteAccess))
	for i, access := range cfg.RemoteAccess {
		field := "RemoteAccess[" + strconv.Itoa(i) + "]"
		identity, n, err := foundation.ParseIdentity(access.Identity)
		if err != nil || n != len(access.Identity) || identity.Hash() == (Hash{}) {
			return destination.DestinationSpec{}, invalidConfig(field + ".Identity")
		}
		if identity.SigningKeyType() != foundation.SigningEdDSASHA512Ed25519 && identity.SigningKeyType() != foundation.SigningRedDSASHA512Ed25519 {
			return destination.DestinationSpec{}, &ConfigError{Field: field + ".Identity", Err: ErrUnsupportedIdentity}
		}
		if _, exists := seen[identity.Hash()]; exists {
			return destination.DestinationSpec{}, invalidConfig(field + ".Identity")
		}
		seen[identity.Hash()] = struct{}{}
		if len(access.Secret) > 0xffff {
			return destination.DestinationSpec{}, invalidConfig(field + ".Secret")
		}
		switch access.Kind {
		case RemoteAuthNone:
			if access.DHPrivate != ([32]byte{}) || access.DHPublic != ([32]byte{}) || access.PSK != ([32]byte{}) {
				return destination.DestinationSpec{}, invalidConfig(field)
			}
		case RemoteAuthDH:
			private, err := ecdh.X25519().NewPrivateKey(access.DHPrivate[:])
			if err != nil || !bytes.Equal(private.PublicKey().Bytes(), access.DHPublic[:]) || access.PSK != ([32]byte{}) {
				return destination.DestinationSpec{}, invalidConfig(field)
			}
		case RemoteAuthPSK:
			if access.DHPrivate != ([32]byte{}) || access.DHPublic != ([32]byte{}) {
				return destination.DestinationSpec{}, invalidConfig(field)
			}
		default:
			return destination.DestinationSpec{}, invalidConfig(field + ".Kind")
		}
	}
	pool := cfg.Tunnels
	spec := destination.DestinationSpec{Local: cfg.Identity, Tunnels: &pool, Policy: destination.LeaseSetPolicy{Encrypted: cfg.Policy.Kind != DestinationPublicLS2, Secret: append([]byte(nil), cfg.Policy.Secret...), DHClients: append([][32]byte(nil), cfg.Policy.DHClients...), PSKClients: append([][32]byte(nil), cfg.Policy.PSKClients...)}, RemoteAccess: make([]RemoteLeaseSetAccess, len(cfg.RemoteAccess))}
	for i, access := range cfg.RemoteAccess {
		spec.RemoteAccess[i] = access
		spec.RemoteAccess[i].Identity = append([]byte(nil), access.Identity...)
		spec.RemoteAccess[i].Secret = append([]byte(nil), access.Secret...)
	}
	return spec, nil
}

func wipeDestinationSpec(spec *destination.DestinationSpec) {
	clear(spec.Policy.Secret)
	clear(spec.Policy.DHClients)
	clear(spec.Policy.PSKClients)
	for i := range spec.RemoteAccess {
		clear(spec.RemoteAccess[i].Identity)
		clear(spec.RemoteAccess[i].Secret)
		spec.RemoteAccess[i] = RemoteLeaseSetAccess{}
	}
}
