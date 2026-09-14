package ivnp

import (
	"bytes"
	"crypto/ecdh"
	"log/slog"
	"net/netip"
	"strconv"
	"time"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/state"
)

type RouterConfig struct {
	Persistence *PersistenceConfig
	// NetworkID through Exploratory configure a single I2P context — the
	// official network when NetworkID is 2. When Networks is non-empty they
	// must all be zero; each entry carries them instead.
	NetworkID   uint32
	NTCP2       TransportConfig
	SSU2        TransportConfig
	Bootstrap   BootstrapConfig
	Exploratory TunnelPoolConfig
	Limits      RouterLimits
	Resolver    NameResolver
	Logger      *slog.Logger
	// DefaultNetwork names the Networks entry serving unqualified "tcp"/"udp"
	// operations. Empty selects the netId=2 entry, or the first entry when no
	// public context is configured.
	DefaultNetwork string
	// Networks lists the I2P protocol contexts this router serves — one
	// independent network (own transports, own NetDB) per entry, each scoped
	// to its netId.
	Networks []NetworkConfig
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
	// Networks names the RouterConfig.Networks entries this destination binds;
	// each bound network gets its own endpoint over the same identity, so one
	// destination address is reachable on every bound network. Empty binds the
	// default network only. Unqualified dials race every bound network.
	Networks []string
	// DialPolicy configures how unqualified dials ("tcp", "stream", "ivnp")
	// explore the bound networks. If omitted, DialHappyEyeballs is used across all
	// bound networks.
	DialPolicy DialPolicy
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

func routerSettings(cfg RouterConfig) (state.ConfigurationOperating, controlplane.ControllerOptions, error) {
	specs, _, err := networkSpecs(cfg)
	if err != nil {
		return state.ConfigurationOperating{}, controlplane.ControllerOptions{}, err
	}
	return specs[0].Operating, specs[0].Options, nil
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
