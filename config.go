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
	"gosuda.org/ivnp/state"
)

type RouterConfig struct {
	Persistence *PersistenceConfig
	NetworkID   uint32
	NTCP2       TransportConfig
	SSU2        TransportConfig
	Bootstrap   BootstrapConfig
	Exploratory TunnelPoolConfig
	Limits      RouterLimits
	Resolver    NameResolver
	Logger      *slog.Logger
}

type PersistenceConfig struct{ Directory string }

type TransportConfig struct {
	Enabled     bool
	Bind        netip.AddrPort
	Advertised  netip.AddrPort
	MaxSessions int
	IdleTimeout time.Duration
}

type BootstrapConfig struct {
	RouterInfos   [][]byte
	ReseedURLs    []string
	ReseedTimeout time.Duration
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
		Bootstrap:   BootstrapConfig{ReseedURLs: defaults.Reseed.Endpoints, ReseedTimeout: 30 * time.Second},
		Exploratory: defaultTunnelPool(4),
		Limits:      RouterLimits{MaxDestinations: 64, PacketQueueBytes: 64 << 20, MaxPendingPacketWrites: 64},
	}
}

func DefaultDestinationConfig() DestinationConfig {
	return DestinationConfig{Policy: DestinationPolicy{Kind: DestinationPublicLS2}, Tunnels: defaultTunnelPool(2), PacketQueue: PacketQueueConfig{MaxPackets: 64, MaxBytes: 1 << 20}}
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
	var empty state.ConfigurationOperating
	var options controlplane.ControllerOptions
	if cfg.NetworkID > 255 {
		return empty, options, invalidConfig("NetworkID")
	}
	if !cfg.NTCP2.Enabled && !cfg.SSU2.Enabled {
		return empty, options, invalidConfig("NTCP2.Enabled")
	}
	if err := validateTransport("NTCP2", cfg.NTCP2); err != nil {
		return empty, options, err
	}
	if err := validateTransport("SSU2", cfg.SSU2); err != nil {
		return empty, options, err
	}
	if err := validateTunnelPool("Exploratory", cfg.Exploratory); err != nil {
		return empty, options, err
	}
	if cfg.Limits.MaxDestinations < 1 || cfg.Limits.MaxDestinations > 64 {
		return empty, options, invalidConfig("Limits.MaxDestinations")
	}
	if cfg.Limits.PacketQueueBytes <= 0 {
		return empty, options, invalidConfig("Limits.PacketQueueBytes")
	}
	if cfg.Limits.MaxPendingPacketWrites <= 0 {
		return empty, options, invalidConfig("Limits.MaxPendingPacketWrites")
	}
	if cfg.Bootstrap.ReseedTimeout < 0 || (len(cfg.Bootstrap.ReseedURLs) > 0 && cfg.Bootstrap.ReseedTimeout == 0) {
		return empty, options, invalidConfig("Bootstrap.ReseedTimeout")
	}
	if len(cfg.Bootstrap.ReseedURLs) > 32 {
		return empty, options, invalidConfig("Bootstrap.ReseedURLs")
	}
	requiredQuery := "netid=" + strconv.FormatUint(uint64(cfg.NetworkID), 10)
	for i, text := range cfg.Bootstrap.ReseedURLs {
		u, err := url.Parse(text)
		if err != nil {
			return empty, options, invalidConfig("Bootstrap.ReseedURLs[" + strconv.Itoa(i) + "]")
		}
		validEndpoint := len(text) <= 512 && u.Scheme == "https" && u.Hostname() != ""
		forbiddenParts := u.User != nil || u.Fragment != "" || u.ForceQuery
		if !validEndpoint || forbiddenParts || u.RawQuery != requiredQuery {
			return empty, options, invalidConfig("Bootstrap.ReseedURLs[" + strconv.Itoa(i) + "]")
		}
	}
	operating := state.ConfigurationDefaultOperating()
	operating.DataDir, operating.StateDir, operating.StatePath, operating.KeyPath = "", "", "", ""
	if cfg.Persistence != nil {
		if cfg.Persistence.Directory == "" || strings.IndexByte(cfg.Persistence.Directory, 0) >= 0 {
			return empty, options, invalidConfig("Persistence.Directory")
		}
		directory, err := filepath.Abs(cfg.Persistence.Directory)
		if err != nil {
			return empty, options, &ConfigError{Field: "Persistence.Directory", Err: err}
		}
		operating.DataDir, operating.StateDir = directory, directory
		operating.StatePath, operating.KeyPath = filepath.Join(directory, "router.state"), filepath.Join(directory, "router.keys")
	}
	operating.Network = state.ConfigurationNetwork{ID: cfg.NetworkID}
	for _, transport := range []TransportConfig{cfg.NTCP2, cfg.SSU2} {
		if transport.Enabled {
			operating.Network.IPv4 = operating.Network.IPv4 || transport.Bind.Addr().Is4()
			operating.Network.IPv6 = operating.Network.IPv6 || transport.Bind.Addr().Is6()
		}
	}
	operating.NTCP2, operating.SSU2 = runtimeTransport(cfg.NTCP2), runtimeTransport(cfg.SSU2)
	operating.Reseed.Enabled = len(cfg.Bootstrap.ReseedURLs) != 0
	operating.Reseed.Required = false
	operating.Reseed.Endpoints = append([]string(nil), cfg.Bootstrap.ReseedURLs...)
	operating.Reseed.Timeout = cfg.Bootstrap.ReseedTimeout
	operating.NetDB.BootstrapRouterInfoPaths = nil
	operating.Control, operating.SOCKS5, operating.Metrics, operating.SAM = state.ConfigurationListener{}, state.ConfigurationListener{}, state.ConfigurationListener{}, state.ConfigurationListener{}
	operating.HTTPProxy = state.ConfigurationHTTPProxy{}
	operating.AddressBook = state.ConfigurationAddressBook{}
	operating.NAT.NATPMPEndpoint, operating.NAT.UPnPEndpoint = netip.AddrPort{}, ""
	operating.State.MaxDestinations = cfg.Limits.MaxDestinations
	pool := cfg.Exploratory
	options.Embedded, options.Exploratory, options.Logger = true, &pool, cfg.Logger
	options.BootstrapRouterInfos = make([][]byte, len(cfg.Bootstrap.RouterInfos))
	for i, raw := range cfg.Bootstrap.RouterInfos {
		options.BootstrapRouterInfos[i] = append([]byte(nil), raw...)
	}
	return operating, options, nil
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
