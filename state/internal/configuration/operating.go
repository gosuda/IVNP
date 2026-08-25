package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"gosuda.org/ivnp/state/internal/filesystem_store"
)

// ErrInvalidOperating reports a syntactically valid file with an unsafe or unsupported operating value.

var ErrInvalidOperating = errors.New("config: invalid operating configuration")

// Operating is the complete process configuration. Paths are absolute and
// bearer tokens are never included in its String representation.
type Operating struct {
	DataDir   string
	StateDir  string
	StatePath string
	KeyPath   string
	Network   Network
	Router    Router
	State     State
	NetDB     NetDB
	Tunnel    Tunnel

	NTCP2  Transport
	SSU2   Transport
	Reseed Reseed
	NAT    NAT

	Control     Listener
	HTTPProxy   Listener
	SOCKS5      Listener
	Metrics     Listener
	SAM         Listener
	AddressBook AddressBook
	Log         Log
}

// Network selects the I2P network and supported IP families.
type Network struct {
	ID   uint32
	IPv4 bool
	IPv6 bool
}

// Router contains identity-related public RouterInfo settings.
type Router struct {
	IdentityType string
	Family       string
	Version      string
}

// NetDB bounds the local RouterInfo routing-table buckets and optionally names
// exact signed RouterInfo files to admit during startup. BootstrapRouterInfoPaths
// is empty by default; configured files are not a replacement for reseed.
type NetDB struct {
	BucketCapacity           int
	BootstrapRouterInfoPaths []string
}

// Tunnel bounds the paired client tunnel pools. A pool must have enough
// capacity for its live target plus one renewing generation.
type Tunnel struct {
	Enabled                     bool
	Hops                        int
	InboundTarget               int
	OutboundTarget              int
	PoolCapacity                int
	BuildPendingCapacity        int
	Lifetime                    time.Duration
	RenewBefore                 time.Duration
	MaintenanceInterval         time.Duration
	BandwidthRateBytesPerSecond int
	BandwidthBurstBytes         int
}

// State sets the durable-state admission limits.
type State struct {
	MaxBytes        int64
	MaxDestinations int
	MaxNameBytes    int
}

// Endpoint is an IP socket endpoint. Host is a canonical IP literal.
type Endpoint struct {
	Host string
	Port uint16
}

func (e Endpoint) String() string { return net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))) }

// Transport controls one native I2P transport. Advertised is empty when
// address publication is left to a later runtime mechanism.
type Transport struct {
	Enabled     bool
	Bind        Endpoint
	Advertised  Endpoint
	MaxSessions int
	IdleTimeout time.Duration
}

// NAT optionally pins discovery endpoints. Zero values retain automatic
// NAT-PMP gateway inference and UPnP SSDP discovery.
type NAT struct {
	NATPMPEndpoint netip.AddrPort
	UPnPEndpoint   string
}

// Reseed controls bounded bootstrap imports.
type Reseed struct {
	Enabled         bool
	Required        bool
	Endpoints       []string
	Timeout         time.Duration
	MaxArchiveBytes int64
	MaxRouterInfos  int
	MaxTotalBytes   int64
}

// Listener controls one client or management listener. BearerToken is only
// used by an owning listener implementation and is redacted by String.
type Listener struct {
	Enabled              bool
	Address              Endpoint
	UDPAddress           Endpoint
	BearerToken          string
	MaxConnections       int
	ReadinessTimeout     time.Duration
	SessionQueue         int
	MaxSessionQueueBytes int64
	MaxServerQueueBytes  int64
}

// AddressBook configures the local hosts resolver and bounded remote refresh.
// An explicitly empty Subscriptions list selects local-hosts-only operation.
type AddressBook struct {
	Enabled          bool
	PrivateHostsPath string
	UserHostsPath    string
	HostsPath        string
	StatePath        string
	// Subscriptions is ordered: earlier verified HTTPS sources win name
	// conflicts. Setting it explicitly to empty disables remote refresh.
	Subscriptions    []string
	RefreshInterval  time.Duration
	RetryInterval    time.Duration
	RequestTimeout   time.Duration
	MaxEntries       int
	MaxFileBytes     int64
	MaxResponseBytes int64
	MaxRedirects     int
}

func (l Listener) String() string {
	if !l.Enabled {
		return "disabled"
	}
	return "address=" + l.Address.String() + ", authenticated=" + strconv.FormatBool(l.BearerToken != "")
}

// Log controls the process log sink encoding.
type Log struct {
	Level  string
	Format string
}

func (o Operating) String() string {
	return fmt.Sprintf("config.Operating{DataDir:%q StateDir:%q StatePath:%q KeyPath:%q Network:%d/%t/%t Router:%s/%s NetDB:%d Tunnel:%t/%d/%d/%d NTCP2:%t SSU2:%t Reseed:%t/%d SAM:%s AddressBook:%t/%d Control:%s HTTPProxy:%s SOCKS5:%s Metrics:%s Log:%s/%s}",
		o.DataDir, o.StateDir, o.StatePath, o.KeyPath, o.Network.ID, o.Network.IPv4, o.Network.IPv6,
		o.Router.Family, o.Router.Version, o.NetDB.BucketCapacity, o.Tunnel.Enabled, o.Tunnel.InboundTarget, o.Tunnel.OutboundTarget, o.Tunnel.PoolCapacity,
		o.NTCP2.Enabled, o.SSU2.Enabled, o.Reseed.Enabled, len(o.Reseed.Endpoints), o.SAM, o.AddressBook.Enabled, len(o.AddressBook.Subscriptions),
		o.Control, o.HTTPProxy, o.SOCKS5, o.Metrics, o.Log.Level, o.Log.Format)
}

// LoadOrCreateOperating atomically installs a private empty configuration on
// first start, then loads it through the same ownership and regular-file checks
// as an existing configuration. Empty configuration text selects the secure
// defaults: control, proxy, SOCKS, and metrics listeners remain disabled.
func LoadOrCreateOperating(path string) (Operating, error) {
	operating, err := LoadOperating(path)
	if err == nil {
		return operating, nil
	}
	absolute, absoluteErr := filepath.Abs(path)
	if absoluteErr != nil {
		return Operating{}, errors.New("config: cannot resolve operating configuration")
	}
	if _, statErr := os.Lstat(absolute); statErr == nil || !errors.Is(statErr, os.ErrNotExist) {
		return Operating{}, err
	}
	file, createErr := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if createErr != nil {
		if errors.Is(createErr, os.ErrExist) {
			return LoadOperating(absolute)
		}
		return Operating{}, errors.New("config: cannot create operating configuration")
	}
	if syncErr := file.Sync(); syncErr != nil {
		_ = file.Close()
		return Operating{}, errors.New("config: cannot persist operating configuration")
	}
	if closeErr := file.Close(); closeErr != nil {
		return Operating{}, errors.New("config: cannot persist operating configuration")
	}
	if syncErr := fsstore.SyncDir(filepath.Dir(absolute)); syncErr != nil {
		return Operating{}, errors.New("config: cannot persist operating configuration")
	}
	return LoadOperating(absolute)
}

// LoadOperating reads and strictly validates an operating configuration file.
func LoadOperating(path string) (Operating, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Operating{}, errors.New("config: cannot resolve operating configuration")
	}
	file, info, err := fsstore.OpenRegular(absolute)
	if err != nil {
		return Operating{}, errors.New("config: cannot open operating configuration")
	}
	defer file.Close()
	if !ownedUnlinkedRegularFile(info) {
		return Operating{}, errors.New("config: unsafe operating configuration")
	}
	contents, err := fsstore.ReadBoundedFile(file, maxConfigBytes)
	if err != nil {
		if errors.Is(err, fsstore.ErrTooLarge) {
			return Operating{}, ErrMalformed
		}
		return Operating{}, errors.New("config: cannot read operating configuration")
	}
	operating, err := ParseOperating(string(contents), absolute)
	if err != nil {
		return Operating{}, err
	}
	if operatingHasBearerCredentials(operating) && info.Mode().Perm()&0o077 != 0 {
		return Operating{}, errors.New("config: bearer credentials require a private configuration file")
	}
	return operating, nil
}

func ownedUnlinkedRegularFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && stat.Uid == uint32(os.Getuid()) && stat.Nlink == 1
}

func operatingHasBearerCredentials(operating Operating) bool {
	return operating.Control.BearerToken != "" || operating.HTTPProxy.BearerToken != "" || operating.SOCKS5.BearerToken != "" || operating.Metrics.BearerToken != ""
}

// ParseOperating validates text as an operating configuration rooted at path.
// Relative paths in text are resolved against path's directory.
func ParseOperating(text, path string) (Operating, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Operating{}, errors.New("config: cannot resolve operating configuration")
	}
	entries, err := Parse(text)
	if err != nil {
		return Operating{}, err
	}
	values := make(map[entryKey]string, len(entries))
	for _, entry := range entries {
		if !knownOperatingKey(entry.Section, entry.Key) {
			return Operating{}, invalid(entry.Section, entry.Key)
		}
		values[entryKey{section: entry.Section, key: entry.Key}] = entry.Value
	}

	operating := defaultOperating(filepath.Dir(absolute))
	if err := applyPaths(&operating, values, filepath.Dir(absolute)); err != nil {
		return Operating{}, err
	}
	if err := applyNetwork(&operating, values); err != nil {
		return Operating{}, err
	}
	if err := applyRouter(&operating, values); err != nil {
		return Operating{}, err
	}
	if err := applyState(&operating, values); err != nil {
		return Operating{}, err
	}
	if err := applyNetDB(&operating, values, filepath.Dir(absolute)); err != nil {
		return Operating{}, err
	}
	if err := applyTunnel(&operating, values); err != nil {
		return Operating{}, err
	}
	if err := applyTransport(&operating.NTCP2, "ntcp2", values); err != nil {
		return Operating{}, err
	}
	if err := applyTransport(&operating.SSU2, "ssu2", values); err != nil {
		return Operating{}, err
	}
	if err := applyNAT(&operating.NAT, values); err != nil {
		return Operating{}, err
	}
	if !operating.NTCP2.Enabled && !operating.SSU2.Enabled {
		return Operating{}, invalid("transport", "enabled")
	}
	if err := applyReseed(&operating, values); err != nil {
		return Operating{}, err
	}
	if err := applyListener(&operating.SAM, "sam", values); err != nil {
		return Operating{}, err
	}
	if err := applyAddressBook(&operating.AddressBook, values, filepath.Dir(absolute)); err != nil {
		return Operating{}, err
	}
	if err := applyListener(&operating.Control, "control", values); err != nil {
		return Operating{}, err
	}
	if err := applyListener(&operating.HTTPProxy, "http_proxy", values); err != nil {
		return Operating{}, err
	}
	if err := applyListener(&operating.SOCKS5, "socks5", values); err != nil {
		return Operating{}, err
	}
	if operating.Control.Enabled && operating.Control.BearerToken == "" {
		return Operating{}, invalid("control", "bearer_token")
	}
	if err := applyListener(&operating.Metrics, "metrics", values); err != nil {
		return Operating{}, err
	}
	if err := applyLog(&operating, values); err != nil {
		return Operating{}, err
	}
	return operating, nil
}

var defaultReseedEndpoints = []string{
	"https://waw01.i2p-reseed.hosted-by.skhron.eu/i2pseeds.su3?netid=2",
	"https://sto01.i2p-reseed.hosted-by.skhron.eu/i2pseeds.su3?netid=2",
	"https://i2p.ntp.poweredbyberlin.de/i2pseeds.su3?netid=2",
	"https://spiral.likogan.dev/i2pseeds.su3?netid=2",
	"https://reseed.sahil.world/i2pseeds.su3?netid=2",
	"https://i2p.diyarciftci.xyz/i2pseeds.su3?netid=2",
	"https://reseed.stormycloud.org/i2pseeds.su3?netid=2",
	"https://reseed-pl.i2pd.xyz/i2pseeds.su3?netid=2",
	"https://reseed-fr.i2pd.xyz/i2pseeds.su3?netid=2",
	"https://www2.mk16.de/i2pseeds.su3?netid=2",
	"https://reseed2.i2p.net/i2pseeds.su3?netid=2",
	"https://reseed.diva.exchange/i2pseeds.su3?netid=2",
	"https://reseed.i2pgit.org/i2pseeds.su3?netid=2",
	"https://i2p.novg.net/i2pseeds.su3?netid=2",
	"https://i2pseed.creativecowpat.net:8443/i2pseeds.su3?netid=2",
	"https://reseed.onion.im/i2pseeds.su3?netid=2",
}

var defaultAddressBookSubscriptions = []string{
	"https://raw.githubusercontent.com/i2p/i2p.i2p/master/installer/resources/hosts.txt",
}

func defaultOperating(base string) Operating {
	return Operating{
		DataDir:   filepath.Join(base, "data"),
		StateDir:  filepath.Join(base, "state"),
		StatePath: filepath.Join(base, "state", "router.state"),
		KeyPath:   filepath.Join(base, "state", "router.keys"),
		Network:   Network{ID: 2, IPv4: true},
		Router:    Router{IdentityType: "ed25519", Version: "2.13.0"},
		State:     State{MaxBytes: 16 << 20, MaxDestinations: 64, MaxNameBytes: 255},
		NetDB:     NetDB{BucketCapacity: 24},
		Tunnel: Tunnel{
			Enabled: true, Hops: 3, InboundTarget: 2, OutboundTarget: 2, PoolCapacity: 4,
			BuildPendingCapacity: 13, Lifetime: 10 * time.Minute,
			RenewBefore: 210 * time.Second, MaintenanceInterval: time.Minute,
			BandwidthRateBytesPerSecond: 1 << 20, BandwidthBurstBytes: 2 << 20,
		},
		NTCP2:  defaultTransport(),
		SSU2:   defaultTransport(),
		Reseed: Reseed{Enabled: true, Endpoints: append([]string(nil), defaultReseedEndpoints...), Timeout: 30 * time.Second, MaxArchiveBytes: 1 << 20, MaxRouterInfos: 4_000, MaxTotalBytes: 64 << 20},
		SAM: Listener{
			Enabled: true, Address: Endpoint{Host: "127.0.0.1", Port: 7656}, UDPAddress: Endpoint{Host: "127.0.0.1", Port: 7655},
			MaxConnections: 128, ReadinessTimeout: 2 * time.Minute, SessionQueue: 64, MaxSessionQueueBytes: 4 << 20, MaxServerQueueBytes: 64 << 20,
		},
		AddressBook: AddressBook{
			Enabled: true, PrivateHostsPath: filepath.Join(base, "privatehosts.txt"), UserHostsPath: filepath.Join(base, "userhosts.txt"), HostsPath: filepath.Join(base, "hosts.txt"), StatePath: filepath.Join(base, "state", "addressbook.json"),
			Subscriptions:   append([]string(nil), defaultAddressBookSubscriptions...),
			RefreshInterval: 12 * time.Hour, RetryInterval: 5 * time.Minute, RequestTimeout: 30 * time.Second,
			MaxEntries: 100_000, MaxFileBytes: 8 << 20, MaxResponseBytes: 16 << 20, MaxRedirects: 3,
		},
		Control:   defaultListener(7650),
		HTTPProxy: defaultListener(4444),
		SOCKS5:    defaultListener(4447),
		Metrics:   defaultListener(9090),
		Log:       Log{Level: "info", Format: "text"},
	}
}

func defaultTransport() Transport {
	return Transport{Enabled: true, Bind: Endpoint{Host: "0.0.0.0", Port: 0}, MaxSessions: 256, IdleTimeout: 10 * time.Minute}
}

func defaultListener(port uint16) Listener {
	return Listener{Address: Endpoint{Host: "127.0.0.1", Port: port}, MaxConnections: 128}
}

func applyPaths(operating *Operating, values map[entryKey]string, base string) error {
	var err error
	if value, ok := valueOf(values, "paths", "data_dir"); ok {
		operating.DataDir, err = resolvePath(value, base)
		if err != nil {
			return invalid("paths", "data_dir")
		}
	}
	if value, ok := valueOf(values, "paths", "state_dir"); ok {
		operating.StateDir, err = resolvePath(value, base)
		if err != nil {
			return invalid("paths", "state_dir")
		}
	}
	if value, ok := valueOf(values, "paths", "state_path"); ok {
		operating.StatePath, err = resolvePath(value, base)
		if err != nil {
			return invalid("paths", "state_path")
		}
	} else if _, stateConfigured := valueOf(values, "paths", "state_dir"); stateConfigured {
		operating.StatePath = filepath.Join(operating.StateDir, "router.state")
	}
	if value, ok := valueOf(values, "paths", "key_path"); ok {
		operating.KeyPath, err = resolvePath(value, base)
		if err != nil {
			return invalid("paths", "key_path")
		}
	} else if _, stateConfigured := valueOf(values, "paths", "state_dir"); stateConfigured {
		operating.KeyPath = filepath.Join(operating.StateDir, "router.keys")
	}
	if _, stateConfigured := valueOf(values, "paths", "state_dir"); stateConfigured {
		operating.AddressBook.StatePath = filepath.Join(operating.StateDir, "addressbook.json")
	}
	return nil
}

func applyNetwork(operating *Operating, values map[entryKey]string) error {
	if value, ok := valueOf(values, "network", "id"); ok {
		parsed, err := parseUint(value, 1, int64(^uint32(0)))
		if err != nil {
			return invalid("network", "id")
		}
		operating.Network.ID = uint32(parsed)
	}
	for _, key := range []string{"ipv4", "ipv6"} {
		if value, ok := valueOf(values, "network", key); ok {
			parsed, err := parseBool(value)
			if err != nil {
				return invalid("network", key)
			}
			if key == "ipv4" {
				operating.Network.IPv4 = parsed
			} else {
				operating.Network.IPv6 = parsed
			}
		}
	}
	if !operating.Network.IPv4 && !operating.Network.IPv6 {
		return invalid("network", "ip_families")
	}
	return nil
}

func applyRouter(operating *Operating, values map[entryKey]string) error {
	if value, ok := valueOf(values, "router", "identity_type"); ok {
		if value != "ed25519" {
			return invalid("router", "identity_type")
		}
		operating.Router.IdentityType = value
	}
	if value, ok := valueOf(values, "router", "family"); ok {
		if !validLabel(value, 64) {
			return invalid("router", "family")
		}
		operating.Router.Family = value
	}
	if value, ok := valueOf(values, "router", "version"); ok {
		if !validLabel(value, 64) {
			return invalid("router", "version")
		}
		operating.Router.Version = value
	}
	return nil
}

func applyState(operating *Operating, values map[entryKey]string) error {
	var err error
	if value, ok := valueOf(values, "state", "max_bytes"); ok {
		operating.State.MaxBytes, err = parseUint(value, 64<<10, 1<<30)
		if err != nil {
			return invalid("state", "max_bytes")
		}
	}
	if value, ok := valueOf(values, "state", "max_destinations"); ok {
		parsed, err := parseUint(value, 1, 64)
		if err != nil {
			return invalid("state", "max_destinations")
		}
		operating.State.MaxDestinations = int(parsed)
	}
	if value, ok := valueOf(values, "state", "max_name_bytes"); ok {
		parsed, err := parseUint(value, 1, 1_024)
		if err != nil {
			return invalid("state", "max_name_bytes")
		}
		operating.State.MaxNameBytes = int(parsed)
	}
	return nil
}

func applyNetDB(operating *Operating, values map[entryKey]string, base string) error {
	if value, ok := valueOf(values, "netdb", "bucket_capacity"); ok {
		parsed, err := parseUint(value, 5, 1_024)
		if err != nil {
			return invalid("netdb", "bucket_capacity")
		}
		operating.NetDB.BucketCapacity = int(parsed)
	}
	if value, ok := valueOf(values, "netdb", "bootstrap_router_info_files"); ok {
		raw := strings.Split(value, ",")
		if len(raw) == 0 || len(raw) > maxBootstrapRouterInfoFiles {
			return invalid("netdb", "bootstrap_router_info_files")
		}
		paths := make([]string, 0, len(raw))
		seen := make(map[string]struct{}, len(raw))
		for _, item := range raw {
			resolved, err := resolvePath(strings.TrimSpace(item), base)
			if err != nil {
				return invalid("netdb", "bootstrap_router_info_files")
			}
			if _, duplicate := seen[resolved]; duplicate {
				return invalid("netdb", "bootstrap_router_info_files")
			}
			seen[resolved] = struct{}{}
			paths = append(paths, resolved)
		}
		operating.NetDB.BootstrapRouterInfoPaths = paths
	}
	return nil
}

func applyTunnel(operating *Operating, values map[entryKey]string) error {
	tunnel := &operating.Tunnel
	if value, ok := valueOf(values, "tunnel", "enabled"); ok {
		parsed, err := parseBool(value)
		if err != nil {
			return invalid("tunnel", "enabled")
		}
		tunnel.Enabled = parsed
	}
	for _, setting := range []struct {
		key string
		dst *int
		min int64
		max int64
	}{
		{"hops", &tunnel.Hops, 1, 7},
		{"inbound_target", &tunnel.InboundTarget, 1, 16},
		{"outbound_target", &tunnel.OutboundTarget, 1, 16},
		{"pool_capacity", &tunnel.PoolCapacity, 2, 64},
		{"build_pending_capacity", &tunnel.BuildPendingCapacity, 1, 256},
		{"bandwidth_rate_bytes_per_second", &tunnel.BandwidthRateBytesPerSecond, 1 << 10, 1 << 30},
		{"bandwidth_burst_bytes", &tunnel.BandwidthBurstBytes, 1 << 10, 1 << 30},
	} {
		if value, ok := valueOf(values, "tunnel", setting.key); ok {
			parsed, err := parseUint(value, setting.min, setting.max)
			if err != nil {
				return invalid("tunnel", setting.key)
			}
			*setting.dst = int(parsed)
		}
	}
	for _, setting := range []struct {
		key string
		dst *time.Duration
		min time.Duration
		max time.Duration
	}{
		{"lifetime", &tunnel.Lifetime, 10 * time.Minute, 10 * time.Minute},
		{"renew_before", &tunnel.RenewBefore, time.Second, 10*time.Minute - time.Nanosecond},
		{"maintenance_interval", &tunnel.MaintenanceInterval, time.Second, 10 * time.Minute},
	} {
		if value, ok := valueOf(values, "tunnel", setting.key); ok {
			parsed, err := parseDuration(value, setting.min, setting.max)
			if err != nil {
				return invalid("tunnel", setting.key)
			}
			*setting.dst = parsed
		}
	}
	if tunnel.RenewBefore >= tunnel.Lifetime {
		return invalid("tunnel", "renew_before")
	}
	if tunnel.MaintenanceInterval > tunnel.RenewBefore {
		return invalid("tunnel", "maintenance_interval")
	}
	if tunnel.PoolCapacity < 2*tunnel.InboundTarget || tunnel.PoolCapacity < 2*tunnel.OutboundTarget {
		return invalid("tunnel", "pool_capacity")
	}
	return nil
}

func applyTransport(transport *Transport, section string, values map[entryKey]string) error {
	if value, ok := valueOf(values, section, "enabled"); ok {
		parsed, err := parseBool(value)
		if err != nil {
			return invalid(section, "enabled")
		}
		transport.Enabled = parsed
	}
	if err := applyEndpoint(&transport.Bind, section, "bind", values, endpointOptions{allowUnspecified: true, allowZeroPort: true}); err != nil {
		return err
	}
	if err := applyOptionalEndpoint(&transport.Advertised, section, "advertise", values); err != nil {
		return err
	}
	if value, ok := valueOf(values, section, "max_sessions"); ok {
		parsed, err := parseUint(value, 1, 65_536)
		if err != nil {
			return invalid(section, "max_sessions")
		}
		transport.MaxSessions = int(parsed)
	}
	if value, ok := valueOf(values, section, "idle_timeout"); ok {
		parsed, err := parseDuration(value, time.Second, 24*time.Hour)
		if err != nil {
			return invalid(section, "idle_timeout")
		}
		transport.IdleTimeout = parsed
	}
	return nil
}
func applyNAT(nat *NAT, values map[entryKey]string) error {
	if value, ok := valueOf(values, "nat", "natpmp_endpoint"); ok {
		endpoint, err := netip.ParseAddrPort(value)
		if err != nil {
			return invalid("nat", "natpmp_endpoint")
		}
		address := endpoint.Addr().Unmap()
		if !address.Is4() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || endpoint.Port() == 0 {
			return invalid("nat", "natpmp_endpoint")
		}
		nat.NATPMPEndpoint = netip.AddrPortFrom(address, endpoint.Port())
	}
	if value, ok := valueOf(values, "nat", "upnp_endpoint"); ok {
		endpoint, err := url.Parse(value)
		applyNATRejected := err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != ""
		if !applyNATRejected {
			applyNATRejected = endpoint.Scheme != "http" && endpoint.Scheme != "https"
		}
		if applyNATRejected {
			return invalid("nat", "upnp_endpoint")
		}
		nat.UPnPEndpoint = endpoint.String()
	}
	return nil
}

func applyReseed(operating *Operating, values map[entryKey]string) error {
	reseed := &operating.Reseed
	if value, ok := valueOf(values, "reseed", "enabled"); ok {
		parsed, err := parseBool(value)
		if err != nil {
			return invalid("reseed", "enabled")
		}
		reseed.Enabled = parsed
	}
	if value, ok := valueOf(values, "reseed", "required"); ok {
		parsed, err := parseBool(value)
		if err != nil {
			return invalid("reseed", "required")
		}
		reseed.Required = parsed
	}
	if value, ok := valueOf(values, "reseed", "endpoints"); ok {
		endpoints, err := parseReseedEndpoints(value)
		if err != nil {
			return invalid("reseed", "endpoints")
		}
		reseed.Endpoints = endpoints
	}
	if value, ok := valueOf(values, "reseed", "timeout"); ok {
		parsed, err := parseDuration(value, time.Second, 10*time.Minute)
		if err != nil {
			return invalid("reseed", "timeout")
		}
		reseed.Timeout = parsed
	}
	if value, ok := valueOf(values, "reseed", "max_archive_bytes"); ok {
		parsed, err := parseUint(value, 64<<10, 1<<30)
		if err != nil {
			return invalid("reseed", "max_archive_bytes")
		}
		reseed.MaxArchiveBytes = parsed
	}
	if value, ok := valueOf(values, "reseed", "max_router_infos"); ok {
		parsed, err := parseUint(value, 1, 100_000)
		if err != nil {
			return invalid("reseed", "max_router_infos")
		}
		reseed.MaxRouterInfos = int(parsed)
	}
	if value, ok := valueOf(values, "reseed", "max_total_bytes"); ok {
		parsed, err := parseUint(value, 64<<10, 2<<30)
		if err != nil {
			return invalid("reseed", "max_total_bytes")
		}
		reseed.MaxTotalBytes = parsed
	}
	if reseed.MaxTotalBytes < reseed.MaxArchiveBytes {
		return invalid("reseed", "max_total_bytes")
	}
	if reseed.Required && !reseed.Enabled {
		return invalid("reseed", "required")
	}
	if reseed.Enabled && len(reseed.Endpoints) == 0 {
		return invalid("reseed", "endpoints")
	}
	if !reseed.Enabled && len(reseed.Endpoints) != 0 {
		return invalid("reseed", "endpoints")
	}
	return nil
}

func applyListener(listener *Listener, section string, values map[entryKey]string) error {
	if value, ok := valueOf(values, section, "enabled"); ok {
		parsed, err := parseBool(value)
		if err != nil {
			return invalid(section, "enabled")
		}
		listener.Enabled = parsed
	}
	if err := applyEndpoint(&listener.Address, section, "listen", values, endpointOptions{}); err != nil {
		return err
	}
	if section == "sam" {
		if err := applyEndpoint(&listener.UDPAddress, section, "udp", values, endpointOptions{}); err != nil {
			return err
		}
	}
	if value, ok := valueOf(values, section, "bearer_token"); ok {
		if !validBearerToken(value) {
			return invalid(section, "bearer_token")
		}
		listener.BearerToken = value
	}
	if value, ok := valueOf(values, section, "max_connections"); ok {
		parsed, err := parseUint(value, 1, 65_536)
		if err != nil {
			return invalid(section, "max_connections")
		}
		listener.MaxConnections = int(parsed)
	}
	if section == "sam" {
		if value, ok := valueOf(values, section, "readiness_timeout"); ok {
			parsed, err := parseDuration(value, 100*time.Millisecond, 10*time.Minute)
			if err != nil {
				return invalid(section, "readiness_timeout")
			}
			listener.ReadinessTimeout = parsed
		}
	}
	for _, setting := range []struct {
		key    string
		target *int64
		min    int64
		max    int64
	}{
		{"max_session_queue_bytes", &listener.MaxSessionQueueBytes, 64 << 10, 1 << 30},
		{"max_server_queue_bytes", &listener.MaxServerQueueBytes, 64 << 10, 16 << 30},
	} {
		if value, ok := valueOf(values, section, setting.key); ok {
			parsed, err := parseUint(value, setting.min, setting.max)
			if err != nil {
				return invalid(section, setting.key)
			}
			*setting.target = parsed
		}
	}
	if value, ok := valueOf(values, section, "session_queue"); ok {
		parsed, err := parseUint(value, 1, 4096)
		if err != nil {
			return invalid(section, "session_queue")
		}
		listener.SessionQueue = int(parsed)
	}
	if listener.MaxSessionQueueBytes > listener.MaxServerQueueBytes {
		return invalid(section, "max_server_queue_bytes")
	}
	if (section == "http_proxy" || section == "socks5") && listener.BearerToken != "" {
		return invalid(section, "bearer_token")
	}
	if !listener.Enabled {
		return nil
	}
	address, err := netip.ParseAddr(listener.Address.Host)
	if err != nil {
		return invalid(section, "listen_host")
	}
	applyListenerRejected := (section == "http_proxy" || section == "socks5")
	if applyListenerRejected {
		applyListenerRejected = (!address.IsLoopback() || listener.BearerToken != "")
	}
	if applyListenerRejected {
		return invalid(section, "listen")
	}
	if !address.IsLoopback() && listener.BearerToken == "" {
		return invalid(section, "bearer_token")
	}
	if section == "sam" && listener.UDPAddress.Host != "" {
		udpAddress, parseErr := netip.ParseAddr(listener.UDPAddress.Host)
		if parseErr != nil || !udpAddress.IsLoopback() || listener.UDPAddress.Port == 0 {
			return invalid(section, "udp")
		}
	}
	return nil
}

func applyAddressBook(book *AddressBook, values map[entryKey]string, base string) error {
	if value, ok := valueOf(values, "addressbook", "enabled"); ok {
		parsed, err := parseBool(value)
		if err != nil {
			return invalid("addressbook", "enabled")
		}
		book.Enabled = parsed
	}
	paths := []struct {
		key    string
		target *string
	}{
		{"privatehosts_path", &book.PrivateHostsPath}, {"userhosts_path", &book.UserHostsPath},
		{"hosts_path", &book.HostsPath}, {"state_path", &book.StatePath},
	}
	for _, item := range paths {
		if value, ok := valueOf(values, "addressbook", item.key); ok {
			if value == "" {
				return invalid("addressbook", item.key)
			}
			resolved, err := resolvePath(value, base)
			if err != nil {
				return invalid("addressbook", item.key)
			}
			*item.target = resolved
		}
	}
	if value, ok := valueOf(values, "addressbook", "subscriptions"); ok {
		raw := strings.Split(value, ",")
		parts := make([]string, 0, len(raw))
		for _, part := range raw {
			if part = strings.TrimSpace(part); part != "" {
				parts = append(parts, part)
			}
		}
		if len(parts) > 32 {
			return invalid("addressbook", "subscriptions")
		}
		book.Subscriptions = parts
	}
	durations := []struct {
		key      string
		target   *time.Duration
		min, max time.Duration
	}{
		{"refresh_interval", &book.RefreshInterval, time.Minute, 7 * 24 * time.Hour},
		{"retry_interval", &book.RetryInterval, time.Second, 24 * time.Hour},
		{"request_timeout", &book.RequestTimeout, time.Second, 10 * time.Minute},
	}
	for _, item := range durations {
		if value, ok := valueOf(values, "addressbook", item.key); ok {
			parsed, err := parseDuration(value, item.min, item.max)
			if err != nil {
				return invalid("addressbook", item.key)
			}
			*item.target = parsed
		}
	}
	if value, ok := valueOf(values, "addressbook", "max_entries"); ok {
		parsed, err := parseUint(value, 1, 1_000_000)
		if err != nil {
			return invalid("addressbook", "max_entries")
		}
		book.MaxEntries = int(parsed)
	}
	if value, ok := valueOf(values, "addressbook", "max_file_bytes"); ok {
		parsed, err := parseUint(value, 1024, 1<<30)
		if err != nil {
			return invalid("addressbook", "max_file_bytes")
		}
		book.MaxFileBytes = int64(parsed)
	}
	if value, ok := valueOf(values, "addressbook", "max_response_bytes"); ok {
		parsed, err := parseUint(value, 1024, 1<<30)
		if err != nil {
			return invalid("addressbook", "max_response_bytes")
		}
		book.MaxResponseBytes = int64(parsed)
	}
	if value, ok := valueOf(values, "addressbook", "max_redirects"); ok {
		parsed, err := parseUint(value, 0, 16)
		if err != nil {
			return invalid("addressbook", "max_redirects")
		}
		book.MaxRedirects = int(parsed)
	}
	return nil
}

func applyLog(operating *Operating, values map[entryKey]string) error {
	if value, ok := valueOf(values, "log", "level"); ok {
		switch value {
		case "debug", "info", "warn", "error":
			operating.Log.Level = value
		default:
			return invalid("log", "level")
		}
	}
	if value, ok := valueOf(values, "log", "format"); ok {
		switch value {
		case "text", "json":
			operating.Log.Format = value
		default:
			return invalid("log", "format")
		}
	}
	return nil
}

type endpointOptions struct {
	allowUnspecified bool
	allowZeroPort    bool
}

func applyEndpoint(endpoint *Endpoint, section, prefix string, values map[entryKey]string, options endpointOptions) error {
	host, hostOK := valueOf(values, section, prefix+"_host")
	port, portOK := valueOf(values, section, prefix+"_port")
	if hostOK != portOK {
		return invalid(section, prefix+"_endpoint")
	}
	if !hostOK {
		return nil
	}
	parsed, err := parseEndpoint(host, port, options.allowUnspecified, options.allowZeroPort)
	if err != nil {
		return invalid(section, prefix+"_endpoint")
	}
	*endpoint = parsed
	return nil
}

func applyOptionalEndpoint(endpoint *Endpoint, section, prefix string, values map[entryKey]string) error {
	host, hostOK := valueOf(values, section, prefix+"_host")
	port, portOK := valueOf(values, section, prefix+"_port")
	if !hostOK && !portOK {
		return nil
	}
	var parsed Endpoint
	if hostOK {
		address, err := netip.ParseAddr(host)
		if err != nil {
			return invalid(section, prefix+"_endpoint")
		}
		address = address.Unmap()
		if address.IsMulticast() || address.IsUnspecified() {
			return invalid(section, prefix+"_endpoint")
		}
		parsed.Host = address.String()
	}
	if portOK {
		value, err := parseUint(port, 0, 65_535)
		if err != nil {
			return invalid(section, prefix+"_endpoint")
		}
		parsed.Port = uint16(value)
	}
	if parsed.Port != 0 && parsed.Host == "" {
		return invalid(section, prefix+"_endpoint")
	}
	*endpoint = parsed
	return nil
}

func parseEndpoint(host, port string, allowUnspecified, allowZeroPort bool) (Endpoint, error) {
	address, err := netip.ParseAddr(host)
	if err != nil {
		return Endpoint{}, errors.New("invalid endpoint")
	}
	address = address.Unmap()
	if address.IsMulticast() || (!allowUnspecified && address.IsUnspecified()) {
		return Endpoint{}, errors.New("invalid endpoint")
	}
	minimumPort := int64(1)
	if allowZeroPort {
		minimumPort = 0
	}
	parsedPort, err := parseUint(port, minimumPort, 65_535)
	if err != nil {
		return Endpoint{}, err
	}
	return Endpoint{Host: address.String(), Port: uint16(parsedPort)}, nil
}

func parseReseedEndpoints(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) == 0 || len(parts) > maxReseedEndpoints {
		return nil, errors.New("invalid endpoint count")
	}
	endpoints := make([]string, 0, len(parts))
	for _, part := range parts {
		endpoint := strings.TrimSpace(part)
		parsed, err := url.Parse(endpoint)
		parseReseedEndpointsRejected := len(endpoint) == 0 || len(endpoint) > maxReseedEndpointBytes || err != nil ||
			parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
			parsed.RawQuery != "netid=2" || parsed.ForceQuery
		if !parseReseedEndpointsRejected {
			parseReseedEndpointsRejected = parsed.Fragment != ""
		}
		if parseReseedEndpointsRejected {
			return nil, errors.New("invalid endpoint")
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}

func parseBool(value string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errors.New("invalid boolean")
	}
}

func parseUint(value string, min, max int64) (int64, error) {
	if value == "" || strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") {
		return 0, errors.New("invalid integer")
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < min || parsed > max {
		return 0, errors.New("integer out of range")
	}
	return parsed, nil
}
func parseDuration(value string, min, max time.Duration) (time.Duration, error) {
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < min || parsed > max {
		return 0, errors.New("duration out of range")
	}
	return parsed, nil
}

func resolvePath(value, base string) (string, error) {
	if value == "" || len(value) > maxOperatingPathBytes || strings.IndexByte(value, 0) >= 0 || !utf8.ValidString(value) {
		return "", errors.New("invalid path")
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value), nil
	}
	return filepath.Join(base, filepath.Clean(value)), nil
}

func validLabel(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validBearerToken(value string) bool {
	if len(value) < 16 || len(value) > 4_096 {
		return false
	}
	for _, character := range value {
		if !validBearerTokenCharacter(character) {
			return false
		}
	}
	return true
}

func validBearerTokenCharacter(character rune) bool {
	return (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9') ||
		strings.ContainsRune("-._~+/=", character)
}

func valueOf(values map[entryKey]string, section, key string) (string, bool) {
	value, ok := values[entryKey{section: section, key: key}]
	return value, ok
}

func invalid(section, key string) error {
	if section == "" {
		return fmt.Errorf("%w: %s", ErrInvalidOperating, key)
	}
	return fmt.Errorf("%w: %s.%s", ErrInvalidOperating, section, key)
}

func knownOperatingKey(section, key string) bool {
	allowed, ok := operatingKeys[section]
	return ok && allowed[key]
}

var operatingKeys = map[string]map[string]bool{
	"paths":       {"data_dir": true, "state_dir": true, "state_path": true, "key_path": true},
	"network":     {"id": true, "ipv4": true, "ipv6": true},
	"router":      {"identity_type": true, "family": true, "version": true},
	"state":       {"max_bytes": true, "max_destinations": true, "max_name_bytes": true},
	"netdb":       {"bucket_capacity": true, "bootstrap_router_info_files": true},
	"tunnel":      {"enabled": true, "hops": true, "inbound_target": true, "outbound_target": true, "pool_capacity": true, "build_pending_capacity": true, "lifetime": true, "renew_before": true, "maintenance_interval": true, "bandwidth_rate_bytes_per_second": true, "bandwidth_burst_bytes": true},
	"ntcp2":       {"enabled": true, "bind_host": true, "bind_port": true, "advertise_host": true, "advertise_port": true, "max_sessions": true, "idle_timeout": true},
	"ssu2":        {"enabled": true, "bind_host": true, "bind_port": true, "advertise_host": true, "advertise_port": true, "max_sessions": true, "idle_timeout": true},
	"nat":         {"natpmp_endpoint": true, "upnp_endpoint": true},
	"reseed":      {"enabled": true, "required": true, "endpoints": true, "timeout": true, "max_archive_bytes": true, "max_router_infos": true, "max_total_bytes": true},
	"control":     {"enabled": true, "listen_host": true, "listen_port": true, "bearer_token": true, "max_connections": true},
	"http_proxy":  {"enabled": true, "listen_host": true, "listen_port": true, "bearer_token": true, "max_connections": true},
	"socks5":      {"enabled": true, "listen_host": true, "listen_port": true, "bearer_token": true, "max_connections": true},
	"metrics":     {"enabled": true, "listen_host": true, "listen_port": true, "bearer_token": true, "max_connections": true},
	"sam":         {"enabled": true, "listen_host": true, "listen_port": true, "udp_host": true, "udp_port": true, "bearer_token": true, "max_connections": true, "readiness_timeout": true, "session_queue": true, "max_session_queue_bytes": true, "max_server_queue_bytes": true},
	"addressbook": {"enabled": true, "privatehosts_path": true, "userhosts_path": true, "hosts_path": true, "state_path": true, "subscriptions": true, "refresh_interval": true, "retry_interval": true, "request_timeout": true, "max_entries": true, "max_file_bytes": true, "max_response_bytes": true, "max_redirects": true},
	"log":         {"level": true, "format": true},
}
