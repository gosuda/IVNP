package config

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseOperatingDefaults(t *testing.T) {
	config, err := ParseOperating("", "/etc/ivnp/ivnp.conf")
	if err != nil {
		t.Fatal(err)
	}
	if config.DataDir != "/etc/ivnp/data" || config.StateDir != "/etc/ivnp/state" || config.StatePath != "/etc/ivnp/state/router.state" || config.KeyPath != "/etc/ivnp/state/router.keys" {
		t.Fatalf("paths = %#v", config)
	}
	if config.Network.ID != 2 || !config.Network.IPv4 || config.Network.IPv6 {
		t.Fatalf("network = %#v", config.Network)
	}
	if !config.NTCP2.Enabled || !config.SSU2.Enabled ||
		config.NTCP2.Bind != (Endpoint{Host: "0.0.0.0"}) || config.SSU2.Bind != (Endpoint{Host: "0.0.0.0"}) {
		t.Fatalf("transport defaults = %#v %#v", config.NTCP2, config.SSU2)
	}
	if config.Control.Enabled || config.HTTPProxy.Enabled || config.SOCKS5.Enabled || config.Metrics.Enabled {
		t.Fatalf("listeners must default disabled: %#v", config)
	}
	if !config.Reseed.Enabled || len(config.Reseed.Endpoints) == 0 || config.Reseed.Timeout != 30*time.Second || config.Log != (Log{Level: "info", Format: "text"}) {
		t.Fatalf("defaults = %#v", config)
	}
	for _, endpoint := range config.Reseed.Endpoints {
		if !strings.HasPrefix(endpoint, "https://") || !strings.HasSuffix(endpoint, "/i2pseeds.su3?netid=2") {
			t.Fatalf("default reseed endpoint = %q", endpoint)
		}
	}
	if !config.Tunnel.Enabled || config.Tunnel.Lifetime != 10*time.Minute || config.Router.Version != "2.13.0" {
		t.Fatalf("production defaults = %#v", config)
	}
}
func TestParseOperatingDisablesReseedOnlyWithExplicitEmptyEndpoints(t *testing.T) {
	disabled, err := ParseOperating("[reseed]\nenabled = false\nendpoints =\n", "/etc/ivnp/ivnp.conf")
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Reseed.Enabled || len(disabled.Reseed.Endpoints) != 0 {
		t.Fatalf("disabled reseed = %#v", disabled.Reseed)
	}
	for _, text := range []string{
		"[reseed]\nenabled = false\n",
		"[reseed]\nenabled = true\nendpoints =\n",
	} {
		if _, err = ParseOperating(text, "/etc/ivnp/ivnp.conf"); !errors.Is(err, ErrInvalidOperating) {
			t.Fatalf("ParseOperating(%q) error = %v, want invalid operating config", text, err)
		}
	}
}

func TestDefaultAddressBookHasVerifiedRemoteSubscription(t *testing.T) {
	cfg, err := ParseOperating("", "/etc/ivnp/ivnp.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AddressBook.Enabled {
		t.Fatal("default hosts resolver is disabled")
	}
	const officialHosts = "https://raw.githubusercontent.com/i2p/i2p.i2p/master/installer/resources/hosts.txt"
	if len(cfg.AddressBook.Subscriptions) != 1 || cfg.AddressBook.Subscriptions[0] != officialHosts {
		t.Fatalf("default addressbook subscriptions = %#v", cfg.AddressBook.Subscriptions)
	}
	localOnly, err := ParseOperating("[addressbook]\nsubscriptions =\n", "/etc/ivnp/ivnp.conf")
	if err != nil {
		t.Fatal(err)
	}
	if len(localOnly.AddressBook.Subscriptions) != 0 {
		t.Fatalf("explicit local-only subscriptions = %#v", localOnly.AddressBook.Subscriptions)
	}
	remote, err := ParseOperating("[addressbook]\nsubscriptions = https://example.com/hosts.txt\n", "/etc/ivnp/ivnp.conf")
	if err != nil {
		t.Fatal(err)
	}
	if len(remote.AddressBook.Subscriptions) != 1 || remote.AddressBook.Subscriptions[0] != "https://example.com/hosts.txt" {
		t.Fatalf("requested remote subscription = %#v", remote.AddressBook.Subscriptions)
	}
}

func TestLoadOperatingResolvesRelativePaths(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "ivnp.conf")
	if err := os.WriteFile(path, []byte("[paths]\ndata_dir = data\nstate_dir = runtime/state\nstate_path = runtime/state/router.bin\nkey_path = keys/router.key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadOperating(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.DataDir != filepath.Join(directory, "data") || config.StateDir != filepath.Join(directory, "runtime", "state") || config.StatePath != filepath.Join(directory, "runtime", "state", "router.bin") || config.KeyPath != filepath.Join(directory, "keys", "router.key") {
		t.Fatalf("relative paths = %#v", config)
	}
}

func TestLoadOrCreateOperatingInstallsPrivateSafeDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ivnp.conf")
	first, err := LoadOrCreateOperating(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("first-run config mode = %v", info.Mode())
	}
	if first.Control.Enabled || first.HTTPProxy.Enabled || first.SOCKS5.Enabled || first.Metrics.Enabled {
		t.Fatalf("first-run privileged listeners enabled: %#v", first)
	}
	second, err := LoadOrCreateOperating(path)
	if err != nil {
		t.Fatal(err)
	}
	if second.StatePath != first.StatePath || second.KeyPath != first.KeyPath {
		t.Fatalf("restart defaults changed: first=%#v second=%#v", first, second)
	}
}

func TestLoadOperatingRejectsUnsafeSecretSources(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("[control]\nenabled = true\nlisten_host = 192.0.2.10\nlisten_port = 7650\nbearer_token = token-token-token-1\n")
	path := filepath.Join(dir, "ivnp.conf")
	if err := os.WriteFile(path, secret, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOperating(path); err == nil {
		t.Fatal("LoadOperating accepted world-readable bearer credentials")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOperating(path); err != nil {
		t.Fatalf("LoadOperating(private secret) error = %v", err)
	}
	link := filepath.Join(dir, "ivnp-link.conf")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOperating(link); err == nil {
		t.Fatal("LoadOperating accepted a symlink")
	}
	fifo := filepath.Join(dir, "ivnp-fifo.conf")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOperating(fifo); err == nil {
		t.Fatal("LoadOperating accepted a FIFO")
	}
}

func TestParseOperatingRejectsUnknownAndDuplicateKeys(t *testing.T) {
	for _, text := range []string{
		"[router]\nunknown = value\n",
		"[ntcp2]\nenabled = true\nenabled = false\n",
		"[unknown]\nvalue = true\n",
	} {
		_, err := ParseOperating(text, "/etc/ivnp/ivnp.conf")
		if err == nil {
			t.Fatalf("ParseOperating(%q) succeeded", text)
		}
		if !errors.Is(err, ErrInvalidOperating) && !errors.Is(err, ErrMalformed) {
			t.Fatalf("ParseOperating(%q) error = %v", text, err)
		}
	}
}

func TestParseOperatingRejectsPartialAndInvalidTransportEndpoints(t *testing.T) {
	for _, text := range []string{
		"[ntcp2]\nbind_host = 127.0.0.1\n",
		"[ssu2]\nadvertise_host = 0.0.0.0\nadvertise_port = 12345\n",
		"[nat]\nnatpmp_endpoint = 127.0.0.1:5351\n",
		"[nat]\nnatpmp_endpoint = 10.2.0.1\n",
		"[nat]\nupnp_endpoint = ftp://192.168.0.1/root.xml\n",
		"[ntcp2]\nenabled = false\n[ssu2]\nenabled = false\n",
	} {
		if _, err := ParseOperating(text, "/etc/ivnp/ivnp.conf"); !errors.Is(err, ErrInvalidOperating) {
			t.Fatalf("ParseOperating(%q) error = %v, want invalid operating config", text, err)
		}
	}
}

func TestParseOperatingAcceptsAutomaticTransportPorts(t *testing.T) {
	operating, err := ParseOperating(
		"[ntcp2]\nbind_host = 0.0.0.0\nbind_port = 0\nadvertise_port = 0\n"+
			"[ssu2]\nadvertise_host = 203.0.113.7\n[nat]\nnatpmp_endpoint = 10.2.0.1:5351\nupnp_endpoint = http://192.168.0.1/rootDesc.xml\n",
		"/etc/ivnp/ivnp.conf",
	)
	if err != nil {
		t.Fatal(err)
	}
	if operating.NTCP2.Bind.Port != 0 || operating.NTCP2.Advertised != (Endpoint{}) {
		t.Fatalf("automatic NTCP2 endpoints = %#v", operating.NTCP2)
	}
	if operating.SSU2.Advertised != (Endpoint{Host: "203.0.113.7"}) {
		t.Fatalf("automatic SSU2 advertisement = %#v", operating.SSU2.Advertised)
	}
	if operating.NAT.NATPMPEndpoint != netip.MustParseAddrPort("10.2.0.1:5351") || operating.NAT.UPnPEndpoint != "http://192.168.0.1/rootDesc.xml" {
		t.Fatalf("explicit NAT endpoints = %#v", operating.NAT)
	}
}

func TestParseOperatingListenerAuthenticationPolicy(t *testing.T) {
	unauthenticated := "[control]\nenabled = true\nlisten_host = 192.0.2.10\nlisten_port = 7650\n"
	if _, err := ParseOperating(unauthenticated, "/etc/ivnp/ivnp.conf"); !errors.Is(err, ErrInvalidOperating) {
		t.Fatalf("unauthenticated remote listener error = %v", err)
	}

	const token = "8GxbrMTEnPS6IQvjGDkAcQ"
	config, err := ParseOperating(unauthenticated+"bearer_token = "+token+"\n", "/etc/ivnp/ivnp.conf")
	if err != nil {
		t.Fatal(err)
	}
	if config.Control.BearerToken != token || !config.Control.Enabled {
		t.Fatal("control listener did not retain its authenticated configuration")
	}
	if strings.Contains(config.String(), token) || strings.Contains(config.Control.String(), token) {
		t.Fatal("configuration string leaked bearer token")
	}

	metrics, err := ParseOperating("[metrics]\nenabled = true\nlisten_host = 192.0.2.10\nlisten_port = 9090\nbearer_token = "+token+"\n", "/etc/ivnp/ivnp.conf")
	if err != nil || !metrics.Metrics.Enabled || metrics.Metrics.BearerToken != token {
		t.Fatalf("authenticated remote metrics = %#v, %v", metrics.Metrics, err)
	}

	secret := "leaked-secret"
	_, err = ParseOperating("[metrics]\nbearer_token = "+secret+"\n", "/etc/ivnp/ivnp.conf")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("token error leaked secret: %v", err)
	}

	loopback, err := ParseOperating("[http_proxy]\nenabled = true\n", "/etc/ivnp/ivnp.conf")
	if err != nil || !loopback.HTTPProxy.Enabled || loopback.HTTPProxy.BearerToken != "" {
		t.Fatalf("loopback listener = %#v, %v", loopback.HTTPProxy, err)
	}
}

func TestParseOperatingRestrictsUnauthenticatedProxyProtocols(t *testing.T) {
	const token = "8GxbrMTEnPS6IQvjGDkAcQ"
	for _, text := range []string{
		"[http_proxy]\nenabled = true\nlisten_host = 192.0.2.10\nlisten_port = 4444\nbearer_token = " + token + "\n",
		"[socks5]\nenabled = true\nlisten_host = 192.0.2.10\nlisten_port = 4447\nbearer_token = " + token + "\n",
		"[http_proxy]\nenabled = true\nbearer_token = " + token + "\n",
		"[socks5]\nenabled = true\nbearer_token = " + token + "\n",
		"[http_proxy]\nbearer_token = " + token + "\n",
		"[socks5]\nbearer_token = " + token + "\n",
		"[metrics]\nenabled = true\nlisten_host = 192.0.2.10\nlisten_port = 9090\n",
	} {
		if _, err := ParseOperating(text, "/etc/ivnp/ivnp.conf"); !errors.Is(err, ErrInvalidOperating) {
			t.Fatalf("ParseOperating(%q) error = %v", text, err)
		}
	}
}

func TestParseOperatingRejectsOutOfRangeNumbersAndDurations(t *testing.T) {
	for _, text := range []string{
		"[network]\nid = 0\n",
		"[state]\nmax_bytes = 1024\n",
		"[ntcp2]\nmax_sessions = 0\n",
		"[ssu2]\nidle_timeout = 0s\n",
		"[metrics]\nmax_connections = 0\n",
		"[reseed]\nenabled = true\nendpoints = https://reseed.example/i2p\nmax_total_bytes = 65536\nmax_archive_bytes = 131072\n",
		"[reseed]\nenabled = true\nendpoints = http://reseed.example/i2p\n",
	} {
		if _, err := ParseOperating(text, "/etc/ivnp/ivnp.conf"); !errors.Is(err, ErrInvalidOperating) {
			t.Fatalf("ParseOperating(%q) error = %v, want invalid operating config", text, err)
		}
	}
}

func TestParseOperatingAcceptsMaximalReseedEndpoints(t *testing.T) {
	const query = "?netid=2"
	endpoint := "https://" + strings.Repeat("a", maxReseedEndpointBytes-len("https:///")-len(query)) + "/" + query
	endpoints := strings.Repeat(endpoint+",", maxReseedEndpoints-1) + endpoint
	text := "[reseed]\nenabled = true\nendpoints = " + endpoints + "\n"
	if len("endpoints = "+endpoints) != len("endpoints = ")+maxReseedEndpoints*maxReseedEndpointBytes+maxReseedEndpoints-1 {
		t.Fatalf("reseed endpoint line length = %d", len("endpoints = "+endpoints))
	}

	config, err := ParseOperating(text, "/etc/ivnp/ivnp.conf")
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Reseed.Endpoints) != maxReseedEndpoints {
		t.Fatalf("reseed endpoints = %d, want %d", len(config.Reseed.Endpoints), maxReseedEndpoints)
	}
	if config.Reseed.Endpoints[0] != endpoint || config.Reseed.Endpoints[maxReseedEndpoints-1] != endpoint {
		t.Fatalf("reseed endpoints = %#v", config.Reseed.Endpoints)
	}
}

func TestParseOperatingRequiresExactReseedNetworkQuery(t *testing.T) {
	for _, endpoint := range []string{
		"https://reseed.example/i2pseeds.su3",
		"https://reseed.example/i2pseeds.su3?",
		"https://reseed.example/i2pseeds.su3?netid=3",
		"https://reseed.example/i2pseeds.su3?netid=2&other=1",
		"https://user:password@reseed.example/i2pseeds.su3?netid=2",
	} {
		text := "[reseed]\nendpoints = " + endpoint + "\n"
		if _, err := ParseOperating(text, "/etc/ivnp/ivnp.conf"); !errors.Is(err, ErrInvalidOperating) {
			t.Fatalf("ParseOperating(%q) error = %v, want invalid operating config", endpoint, err)
		}
	}
	if _, err := parseReseedEndpoints("https://reseed.example/i2pseeds.su3?netid=2#fragment"); err == nil {
		t.Fatal("parseReseedEndpoints() accepted a fragment")
	}
}

func TestParseOperatingTunnelAndNetDB(t *testing.T) {
	text := "[router]\nversion = 1.2.3\n[netdb]\nbucket_capacity = 48\n[tunnel]\nenabled = true\nhops = 3\ninbound_target = 3\noutbound_target = 2\npool_capacity = 6\nbuild_pending_capacity = 12\nlifetime = 10m\nrenew_before = 3m\nmaintenance_interval = 45s\nbandwidth_rate_bytes_per_second = 65536\nbandwidth_burst_bytes = 131072\n"
	operating, err := ParseOperating(text, "/etc/ivnp/ivnp.conf")
	if err != nil {
		t.Fatal(err)
	}
	parseOperatingTunnelAndNetDBRejected := operating.Router.Version != "1.2.3" || operating.NetDB.BucketCapacity != 48 || !operating.Tunnel.Enabled || operating.Tunnel.Hops != 3 || operating.Tunnel.Lifetime != 10*time.Minute || operating.Tunnel.BandwidthRateBytesPerSecond != 65_536
	if !parseOperatingTunnelAndNetDBRejected {
		parseOperatingTunnelAndNetDBRejected = operating.Tunnel.BandwidthBurstBytes != 131_072
	}
	if parseOperatingTunnelAndNetDBRejected {
		t.Fatalf("operating = %#v", operating)
	}
}

func TestParseOperatingRejectsUnsafeTunnelBoundsAndUnknownKeys(t *testing.T) {
	for _, text := range []string{
		"[netdb]\nunknown = 1\n",
		"[tunnel]\ninbound_target = 3\npool_capacity = 5\n",
		"[tunnel]\nlifetime = 9m\n",
		"[tunnel]\nlifetime = 11m\n",
		"[tunnel]\nhops = 8\n",
		"[tunnel]\nrenew_before = 10m\n",
		"[tunnel]\nrenew_before = 30s\nmaintenance_interval = 31s\n",
		"[state]\nmax_destinations = 65\n",
	} {
		if _, err := ParseOperating(text, "/etc/ivnp/ivnp.conf"); !errors.Is(err, ErrInvalidOperating) {
			t.Fatalf("ParseOperating(%q) error = %v", text, err)
		}
	}
}

func TestParseOperatingStaticBootstrapFilesAreOptionalAndResolved(t *testing.T) {
	config, err := ParseOperating("[netdb]\nbootstrap_router_info_files = peers/a.dat, /var/lib/ivnp/b.dat\n", "/etc/ivnp/ivnp.conf")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/etc/ivnp/peers/a.dat", "/var/lib/ivnp/b.dat"}
	if len(config.NetDB.BootstrapRouterInfoPaths) != len(want) {
		t.Fatalf("bootstrap paths = %#v", config.NetDB.BootstrapRouterInfoPaths)
	}
	for index := range want {
		if config.NetDB.BootstrapRouterInfoPaths[index] != want[index] {
			t.Fatalf("bootstrap paths = %#v, want %#v", config.NetDB.BootstrapRouterInfoPaths, want)
		}
	}
	defaults, err := ParseOperating("", "/etc/ivnp/ivnp.conf")
	if err != nil {
		t.Fatal(err)
	}
	if len(defaults.NetDB.BootstrapRouterInfoPaths) != 0 {
		t.Fatalf("default bootstrap paths = %#v, want none", defaults.NetDB.BootstrapRouterInfoPaths)
	}
}

func TestParseOperatingRejectsDuplicateStaticBootstrapFiles(t *testing.T) {
	if _, err := ParseOperating("[netdb]\nbootstrap_router_info_files = peers/a.dat, peers/../peers/a.dat\n", "/etc/ivnp/ivnp.conf"); !errors.Is(err, ErrInvalidOperating) {
		t.Fatalf("duplicate bootstrap path error = %v", err)
	}
}
