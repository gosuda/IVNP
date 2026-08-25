package daemon

import state "gosuda.org/ivnp/state"

import networking "gosuda.org/ivnp/networking"

import "cmp"

import (
	"context"
	"errors"
	ivnp "gosuda.org/ivnp/foundation"

	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"
)

type fakeNATPMPClient struct {
	mu               sync.Mutex
	gateway          netip.Addr
	public           netip.Addr
	publicErr        error
	mapErr           error
	external         uint16
	lifetime         time.Duration
	requests         []networking.NetworkAddressTranslationPortMappingMappingRequest
	unmapCalls       int
	publicCalls      chan int
	publicCallsCount int
	events           *[]string
}

func (f *fakeNATPMPClient) PublicAddress(context.Context) (networking.NetworkAddressTranslationPortMappingPublicAddress, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.events != nil {
		*f.events = append(*f.events, "natpmp-public")
	}
	f.publicCallsCount++
	if f.publicCalls != nil {
		select {
		case f.publicCalls <- f.publicCallsCount:
		default:
		}
	}
	return networking.NetworkAddressTranslationPortMappingPublicAddress{Address: f.public}, f.publicErr
}

func (f *fakeNATPMPClient) Map(_ context.Context, request networking.NetworkAddressTranslationPortMappingMappingRequest) (networking.NetworkAddressTranslationPortMappingMapping, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.events != nil {
		*f.events = append(*f.events, "natpmp-map")
	}
	f.requests = append(f.requests, request)
	if f.mapErr != nil {
		return networking.NetworkAddressTranslationPortMappingMapping{}, f.mapErr
	}
	external := f.external

	external = cmp.Or(external, request.ExternalPort)

	return networking.NetworkAddressTranslationPortMappingMapping{Gateway: f.gateway, Protocol: request.Protocol, InternalPort: request.InternalPort, ExternalPort: external, Lifetime: f.lifetime}, nil
}

func (f *fakeNATPMPClient) Unmap(context.Context, networking.NetworkAddressTranslationPortMappingMapping) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unmapCalls++
	return nil
}

type fakeUPnPClient struct {
	events            *[]string
	discoverErr       error
	responses         []networking.UniversalPlugAndPlayDiscoveryResponse
	gateway           networking.UniversalPlugAndPlayGateway
	public            netip.Addr
	mapping           networking.UniversalPlugAndPlayPortMapping
	addCalls          int
	deleteCalls       int
	discoverCalls     int
	describedLocation *url.URL
}

func (f *fakeUPnPClient) Discover(context.Context) ([]networking.UniversalPlugAndPlayDiscoveryResponse, error) {
	f.discoverCalls++
	if f.events != nil {
		*f.events = append(*f.events, "upnp-discover")
	}
	return f.responses, f.discoverErr
}
func (f *fakeUPnPClient) Describe(_ context.Context, location *url.URL) (networking.UniversalPlugAndPlayGateway, error) {
	f.describedLocation = location
	return f.gateway, nil
}
func (f *fakeUPnPClient) ExternalAddress(context.Context, networking.UniversalPlugAndPlayGateway) (netip.Addr, error) {
	return f.public, nil
}
func (f *fakeUPnPClient) AddPortMapping(_ context.Context, _ networking.UniversalPlugAndPlayGateway, mapping networking.UniversalPlugAndPlayPortMapping) error {
	f.mapping = mapping
	f.addCalls++
	return nil
}
func (f *fakeUPnPClient) DeletePortMapping(context.Context, networking.UniversalPlugAndPlayGateway, string, uint16, string) error {
	f.deleteCalls++
	return nil
}

type wildcardSockets struct{}

func (wildcardSockets) ListenStream(context.Context, networking.RouterEndpoint) (net.Listener, error) {
	return net.Listen("tcp4", "0.0.0.0:0")
}
func (wildcardSockets) DialStream(ctx context.Context, endpoint networking.RouterEndpoint) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, endpoint.Network, endpoint.Address)
}
func (wildcardSockets) ListenUDP(context.Context, networking.RouterEndpoint) (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
}

func TestDaemonRemainsRunningWhenInitialMappingFailsAndRetries(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.NTCP2 = state.ConfigurationTransport{Enabled: true, Bind: state.ConfigurationEndpoint{Host: "0.0.0.0"}, MaxSessions: 4}
	cfg.NAT.NATPMPEndpoint = netip.MustParseAddrPort("10.2.0.1:5351")
	calls := make(chan int, 4)
	natClient := &fakeNATPMPClient{publicErr: errors.New("NAT-PMP unavailable"), publicCalls: calls}
	upnpClient := &fakeUPnPClient{discoverErr: errors.New("UPnP unavailable")}
	waited := make(chan time.Duration, 2)
	var waitMu sync.Mutex
	waitCalls := 0
	virtualWait := func(ctx context.Context, delay time.Duration) bool {
		waited <- delay
		waitMu.Lock()
		waitCalls++
		first := waitCalls == 1
		waitMu.Unlock()
		if first {
			return true
		}
		<-ctx.Done()
		return false
	}
	d, err := New(cfg, Options{
		SocketRuntime: wildcardSockets{},
		Logger:        discardNATLogger(),
		NAT: testNATRuntime{
			newNATPMP: func(netip.AddrPort) natPMPClient { return natClient },
			upnp:      upnpClient,
			prefixes: func() ([]netip.Prefix, error) {
				return []netip.Prefix{netip.MustParsePrefix("10.2.0.2/32")}, nil
			},
			route: func(context.Context, string, uint16) (netip.Addr, error) {
				return netip.MustParseAddr("10.2.0.2"), nil
			},
			wait: virtualWait,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !d.Status().Running {
		t.Fatal("daemon stopped after both automatic mappers failed")
	}
	for want := 1; want <= 2; want++ {
		select {
		case got := <-calls:
			if got != want {
				t.Fatalf("NAT-PMP attempt = %d, want %d", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("NAT-PMP attempt %d was not observed", want)
		}
	}
	for range 2 {
		select {
		case delay := <-waited:
			if delay != 30*time.Second {
				t.Fatalf("mapping retry delay = %s, want 30s", delay)
			}
		case <-time.After(time.Second):
			t.Fatal("default 30-second retry was not scheduled")
		}
	}
	if upnpClient.addCalls != 0 {
		t.Fatal("UPnP mapping was added despite discovery failure")
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	if err = d.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestAutomaticMappingUsesNATPMPFirstAndObservedLease(t *testing.T) {
	local := newNATMappingTestLocal(t)
	base := staticAddressPublisher{{Transport: "NTCP2", Options: []networking.RouterMappingOption{{Key: "v", Value: "2"}}}}
	publisher := newNATMappingPublisher(base, autoTransportConfig{enabled: true, automatic: true}, autoTransportConfig{}, netip.AddrPort{}, "", local, discardNATLogger()).(*natMappingPublisher)
	client := &fakeNATPMPClient{gateway: netip.MustParseAddr("10.2.0.1"), public: netip.MustParseAddr("198.51.100.20"), external: 42832, lifetime: time.Minute}
	fallback := &fakeUPnPClient{discoverErr: errors.New("UPnP must not run after NAT-PMP succeeds")}
	publisher.prefixes = func() ([]netip.Prefix, error) { return []netip.Prefix{netip.MustParsePrefix("10.2.0.2/32")}, nil }
	publisher.route = func(context.Context, string, uint16) (netip.Addr, error) { return netip.MustParseAddr("10.2.0.2"), nil }
	publisher.newNATPMP = func(endpoint netip.AddrPort) natPMPClient {
		if endpoint != netip.MustParseAddrPort("10.2.0.1:5351") {
			t.Fatalf("first NAT-PMP endpoint = %s", endpoint)
		}
		return client
	}
	publisher.upnp = fallback

	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addresses, err := publisher.AddressesForSockets(context.Background(), listener, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := addressOptions(addresses[0])
	if options["host"] != "198.51.100.20" || options["port"] != "42832" {
		t.Fatalf("mapped address options = %#v", options)
	}
	client.mu.Lock()
	request := client.requests[0]
	client.lifetime = 30 * time.Second
	client.mu.Unlock()
	if request.ExternalPort != 0 || request.InternalPort == 0 || request.Lifetime != 2*time.Minute || request.Protocol != networking.NetworkAddressTranslationPortMappingTCP {
		t.Fatalf("initial NAT-PMP request = %#v", request)
	}
	publisher.mu.Lock()
	active := publisher.active[0]
	publisher.mu.Unlock()
	renewed, err := publisher.renew(context.Background(), active)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.lifetime != 30*time.Second || adaptiveRenewDelay(renewed.lifetime) != 20*time.Second {
		t.Fatalf("observed renewal lease = %s, delay = %s", renewed.lifetime, adaptiveRenewDelay(renewed.lifetime))
	}
	if fallback.addCalls != 0 {
		t.Fatal("UPnP ran despite successful NAT-PMP mapping")
	}
	if err = publisher.Close(); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	unmaps := client.unmapCalls
	client.mu.Unlock()
	if unmaps != 1 {
		t.Fatalf("NAT-PMP unmap calls = %d", unmaps)
	}
}

func TestAutomaticMappingFallsBackToUPnP(t *testing.T) {
	local := newNATMappingTestLocal(t)
	base := staticAddressPublisher{{Transport: "NTCP2"}}
	publisher := newNATMappingPublisher(base, autoTransportConfig{enabled: true, automatic: true}, autoTransportConfig{}, netip.AddrPort{}, "", local, discardNATLogger()).(*natMappingPublisher)
	events := make([]string, 0, 2)
	natClient := &fakeNATPMPClient{publicErr: errors.New("no NAT-PMP response"), events: &events}
	location, _ := url.Parse("http://192.168.1.1/igd.xml")
	control, _ := url.Parse("http://192.168.1.1/control")
	upnpClient := &fakeUPnPClient{
		events: &events, responses: []networking.UniversalPlugAndPlayDiscoveryResponse{{Location: location}},
		gateway: networking.UniversalPlugAndPlayGateway{ControlURL: control, ServiceType: "urn:schemas-upnp-org:service:WANIPConnection:2"},
		public:  netip.MustParseAddr("198.51.100.30"),
	}
	publisher.prefixes = func() ([]netip.Prefix, error) { return []netip.Prefix{netip.MustParsePrefix("10.2.0.2/32")}, nil }
	publisher.route = func(_ context.Context, host string, _ uint16) (netip.Addr, error) {
		if host == "10.2.0.1" {
			return netip.MustParseAddr("10.2.0.2"), nil
		}
		return netip.MustParseAddr("192.168.1.20"), nil
	}
	publisher.newNATPMP = func(netip.AddrPort) natPMPClient { return natClient }
	publisher.upnp = upnpClient

	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addresses, err := publisher.AddressesForSockets(context.Background(), listener, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 || events[0] != "natpmp-public" || events[1] != "upnp-discover" {
		t.Fatalf("mapping attempt order = %#v", events)
	}
	options := addressOptions(addresses[0])
	if options["host"] != "198.51.100.30" || options["port"] == "" || upnpClient.addCalls != 1 {
		t.Fatalf("UPnP mapping = options %#v, calls %d", options, upnpClient.addCalls)
	}
	if upnpClient.mapping.ExternalPort != upnpClient.mapping.InternalPort || upnpClient.mapping.LeaseDuration != 120 {
		t.Fatalf("UPnP mapping request = %#v", upnpClient.mapping)
	}
	if err = publisher.Close(); err != nil {
		t.Fatal(err)
	}
	if upnpClient.deleteCalls != 1 {
		t.Fatalf("UPnP delete calls = %d", upnpClient.deleteCalls)
	}
}

func TestExplicitNATPMPEndpointBypassesGatewayDiscovery(t *testing.T) {
	local := newNATMappingTestLocal(t)
	endpoint := netip.MustParseAddrPort("10.9.0.1:6000")
	publisher := newNATMappingPublisher(
		staticAddressPublisher{{Transport: "NTCP2"}},
		autoTransportConfig{enabled: true, automatic: true},
		autoTransportConfig{},
		endpoint,
		"",
		local,
		discardNATLogger(),
	).(*natMappingPublisher)
	publisher.prefixes = func() ([]netip.Prefix, error) {
		t.Fatal("interface discovery ran for an explicit NAT-PMP endpoint")
		return nil, nil
	}
	publisher.route = func(_ context.Context, host string, port uint16) (netip.Addr, error) {
		if host != "10.9.0.1" || port != 6000 {
			t.Fatalf("routed explicit endpoint = %s:%d", host, port)
		}
		return netip.MustParseAddr("10.9.0.2"), nil
	}
	client := &fakeNATPMPClient{
		gateway: netip.MustParseAddr("10.9.0.1"), public: netip.MustParseAddr("198.51.100.50"),
		external: 45000, lifetime: time.Minute,
	}
	publisher.newNATPMP = func(got netip.AddrPort) natPMPClient {
		if got != endpoint {
			t.Fatalf("NAT-PMP factory endpoint = %s", got)
		}
		return client
	}
	mapping, err := publisher.attemptNATPMP(context.Background(), natMappingSpec{
		transport: "NTCP2", protocol: "TCP", internalPort: 44000,
		boundAddress: netip.IPv4Unspecified(),
	}, 0)
	if err != nil || mapping.externalPort != 45000 {
		t.Fatalf("explicit NAT-PMP mapping = %#v, %v", mapping, err)
	}
}

func TestExplicitUPnPEndpointBypassesSSDPDiscovery(t *testing.T) {
	local := newNATMappingTestLocal(t)
	const location = "http://192.168.0.1/rootDesc.xml"
	publisher := newNATMappingPublisher(
		staticAddressPublisher{{Transport: "NTCP2"}},
		autoTransportConfig{enabled: true, automatic: true},
		autoTransportConfig{},
		netip.AddrPort{},
		location,
		local,
		discardNATLogger(),
	).(*natMappingPublisher)
	control, _ := url.Parse("http://192.168.0.1/control")
	client := &fakeUPnPClient{gateway: networking.UniversalPlugAndPlayGateway{ControlURL: control, ServiceType: "urn:schemas-upnp-org:service:WANIPConnection:2"}}
	publisher.upnp = client
	gateway, err := publisher.upnpGateway(context.Background())
	if err != nil || gateway.ControlURL.String() != control.String() {
		t.Fatalf("explicit UPnP gateway = %#v, %v", gateway, err)
	}
	if client.discoverCalls != 0 || client.describedLocation == nil || client.describedLocation.String() != location {
		t.Fatalf("UPnP explicit discovery calls=%d location=%v", client.discoverCalls, client.describedLocation)
	}
}

func TestUnavailableUPnPDiscoveryIsNotRepeated(t *testing.T) {
	local := newNATMappingTestLocal(t)
	publisher := newNATMappingPublisher(
		staticAddressPublisher{{Transport: "NTCP2"}},
		autoTransportConfig{enabled: true, automatic: true},
		autoTransportConfig{},
		netip.AddrPort{},
		"",
		local,
		discardNATLogger(),
	).(*natMappingPublisher)
	client := new(fakeUPnPClient)
	publisher.upnp = client
	for range 2 {
		if _, err := publisher.upnpGateway(context.Background()); !errors.Is(err, errUPnPDiscoveryUnavailable) {
			t.Fatalf("unavailable discovery error = %v", err)
		}
	}
	if client.discoverCalls != 1 {
		t.Fatalf("UPnP discovery calls = %d, want one definitive probe", client.discoverCalls)
	}
}

func TestGatewayCandidatesPrioritizePointToPointPeer(t *testing.T) {
	candidates := gatewayCandidates([]netip.Prefix{
		netip.MustParsePrefix("192.168.1.25/24"),
		netip.MustParsePrefix("10.2.0.2/32"),
	})
	if len(candidates) < 2 || candidates[0] != netip.MustParseAddr("10.2.0.1") {
		t.Fatalf("gateway candidates = %v", candidates)
	}
	foundLAN := false
	for _, candidate := range candidates {
		foundLAN = foundLAN || candidate == netip.MustParseAddr("192.168.1.1")
	}
	if !foundLAN {
		t.Fatalf("LAN gateway missing from %v", candidates)
	}
}

func TestAdaptiveRenewDelayUsesGrantedLifetime(t *testing.T) {
	for granted, want := range map[time.Duration]time.Duration{
		60 * time.Second:       40 * time.Second,
		2 * time.Minute:        80 * time.Second,
		500 * time.Millisecond: 250 * time.Millisecond,
		0:                      natRetryInterval,
	} {
		if got := adaptiveRenewDelay(granted); got != want {
			t.Errorf("adaptiveRenewDelay(%s) = %s, want %s", granted, got, want)
		}
	}
}

func TestMappingChangeRepublishesRouterInfo(t *testing.T) {
	local := newNATMappingTestLocal(t)
	base := staticAddressPublisher{{Transport: "NTCP2", Options: []networking.RouterMappingOption{{Key: "v", Value: "2"}}}}
	if err := local.ReplaceAddresses([]networking.RouterPublishedAddress(base)); err != nil {
		t.Fatal(err)
	}
	local.SetReachability(networking.RouterReachabilityFirewalled)
	if err := local.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := string(local.Snapshot().Bytes())
	publisher := newNATMappingPublisher(base, autoTransportConfig{enabled: true, automatic: true}, autoTransportConfig{}, netip.AddrPort{}, "", local, discardNATLogger()).(*natMappingPublisher)
	publisher.setActive(context.Background(), &activeNATMapping{
		spec:   natMappingSpec{addressIndex: 0, transport: "NTCP2"},
		public: netip.MustParseAddr("198.51.100.40"), externalPort: 42424,
	})
	snapshot := local.Snapshot()
	valid, err := snapshot.Verify()
	if err != nil || !valid {
		t.Fatalf("republished RouterInfo verification = %t, %v", valid, err)
	}
	if string(snapshot.Bytes()) == before {
		t.Fatal("mapping change did not republish RouterInfo")
	}
	options := snapshotTransportOptions(t, snapshot, "NTCP2")
	if options["host"] != "198.51.100.40" || options["port"] != "42424" {
		t.Fatalf("republished options = %#v", options)
	}
}

func snapshotTransportOptions(t *testing.T, info networking.NetworkDatabaseRouterInfo, transport string) map[string]string {
	t.Helper()
	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("RouterInfo has no %s address", transport)
		}
		if string(address.TransportStyle) != transport {
			continue
		}
		options := make(map[string]string)
		iterator := address.Options.Iterator()
		for {
			key, value, ok, err := iterator.Next()
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				return options
			}
			options[string(key)] = string(value)
		}
	}
}

func newNATMappingTestLocal(t *testing.T) *networking.RouterLocalRouterInfo {
	t.Helper()
	identity, err := ivnp.GenerateLocalRouterAddress()
	if err != nil {
		t.Fatal(err)
	}
	local, err := networking.RouterNewLocalRouterInfo(networking.RouterLocalRouterInfoConfig{Local: identity, RouterVersion: "nat-mapping-test"})
	if err != nil {
		t.Fatal(err)
	}
	return local
}

func discardNATLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func addressOptions(address networking.RouterPublishedAddress) map[string]string {
	options := make(map[string]string, len(address.Options))
	for _, option := range address.Options {
		options[option.Key] = option.Value
	}
	return options
}

type testNATRuntime struct {
	newNATPMP func(netip.AddrPort) natPMPClient
	upnp      upnpClient
	prefixes  func() ([]netip.Prefix, error)
	route     func(context.Context, string, uint16) (netip.Addr, error)
	retry     time.Duration
	wait      func(context.Context, time.Duration) bool
}

func (r testNATRuntime) NewNATPMP(endpoint netip.AddrPort) natPMPClient { return r.newNATPMP(endpoint) }
func (r testNATRuntime) UPnP() upnpClient                               { return r.upnp }
func (r testNATRuntime) Prefixes() ([]netip.Prefix, error)              { return r.prefixes() }
func (r testNATRuntime) Route(ctx context.Context, network string, port uint16) (netip.Addr, error) {
	return r.route(ctx, network, port)
}
func (r testNATRuntime) RetryInterval() time.Duration { return r.retry }
func (r testNATRuntime) Wait(ctx context.Context, delay time.Duration) bool {
	return r.wait(ctx, delay)
}
