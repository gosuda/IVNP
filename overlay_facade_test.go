package ivnp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp/authn"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/overlay"
)

// nativeEntry moves a legacy RouterConfig's network fields into the canonical
// "i2p" Networks entry — the exact shape the legacy bridging path produces.
func nativeEntry(cfg RouterConfig) NetworkConfig {
	return NetworkConfig{
		Name: networkNativeName, Kind: NetworkNativeI2P, NetworkID: cfg.NetworkID,
		NTCP2: cfg.NTCP2, SSU2: cfg.SSU2, Bootstrap: cfg.Bootstrap, Exploratory: cfg.Exploratory,
	}
}

func useNetworks(cfg *RouterConfig, entries ...NetworkConfig) {
	cfg.Networks = entries
	cfg.NetworkID = 0
	cfg.NTCP2, cfg.SSU2 = TransportConfig{}, TransportConfig{}
	cfg.Bootstrap, cfg.Exploratory = BootstrapConfig{}, TunnelPoolConfig{}
}

func freeTCP(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// TestOverlayPrivateFabricEndToEnd runs the full facade path: two embedded
// routers each operate the official I2P context and a shared private fabric;
// one destination listens on the fabric, the other dials it by endpoint id.
func TestOverlayPrivateFabricEndToEnd(t *testing.T) {
	flood := embeddedTestFloodfill(t)
	network := newEmbeddedMemoryNetwork(flood)

	// B's identity must exist before A's static membership is configured:
	// its endpoint id and signing key pin A's view of B. The streaming layer
	// requires the legacy ElGamal/Ed25519 shape.
	destB, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destB.ReleaseSensitive)
	identityB, err := destB.Identity()
	if err != nil {
		t.Fatal(err)
	}
	canonicalB := identityB.Bytes()
	endpointB, err := overlay.EndpointIDFromDestination(canonicalB)
	if err != nil {
		t.Fatal(err)
	}
	addrB := freeTCP(t)

	realm := &RealmProfile{
		ID: RealmIDFor("corp-e2e"), Admission: AdmissionOpen, AcknowledgeOpen: true,
		AcknowledgeExposure: true,
		Discovery:           DiscoveryLocalOnly, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOverlayDirect, Publication: PublicationNone,
		Prefix:  PrefixPolicy{Mode: PrefixDisabled},
		Fabrics: []string{"corp"}, IncludeNative: true,
	}
	fabricID := FabricIDFor("corp")

	// Router identities are fixed by their persistence directories, so the
	// capture and the final run must share each config. The third router is
	// required for tunnel diversity: an outbound build may not reuse the
	// inbound gateway, and the synthetic floodfill is not an eligible hop.
	cfgA, cfgB, cfgC := embeddedTestConfig(t), embeddedTestConfig(t), embeddedTestConfig(t)
	infoA := captureEmbeddedRouterInfo(t, cfgA, network)
	infoB := captureEmbeddedRouterInfo(t, cfgB, network)
	infoC := captureEmbeddedRouterInfo(t, cfgC, network)

	// C stays on the legacy single-network configuration — a plain I2P
	// router coexisting with the dual-configured ones.
	cfgC.Bootstrap.RouterInfos = [][]byte{infoA, infoB, flood.Bytes()}

	nativeB := nativeEntry(cfgB)
	nativeB.Bootstrap.RouterInfos = [][]byte{infoA, infoC, flood.Bytes()}
	useNetworks(&cfgB, nativeB,
		IVNPFabricNetwork("corp", 77, 8, []string{addrB}, nil))
	cfgB.Realm = realm

	nativeA := nativeEntry(cfgA)
	nativeA.Bootstrap.RouterInfos = [][]byte{infoB, infoC, flood.Bytes()}
	useNetworks(&cfgA, nativeA,
		IVNPFabricNetwork("corp", 77, 8, nil, []StaticPeer{
			{Destination: canonicalB, Contact: "ivnp-tls@" + addrB},
		}))
	cfgA.Realm = realm

	routerC := newEmbeddedTestRouter(t, cfgC, network.transport())
	if routerC.Overlay() != nil {
		t.Fatal("legacy router unexpectedly composed an overlay host")
	}
	routerB := newEmbeddedTestRouter(t, cfgB, network.transport())
	routerA := newEmbeddedTestRouter(t, cfgA, network.transport())
	if routerA.Overlay() == nil || routerB.Overlay() == nil {
		t.Fatal("realm configuration did not compose the overlay host")
	}

	ctx, cancel := context.WithTimeout(context.Background(), embeddedTestTimeout)
	defer cancel()

	profile := &ServiceProfile{
		Port:        47001,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
		Publication: PublicationNone,
	}
	destCfgB := DefaultDestinationConfig()
	destCfgB.Tunnels = nativeB.Exploratory
	destCfgB.Identity = destB
	destCfgB.Networks = []string{"corp"}
	destCfgB.Overlay = profile
	target, err := routerB.NewDestination(ctx, destCfgB)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	destCfgA := DefaultDestinationConfig()
	destCfgA.Tunnels = nativeA.Exploratory
	destCfgA.Networks = []string{"corp"}
	destCfgA.Overlay = &ServiceProfile{Protocols: profile.Protocols, Publication: PublicationNone}
	source, err := routerA.NewDestination(ctx, destCfgA)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	listener, err := target.ListenOverlay(OverlayListenPolicy{
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Classes:   []RouteClass{RouteDirect},
		Privacy:   PrivacyExplicitDirect, Queue: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan *OverlayConnection, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- conn
	}()

	conn, err := source.DialOverlay(ctx, OverlayTarget{
		Endpoint: EndpointRef{ID: endpointB}, Port: 47001,
	}, OverlayDialPolicy{
		Fabrics:           []FabricID{fabricID},
		RouteClasses:      []RouteClass{RouteDirect},
		EndpointProtocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Privacy:           PrivacyExplicitDirect,
		Fallback:          ProtocolIVNPOnly, Failover: FailoverReconnect,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var inbound *OverlayConnection
	select {
	case inbound = <-accepted:
	case err = <-acceptErrors:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer inbound.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(inbound, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("inbound read %q", buf)
	}
	if _, err := inbound.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "pong" {
		t.Fatalf("outbound read %q", buf)
	}
}

// TestOverlayAbsentWithoutRealm keeps the legacy single-network router free
// of overlay state.
func TestOverlayAbsentWithoutRealm(t *testing.T) {
	network := newEmbeddedMemoryNetwork(embeddedTestFloodfill(t))
	router := newEmbeddedTestRouter(t, embeddedTestConfig(t), network.transport())
	if router.Overlay() != nil {
		t.Fatal("router without a realm exposed an overlay host")
	}
}

func TestParseOverlayTarget(t *testing.T) {
	dest, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	ident, err := dest.Identity()
	if err != nil {
		t.Fatal(err)
	}
	endpointID, err := overlay.EndpointIDFromDestination(ident.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	b32 := endpointID.String() // "ivnp://<b32>"
	rawB32 := b32[7:]

	// "ivnp://<b32>:47001"
	target, err := ParseOverlayTarget(b32 + ":47001")
	if err != nil || target.Endpoint.ID != endpointID || target.Port != 47001 {
		t.Fatalf("ParseOverlayTarget(%q) = (%+v, %v)", b32+":47001", target, err)
	}

	// "<b32>:47001"
	target, err = ParseOverlayTarget(rawB32 + ":47001")
	if err != nil || target.Endpoint.ID != endpointID || target.Port != 47001 {
		t.Fatalf("ParseOverlayTarget(%q) = (%+v, %v)", rawB32+":47001", target, err)
	}

	// "<b32>.b32.i2p:47001"
	target, err = ParseOverlayTarget(rawB32 + ".b32.i2p:47001")
	if err != nil || target.Endpoint.ID != endpointID || target.Port != 47001 {
		t.Fatalf("ParseOverlayTarget(%q) = (%+v, %v)", rawB32+".b32.i2p:47001", target, err)
	}

	// "ivnp://<b32>" (port 0)
	target, err = ParseOverlayTarget(b32)
	if err != nil || target.Endpoint.ID != endpointID || target.Port != 0 {
		t.Fatalf("ParseOverlayTarget(%q) = (%+v, %v)", b32, target, err)
	}

	// Invalid inputs
	for _, bad := range []string{"", "not-an-endpoint", "ivnp://invalid:47001", rawB32 + ":badport", ":47001"} {
		if _, err := ParseOverlayTarget(bad); err == nil {
			t.Fatalf("ParseOverlayTarget(%q) expected error", bad)
		}
	}
}

func TestOverlayBuildersAndPresets(t *testing.T) {
	realm := NewDualStackRealm("corp", "corp")
	if realm.ID != RealmIDFor("corp") || !realm.IncludeNative || realm.Discovery != DiscoveryHedged {
		t.Fatalf("NewDualStackRealm = %+v", realm)
	}

	privRealm := NewPrivateRealm("isolated", []byte("secret-psk-1234567890123456789012"), "isolated")
	if privRealm.IncludeNative || privRealm.Privacy != PrivacyPrivateConfined || privRealm.Admission != AdmissionPSK {
		t.Fatalf("NewPrivateRealm = %+v", privRealm)
	}

	credRealm := authn.NewCredentialRealm("enterprise", "enterprise")
	if credRealm.IncludeNative || credRealm.Admission != authn.AdmissionCredential {
		t.Fatalf("authn.NewCredentialRealm = %+v", credRealm)
	}

	cfg := DefaultDualStackRouterConfig("corp", 77, "127.0.0.1:47001")
	if len(cfg.Networks) != 2 || cfg.Realm == nil {
		t.Fatalf("DefaultDualStackRouterConfig = %+v", cfg)
	}
	if cfg.NetworkID != 0 || cfg.NTCP2 != (TransportConfig{}) {
		t.Fatal("DefaultDualStackRouterConfig left legacy fields set")
	}

	peer := NewStaticPeer([]byte("canonical-dest"), "127.0.0.1:47001")
	if peer.Contact != "ivnp-tls@127.0.0.1:47001" {
		t.Fatalf("NewStaticPeer contact = %q", peer.Contact)
	}
}

// TestOverlayUnifiedDialListenEndToEnd tests the unified dest.DialContext and
// dest.Listen standard Go API using "ivnp" and fabric network identifiers.
func TestOverlayUnifiedDialListenEndToEnd(t *testing.T) {
	flood := embeddedTestFloodfill(t)
	network := newEmbeddedMemoryNetwork(flood)

	destB, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destB.ReleaseSensitive)
	identityB, err := destB.Identity()
	if err != nil {
		t.Fatal(err)
	}
	canonicalB := identityB.Bytes()
	endpointB, err := overlay.EndpointIDFromDestination(canonicalB)
	if err != nil {
		t.Fatal(err)
	}
	addrB := freeTCP(t)

	realm := NewDualStackRealm("unified-e2e", "corp")
	cfgA, cfgB, cfgC := embeddedTestConfig(t), embeddedTestConfig(t), embeddedTestConfig(t)
	infoA := captureEmbeddedRouterInfo(t, cfgA, network)
	infoB := captureEmbeddedRouterInfo(t, cfgB, network)
	infoC := captureEmbeddedRouterInfo(t, cfgC, network)

	cfgC.Bootstrap.RouterInfos = [][]byte{infoA, infoB, flood.Bytes()}

	nativeB := nativeEntry(cfgB)
	nativeB.Bootstrap.RouterInfos = [][]byte{infoA, infoC, flood.Bytes()}
	cfgB.SetNetworks(realm, nativeB,
		IVNPFabricNetwork("corp", 77, 8, []string{addrB}, nil))

	nativeA := nativeEntry(cfgA)
	nativeA.Bootstrap.RouterInfos = [][]byte{infoB, infoC, flood.Bytes()}
	cfgA.SetNetworks(realm, nativeA,
		IVNPFabricNetwork("corp", 77, 8, nil, []StaticPeer{
			NewStaticPeer(canonicalB, addrB),
		}))

	_ = newEmbeddedTestRouter(t, cfgC, network.transport())
	routerB := newEmbeddedTestRouter(t, cfgB, network.transport())
	routerA := newEmbeddedTestRouter(t, cfgA, network.transport())

	ctx, cancel := context.WithTimeout(context.Background(), embeddedTestTimeout)
	defer cancel()

	destCfgB := DefaultDestinationConfig()
	destCfgB.Tunnels = nativeB.Exploratory
	destCfgB.Identity = destB
	destCfgB.Networks = []string{"corp"}
	destCfgB.Overlay = &ServiceProfile{
		Port:        47001,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
		Publication: PublicationNone,
	}
	target, err := routerB.NewDestination(ctx, destCfgB)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	destCfgA := DefaultDestinationConfig()
	destCfgA.Tunnels = nativeA.Exploratory
	destCfgA.Networks = []string{"corp"}
	destCfgA.Overlay = &ServiceProfile{
		Port:        47002,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
		Publication: PublicationNone,
	}
	source, err := routerA.NewDestination(ctx, destCfgA)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	// Listen using standard Go net.Listener via "ivnp"
	listener, err := target.Listen("ivnp", ":47001")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Verify mismatched port is rejected
	if _, err := target.Listen("ivnp", ":9999"); err == nil {
		t.Fatal("expected error for mismatched port on overlay listen")
	}
	// Verify wildcard / empty address is accepted
	lEmpty, err := target.Listen("ivnp", "")
	if err != nil {
		t.Fatalf("target.Listen with empty address: %v", err)
	}
	_ = lEmpty.Close()

	if listener.Addr().Network() != "ivnp" {
		t.Fatalf("listener.Addr().Network() = %q, want ivnp", listener.Addr().Network())
	}

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	// Verify negative timeout is rejected
	dialerBad := &Dialer{Destination: source, Timeout: -time.Second}
	if _, err := dialerBad.DialContext(ctx, "ivnp", endpointB.String()+":47001"); err == nil {
		t.Fatal("expected error for negative Dialer.Timeout on overlay dial")
	}

	// Dial using standard Go DialContext via "ivnp"
	targetAddr := endpointB.String() + ":47001"
	conn, err := source.DialContext(ctx, "ivnp", targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Verify net.Conn interface methods
	if conn.RemoteAddr().Network() != "ivnp" {
		t.Fatalf("conn.RemoteAddr().Network() = %q, want ivnp", conn.RemoteAddr().Network())
	}

	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer serverConn.Close()

	// Test I/O over standard net.Conn
	if _, err := conn.Write([]byte("hello-unified")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 13)
	if _, err := io.ReadFull(serverConn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello-unified" {
		t.Fatalf("received %q", buf)
	}

	if _, err := serverConn.Write([]byte("world-unified")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "world-unified" {
		t.Fatalf("received %q", buf)
	}

	// Dial using fabric name directly ("corp")
	conn2, err := source.DialContext(ctx, "corp", targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	serverConn2, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn2.Close()

	if _, err := conn2.Write([]byte("ping-fabric")); err != nil {
		t.Fatal(err)
	}
	buf2 := make([]byte, 11)
	if _, err := io.ReadFull(serverConn2, buf2); err != nil {
		t.Fatal(err)
	}
	if string(buf2) != "ping-fabric" {
		t.Fatalf("received %q", buf2)
	}

	// Verify DialOverlay without explicit policy
	connOverlay, err := source.DialOverlay(ctx, OverlayTarget{Endpoint: EndpointRef{ID: endpointB}, Port: 47001})
	if err != nil {
		t.Fatalf("DialOverlay without explicit policy: %v", err)
	}
	defer connOverlay.Close()
	serverConnOverlay, err := listener.Accept()
	if err != nil {
		t.Fatalf("listener.Accept for DialOverlay: %v", err)
	}
	_ = serverConnOverlay.Close()
}

// TestOverlayMultiNetworkSingleRouter verifies that a single router can host
// the official I2P network and multiple private fabrics simultaneously.
func TestOverlayMultiNetworkSingleRouter(t *testing.T) {
	flood := embeddedTestFloodfill(t)
	network := newEmbeddedMemoryNetwork(flood)

	destB, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destB.ReleaseSensitive()
	identB, _ := destB.Identity()
	canonicalB := identB.Bytes()
	endpointB, _ := overlay.EndpointIDFromDestination(canonicalB)
	addrB1 := freeTCP(t)
	addrB2 := freeTCP(t)

	cfgA, cfgB, cfgC := embeddedTestConfig(t), embeddedTestConfig(t), embeddedTestConfig(t)
	infoA := captureEmbeddedRouterInfo(t, cfgA, network)
	infoB := captureEmbeddedRouterInfo(t, cfgB, network)
	infoC := captureEmbeddedRouterInfo(t, cfgC, network)

	realmB := NewDualStackRealm("multi-net", "corp")
	nativeB := nativeEntry(cfgB)
	nativeB.Bootstrap.RouterInfos = [][]byte{infoA, infoC, flood.Bytes()}
	cfgB.SetNetworks(realmB, nativeB,
		IVNPFabricNetwork("corp", 77, 8, []string{addrB1}, nil),
		IVNPFabricNetwork("mesh", 88, 8, []string{addrB2}, nil),
	)

	realmA := NewDualStackRealm("multi-net", "corp")
	nativeA := nativeEntry(cfgA)
	nativeA.Bootstrap.RouterInfos = [][]byte{infoB, infoC, flood.Bytes()}
	cfgA.SetNetworks(realmA, nativeA,
		IVNPFabricNetwork("corp", 77, 8, nil, []StaticPeer{
			NewStaticPeer(canonicalB, addrB1),
		}),
	)

	cfgC.Bootstrap.RouterInfos = [][]byte{infoA, infoB, flood.Bytes()}

	_ = newEmbeddedTestRouter(t, cfgC, network.transport())
	routerB := newEmbeddedTestRouter(t, cfgB, network.transport())
	routerA := newEmbeddedTestRouter(t, cfgA, network.transport())

	ctx, cancel := context.WithTimeout(context.Background(), embeddedTestTimeout)
	defer cancel()

	destCfgB := DefaultDestinationConfig()
	destCfgB.Tunnels = nativeB.Exploratory
	destCfgB.Identity = destB
	destCfgB.Networks = []string{"corp"}
	destCfgB.Overlay = &ServiceProfile{
		Port:        47001,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
		Publication: PublicationNone,
	}
	target, err := routerB.NewDestination(ctx, destCfgB)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	destCfgA := DefaultDestinationConfig()
	destCfgA.Tunnels = nativeA.Exploratory
	destCfgA.Networks = []string{"corp"}
	destCfgA.Overlay = &ServiceProfile{
		Port:        47002,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
		Publication: PublicationNone,
	}
	source, err := routerA.NewDestination(ctx, destCfgA)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	listener, err := target.Listen("corp", ":47001")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	conn, err := source.DialContext(ctx, "corp", endpointB.String()+":47001")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	srvConn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()

	if _, err := conn.Write([]byte("multi-fab")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 9)
	if _, err := io.ReadFull(srvConn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "multi-fab" {
		t.Fatalf("read %q, want multi-fab", buf)
	}
}

type mockCustomTransport struct {
	carrier string
	mu      sync.Mutex
	inbound chan customInboundPair
	dialed  bool
}

type customInboundPair struct {
	ch    Channel
	scope ChannelScope
}

func newMockCustomTransport(carrier string) *mockCustomTransport {
	return &mockCustomTransport{
		carrier: carrier,
		inbound: make(chan customInboundPair, 8),
	}
}

func (m *mockCustomTransport) Carrier() string { return m.carrier }

func (m *mockCustomTransport) Capabilities() TransportCapabilities {
	return TransportCapabilities{
		DirectBinding: true,
		Exporter:      true,
		Speculative:   true,
	}
}

func (m *mockCustomTransport) Setup(ctx context.Context, candidate RouteCandidate, scope ChannelScope, admission *AdmissionRequest) (Channel, error) {
	m.mu.Lock()
	m.dialed = true
	m.mu.Unlock()

	clientConn, serverConn := net.Pipe()

	serverScope := scope
	clientChan := NewChannel(clientConn, scope, candidate.ContactKey)
	serverChan := NewChannel(serverConn, serverScope, candidate.ContactKey)

	select {
	case m.inbound <- customInboundPair{ch: serverChan, scope: serverScope}:
		return clientChan, nil
	case <-ctx.Done():
		clientConn.Close()
		serverConn.Close()
		return nil, ctx.Err()
	}
}

func (m *mockCustomTransport) Accept(ctx context.Context, svc *OverlayService) (Channel, ChannelScope, error) {
	select {
	case item := <-m.inbound:
		return item.ch, item.scope, nil
	case <-ctx.Done():
		return nil, ChannelScope{}, ctx.Err()
	}
}

func TestCustomTransportProvider(t *testing.T) {
	flood := embeddedTestFloodfill(t)
	network := newEmbeddedMemoryNetwork(flood)

	destB, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destB.ReleaseSensitive()
	identB, _ := destB.Identity()
	canonicalB := identB.Bytes()
	endpointB, _ := overlay.EndpointIDFromDestination(canonicalB)

	cfgA, cfgB, cfgC := embeddedTestConfig(t), embeddedTestConfig(t), embeddedTestConfig(t)
	infoA := captureEmbeddedRouterInfo(t, cfgA, network)
	infoB := captureEmbeddedRouterInfo(t, cfgB, network)
	infoC := captureEmbeddedRouterInfo(t, cfgC, network)

	transport := newMockCustomTransport("custom-pipe")

	realmB := NewDualStackRealm("custom-net", "corp")
	nativeB := nativeEntry(cfgB)
	nativeB.Bootstrap.RouterInfos = [][]byte{infoA, infoC, flood.Bytes()}
	cfgB.SetNetworks(realmB, nativeB,
		IVNPFabricNetwork("corp", 77, 8, nil, nil),
	)

	realmA := NewDualStackRealm("custom-net", "corp")
	nativeA := nativeEntry(cfgA)
	nativeA.Bootstrap.RouterInfos = [][]byte{infoB, infoC, flood.Bytes()}
	cfgA.SetNetworks(realmA, nativeA,
		IVNPFabricNetwork("corp", 77, 8, nil, []StaticPeer{
			NewCustomStaticPeer(canonicalB, "custom-pipe", "127.0.0.1:9999"),
		}),
	)
	// Register via RouterConfig on Router A
	cfgA.RegisterTransport(transport)

	cfgC.Bootstrap.RouterInfos = [][]byte{infoA, infoB, flood.Bytes()}

	_ = newEmbeddedTestRouter(t, cfgC, network.transport())
	routerB := newEmbeddedTestRouter(t, cfgB, network.transport())
	routerA := newEmbeddedTestRouter(t, cfgA, network.transport())

	// Register dynamically on running Router B
	if err := routerB.RegisterTransport(transport); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), embeddedTestTimeout)
	defer cancel()

	destCfgB := DefaultDestinationConfig()
	destCfgB.Tunnels = nativeB.Exploratory
	destCfgB.Identity = destB
	destCfgB.Networks = []string{"corp"}
	destCfgB.Overlay = &ServiceProfile{
		Port:        47001,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
		Publication: PublicationNone,
	}
	target, err := routerB.NewDestination(ctx, destCfgB)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	destCfgA := DefaultDestinationConfig()
	destCfgA.Tunnels = nativeA.Exploratory
	destCfgA.Networks = []string{"corp"}
	destCfgA.Overlay = &ServiceProfile{
		Port:        47002,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
		Publication: PublicationNone,
	}
	source, err := routerA.NewDestination(ctx, destCfgA)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	listener, err := target.Listen("corp", ":47001")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	conn, err := source.DialContext(ctx, "corp", endpointB.String()+":47001")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	srvConn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()

	transport.mu.Lock()
	dialed := transport.dialed
	transport.mu.Unlock()
	if !dialed {
		t.Fatal("expected custom transport to be used")
	}

	errCh := make(chan error, 1)
	go func() {
		_, writeErr := conn.Write([]byte("custom-transport-data"))
		errCh <- writeErr
	}()

	buf := make([]byte, 21)
	if _, err := io.ReadFull(srvConn, buf); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if string(buf) != "custom-transport-data" {
		t.Fatalf("read %q, want custom-transport-data", buf)
	}
}

// TestOverlayDefaultNetworkRoutingAndPackets verifies that setting a fabric as the
// default network dynamically routes "tcp" stream and "udp" packet operations to it,
// and tests all packet protocol identifiers.
func TestOverlayDefaultNetworkRoutingAndPackets(t *testing.T) {
	flood := embeddedTestFloodfill(t)
	network := newEmbeddedMemoryNetwork(flood)

	destB, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destB.ReleaseSensitive)
	identityB, err := destB.Identity()
	if err != nil {
		t.Fatal(err)
	}
	canonicalB := identityB.Bytes()
	endpointB, err := overlay.EndpointIDFromDestination(canonicalB)
	if err != nil {
		t.Fatal(err)
	}
	addrB := freeTCP(t)

	realm := NewDualStackRealm("default-net-e2e", "corp")
	cfgA, cfgB, cfgC := embeddedTestConfig(t), embeddedTestConfig(t), embeddedTestConfig(t)
	infoA := captureEmbeddedRouterInfo(t, cfgA, network)
	infoB := captureEmbeddedRouterInfo(t, cfgB, network)
	infoC := captureEmbeddedRouterInfo(t, cfgC, network)

	cfgC.Bootstrap.RouterInfos = [][]byte{infoA, infoB, flood.Bytes()}

	// Router B configures corp with Default: true
	nativeB := nativeEntry(cfgB)
	nativeB.Bootstrap.RouterInfos = [][]byte{infoA, infoC, flood.Bytes()}
	fabricB := IVNPFabricNetwork("corp", 77, 8, []string{addrB}, nil)
	fabricB.Default = true
	cfgB.SetNetworks(realm, nativeB, fabricB)

	// Router A configures DefaultNetwork: "corp"
	nativeA := nativeEntry(cfgA)
	nativeA.Bootstrap.RouterInfos = [][]byte{infoB, infoC, flood.Bytes()}
	fabricA := IVNPFabricNetwork("corp", 77, 8, nil, []StaticPeer{
		NewStaticPeer(canonicalB, addrB),
	})
	cfgA.SetNetworks(realm, nativeA, fabricA)
	cfgA.DefaultNetwork = "corp"

	_ = newEmbeddedTestRouter(t, cfgC, network.transport())
	routerB := newEmbeddedTestRouter(t, cfgB, network.transport())
	routerA := newEmbeddedTestRouter(t, cfgA, network.transport())

	if routerA.DefaultNetwork() != "corp" {
		t.Fatalf("routerA default network = %q, want corp", routerA.DefaultNetwork())
	}
	if routerB.DefaultNetwork() != "corp" {
		t.Fatalf("routerB default network = %q, want corp", routerB.DefaultNetwork())
	}

	ctx, cancel := context.WithTimeout(context.Background(), embeddedTestTimeout)
	defer cancel()

	destCfgB := DefaultDestinationConfig()
	destCfgB.Tunnels = nativeB.Exploratory
	destCfgB.Identity = destB
	destCfgB.Networks = []string{"corp"}
	destCfgB.Overlay = &ServiceProfile{
		Port:        47001,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
		Publication: PublicationNone,
	}
	target, err := routerB.NewDestination(ctx, destCfgB)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	destCfgA := DefaultDestinationConfig()
	destCfgA.Tunnels = nativeA.Exploratory
	destCfgA.Networks = []string{"corp"}
	destCfgA.Overlay = &ServiceProfile{
		Port:        47002,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
		Publication: PublicationNone,
	}
	source, err := routerA.NewDestination(ctx, destCfgA)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	// 1. Test "tcp" stream listening routed to default network "corp"
	listener, err := target.Listen("tcp", ":47001")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer listener.Close()

	if listener.Addr().Network() != "ivnp" {
		t.Fatalf("listener network = %q, want ivnp", listener.Addr().Network())
	}

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()

	// 2. Test "tcp" dialing routed to default network "corp"
	targetAddr := endpointB.String() + ":47001"
	conn, err := source.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer conn.Close()

	if conn.RemoteAddr().Network() != "ivnp" {
		t.Fatalf("conn remote network = %q, want ivnp", conn.RemoteAddr().Network())
	}

	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("accept tcp: %v", err)
	case <-ctx.Done():
		t.Fatalf("timeout: %v", ctx.Err())
	}
	defer serverConn.Close()

	if _, err := conn.Write([]byte("ping-tcp-default")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, err := io.ReadFull(serverConn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping-tcp-default" {
		t.Fatalf("received %q, want ping-tcp-default", buf)
	}

	// 3. Test packet protocol resolution on modern packet sockets
	for _, netName := range []string{"udp", "udp4", "packet", "datagram", "ivnp", "ivnp-packet", "corp-packet"} {
		pconn, err := source.ListenPacket(netName, ":0")
		if err != nil {
			t.Fatalf("ListenPacket(%q): %v", netName, err)
		}
		if pconn.LocalAddr() == nil {
			t.Fatalf("ListenPacket(%q) LocalAddr is nil", netName)
		}
		_ = pconn.Close()
	}

	// 4. Test ListenConfig.ListenPacket returning *PacketConn (satisfying net.PacketConn)
	lc := &ListenConfig{Destination: source}
	pconnLC, err := lc.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		t.Fatalf("ListenConfig.ListenPacket(udp): %v", err)
	}
	var _ *PacketConn = pconnLC
	var _ net.PacketConn = pconnLC
	_ = pconnLC.Close()

	// 5. Test unauthenticated packet protocols (raw and datagram3)
	for _, netName := range []string{"raw", "udp-raw", "ivnp-raw", "corp-raw"} {
		unauth, err := source.ListenUnauthPacket(netName, ":0")
		if err != nil {
			t.Fatalf("ListenUnauthPacket(%q): %v", netName, err)
		}
		_ = unauth.Close()
	}

	for _, netName := range []string{"meta", "i2p-datagram3", "ivnp-datagram3", "corp-datagram3"} {
		unauth, err := source.ListenUnauthPacket(netName, ":0")
		if err != nil {
			t.Fatalf("ListenUnauthPacket(%q): %v", netName, err)
		}
		_ = unauth.Close()
	}

	// 6. Test unsupported network names
	if _, err := source.ListenPacket("unsupported-net", ":0"); err == nil {
		t.Fatal("expected error for unsupported packet network")
	}
	if _, err := source.ListenUnauthPacket("unsupported-net", ":0"); err == nil {
		t.Fatal("expected error for unsupported unauth packet network")
	}
}

func TestOverlayRemediationAndPolish(t *testing.T) {
	// 1. Verify ParseOverlayTarget accepts ":0" as wildcard/default port (port = 0)
	var id EndpointID
	for i := range id {
		id[i] = byte(i)
	}
	target0, err := ParseOverlayTarget(id.String() + ":0")
	if err != nil {
		t.Fatalf("ParseOverlayTarget with :0 failed: %v", err)
	}
	if target0.Port != 0 {
		t.Fatalf("expected Port 0, got %d", target0.Port)
	}

	// 2. Verify DefaultRouterConfigWithNetworks produces valid config
	realm := NewDualStackRealmProfile("corp-test", "corp-test")
	cfg := DefaultRouterConfigWithNetworks(realm, DefaultI2PNetwork(), IVNPFabricNetwork("corp-test", 77, 8, nil, nil))
	if len(cfg.Networks) != 2 || cfg.Realm == nil {
		t.Fatalf("unexpected DefaultRouterConfigWithNetworks output: %+v", cfg)
	}
	if cfg.NetworkID != 0 || cfg.NTCP2.Enabled || cfg.SSU2.Enabled {
		t.Fatalf("legacy fields were not cleared: %+v", cfg)
	}
	_, _, _, err = routerSettings(cfg)
	if err != nil {
		t.Fatalf("routerSettings(cfg) failed: %v", err)
	}

	// 3. Verify ServiceProfile.Networks propagation
	destCfg := DefaultDestinationConfig()
	destCfg.Overlay = &ServiceProfile{
		Port:     47001,
		Networks: []string{"corp-test"},
	}
	// Verify NewDestination recognizes Overlay.Networks even when cfg.Networks is empty
	router := &Router{children: make(map[*Destination]struct{})}
	// Without realm, should report ErrOverlayRequired
	_, err = router.NewDestination(t.Context(), destCfg)
	if err == nil || !errors.Is(err, ErrOverlayRequired) {
		t.Fatalf("expected ErrOverlayRequired, got: %v", err)
	}
}

func TestOverlayDynamicPortAndEphemeralListen(t *testing.T) {
	flood := embeddedTestFloodfill(t)
	network := newEmbeddedMemoryNetwork(flood)

	destB, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destB.ReleaseSensitive)
	identityB, err := destB.Identity()
	if err != nil {
		t.Fatal(err)
	}
	canonicalB := identityB.Bytes()
	addrB := freeTCP(t)

	realm := NewDualStackRealm("dynamic-port-test", "corp")
	cfgA, cfgB, cfgC := embeddedTestConfig(t), embeddedTestConfig(t), embeddedTestConfig(t)
	infoA := captureEmbeddedRouterInfo(t, cfgA, network)
	infoB := captureEmbeddedRouterInfo(t, cfgB, network)
	infoC := captureEmbeddedRouterInfo(t, cfgC, network)

	cfgC.Bootstrap.RouterInfos = [][]byte{infoA, infoB, flood.Bytes()}

	nativeB := nativeEntry(cfgB)
	nativeB.Bootstrap.RouterInfos = [][]byte{infoA, infoC, flood.Bytes()}
	cfgB.SetNetworks(realm, nativeB,
		IVNPFabricNetwork("corp", 77, 8, []string{addrB}, nil))

	nativeA := nativeEntry(cfgA)
	nativeA.Bootstrap.RouterInfos = [][]byte{infoB, infoC, flood.Bytes()}
	cfgA.SetNetworks(realm, nativeA,
		IVNPFabricNetwork("corp", 77, 8, nil, []StaticPeer{
			NewStaticPeer(canonicalB, addrB),
		}))

	_ = newEmbeddedTestRouter(t, cfgC, network.transport())
	routerB := newEmbeddedTestRouter(t, cfgB, network.transport())
	routerA := newEmbeddedTestRouter(t, cfgA, network.transport())

	ctx, cancel := context.WithTimeout(context.Background(), embeddedTestTimeout)
	defer cancel()

	// 1. Create target Destination on routerB without declaring any port (Port == 0)
	destCfgB := DefaultDestinationConfig()
	destCfgB.Tunnels = nativeB.Exploratory
	destCfgB.Identity = destB
	destCfgB.Networks = []string{"corp"}
	destCfgB.Overlay = &ServiceProfile{
		Publication: PublicationNone,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
	}
	target, err := routerB.NewDestination(ctx, destCfgB)
	if err != nil {
		t.Fatalf("routerB.NewDestination: %v", err)
	}
	defer target.Close()

	if target.EndpointID() == (EndpointID{}) {
		t.Fatal("target.EndpointID() should not be empty")
	}

	// 2. Listen with ":0" to request an ephemeral random port
	listener, err := target.Listen("ivnp", ":0")
	if err != nil {
		t.Fatalf("target.Listen(ivnp, :0): %v", err)
	}
	defer listener.Close()

	boundAddr, ok := listener.Addr().(OverlayAddr)
	if !ok {
		t.Fatalf("listener.Addr() type = %T, want OverlayAddr", listener.Addr())
	}
	if boundAddr.Port < 49152 || boundAddr.Port > 65535 {
		t.Fatalf("listener bound port %d outside ephemeral range [49152, 65535]", boundAddr.Port)
	}
	if boundAddr.Endpoint != target.EndpointID() {
		t.Fatalf("listener endpoint %v != target %v", boundAddr.Endpoint, target.EndpointID())
	}

	// 3. Verify listening on a different port on the same destination is rejected
	if _, err := target.Listen("ivnp", ":9999"); err == nil {
		t.Fatal("expected error listening on mismatched port on bound destination")
	}

	// 4. Client dials the dynamically allocated ephemeral port
	destCfgA := DefaultDestinationConfig()
	destCfgA.Tunnels = nativeA.Exploratory
	destCfgA.Networks = []string{"corp"}
	destCfgA.Overlay = &ServiceProfile{
		Publication: PublicationNone,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
	}
	client, err := routerA.NewDestination(ctx, destCfgA)
	if err != nil {
		t.Fatalf("routerA.NewDestination: %v", err)
	}
	defer client.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	conn, err := client.DialContext(ctx, "ivnp", listener.Addr().String())
	if err != nil {
		t.Fatalf("client.DialContext: %v", err)
	}
	defer conn.Close()

	select {
	case serverConn := <-accepted:
		defer serverConn.Close()
		msg := []byte("hello ephemeral port")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("conn.Write: %v", err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			t.Fatalf("serverConn.Read: %v", err)
		}
		if string(buf) != string(msg) {
			t.Fatalf("received %q, want %q", string(buf), string(msg))
		}
	case err := <-acceptErr:
		t.Fatalf("listener.Accept: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for connection")
	}

	// 5. Test another destination dynamically binding an explicit port
	destCfgB2 := DefaultDestinationConfig()
	destCfgB2.Tunnels = nativeB.Exploratory
	destCfgB2.Networks = []string{"corp"}
	destCfgB2.Overlay = &ServiceProfile{
		Publication: PublicationNone,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
	}
	target2, err := routerB.NewDestination(ctx, destCfgB2)
	if err != nil {
		t.Fatalf("routerB.NewDestination(target2): %v", err)
	}
	defer target2.Close()

	l2, err := target2.Listen("ivnp", ":48888")
	if err != nil {
		t.Fatalf("target2.Listen(:48888): %v", err)
	}
	defer l2.Close()
	if l2.Addr().(OverlayAddr).Port != 48888 {
		t.Fatalf("target2 bound port %d, want 48888", l2.Addr().(OverlayAddr).Port)
	}

	// 6. Test another destination allocating a unique ephemeral port
	destCfgB3 := DefaultDestinationConfig()
	destCfgB3.Tunnels = nativeB.Exploratory
	destCfgB3.Networks = []string{"corp"}
	destCfgB3.Overlay = &ServiceProfile{
		Publication: PublicationNone,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
	}
	target3, err := routerB.NewDestination(ctx, destCfgB3)
	if err != nil {
		t.Fatalf("routerB.NewDestination(target3): %v", err)
	}
	defer target3.Close()
	l3, err := target3.Listen("ivnp", ":0")
	if err != nil {
		t.Fatalf("target3.Listen(:0): %v", err)
	}
	defer l3.Close()
	port3 := l3.Addr().(OverlayAddr).Port
	if port3 < 49152 || port3 > 65535 {
		t.Fatalf("target3 ephemeral port %d outside range", port3)
	}
	if port3 == boundAddr.Port {
		t.Fatalf("target3 allocated duplicate ephemeral port %d", port3)
	}
}

func TestUnifiedNetworkBuildersAndPolicies(t *testing.T) {
	// 1. Test NewNativeI2PNetwork with options
	reseedURLs := []string{"https://reseed1.example.org/i2pseeds.su3", "https://reseed2.example.org/i2pseeds.su3"}
	customPool := TunnelPoolConfig{
		Inbound:     TunnelDirectionConfig{Hops: 3, Count: 4, Backup: 1},
		Outbound:    TunnelDirectionConfig{Hops: 3, Count: 4, Backup: 1},
		RenewBefore: 120 * time.Second,
	}
	native := NewNativeI2PNetwork(
		WithFloodfill(true),
		WithReseedURLs(reseedURLs),
		WithExploratoryPool(customPool),
		WithDefaultNetwork(),
	)
	if native.Kind != NetworkNativeI2P || native.Name != "i2p" {
		t.Fatalf("native network kind/name mismatch: %+v", native)
	}
	if native.Participation != ParticipationContributor {
		t.Fatalf("expected ParticipationContributor, got %v", native.Participation)
	}
	if len(native.Bootstrap.ReseedURLs) != 2 || native.Bootstrap.ReseedURLs[0] != reseedURLs[0] {
		t.Fatalf("unexpected ReseedURLs: %v", native.Bootstrap.ReseedURLs)
	}
	if native.Exploratory.Inbound.Hops != 3 || native.Exploratory.Outbound.Count != 4 {
		t.Fatalf("unexpected Exploratory pool: %+v", native.Exploratory)
	}
	if !native.Default {
		t.Fatal("expected native.Default to be true")
	}

	// 2. Test NewFabricNetwork with options
	peer := NewStaticPeer([]byte("peer-destination-bytes"), "127.0.0.1:48123")
	fabric := NewFabricNetwork("vpn", "127.0.0.1:48000",
		WithFabricNetworkID(88),
		WithFabricMaxPeers(512),
		WithStaticPeers(peer),
		WithFabricListeners("127.0.0.1:48001"),
	)
	if fabric.Kind != NetworkIVNPFabric || fabric.Name != "vpn" {
		t.Fatalf("fabric network kind/name mismatch: %+v", fabric)
	}
	if fabric.NetworkID != 88 || fabric.Fabric.NetworkID != 88 {
		t.Fatalf("fabric NetworkID mismatch: %d / %d", fabric.NetworkID, fabric.Fabric.NetworkID)
	}
	if fabric.Fabric.MaxPeers != 512 {
		t.Fatalf("fabric MaxPeers: %d, want 512", fabric.Fabric.MaxPeers)
	}
	if len(fabric.Peers) != 1 || fabric.Peers[0].Contact != "ivnp-tls@127.0.0.1:48123" {
		t.Fatalf("unexpected fabric Peers: %+v", fabric.Peers)
	}
	if len(fabric.Listeners) != 2 || fabric.Listeners[0] != "127.0.0.1:48000" || fabric.Listeners[1] != "127.0.0.1:48001" {
		t.Fatalf("unexpected fabric Listeners: %v", fabric.Listeners)
	}

	// 3. Test RouterConfig with Policy (OverlayPolicy alias) and live communication
	flood := embeddedTestFloodfill(t)
	network := newEmbeddedMemoryNetwork(flood)

	destB, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destB.ReleaseSensitive)
	identityB, err := destB.Identity()
	if err != nil {
		t.Fatal(err)
	}
	canonicalB := identityB.Bytes()
	addrB := freeTCP(t)

	destA, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destA.ReleaseSensitive)
	identityA, err := destA.Identity()
	if err != nil {
		t.Fatal(err)
	}
	canonicalA := identityA.Bytes()
	addrA := freeTCP(t)

	peerOnA := NewStaticPeer(canonicalB, addrB)
	peerOnB := NewStaticPeer(canonicalA, addrA)

	cfgA, cfgB, cfgC := embeddedTestConfig(t), embeddedTestConfig(t), embeddedTestConfig(t)
	infoA := captureEmbeddedRouterInfo(t, cfgA, network)
	infoB := captureEmbeddedRouterInfo(t, cfgB, network)
	infoC := captureEmbeddedRouterInfo(t, cfgC, network)

	cfgC.Bootstrap.RouterInfos = [][]byte{infoA, infoB, flood.Bytes()}

	netA := nativeEntry(cfgA)
	netA.Bootstrap.RouterInfos = [][]byte{infoB, infoC, flood.Bytes()}
	fabricA := NewFabricNetwork("mesh", addrA, WithStaticPeers(peerOnA))

	netB := nativeEntry(cfgB)
	netB.Bootstrap.RouterInfos = [][]byte{infoA, infoC, flood.Bytes()}
	fabricB := NewFabricNetwork("mesh", addrB, WithStaticPeers(peerOnB))

	policy := &OverlayPolicy{
		ID:                  RealmIDFor("mesh"),
		Admission:           AdmissionOpen,
		AcknowledgeOpen:     true,
		AcknowledgeExposure: true,
		Discovery:           DiscoveryLocalOnly,
		Privacy:             PrivacyExplicitDirect,
		Routing:             RoutingOverlayDirect,
		Publication:         PublicationNone,
		Prefix:              PrefixPolicy{Mode: PrefixDisabled},
		Fabrics:             []string{"mesh"},
	}

	cfgA.SetNetworks(nil, netA, fabricA)
	cfgA.Policy = policy

	cfgB.SetNetworks(nil, netB, fabricB)
	cfgB.Policy = policy

	_ = newEmbeddedTestRouter(t, cfgC, network.transport())
	routerB := newEmbeddedTestRouter(t, cfgB, network.transport())
	routerA := newEmbeddedTestRouter(t, cfgA, network.transport())

	ctx, cancel := context.WithTimeout(context.Background(), embeddedTestTimeout)
	defer cancel()

	// Destination on router B
	destCfgB := DefaultDestinationConfig()
	destCfgB.Tunnels = netB.Exploratory
	destCfgB.Identity = destB
	destCfgB.Networks = []string{"mesh"}
	destCfgB.Overlay = &ServiceProfile{
		Publication: PublicationNone,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
	}
	targetB, err := routerB.NewDestination(ctx, destCfgB)
	if err != nil {
		t.Fatalf("routerB.NewDestination: %v", err)
	}
	defer targetB.Close()

	// Listen using ListenConfig with Policy
	lc := &ListenConfig{
		Destination: targetB,
		Policy: OverlayListenPolicy{
			Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
			Classes:   []RouteClass{RouteDirect},
		},
	}
	listener, err := lc.Listen(ctx, "mesh", ":0")
	if err != nil {
		t.Fatalf("lc.Listen(:0): %v", err)
	}
	defer listener.Close()

	boundPort := listener.Addr().(OverlayAddr).Port
	if boundPort == 0 {
		t.Fatal("expected non-zero bound port")
	}

	// Echo server on router B
	errCh := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		defer conn.Close()
		buf := make([]byte, 11)
		if _, readErr := io.ReadFull(conn, buf); readErr != nil {
			errCh <- readErr
			return
		}
		if _, writeErr := conn.Write(buf); writeErr != nil {
			errCh <- writeErr
			return
		}
		errCh <- nil
	}()

	// Destination on router A
	destCfgA := DefaultDestinationConfig()
	destCfgA.Tunnels = netA.Exploratory
	destCfgA.Identity = destA
	destCfgA.Networks = []string{"mesh"}
	destCfgA.Overlay = &ServiceProfile{
		Publication: PublicationNone,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
	}
	clientA, err := routerA.NewDestination(ctx, destCfgA)
	if err != nil {
		t.Fatalf("routerA.NewDestination: %v", err)
	}
	defer clientA.Close()

	// Dial using Dialer with Policy
	dialer := &Dialer{
		Destination: clientA,
		Timeout:     5 * time.Second,
		Policy: OverlayDialPolicy{
			RouteClasses: []RouteClass{RouteDirect},
		},
	}
	targetAddr := listener.Addr().String()
	conn, err := dialer.DialContext(ctx, "mesh", targetAddr)
	if err != nil {
		t.Fatalf("dialer.DialContext(%s): %v", targetAddr, err)
	}
	defer conn.Close()

	// Ping-pong verification
	msg := []byte("hello-mesh!")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}
	reply := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("conn.ReadFull: %v", err)
	}
	if string(reply) != string(msg) {
		t.Fatalf("got echo %q, want %q", reply, msg)
	}

	if serverErr := <-errCh; serverErr != nil {
		t.Fatalf("echo server error: %v", serverErr)
	}
}

func TestComposableNetworkArchitecturesAndCustomNames(t *testing.T) {
	// 1. Verify that NewNativeI2PNetwork is composed of universal primitives
	nativeComposed := NewNativeI2PNetwork(
		WithNetworkName("main"),
		WithDefaultNetwork(),
	)
	if nativeComposed.Name != "main" {
		t.Fatalf("expected network name 'main', got %q", nativeComposed.Name)
	}
	if nativeComposed.Routing != RoutingGarlic {
		t.Fatalf("expected RoutingGarlic, got %v", nativeComposed.Routing)
	}
	if nativeComposed.Discovery != DiscoveryNetDB {
		t.Fatalf("expected DiscoveryNetDB, got %v", nativeComposed.Discovery)
	}
	if nativeComposed.NetworkID != 2 {
		t.Fatalf("expected NetworkID 2, got %d", nativeComposed.NetworkID)
	}
	if !nativeComposed.Default {
		t.Fatal("expected Default to be true")
	}

	// 2. Verify that NewDirectNetwork is composed of direct & static primitives
	directComposed := NewDirectNetwork("fast-mesh",
		WithNetworkID(88),
		WithListeners("127.0.0.1:0"),
	)
	if directComposed.Name != "fast-mesh" {
		t.Fatalf("expected network name 'fast-mesh', got %q", directComposed.Name)
	}
	if directComposed.Routing != RoutingDirect {
		t.Fatalf("expected RoutingDirect, got %v", directComposed.Routing)
	}
	if directComposed.Discovery != DiscoveryStatic {
		t.Fatalf("expected DiscoveryStatic, got %v", directComposed.Discovery)
	}
	if directComposed.NetworkID != 88 {
		t.Fatalf("expected NetworkID 88, got %d", directComposed.NetworkID)
	}

	// 3. Test NewNetwork universal constructor
	customNet := NewNetwork("custom-consortium",
		WithNetworkID(99),
		WithGarlicRouting(),
		WithNetDBDiscovery(),
	)
	if customNet.Name != "custom-consortium" || customNet.NetworkID != 99 || customNet.Routing != RoutingGarlic {
		t.Fatalf("unexpected customNet: %+v", customNet)
	}

	// 4. Run dual-node test using custom-named native network ("main") and direct network ("fast-mesh")
	flood := embeddedTestFloodfill(t)
	network := newEmbeddedMemoryNetwork(flood)

	destB, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destB.ReleaseSensitive)
	identityB, err := destB.Identity()
	if err != nil {
		t.Fatal(err)
	}
	canonicalB := identityB.Bytes()
	addrB := freeTCP(t)

	destA, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destA.ReleaseSensitive)
	identityA, err := destA.Identity()
	if err != nil {
		t.Fatal(err)
	}
	canonicalA := identityA.Bytes()
	addrA := freeTCP(t)

	peerOnA := NewStaticPeer(canonicalB, addrB)
	peerOnB := NewStaticPeer(canonicalA, addrA)

	cfgA, cfgB, cfgC := embeddedTestConfig(t), embeddedTestConfig(t), embeddedTestConfig(t)
	infoA := captureEmbeddedRouterInfo(t, cfgA, network)
	infoB := captureEmbeddedRouterInfo(t, cfgB, network)
	infoC := captureEmbeddedRouterInfo(t, cfgC, network)

	cfgC.Bootstrap.RouterInfos = [][]byte{infoA, infoB, flood.Bytes()}

	netA := nativeEntry(cfgA)
	netA.Name = "main"
	netA.Default = true
	netA.Bootstrap.RouterInfos = [][]byte{infoB, infoC, flood.Bytes()}
	meshA := NewDirectNetwork("fast-mesh", WithNetworkID(77), WithListeners(addrA), WithStaticPeers(peerOnA))

	netB := nativeEntry(cfgB)
	netB.Name = "main"
	netB.Default = true
	netB.Bootstrap.RouterInfos = [][]byte{infoA, infoC, flood.Bytes()}
	meshB := NewDirectNetwork("fast-mesh", WithNetworkID(77), WithListeners(addrB), WithStaticPeers(peerOnB))

	policy := &OverlayPolicy{
		ID:                  RealmIDFor("custom-domain"),
		Admission:           AdmissionOpen,
		AcknowledgeOpen:     true,
		AcknowledgeExposure: true,
		Discovery:           DiscoveryLocalOnly,
		Privacy:             PrivacyExplicitDirect,
		Routing:             RoutingOverlayDirect,
		Publication:         PublicationNone,
		Prefix:              PrefixPolicy{Mode: PrefixDisabled},
		Fabrics:             []string{"fast-mesh"},
		IncludeNative:       true,
	}

	cfgA.SetNetworks(nil, netA, meshA)
	cfgA.Policy = policy

	cfgB.SetNetworks(nil, netB, meshB)
	cfgB.Policy = policy

	_ = newEmbeddedTestRouter(t, cfgC, network.transport())
	routerB := newEmbeddedTestRouter(t, cfgB, network.transport())
	routerA := newEmbeddedTestRouter(t, cfgA, network.transport())

	// Verify DefaultNetwork is "main"
	if routerA.DefaultNetwork() != "main" {
		t.Fatalf("expected DefaultNetwork 'main', got %q", routerA.DefaultNetwork())
	}

	ctx, cancel := context.WithTimeout(context.Background(), embeddedTestTimeout)
	defer cancel()

	// Destination on router B
	destCfgB := DefaultDestinationConfig()
	destCfgB.Tunnels = netB.Exploratory
	destCfgB.Identity = destB
	destCfgB.Networks = []string{"fast-mesh"}
	destCfgB.Overlay = &ServiceProfile{
		Publication: PublicationNone,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
	}
	targetB, err := routerB.NewDestination(ctx, destCfgB)
	if err != nil {
		t.Fatalf("routerB.NewDestination: %v", err)
	}
	defer targetB.Close()

	// Listen using ListenConfig with Policy on "fast-mesh"
	lc := &ListenConfig{
		Destination: targetB,
		Policy: OverlayListenPolicy{
			Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
			Classes:   []RouteClass{RouteDirect},
		},
	}
	listener, err := lc.Listen(ctx, "fast-mesh", ":0")
	if err != nil {
		t.Fatalf("lc.Listen(:0): %v", err)
	}
	defer listener.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		defer conn.Close()
		buf := make([]byte, 23)
		if _, readErr := io.ReadFull(conn, buf); readErr != nil {
			errCh <- readErr
			return
		}
		if _, writeErr := conn.Write(buf); writeErr != nil {
			errCh <- writeErr
			return
		}
		errCh <- nil
	}()

	// Destination on router A
	destCfgA := DefaultDestinationConfig()
	destCfgA.Tunnels = netA.Exploratory
	destCfgA.Identity = destA
	destCfgA.Networks = []string{"fast-mesh"}
	destCfgA.Overlay = &ServiceProfile{
		Publication: PublicationNone,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
	}
	clientA, err := routerA.NewDestination(ctx, destCfgA)
	if err != nil {
		t.Fatalf("routerA.NewDestination: %v", err)
	}
	defer clientA.Close()

	dialer := &Dialer{
		Destination: clientA,
		Timeout:     5 * time.Second,
		Policy: OverlayDialPolicy{
			RouteClasses: []RouteClass{RouteDirect},
		},
	}
	conn, err := dialer.DialContext(ctx, "fast-mesh", listener.Addr().String())
	if err != nil {
		t.Fatalf("dialer.DialContext: %v", err)
	}
	defer conn.Close()

	testPayload := []byte("ping-recomposed-network")
	if _, err := conn.Write(testPayload); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}
	recv := make([]byte, len(testPayload))
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("conn.ReadFull: %v", err)
	}
	if string(recv) != string(testPayload) {
		t.Fatalf("got %q, want %q", recv, testPayload)
	}

	if sErr := <-errCh; sErr != nil {
		t.Fatalf("server error: %v", sErr)
	}
}
