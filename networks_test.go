package ivnp

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"gosuda.org/ivnp/interfaces/destination"
)

func TestNetworkPlanLegacyDefaults(t *testing.T) {
	networks, def, err := networkPlan(DefaultRouterConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 1 || networks[0].NetworkID != 2 || networks[0].Name != networkNativeName {
		t.Fatalf("networks = %+v", networks)
	}
	if def != networkNativeName {
		t.Fatalf("default = %q", def)
	}
}

func TestNetworkPlanRejectsLegacyMixing(t *testing.T) {
	cfg := RouterConfig{
		NetworkID: 2, // legacy field set alongside Networks
		Networks:  []NetworkConfig{DefaultI2PNetwork()},
		Limits:    DefaultRouterConfig().Limits,
	}
	if _, _, err := networkPlan(cfg); err == nil {
		t.Fatal("legacy fields combined with Networks were accepted")
	}
}

func TestNetworkPlanEntryRules(t *testing.T) {
	// An entry with an empty name is rejected.
	bad := DefaultI2PNetwork()
	bad.Name = ""
	if _, _, err := networkPlan(RouterConfig{Networks: []NetworkConfig{bad}}); err == nil {
		t.Fatal("entry with an empty name was accepted")
	}

	// A name outside [a-zA-Z0-9_] collides with the protocol suffix grammar.
	bad = DefaultI2PNetwork()
	bad.Name = "corp-net"
	if _, _, err := networkPlan(RouterConfig{Networks: []NetworkConfig{bad}}); err == nil {
		t.Fatal("entry with a hyphenated name was accepted")
	}

	// A custom public-network name is valid.
	custom := DefaultI2PNetwork()
	custom.Name = "main"
	networks, def, err := networkPlan(RouterConfig{Networks: []NetworkConfig{custom}})
	if err != nil || def != "main" || networks[0].Name != "main" {
		t.Fatalf("custom named entry failed: %v def=%q", err, def)
	}

	// A zero or out-of-range network id.
	bad = DefaultI2PNetwork()
	bad.NetworkID = 0
	if _, _, err := networkPlan(RouterConfig{Networks: []NetworkConfig{bad}}); err == nil {
		t.Fatal("entry with netId 0 was accepted")
	}
	bad = DefaultI2PNetwork()
	bad.NetworkID = 256
	if _, _, err := networkPlan(RouterConfig{Networks: []NetworkConfig{bad}}); err == nil {
		t.Fatal("entry with netId 256 was accepted")
	}

	// Duplicate network ids.
	two := DefaultI2PNetwork()
	two.Name = "other"
	if _, _, err := networkPlan(RouterConfig{Networks: []NetworkConfig{DefaultI2PNetwork(), two}}); err == nil {
		t.Fatal("duplicate netIds were accepted")
	}

	// No enabled transport.
	bad = DefaultI2PNetwork()
	bad.NTCP2, bad.SSU2 = TransportConfig{}, TransportConfig{}
	if _, _, err := networkPlan(RouterConfig{Networks: []NetworkConfig{bad}}); err == nil {
		t.Fatal("entry without transports was accepted")
	}

	// An out-of-range participation value.
	bad = DefaultI2PNetwork()
	bad.Participation = PublicParticipation(99)
	if _, _, err := networkPlan(RouterConfig{Networks: []NetworkConfig{bad}}); err == nil {
		t.Fatal("entry with an invalid participation was accepted")
	}

	// A dedicated network without the public context is valid — netId 2 is a
	// field value, not a requirement.
	dedicated := NewNetwork("corp", 77)
	networks, def, err = networkPlan(RouterConfig{Networks: []NetworkConfig{dedicated}})
	if err != nil {
		t.Fatal(err)
	}
	if def != "corp" || len(networks) != 1 || networks[0].NetworkID != 77 {
		t.Fatalf("dedicated plan: def=%q networks=%+v", def, networks)
	}
}

func TestNetworkSpecsMapParticipationToOperatingRoles(t *testing.T) {
	for _, test := range []struct {
		participation PublicParticipation
		transit       bool
		floodfill     bool
	}{
		{ParticipationOnDemand, false, false},
		{ParticipationWarm, true, false},
		{ParticipationContributor, true, true},
	} {
		cfg := DefaultRouterConfig()
		cfg.NetworkID, cfg.NTCP2, cfg.SSU2 = 0, TransportConfig{}, TransportConfig{}
		cfg.Bootstrap, cfg.Exploratory = BootstrapConfig{}, TunnelPoolConfig{}
		native := DefaultI2PNetwork()
		native.Participation = test.participation
		cfg.Networks = []NetworkConfig{native}
		specs, _, err := networkSpecs(cfg)
		if err != nil {
			t.Fatalf("participation %d settings error = %v", test.participation, err)
		}
		operating := specs[0].Operating
		if operating.Router.Transit != test.transit || operating.Router.Floodfill != test.floodfill {
			t.Fatalf("participation %d mapped transit=%t floodfill=%t", test.participation, operating.Router.Transit, operating.Router.Floodfill)
		}
	}
}

func TestNetworkSpecsScopeEachContextToItsNetID(t *testing.T) {
	cfg := DefaultRouterConfig()
	cfg.SetNetworks(DefaultI2PNetwork(), NewNetwork("corp", 77))
	specs, def, err := networkSpecs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if def != networkNativeName {
		t.Fatalf("default = %q", def)
	}
	if len(specs) != 2 || specs[0].Name != networkNativeName || specs[1].Name != "corp" {
		t.Fatalf("specs = %+v", specs)
	}
	if specs[0].Operating.Network.ID != 2 || specs[1].Operating.Network.ID != 77 {
		t.Fatalf("netIds = %d, %d", specs[0].Operating.Network.ID, specs[1].Operating.Network.ID)
	}
}

func TestNetworkSpecsIsolationPerPersistenceDirectory(t *testing.T) {
	cfg := DefaultRouterConfig()
	dir := t.TempDir()
	cfg.Persistence = DefaultPersistenceConfig(dir)
	cfg.SetNetworks(DefaultI2PNetwork(), NewNetwork("corp", 77))
	specs, _, err := networkSpecs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if specs[0].Operating.StatePath != filepath.Join(dir, "i2p", "router.state") {
		t.Fatalf("i2p state path = %q", specs[0].Operating.StatePath)
	}
	if specs[1].Operating.StatePath != filepath.Join(dir, "corp", "router.state") {
		t.Fatalf("corp state path = %q", specs[1].Operating.StatePath)
	}
}

func TestPeerAdmissionHelpers(t *testing.T) {
	var alice, bob Hash
	alice[0], bob[0] = 1, 2
	request := func(peer Hash) PeerAdmission {
		return PeerAdmission{Peer: peer, Transport: PeerTransportNTCP2, Inbound: true}
	}

	admit := AdmitPeers(alice)
	if err := admit(context.Background(), request(alice)); err != nil {
		t.Fatalf("allowlisted peer denied: %v", err)
	}
	if err := admit(context.Background(), request(bob)); !errors.Is(err, ErrPeerDenied) {
		t.Fatalf("unlisted peer error = %v, want %v", err, ErrPeerDenied)
	}

	reject := RejectPeers(bob)
	if err := reject(context.Background(), request(alice)); err != nil {
		t.Fatalf("non-denylisted peer denied: %v", err)
	}
	if err := reject(context.Background(), request(bob)); !errors.Is(err, ErrPeerDenied) {
		t.Fatalf("denylisted peer error = %v, want %v", err, ErrPeerDenied)
	}

	// A chain admits only when every check does, and the first denial wins.
	var sentinel = errors.New("sentinel denial")
	chain := ChainAdmission(nil, AdmitPeers(alice), func(context.Context, PeerAdmission) error { return sentinel })
	if err := chain(context.Background(), request(alice)); !errors.Is(err, sentinel) {
		t.Fatalf("chain denial = %v, want %v", err, sentinel)
	}
	if err := ChainAdmission(AdmitPeers(alice))(context.Background(), request(bob)); !errors.Is(err, ErrPeerDenied) {
		t.Fatalf("chain allowlist miss = %v, want %v", err, ErrPeerDenied)
	}
	if err := ChainAdmission(RejectPeers(bob))(context.Background(), request(alice)); err != nil {
		t.Fatalf("chain admit error = %v", err)
	}
}

func TestNetworkSpecsCarryPeerAdmissionPerContext(t *testing.T) {
	cfg := DefaultRouterConfig()
	corp := NewNetwork("corp", 77)
	corp.AdmitPeer = AdmitPeers()
	cfg.SetNetworks(DefaultI2PNetwork(), corp)
	specs, _, err := networkSpecs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if specs[0].Options.PeerAdmission != nil {
		t.Fatal("public context inherited a peer admission callback")
	}
	if specs[1].Options.PeerAdmission == nil {
		t.Fatal("dedicated context lost the configured admission callback")
	}
}

func TestBootstrapEmpty(t *testing.T) {
	if !bootstrapEmpty(BootstrapConfig{}) {
		t.Fatal("zero bootstrap reported non-empty")
	}
	b := BootstrapConfig{RouterInfos: [][]byte{{1}}}
	if bootstrapEmpty(b) {
		t.Fatal("RouterInfos-only bootstrap reported empty")
	}
	b = BootstrapConfig{ReseedTimeout: time.Second}
	if bootstrapEmpty(b) {
		t.Fatal("ReseedTimeout-only bootstrap reported empty")
	}
}

func TestResolveDefaultNetwork(t *testing.T) {
	native := DefaultI2PNetwork()
	corp := NewNetwork("corp", 77)

	// The public context is preferred when present.
	def, err := resolveDefaultNetwork(RouterConfig{}, []NetworkConfig{corp, native})
	if err != nil || def != "i2p" {
		t.Fatalf("dual-stack default = %q, err = %v", def, err)
	}

	// Without a netId-2 entry the first entry wins.
	def, err = resolveDefaultNetwork(RouterConfig{}, []NetworkConfig{corp})
	if err != nil || def != "corp" {
		t.Fatalf("dedicated default = %q, err = %v", def, err)
	}

	// An explicit DefaultNetwork names an existing entry.
	def, err = resolveDefaultNetwork(RouterConfig{DefaultNetwork: "corp"}, []NetworkConfig{native, corp})
	if err != nil || def != "corp" {
		t.Fatalf("explicit default = %q, err = %v", def, err)
	}

	// An unknown DefaultNetwork fails.
	if _, err = resolveDefaultNetwork(RouterConfig{DefaultNetwork: "ghost"}, []NetworkConfig{native, corp}); err == nil {
		t.Fatal("unknown DefaultNetwork was accepted")
	}
}

func TestDialPolicyInheritanceAndResolve(t *testing.T) {
	dest := &Destination{
		dialPolicy: DialPolicy{
			Strategy: DialParallel,
			Networks: []string{"corp"},
		},
	}

	// 1. Inherit from Destination when Dialer.Policy is nil
	dialer := &Dialer{Destination: dest}
	resolved := dialer.resolvePolicy()
	if resolved.Strategy != DialParallel || len(resolved.Networks) != 1 || resolved.Networks[0] != "corp" {
		t.Fatalf("expected inherited policy, got %+v", resolved)
	}

	// 2. Override when Dialer.Policy is explicitly provided
	custom := &DialPolicy{
		Strategy:      DialHappyEyeballs,
		FallbackDelay: 500 * time.Millisecond,
		Networks:      []string{"i2p"},
	}
	dialer.Policy = custom
	resolved = dialer.resolvePolicy()
	if resolved.Strategy != DialHappyEyeballs || resolved.FallbackDelay != 500*time.Millisecond || len(resolved.Networks) != 1 || resolved.Networks[0] != "i2p" {
		t.Fatalf("expected overridden policy, got %+v", resolved)
	}

	// 3. Fallback to default DialHappyEyeballs when both are nil
	nilDialer := &Dialer{}
	resolved = nilDialer.resolvePolicy()
	if resolved.Strategy != DialHappyEyeballs || resolved.FallbackDelay != DefaultHappyEyeballsDelay {
		t.Fatalf("expected default HappyEyeballs policy, got %+v", resolved)
	}
}

func TestConnectionNetwork(t *testing.T) {
	c1 := &streamConn{netName: "corp-mesh"}
	if got := ConnectionNetwork(c1); got != "corp-mesh" {
		t.Fatalf("ConnectionNetwork = %q, want corp-mesh", got)
	}

	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()
	if got := ConnectionNetwork(pipeA); got != "" {
		t.Fatalf("ConnectionNetwork on plain net.Conn = %q, want empty", got)
	}
}

var (
	errMockStreamNotImplemented = errors.New("not implemented")
	errMockStreamDialFailed     = errors.New("mock dial failed")
)

type mockStreamEndpoint struct {
	destination.DestinationEndpoint
	dialFn func(ctx context.Context, target string, localPort uint16) (net.Conn, error)
}

func (m *mockStreamEndpoint) DialStream(ctx context.Context, target string, localPort uint16) (net.Conn, error) {
	if m.dialFn != nil {
		return m.dialFn(ctx, target, localPort)
	}
	return nil, errMockStreamNotImplemented
}

func (m *mockStreamEndpoint) ListenStream(ctx context.Context, addr string) (net.Listener, error) {
	return nil, errMockStreamNotImplemented
}

func TestDialEndpointsParallel(t *testing.T) {
	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()

	startedA := make(chan struct{})
	startedB := make(chan struct{})

	epA := &mockStreamEndpoint{
		dialFn: func(ctx context.Context, target string, localPort uint16) (net.Conn, error) {
			close(startedA)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	epB := &mockStreamEndpoint{
		dialFn: func(ctx context.Context, target string, localPort uint16) (net.Conn, error) {
			close(startedB)
			return pipeA, nil
		},
	}

	eps := []namedEndpoint{
		{name: "netA", ep: epA},
		{name: "netB", ep: epB},
	}

	policy := DialPolicy{Strategy: DialParallel}
	conn, winNet, err := dialEndpoints(context.Background(), eps, policy, "target.b32.i2p:80", 0)
	if err != nil {
		t.Fatalf("dialEndpoints failed: %v", err)
	}
	if winNet != "netB" {
		t.Fatalf("winning net = %q, want netB", winNet)
	}
	if conn == nil {
		t.Fatal("expected non-nil connection")
	}

	// Verify that both legs started simultaneously
	select {
	case <-startedA:
	case <-time.After(time.Second):
		t.Fatal("leg A did not start")
	}
	select {
	case <-startedB:
	case <-time.After(time.Second):
		t.Fatal("leg B did not start")
	}
}

func TestDialEndpointsSequential(t *testing.T) {
	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()

	var order []string
	epA := &mockStreamEndpoint{
		dialFn: func(ctx context.Context, target string, localPort uint16) (net.Conn, error) {
			order = append(order, "netA")
			return nil, errMockStreamDialFailed
		},
	}
	epB := &mockStreamEndpoint{
		dialFn: func(ctx context.Context, target string, localPort uint16) (net.Conn, error) {
			order = append(order, "netB")
			return pipeA, nil
		},
	}

	eps := []namedEndpoint{
		{name: "netA", ep: epA},
		{name: "netB", ep: epB},
	}

	policy := DialPolicy{Strategy: DialSequential}
	conn, winNet, err := dialEndpoints(context.Background(), eps, policy, "target.b32.i2p:80", 0)
	if err != nil {
		t.Fatalf("dialEndpoints failed: %v", err)
	}
	if winNet != "netB" {
		t.Fatalf("winning net = %q, want netB", winNet)
	}
	if conn == nil {
		t.Fatal("expected non-nil connection")
	}
	if len(order) != 2 || order[0] != "netA" || order[1] != "netB" {
		t.Fatalf("execution order = %v, want [netA netB]", order)
	}
}

func TestStreamEndpointsFiltering(t *testing.T) {
	epA := &mockStreamEndpoint{}
	epB := &mockStreamEndpoint{}
	epC := &mockStreamEndpoint{}

	dest := &Destination{
		nets: []string{"netA", "netB", "netC"},
		endpoints: map[string]destination.DestinationEndpoint{
			"netA": epA,
			"netB": epB,
			"netC": epC,
		},
	}

	// 1. Unfiltered (empty policy.Networks) -> all endpoints
	eps, err := dest.streamEndpoints("tcp", DialPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(eps))
	}

	// 2. Filtered with policy.Networks = ["netC", "netA"] -> exactly 2 in specified order
	eps, err = dest.streamEndpoints("tcp", DialPolicy{Networks: []string{"netC", "netA"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 || eps[0].name != "netC" || eps[1].name != "netA" {
		t.Fatalf("unexpected filtered endpoints: %+v", eps)
	}

	// 3. Filtered with non-matching network -> ErrUnsupportedNetwork
	_, err = dest.streamEndpoints("tcp", DialPolicy{Networks: []string{"unknown"}})
	if !errors.Is(err, ErrUnsupportedNetwork) {
		t.Fatalf("expected ErrUnsupportedNetwork, got %v", err)
	}
}
