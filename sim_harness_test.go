//go:build dst || synctest

package ivnp

import (
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/simnet"
)

// Deterministic router-mesh harness. Every router binds simnet sockets instead
// of kernel UDP/TCP, so the whole fleet — NTCP2 streams, SSU2 datagrams, tunnel
// builds, NetDB traffic — runs on the ambient clock. Inside a testing/synctest
// bubble that clock is virtual: tests advance through latency, jitter, and
// maintenance timers without wall-clock sleeps.
//
// Create the simNet and every router inside the synctest test function; the
// scheduler goroutine and all channels are then bubble-local.

const (
	simNTCP2Port = 40001
	simSSU2Port  = 40002
)

// Simulation recovery profile: low-latency links make the production health
// knobs (60s probe timeout, 2 consecutive failures) the dominant convergence
// delay, so sim nodes detect a dead circuit on a single 12s probe miss. The
// maintenance interval feeds the RouterInfo refresh cadence; the periodic
// maintenance tick itself is capped at 1s regardless.
const (
	simMaintenanceInterval         = 5 * time.Second
	simHealthProbeTimeout          = 12 * time.Second
	simHealthProbeFailureThreshold = 1
)

// simNet hosts a fleet of embedded routers over one simnet.Network.
type simNet struct {
	net   *simnet.Network
	nodes []*simNode
}

// simNode couples one sim host to one running embedded router.
type simNode struct {
	name   string
	host   *simnet.Host
	router *Router
}

// Hash returns the router identity hash.
func (n *simNode) Hash() Hash { return n.router.Hash() }

// Addr returns the host's simulated address.
func (n *simNode) Addr() netip.Addr { return n.host.Addr() }

// simNodeConfig selects a node's role in the simulated network.
type simNodeConfig struct {
	Name string
	// Participation defaults to ParticipationWarm (transit, no floodfill).
	Participation PublicParticipation
	// Hops sets exploratory tunnel length; zero selects 1.
	Hops int
	// TunnelCount sets exploratory tunnels per direction; zero selects 1.
	TunnelCount int
	// DisableNTCP2 forces all sessions onto SSU2/UDP so UDP-scoped fault
	// models provably engage instead of passing over TCP.
	DisableNTCP2 bool
}

// newSimNet creates an empty simulation. The seed feeds every link's loss,
// jitter, and duplication sampler; equal seeds reproduce equal link behavior.
// If DST_SEED or IVNP_DST_SEED is present in the environment, it overrides seed.
func newSimNet(tb testing.TB, seed uint64) *simNet {
	tb.Helper()
	if env := cmp.Or(os.Getenv("DST_SEED"), os.Getenv("IVNP_DST_SEED")); env != "" {
		if s, err := strconv.ParseUint(env, 10, 64); err == nil {
			seed = s
		}
	}
	var identitySeed [32]byte
	binary.LittleEndian.PutUint64(identitySeed[:8], seed)
	foundation.SetDeterministicRandomSource(rand.NewChaCha8(identitySeed))
	n := simnet.NewNetwork(simnet.Config{Seed: seed})
	s := &simNet{net: n}
	tb.Cleanup(func() {
		for _, node := range s.nodes {
			_ = node.router.Close()
		}
		if err := n.Close(); err != nil {
			tb.Errorf("simnet close: %v", err)
		}
	})
	return s
}

// AddRouter constructs and starts one embedded router bound to a new host.
// Construction happens inside the caller's clock domain, so call it inside the
// synctest test function.
func (s *simNet) AddRouter(tb testing.TB, cfg simNodeConfig) *simNode {
	tb.Helper()
	host := s.net.Host(cfg.Name)
	if host == nil {
		tb.Fatal("simnet prefix exhausted")
	}
	hops := cmp.Or(cfg.Hops, 1)
	count := cmp.Or(cfg.TunnelCount, 1)
	pool := TunnelPoolConfig{
		Inbound:     TunnelDirectionConfig{Hops: hops, Count: count},
		Outbound:    TunnelDirectionConfig{Hops: hops, Count: count},
		RenewBefore: 10 * time.Second,
	}
	ntcp2 := netip.AddrPortFrom(host.Addr(), simNTCP2Port)
	ssu2 := netip.AddrPortFrom(host.Addr(), simSSU2Port)
	transport := func(bind netip.AddrPort) TransportConfig {
		return TransportConfig{Enabled: true, Bind: bind, Advertised: bind, MaxSessions: 64, IdleTimeout: 10 * time.Minute}
	}
	routerCfg := DefaultRouterConfig()
	routerCfg.Logger = slog.New(slog.DiscardHandler)
	if os.Getenv("DST_LOG") != "" {
		routerCfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})).With("node", cfg.Name)
	}
	opts := []NetworkOption{
		WithPublicParticipation(cfg.Participation),
		WithTransportSSU2(transport(ssu2)),
		WithExploratoryPool(pool),
	}
	if !cfg.DisableNTCP2 {
		opts = append(opts, WithTransportNTCP2(transport(ntcp2)))
	}
	routerCfg.SetNetworks(NewNetwork(networkNativeName, NetworkIDPublicI2P, opts...))
	specs, def, err := networkSpecs(routerCfg)
	if err != nil {
		tb.Fatal(err)
	}
	runtime := &simSocketRuntime{host: host}
	for i := range specs {
		specs[i].Options.SocketRuntime = runtime
		specs[i].Operating.Tunnel.MaintenanceInterval = simMaintenanceInterval
		specs[i].Operating.Tunnel.ProbeTimeout = simHealthProbeTimeout
		specs[i].Operating.Tunnel.ProbeFailureThreshold = simHealthProbeFailureThreshold
	}
	router, err := newRouter(tb.Context(), routerCfg, specs, def)
	if err != nil {
		tb.Fatal(err)
	}
	node := &simNode{name: cfg.Name, host: host, router: router}
	s.nodes = append(s.nodes, node)
	return node
}

// ExchangeRouterInfos installs every node's signed RouterInfo into every other
// node's NetDB — the static-membership bootstrap of a dedicated network.
func (s *simNet) ExchangeRouterInfos(tb testing.TB) {
	tb.Helper()
	ctx := tb.Context()
	for _, from := range s.nodes {
		wire, err := from.router.Node().ExportLocalRouterInfo("")
		if err != nil {
			tb.Fatalf("export RouterInfo from %q: %v", from.name, err)
		}
		if len(wire) == 0 {
			tb.Fatalf("empty RouterInfo from %q", from.name)
		}
		for _, to := range s.nodes {
			if to == from {
				continue
			}
			if _, err := to.router.Node().ImportRouterInfo(ctx, "", wire); err != nil {
				tb.Fatalf("import %q RouterInfo into %q: %v", from.name, to.name, err)
			}
		}
	}
}

// Link configures both directions between two nodes.
func (s *simNet) Link(a, b *simNode, cfg simnet.LinkConfig) {
	s.net.SetBidirectional(a.Addr(), b.Addr(), cfg)
}

// Mesh links every node pair with the same bidirectional profile.
func (s *simNet) Mesh(cfg simnet.LinkConfig) {
	for i, a := range s.nodes {
		for _, b := range s.nodes[i+1:] {
			s.Link(a, b, cfg)
		}
	}
}

// WaitReady blocks until every node reports ready or the timeout elapses on
// the ambient clock — inside a bubble the wait advances fake time.
func (s *simNet) WaitReady(tb testing.TB, timeout time.Duration) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(tb.Context(), timeout)
	defer cancel()
	if err := s.waitReady(ctx); err != nil {
		tb.Fatal(err)
	}
}

func (s *simNet) waitReady(ctx context.Context) error {
	for _, node := range s.nodes {
		if err := node.router.WaitReady(ctx); err != nil {
			return fmt.Errorf("%s WaitReady: %w", node.name, err)
		}
	}
	return nil
}

// CrashNode simulates an abrupt, unannounced process termination (e.g. SIGKILL,
// power loss): all links to and from the node are immediately severed without
// sending TCP FIN/RST or SSU2 teardown packets. Surviving peers observe silent
// unresponsiveness until their retransmission or probe deadlines expire.
func (s *simNet) CrashNode(tb testing.TB, node *simNode) {
	tb.Helper()
	for _, other := range s.nodes {
		if other != node {
			s.net.Blackhole(node.Addr(), other.Addr())
			s.net.Blackhole(other.Addr(), node.Addr())
		}
	}
	_ = node.router.Close()
}

// Stats returns network-level counters.
func (s *simNet) Stats() simnet.Stats { return s.net.Stats() }

// simSocketRuntime adapts one sim host to the dataplane socket contract, so
// real NTCP2 and SSU2 managers run over virtual sockets.
type simSocketRuntime struct {
	host *simnet.Host
}

var _ dataplane.RouterSocketRuntime = (*simSocketRuntime)(nil)
var _ dataplane.RouterUDPSocket = (*simnet.UDPConn)(nil)
var _ net.Listener = (*simnet.TCPListener)(nil)
var _ net.Conn = (*simnet.TCPConn)(nil)

func (s *simSocketRuntime) ListenStream(_ context.Context, endpoint dataplane.RouterEndpoint) (net.Listener, error) {
	addr, err := netip.ParseAddrPort(endpoint.Address)
	if err != nil {
		return nil, err
	}
	return s.host.ListenTCP(addr)
}

func (s *simSocketRuntime) DialStream(ctx context.Context, endpoint dataplane.RouterEndpoint) (net.Conn, error) {
	addr, err := netip.ParseAddrPort(endpoint.Address)
	if err != nil {
		return nil, err
	}
	return s.host.DialTCP(ctx, addr)
}

func (s *simSocketRuntime) ListenUDP(_ context.Context, endpoint dataplane.RouterEndpoint) (dataplane.RouterUDPSocket, error) {
	addr, err := netip.ParseAddrPort(endpoint.Address)
	if err != nil {
		return nil, err
	}
	return s.host.ListenUDP(addr)
}
