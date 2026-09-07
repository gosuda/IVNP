package noderuntime

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/controlplane/internal/router"
	"gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/observability"
	"gosuda.org/ivnp/state"
)

type recordingSockets struct{ calls int }

func (s *recordingSockets) ListenStream(context.Context, dataplane.RouterEndpoint) (net.Listener, error) {
	s.calls++
	return nil, errors.New("unexpected socket")
}
func (s *recordingSockets) DialStream(context.Context, dataplane.RouterEndpoint) (net.Conn, error) {
	s.calls++
	return nil, errors.New("unexpected socket")
}
func (s *recordingSockets) ListenUDP(context.Context, dataplane.RouterEndpoint) (*net.UDPConn, error) {
	s.calls++
	return nil, errors.New("unexpected socket")
}

type blockingRequestSender struct {
	entered chan struct{}
	once    sync.Once
}

func (s *blockingRequestSender) Send(ctx context.Context, _ netdb.RouterRef, _ foundation.I2NPMessage) error {
	s.once.Do(func() { close(s.entered) })
	<-ctx.Done()
	return ctx.Err()
}

type requestDirectCapture struct {
	calls  int
	target foundation.Hash
}

func (s *requestDirectCapture) Send(_ context.Context, target foundation.Hash, _ foundation.I2NPMessage) error {
	s.calls++
	s.target = target
	return nil
}

type requestTunnelCapture struct {
	calls int
	id    uint32
	block dataplane.TunnelBlock
	err   error
}

func (s *requestTunnelCapture) SendBlock(_ context.Context, id uint32, block dataplane.TunnelBlock) error {
	s.calls++
	s.id = id
	s.block = block
	s.block.Data = append([]byte(nil), block.Data...)
	return s.err
}

type requestPairCapture struct{ pair tunnel.CircuitPair }

func (s requestPairCapture) Pair(uint64) (tunnel.CircuitPair, bool) { return s.pair, true }

type requestReplyRouteCapture struct {
	gateway foundation.Hash
	tunnel  uint32
}

func (r requestReplyRouteCapture) DatabaseLookupReplyRoute() (foundation.Hash, uint32, bool) {
	return r.gateway, r.tunnel, true
}

type loopbackSockets struct{}

func (loopbackSockets) ListenStream(context.Context, dataplane.RouterEndpoint) (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}
func (loopbackSockets) DialStream(ctx context.Context, endpoint dataplane.RouterEndpoint) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, endpoint.Network, endpoint.Address)
}
func (loopbackSockets) ListenUDP(context.Context, dataplane.RouterEndpoint) (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

type defaultTransportSockets struct {
	streams int
	packets int
}

func (s *defaultTransportSockets) ListenStream(context.Context, dataplane.RouterEndpoint) (net.Listener, error) {
	s.streams++
	return net.Listen("tcp", "127.0.0.1:0")
}
func (s *defaultTransportSockets) DialStream(ctx context.Context, endpoint dataplane.RouterEndpoint) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, endpoint.Network, endpoint.Address)
}
func (s *defaultTransportSockets) ListenUDP(context.Context, dataplane.RouterEndpoint) (*net.UDPConn, error) {
	s.packets++
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

type daemonMemoryNetwork struct {
	mu        sync.RWMutex
	endpoints map[foundation.Hash]*daemonMemoryTransport
	flood     foundation.Hash
	floodDB   *netdb.Database
	now       func() uint64
	stores    []foundation.I2NPDatabaseStoreMessage
	lookups   int
	nextID    uint32
}

type daemonMemoryTransport struct {
	network  *daemonMemoryNetwork
	local    foundation.Hash
	bindings dataplane.RouterTransportBindings
	done     chan struct{}
	once     sync.Once
	running  bool
}

func newDaemonMemoryNetwork(flood foundation.NetworkDatabaseRouterInfo, now func() uint64) *daemonMemoryNetwork {
	return &daemonMemoryNetwork{
		endpoints: make(map[foundation.Hash]*daemonMemoryTransport), flood: flood.Hash(),
		floodDB: netdb.NewDatabase(flood.Hash(), netdb.DefaultBucketCapacity), now: now,
	}
}

func (n *daemonMemoryNetwork) messageID() uint32 {
	n.mu.Lock()
	n.nextID++
	if n.nextID == 0 {
		n.nextID++
	}
	id := n.nextID
	n.mu.Unlock()
	return id
}

func (n *daemonMemoryNetwork) transport() *daemonMemoryTransport {
	return &daemonMemoryTransport{network: n, done: make(chan struct{})}
}

func (t *daemonMemoryTransport) Start(ctx context.Context, bindings dataplane.RouterTransportBindings) error {
	localInfo, ok := bindings.LocalInfo.(router.LocalInfo)
	if !ok {
		return errors.New("memory network requires control-plane identity publication")
	}
	localInfo.SetReachability(router.ReachabilityReachable)
	if err := localInfo.Publish(ctx); err != nil {
		return err
	}
	t.local, t.bindings, t.running = bindings.LocalInfo.Hash(), bindings, true
	t.network.mu.Lock()
	t.network.endpoints[t.local] = t
	t.network.mu.Unlock()
	return nil
}

func (t *daemonMemoryTransport) Send(ctx context.Context, target foundation.Hash, message foundation.I2NPMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return t.network.route(t.local, target, message)
}

func (t *daemonMemoryTransport) Close() error {
	t.once.Do(func() {
		t.network.mu.Lock()
		delete(t.network.endpoints, t.local)
		t.running = false
		t.network.mu.Unlock()
		close(t.done)
	})
	return nil
}

func (t *daemonMemoryTransport) Wait() error {
	<-t.done
	return nil
}

func (t *daemonMemoryTransport) Status() dataplane.RouterTransportStatus {
	return dataplane.RouterTransportStatus{Running: t.running}
}

func (n *daemonMemoryNetwork) route(from, target foundation.Hash, message foundation.I2NPMessage) error {
	if target == n.flood {
		return n.handleFlood(from, message)
	}
	if message.Header.Type == foundation.I2NPShortTunnelBuild {
		if _, err := foundation.I2NPParseBuildRecords(foundation.I2NPShortTunnelBuild, message.Payload); err != nil {
			return err
		}
	}
	n.mu.RLock()
	endpoint := n.endpoints[target]
	n.mu.RUnlock()
	if endpoint == nil {
		return router.ErrTransportUnavailable
	}
	return endpoint.bindings.HandleI2NPFrom(from, message, n.now(), false)
}

func (n *daemonMemoryNetwork) handleFlood(from foundation.Hash, message foundation.I2NPMessage) error {
	switch message.Header.Type {
	case foundation.I2NPDatabaseStore:
		store, err := foundation.I2NPParseDatabaseStore(message.Payload)
		if err != nil {
			return err
		}
		if err = n.floodDB.HandleDatabaseStore(store, false, n.now()); err != nil {
			return err
		}
		n.mu.Lock()
		n.stores = append(n.stores, store)
		n.mu.Unlock()
		if store.ReplyToken != 0 {
			var payload [12]byte
			binary.BigEndian.PutUint32(payload[:4], store.ReplyToken)
			binary.BigEndian.PutUint64(payload[4:], n.now())
			status := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: n.messageID(), Expiration: n.now() + 60_000}, Payload: payload[:]}
			return n.reply(n.flood, store.ReplyGateway, store.ReplyTunnelID, status)
		}
		return nil
	case foundation.I2NPDatabaseLookup:
		lookup, err := foundation.I2NPParseDatabaseLookup(message.Payload)
		if err != nil {
			return err
		}
		n.mu.Lock()
		n.lookups++
		n.mu.Unlock()
		typeID, data, found := n.floodDB.StoredLeaseSet(lookup.Key)
		if !found {
			return netdb.ErrNoFloodfill
		}
		payload, err := foundation.NetworkDatabaseMarshalDatabaseStore(lookup.Key, typeID, data, 0, foundation.Hash{}, 0)
		if err != nil {
			return err
		}
		reply := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: n.messageID(), Expiration: n.now() + 60_000}, Payload: payload}
		return n.reply(n.flood, lookup.From, lookup.ReplyTunnelID, reply)
	default:
		return n.route(from, from, message)
	}
}

func (n *daemonMemoryNetwork) reply(from, gateway foundation.Hash, tunnelID uint32, message foundation.I2NPMessage) error {
	if tunnelID == 0 {
		return n.route(from, gateway, message)
	}
	frame := make([]byte, message.EncodedLen())
	if _, err := message.MarshalTo(frame); err != nil {
		return err
	}
	payload := make([]byte, foundation.I2NPTunnelGatewayHeaderLen+len(frame))
	binary.BigEndian.PutUint32(payload[:4], tunnelID)
	binary.BigEndian.PutUint16(payload[4:6], uint16(len(frame)))
	copy(payload[6:], frame)
	gatewayMessage := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPTunnelGateway, ID: n.messageID(), Expiration: message.Header.Expiration}, Payload: payload}
	return n.route(from, gateway, gatewayMessage)
}

func daemonProductionFloodfill(t *testing.T, now uint64) foundation.NetworkDatabaseRouterInfo {
	t.Helper()
	public, private, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := make([]byte, foundation.IdentityBaseLength+7)
	copy(identity[352:384], public)
	identity[384] = byte(foundation.CertificateKey)
	identity[385], identity[386] = 0, 4
	identity[387], identity[388] = 0, byte(foundation.SigningEdDSASHA512Ed25519)
	identity[389], identity[390] = 0, byte(foundation.CryptoElGamal)
	options := make([]byte, 16)
	optionLen, err := foundation.MarshalMappingTo(options, []foundation.MappingEntry{{Key: []byte("caps"), Value: []byte("f")}})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := append(identity, make([]byte, 10)...)
	binary.BigEndian.PutUint64(unsigned[len(identity):len(identity)+8], now)
	unsigned = append(unsigned, options[:optionLen]...)
	info, err := foundation.NetworkDatabaseParseRouterInfo(append(unsigned, ed25519.Sign(private, unsigned)...))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestDefaultOperatingStartsOutboundNTCP2AndBoundSSU2(t *testing.T) {
	cfg, err := state.ConfigurationParseOperating("", filepath.Join(t.TempDir(), "ivnp.conf"))
	if err != nil {
		t.Fatal(err)
	}
	sockets := new(defaultTransportSockets)
	d, err := NewController(cfg, ControllerOptions{SocketRuntime: sockets, Logger: discardNATLogger()})
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !d.Status().Running || sockets.streams != 1 || sockets.packets != 1 {
		t.Fatalf("default transport startup: running=%t streams=%d packets=%d", d.Status().Running, sockets.streams, sockets.packets)
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	if err = d.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestDaemonReplyKeyCapacityIncludesJavaBuildGrace(t *testing.T) {
	const (
		buildPending = 4
		destinations = 16
	)
	const want = (destinations + 1) * buildPending * 13
	if got := daemonReplyKeyCapacity(buildPending, destinations); got != want {
		t.Fatalf("reply-key capacity = %d, want %d", got, want)
	}
}

func daemonTestConfig(t *testing.T) state.ConfigurationOperating {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	return state.ConfigurationOperating{
		StatePath: filepath.Join(base, "router.state"),
		KeyPath:   filepath.Join(base, "router.keys"),
		Network:   state.ConfigurationNetwork{ID: 2, IPv4: true},
		Router:    state.ConfigurationRouter{Version: "0.9.70"},
		State:     state.ConfigurationState{MaxBytes: 1 << 20, MaxDestinations: 16, MaxNameBytes: 64},
		NetDB:     state.ConfigurationNetDB{BucketCapacity: 4, LookupCapacity: 8},
		Tunnel: state.ConfigurationTunnel{
			Hops:                     1,
			ExploratoryInboundTarget: 1, ExploratoryOutboundTarget: 1, ExploratoryPoolCapacity: 4,
			ClientInboundTarget: 1, ClientOutboundTarget: 1, ClientPoolCapacity: 4, BuildPendingCapacity: 4,
			Lifetime: 10 * time.Minute, RenewBefore: 10 * time.Second, MaintenanceInterval: time.Minute,
			BandwidthRateBytesPerSecond: 64 * 1024,
		},
		NTCP2: state.ConfigurationTransport{Enabled: true, Bind: state.ConfigurationEndpoint{Host: "127.0.0.1", Port: 12345}, MaxSessions: 4},
	}
}

func TestNewDoesNotOpenSocketsAndReloadsState(t *testing.T) {
	cfg := daemonTestConfig(t)
	sockets := new(recordingSockets)
	first, err := NewController(cfg, ControllerOptions{SocketRuntime: sockets})
	if err != nil {
		t.Fatal(err)
	}
	if sockets.calls != 0 {
		t.Fatalf("New opened %d sockets", sockets.calls)
	}
	if _, err := NewController(cfg, ControllerOptions{SocketRuntime: sockets}); !errors.Is(err, state.SecureStateErrStateLocked) {
		t.Fatalf("second New error = %v, want state lock error", err)
	}
	wantHash := first.bundle.Router.Hash
	wantPrivate := first.bundle.Router.X25519Private
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	newDoesNotOpenSocketsAndReloadsStateRejected := first.bundle.Router.Hash != (foundation.Hash{}) || len(first.bundle.Router.SigningPrivate) != 0 || first.bundle.Router.X25519Private != ([32]byte{}) ||
		len(first.bundle.NTCP2StaticPrivate) != 0 || len(first.bundle.SSU2StaticPrivate) != 0 || first.bundle.DestinationPrivate != nil ||
		first.bundle.EncryptedLeaseSetPolicies != nil
	if !newDoesNotOpenSocketsAndReloadsStateRejected {
		newDoesNotOpenSocketsAndReloadsStateRejected = first.bundle.DestinationAddressPolicies != nil
	}
	if newDoesNotOpenSocketsAndReloadsStateRejected {
		t.Fatal("closed daemon retained its in-memory sensitive state bundle")
	}
	second, err := NewController(cfg, ControllerOptions{SocketRuntime: sockets})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.bundle.Router.Hash != wantHash || second.bundle.Router.X25519Private != wantPrivate {
		t.Fatal("router identity was not reloaded from durable state")
	}
}

func TestNewFailureReleasesStateOwnership(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.NTCP2.Enabled = false
	if _, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)}); err == nil {
		t.Fatal("New accepted a configuration without transports")
	}
	cfg.NTCP2.Enabled = true
	d, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatalf("New after construction failure error = %v", err)
	}
	defer d.Close()
}

func TestNewRejectsEnabledTunnelLifetimeOutsideWireLifetime(t *testing.T) {
	for _, lifetime := range []time.Duration{9 * time.Minute, 11 * time.Minute} {
		t.Run(lifetime.String(), func(t *testing.T) {
			cfg := daemonTestConfig(t)
			cfg.Tunnel.Enabled = true
			cfg.Tunnel.Lifetime = lifetime
			if _, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)}); !errors.Is(err, state.ConfigurationErrInvalidOperating) {
				t.Fatalf("New lifetime %s error = %v, want invalid operating config", lifetime, err)
			}
		})
	}
}

func TestNewRejectsDestinationBoundsAndDuplicateIdentities(t *testing.T) {
	t.Run("duplicate", func(t *testing.T) {
		cfg := daemonTestConfig(t)
		d, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
		if err != nil {
			t.Fatal(err)
		}
		address, err := foundation.GenerateLocalAddress()
		if err != nil {
			t.Fatal(err)
		}
		d.bundle.Destinations = map[string]foundation.LocalAddress{"first": address, "second": address}
		if err := d.store.Save(d.bundle); err != nil {
			t.Fatal(err)
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		cfg.Tunnel.Enabled = true
		if _, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)}); !errors.Is(err, ErrDuplicateDestination) {
			t.Fatalf("duplicate destinations error = %v", err)
		}
	})

	t.Run("bound", func(t *testing.T) {
		cfg := daemonTestConfig(t)
		cfg.State.MaxDestinations = 65
		d, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
		if err != nil {
			t.Fatal(err)
		}
		address, err := foundation.GenerateLocalAddress()
		if err != nil {
			t.Fatal(err)
		}
		d.bundle.Destinations = make(map[string]foundation.LocalAddress, 65)
		for index := range 65 {
			d.bundle.Destinations[string(rune(index+1))] = address
		}
		if err := d.store.Save(d.bundle); err != nil {
			t.Fatal(err)
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		cfg.Tunnel.Enabled = true
		if _, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)}); !errors.Is(err, ErrTooManyDestinations) {
			t.Fatalf("too many destinations error = %v", err)
		}
	})
}

func TestDataPlaneReadyDoesNotRequireOptionalAccelerationOrPublicReachability(t *testing.T) {
	ready := ReadinessDetails{
		NetDBRouters:               50,
		RouterInfoPublications:     1,
		LeaseSet2Publications:      1,
		ExploratoryInboundTunnels:  1,
		ExploratoryOutboundTunnels: 1,
		ClientInboundTunnels:       1,
		ClientOutboundTunnels:      1,
	}
	if !dataPlaneReady(ready) {
		t.Fatal("operational firewalled router with portable SSU2 I/O was not ready")
	}
	floodfill := ready
	floodfill.FloodfillConfigured = true
	if dataPlaneReady(floodfill) {
		t.Fatal("configured floodfill reported ready before advertising its role")
	}
	floodfill.FloodfillAdvertised = true
	if !dataPlaneReady(floodfill) {
		t.Fatal("advertised floodfill with an operational data plane was not ready")
	}
	required := []struct {
		name   string
		mutate func(*ReadinessDetails)
	}{
		{"netdb", func(value *ReadinessDetails) { value.NetDBRouters = 49 }},
		{"router publication", func(value *ReadinessDetails) { value.RouterInfoPublications = 0 }},
		{"lease set publication", func(value *ReadinessDetails) { value.LeaseSet2Publications = 0 }},
		{"exploratory inbound", func(value *ReadinessDetails) { value.ExploratoryInboundTunnels = 0 }},
		{"exploratory outbound", func(value *ReadinessDetails) { value.ExploratoryOutboundTunnels = 0 }},
		{"client inbound", func(value *ReadinessDetails) { value.ClientInboundTunnels = 0 }},
		{"client outbound", func(value *ReadinessDetails) { value.ClientOutboundTunnels = 0 }},
	}
	for _, test := range required {
		t.Run(test.name, func(t *testing.T) {
			value := ready
			test.mutate(&value)
			if dataPlaneReady(value) {
				t.Fatal("incomplete data plane reported ready")
			}
		})
	}
}

func TestOutproxyWarmupReadinessDoesNotWaitOnTheDestinationItCreates(t *testing.T) {
	ready := ReadinessDetails{
		NetDBRouters:               50,
		RouterInfoPublications:     1,
		ExploratoryInboundTunnels:  1,
		ExploratoryOutboundTunnels: 1,
	}
	if !outproxyWarmupReady(ready, 1, 1) {
		t.Fatal("operational exploratory plane did not release outproxy warmup")
	}
	required := []struct {
		name   string
		mutate func(*ReadinessDetails)
	}{
		{"netdb", func(value *ReadinessDetails) { value.NetDBRouters = 49 }},
		{"router publication", func(value *ReadinessDetails) { value.RouterInfoPublications = 0 }},
		{"exploratory inbound", func(value *ReadinessDetails) { value.ExploratoryInboundTunnels = 0 }},
		{"exploratory outbound", func(value *ReadinessDetails) { value.ExploratoryOutboundTunnels = 0 }},
	}
	for _, test := range required {
		t.Run(test.name, func(t *testing.T) {
			value := ready
			test.mutate(&value)
			if outproxyWarmupReady(value, 1, 1) {
				t.Fatal("incomplete exploratory plane released outproxy warmup")
			}
		})
	}
	if outproxyWarmupReady(ready, 2, 1) || outproxyWarmupReady(ready, 1, 2) {
		t.Fatal("partial exploratory pool released outproxy warmup")
	}
}

func TestRequestAllTunnelMaintenanceQueuesEveryPool(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Tunnel.Enabled = true
	d, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	runtimes := d.clientRuntimeSnapshot()
	if len(runtimes) != 1 {
		t.Fatalf("client runtimes = %d, want 1", len(runtimes))
	}
	d.requestAllTunnelMaintenance()
	if len(d.tunnelWake) != 1 || len(d.destinationTunnelWake) != 1 {
		t.Fatalf("queued maintenance = exploratory %d destination %d", len(d.tunnelWake), len(d.destinationTunnelWake))
	}
	if !runtimes[0].tunnelMaintenanceDirty.Load() || !runtimes[0].tunnelMaintenanceQueued.Load() {
		t.Fatal("destination maintenance state was not queued")
	}
	d.requestAllTunnelMaintenance()
	if len(d.tunnelWake) != 1 || len(d.destinationTunnelWake) != 1 {
		t.Fatalf("duplicate wake was not coalesced: exploratory %d destination %d", len(d.tunnelWake), len(d.destinationTunnelWake))
	}
}

type requeueTunnelSource struct {
	next func()
}

func (s requeueTunnelSource) NextInbound(context.Context, uint64, uint32) (tunnel.InboundBuild, error) {
	s.next()
	return tunnel.InboundBuild{}, context.Canceled
}

func (s requeueTunnelSource) NextOutboundForReply(context.Context, uint64, tunnel.ReplyRoute) (tunnel.OutboundBuild, error) {
	return tunnel.OutboundBuild{}, context.Canceled
}

func TestDestinationTunnelMaintenanceRequeuesBehindOtherOwners(t *testing.T) {
	const now = uint64(100)
	d := &Controller{ctx: t.Context(), destinationTunnelWake: make(chan *destinationRuntime, 2)}
	first, second := new(destinationRuntime), new(destinationRuntime)
	calls := 0
	source := requeueTunnelSource{next: func() {
		calls++
		if calls == 1 {
			d.requestDestinationTunnelMaintenance(first)
		}
	}}
	pool := tunnel.NewPool(2)
	sender := new(requestDirectCapture)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	builder, err := tunnel.NewBuildManager(tunnel.BuildManagerConfig{Runtime: runtime, Pool: pool, Sender: sender, ReplyKeys: dataplane.GarlicNewReplyKeyRegistry(4), Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(builder.ReleaseSensitive)
	first.maintainer, err = tunnel.NewPairedPoolMaintainer(tunnel.PairedPoolMaintainerConfig{Pool: pool, Runtime: runtime, Builder: builder, InboundSource: source, OutboundSource: source, Now: func() uint64 { return now }, InboundTarget: 1, OutboundTarget: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.maintainer.Close() })
	d.requestDestinationTunnelMaintenance(first)
	d.requestDestinationTunnelMaintenance(second)
	d.maintainDestinationTunnels(<-d.destinationTunnelWake)
	if calls != 1 {
		t.Fatalf("dirty owner consumed %d transitions in one worker turn", calls)
	}
	if len(d.destinationTunnelWake) != 2 {
		t.Fatalf("queued owners = %d, want 2", len(d.destinationTunnelWake))
	}
	if got := <-d.destinationTunnelWake; got != second {
		t.Fatal("dirty owner bypassed an already queued owner")
	}
	if got := <-d.destinationTunnelWake; got != first {
		t.Fatal("dirty owner was not requeued")
	}
}

func TestTunnelCompositionUsesLiveInboundGatewayRoute(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Tunnel.Enabled = true
	d, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	tunnelCompositionUsesLiveInboundGatewayRouteRejected := d.service == nil || d.tunnels == nil || d.pool == nil || d.buildManager == nil || d.requests == nil || d.replyKeys == nil
	if !tunnelCompositionUsesLiveInboundGatewayRouteRejected {
		tunnelCompositionUsesLiveInboundGatewayRouteRejected = d.maintainer == nil || d.destinationFactory == nil || d.destinationFactory.eligible == nil
	}
	if tunnelCompositionUsesLiveInboundGatewayRouteRejected {
		t.Fatal("native tunnel data plane is incomplete")
	}
	if d.destinationFactory.eligible(foundation.Hash{255}) {
		t.Fatal("unknown RouterInfo was eligible for tunnel selection")
	}
	if len(d.bundle.DestinationPrivate["default"]) == 0 || len(d.clientRuntimeSnapshot()) != 1 {
		t.Fatal("tunnel-only daemon did not create its default destination runtime")
	}
	snapshot, ok := d.DestinationBandwidthSnapshot("default")
	if !ok || snapshot.RateBytesPerSecond == 0 || snapshot.BurstBytes == 0 {
		t.Fatalf("default destination bandwidth snapshot = %#v, %t", snapshot, ok)
	}
	now := uint64(d.clock.Now().UnixMilli())
	gateway := foundation.Hash{9}
	if err := d.pool.Add(tunnel.Entry{ID: 1, Direction: tunnel.Outbound, Expires: now + 30_000}, now); err != nil {
		t.Fatal(err)
	}
	if err := d.pool.Add(tunnel.Entry{ID: 2, Direction: tunnel.Inbound, Gateway: gateway, GatewayTunnelID: 77, Expires: now + 30_000}, now); err != nil {
		t.Fatal(err)
	}
	clientRuntime := d.clientRuntimeSnapshot()[0]
	if clientRuntime.profiles != d.profiles {
		t.Fatal("destination pool did not share router-wide peer reliability profiles")
	}
	owner := clientRuntime.local.Hash()
	if err := clientRuntime.pool.Add(tunnel.Entry{ID: 3, Direction: tunnel.Outbound, Expires: now + 30_000, Owner: owner}, now); err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.pool.Add(tunnel.Entry{ID: 4, Direction: tunnel.Inbound, Expires: now + 30_000, Owner: owner}, now); err != nil {
		t.Fatal(err)
	}
	if err := d.database.AdmitRouterInfo(daemonProductionFloodfill(t, now), true, now); err != nil {
		t.Fatal(err)
	}
	d.refreshObservability()
	tunnels := d.registry.Snapshot().Tunnel
	if tunnels.ExploratoryInboundActive != 1 || tunnels.ExploratoryOutboundActive != 1 || tunnels.ClientInboundActive != 1 || tunnels.ClientOutboundActive != 1 {
		t.Fatalf("pool-owned active tunnel metrics = %+v", tunnels)
	}
	netdb := d.registry.Snapshot().NetDB
	if netdb.Routers != 1 || netdb.Floodfills != 1 {
		t.Fatalf("NetDB gauges = %+v", netdb)
	}
	gotGateway, gotTunnel, viaTunnel := (daemonReplyRoute{local: d.bundle.Router.Hash, maintainer: d.maintainer, now: func() uint64 { return now }}).DatabaseLookupReplyRoute()
	if !viaTunnel || gotGateway != gateway || gotTunnel != 77 {
		t.Fatalf("reply route = %x/%d/%t, want gateway tunnel 77", gotGateway, gotTunnel, viaTunnel)
	}
}

func TestMuxRequestSenderUsesEstablishedOutboundTunnel(t *testing.T) {
	target, replyGateway := foundation.Hash{1}, foundation.Hash{2}
	payload, err := netdb.BuildDatabaseLookup(foundation.Hash{3}, netdb.LeaseSetLookup, requestReplyRouteCapture{
		gateway: replyGateway, tunnel: 7,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	direct := new(requestDirectCapture)
	throughTunnel := new(requestTunnelCapture)
	replyKeys := dataplane.GarlicNewReplyKeyRegistry(2)
	private, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var staticKey [32]byte
	copy(staticKey[:], private.PublicKey().Bytes())
	sender := muxRequestSender{
		sender: direct, tunnels: throughTunnel,
		pairs: requestPairCapture{pair: tunnel.CircuitPair{OutboundID: 11}},
		now:   func() uint64 { return 100 }, replyKeys: replyKeys,
		staticKeyLookup: func(hash foundation.Hash) ([32]byte, bool) {
			return staticKey, hash == target
		},
	}
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseLookup, ID: 9, Expiration: 1_000}, Payload: payload}
	if err = sender.Send(context.Background(), netdb.RouterRef{Hash: target}, message); err != nil {
		t.Fatal(err)
	}
	if direct.calls != 0 || throughTunnel.calls != 1 || throughTunnel.id != 11 {
		t.Fatalf("send paths direct=%d tunnel=%d/%d", direct.calls, throughTunnel.calls, throughTunnel.id)
	}
	if throughTunnel.block.Delivery != dataplane.TunnelDeliveryRouter || throughTunnel.block.Gateway != target || !throughTunnel.block.Last {
		t.Fatalf("tunnel block = %#v", throughTunnel.block)
	}
	decoded, used, err := foundation.I2NPParse(throughTunnel.block.Data)
	if err != nil || used != len(throughTunnel.block.Data) || decoded.Header.Type != foundation.I2NPGarlic {
		t.Fatalf("embedded wrapper = %#v/%d, %v", decoded.Header, used, err)
	}
	if len(decoded.Payload) < 4 || int(binary.BigEndian.Uint32(decoded.Payload[:4])) != len(decoded.Payload)-4 {
		t.Fatalf("garlic payload length = %d", len(decoded.Payload))
	}
	inner, err := dataplane.GarlicECIESOpenRouterMessage(make([]byte, len(decoded.Payload)), private.Bytes(), decoded.Payload[4:], 100)
	wantHeader := message.Header
	wantHeader.Expiration = 1_500
	if err != nil || inner.Header != wantHeader {
		t.Fatalf("embedded lookup = %#v, want %#v: %v", inner.Header, wantHeader, err)
	}
	lookup, err := foundation.I2NPParseDatabaseLookup(inner.Payload)
	muxRequestSenderUsesEstablishedOutboundTunnelRejected := err != nil || lookup.From != replyGateway || lookup.ReplyTunnelID != 7 || !lookup.ReplyUsesECIES() ||
		len(lookup.ReplyKey) != 32 || lookup.ReplyTagCount() != 1
	if !muxRequestSenderUsesEstablishedOutboundTunnelRejected {
		muxRequestSenderUsesEstablishedOutboundTunnelRejected = replyKeys.Len() != 1
	}
	if muxRequestSenderUsesEstablishedOutboundTunnelRejected {
		t.Fatalf("embedded lookup route = %#v, reply_keys=%d, %v", lookup, replyKeys.Len(), err)
	}
	var tag [8]byte
	copy(tag[:], lookup.ReplyTags)
	replyKeys.RemoveGarlicReplyKey(tag)
	retryPayload, err := netdb.BuildDatabaseLookup(foundation.Hash{3}, netdb.LeaseSetLookup, requestReplyRouteCapture{
		gateway: replyGateway, tunnel: 7,
	}, []foundation.Hash{{9}})
	if err != nil {
		t.Fatal(err)
	}
	message.Payload = retryPayload
	if err = sender.Send(context.Background(), netdb.RouterRef{Hash: target}, message); err != nil {
		t.Fatal(err)
	}
	decoded, _, err = foundation.I2NPParse(throughTunnel.block.Data)
	if err != nil {
		t.Fatal(err)
	}
	inner, err = dataplane.GarlicECIESOpenRouterMessage(make([]byte, len(decoded.Payload)), private.Bytes(), decoded.Payload[4:], 100)
	if err != nil {
		t.Fatal(err)
	}
	retryLookup, err := foundation.I2NPParseDatabaseLookup(inner.Payload)
	if err != nil || retryLookup.ReplyEncrypted() || replyKeys.Len() != 0 {
		t.Fatalf("retry lookup encryption = %#v, reply_keys=%d, %v", retryLookup, replyKeys.Len(), err)
	}
	message.Payload = payload
	throughTunnel.err = errors.New("tunnel send failed")
	if err = sender.Send(context.Background(), netdb.RouterRef{Hash: target}, message); !errors.Is(err, throughTunnel.err) || replyKeys.Len() != 0 {
		t.Fatalf("failed send = %v, reply_keys=%d", err, replyKeys.Len())
	}
}

func TestRequestManagerFiveAttemptChurnDoesNotRegisterZeroExclusionReplyKeys(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := uint64(1_700_000_000_000)
		database := netdb.NewDatabase(foundation.Hash{99}, netdb.DefaultBucketCapacity)
		for range 8 {
			if err := database.AdmitRouterInfo(daemonProductionFloodfill(t, now), true, now); err != nil {
				t.Fatal(err)
			}
		}
		private, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var staticKey [32]byte
		copy(staticKey[:], private.PublicKey().Bytes())
		replyKeys := dataplane.GarlicNewReplyKeyRegistry(1)
		throughTunnel := new(requestTunnelCapture)
		sender := muxRequestSender{
			sender: new(requestDirectCapture), tunnels: throughTunnel,
			pairs: requestPairCapture{pair: tunnel.CircuitPair{OutboundID: 11}},
			now:   func() uint64 { return now }, replyKeys: replyKeys,
			staticKeyLookup: func(foundation.Hash) ([32]byte, bool) {
				return staticKey, true
			},
		}
		manager, err := netdb.NewRequestManager(
			database,
			sender,
			requestReplyRouteCapture{gateway: foundation.Hash{2}, tunnel: 7},
			netdb.RequestManagerConfig{
				Capacity: 1, MaxCandidates: 8, TimeoutMillis: 50_000, Now: func() uint64 { return now },
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = manager.Close() })
		result, err := manager.LookupLeaseSet(context.Background(), foundation.Hash{3})
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if throughTunnel.calls != 1 || replyKeys.Len() != 0 {
			t.Fatalf("initial lookup sends=%d reply_keys=%d", throughTunnel.calls, replyKeys.Len())
		}
		const attemptTimeout = uint64(3_000)
		for tick := 1; tick <= 5; tick++ {
			now += attemptTimeout
			manager.Expire(now)
			synctest.Wait()
			wantSends := min(tick+1, 5)
			if throughTunnel.calls != wantSends || replyKeys.Len() != 0 {
				t.Fatalf("tick %d sends=%d want=%d reply_keys=%d", tick, throughTunnel.calls, wantSends, replyKeys.Len())
			}
		}
		if outcome := <-result; outcome.Err == nil {
			t.Fatalf("five-attempt lookup outcome = %#v", outcome)
		}
	})
}

func TestMuxLeaseSetSenderUsesOutboundTunnelAndSeedsBothRoutes(t *testing.T) {
	target, replyGateway, outboundEndpoint := foundation.Hash{1}, foundation.Hash{2}, foundation.Hash{3}
	payload, err := foundation.NetworkDatabaseMarshalDatabaseStore(foundation.Hash{4}, foundation.I2NPStoreLeaseSet2, []byte{1}, 5, replyGateway, 7)
	if err != nil {
		t.Fatal(err)
	}
	direct := new(requestDirectCapture)
	throughTunnel := new(requestTunnelCapture)
	var seeded [][2]foundation.Hash
	sender := muxLeaseSetSender{
		sender: direct, tunnels: throughTunnel,
		pairs: requestPairCapture{pair: tunnel.CircuitPair{OutboundID: 11, OutboundEndpoint: outboundEndpoint}},
		now:   func() uint64 { return 100 },
		seedReplyRouterInfo: func(_ context.Context, endpoint, reply foundation.Hash) error {
			seeded = append(seeded, [2]foundation.Hash{endpoint, reply})
			return nil
		},
	}
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: 9, Expiration: 1_000}, Payload: payload}
	if err = sender.Send(context.Background(), netdb.RouterRef{Hash: target}, message); err != nil {
		t.Fatal(err)
	}
	if direct.calls != 0 || throughTunnel.calls != 1 || throughTunnel.id != 11 {
		t.Fatalf("send paths direct=%d tunnel=%d/%d", direct.calls, throughTunnel.calls, throughTunnel.id)
	}
	if throughTunnel.block.Delivery != dataplane.TunnelDeliveryRouter || throughTunnel.block.Gateway != target || !throughTunnel.block.Last {
		t.Fatalf("tunnel block = %#v", throughTunnel.block)
	}
	if len(seeded) != 2 || seeded[0] != [2]foundation.Hash{target, replyGateway} || seeded[1] != [2]foundation.Hash{outboundEndpoint, target} {
		t.Fatalf("RouterInfo seeds = %#v", seeded)
	}
	decoded, used, err := foundation.I2NPParse(throughTunnel.block.Data)
	if err != nil || used != len(throughTunnel.block.Data) || decoded.Header != message.Header {
		t.Fatalf("embedded store = %#v/%d, %v", decoded.Header, used, err)
	}
	store, err := foundation.I2NPParseDatabaseStore(decoded.Payload)
	if err != nil || store.ReplyGateway != replyGateway || store.ReplyTunnelID != 7 || store.ReplyToken != 5 {
		t.Fatalf("embedded store route = %#v, %v", store, err)
	}
}

func TestTunneledNetDBTargetsRequireSeedableRouterInfo(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	direct := new(requestDirectCapture)
	pairs := requestPairCapture{pair: tunnel.CircuitPair{OutboundID: 11, OutboundEndpoint: foundation.Hash{3}}}
	clock := func() uint64 { return now }
	seed := func(context.Context, foundation.Hash, foundation.Hash) error { return nil }
	lookup := muxRequestSender{sender: direct, pairs: pairs, now: clock, seedReplyRouterInfo: seed}
	publication := muxLeaseSetSender{sender: direct, pairs: pairs, now: clock, seedReplyRouterInfo: seed}
	fresh := netdb.RouterRef{Hash: foundation.Hash{1}, Info: foundation.NetworkDatabaseRouterInfo{Published: now - netdb.RouterInfoMaxAgeMillis}}
	stale := netdb.RouterRef{Hash: foundation.Hash{2}, Info: foundation.NetworkDatabaseRouterInfo{Published: now - netdb.RouterInfoMaxAgeMillis - 1}}
	for _, sender := range []struct {
		name     string
		eligible func(netdb.RouterRef) bool
	}{{"lookup", lookup.Eligible}, {"publication", publication.Eligible}} {
		t.Run(sender.name, func(t *testing.T) {
			if !sender.eligible(fresh) {
				t.Fatal("rejected RouterInfo at the seed freshness boundary")
			}
			if sender.eligible(stale) {
				t.Fatal("selected a RouterInfo which the required seed would reject")
			}
		})
	}
	lookup.pairs, publication.pairs = nil, nil
	if !lookup.Eligible(stale) || !publication.Eligible(stale) {
		t.Fatal("direct bootstrap requires a seed even before tunnels exist")
	}
}

func TestProxyRequiresTunnelAndPersistsDefaultDestination(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.HTTPProxy.Enabled = true
	cfg.HTTPProxy.Address = state.ConfigurationEndpoint{Host: "127.0.0.1"}
	if _, err := NewController(cfg, ControllerOptions{}); !errors.Is(err, ErrProxyWithoutTunnels) {
		t.Fatalf("New without tunnels error = %v", err)
	}
	cfg.Tunnel.Enabled = true
	first, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.bundle.DestinationPrivate["default"]) == 0 {
		t.Fatal("default ECIES destination was not persisted")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	items, err := second.ListDestinations(context.Background())
	if err != nil || len(items) != 1 || !items[0].Default {
		t.Fatalf("destinations = %#v, %v", items, err)
	}
}

func TestStaticNTCP2PublisherRequiresExplicitAdvertisement(t *testing.T) {
	cfg := daemonTestConfig(t)
	d, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	publishedOptions := func() map[string]string {
		publisher, publishErr := newStaticAddressPublisher(cfg, d.bundle)
		if publishErr != nil {
			t.Fatal(publishErr)
		}
		addresses, publishErr := publisher.Addresses(context.Background())
		if publishErr != nil || len(addresses) != 1 {
			t.Fatalf("addresses = %#v, %v", addresses, publishErr)
		}
		options := make(map[string]string)
		for _, option := range addresses[0].Options {
			options[option.Key] = option.Value
		}
		return options
	}
	options := publishedOptions()
	if options["host"] != "" || options["port"] != "" || options["s"] == "" || options["i"] == "" {
		t.Fatalf("hostless options = %#v", options)
	}
	cfg.NTCP2.Advertised = state.ConfigurationEndpoint{Host: "127.0.0.1", Port: 12345}
	options = publishedOptions()
	if options["host"] != "127.0.0.1" || options["port"] != "12345" {
		t.Fatalf("advertised options = %#v", options)
	}
}

func TestDaemonRotatesPersistedNonInteroperablePublicDestination(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Tunnel.Enabled = true
	first, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	modern, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	oldHash := modern.Hash()
	encoded, err := destinationPrivate(modern)
	modern.ReleaseSensitive()
	if err != nil {
		t.Fatal(err)
	}
	clear(first.bundle.DestinationPrivate["default"])
	first.bundle.DestinationPrivate["default"] = encoded
	if err = first.store.Save(first.bundle); err != nil {
		t.Fatal(err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	migrated, err := foundation.ImportLocalDestination(reopened.bundle.DestinationPrivate["default"])
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.ReleaseSensitive()
	identity, err := migrated.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if identity.CryptoKeyType() != foundation.CryptoElGamal || migrated.Hash() == oldHash {
		t.Fatalf("migrated public destination type/hash = %d/%x", identity.CryptoKeyType(), migrated.Hash())
	}
}

func TestDestinationAddressPoliciesPersistAndWireRemoteELS(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Tunnel.Enabled = true
	first, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := destinationPrivate(local)
	if err != nil {
		t.Fatal(err)
	}
	local.ReleaseSensitive()
	first.bundle.DestinationPrivate["default"] = encoded
	if err = first.store.Save(first.bundle); err != nil {
		t.Fatal(err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}

	d, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	none, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	dh, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	noneIdentity, err := none.Identity()
	if err != nil {
		t.Fatal(err)
	}
	dhIdentity, err := dh.Identity()
	if err != nil {
		t.Fatal(err)
	}
	pskIdentity, err := psk.Identity()
	if err != nil {
		t.Fatal(err)
	}
	dhPrivate, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var private, public, pskKey [32]byte
	copy(private[:], dhPrivate.Bytes())
	copy(public[:], dhPrivate.PublicKey().Bytes())
	for index := range pskKey {
		pskKey[index] = byte(index + 1)
	}
	policies := []state.SecureStateRemoteELSAuthorization{
		{Identity: append([]byte(nil), noneIdentity.Bytes()...), Secret: []byte("none")},
		{Identity: append([]byte(nil), dhIdentity.Bytes()...), Secret: []byte("dh"), Kind: state.SecureStateRemoteELSAuthorizationDH, DHPrivate: private, DHPublic: public},
		{Identity: append([]byte(nil), pskIdentity.Bytes()...), Secret: []byte("psk"), Kind: state.SecureStateRemoteELSAuthorizationPSK, PSK: pskKey},
	}
	if err = d.UpdateDestinationAddressPolicies("default", policies); err != nil {

		t.Fatal(err)
	}
	if got := d.bundle.DestinationAddressPolicies["default"]; len(got) != len(policies) {
		t.Fatalf("durable policies = %#v", got)
	}
	retainedSecrets := make([][]byte, len(policies))
	for index := range policies {
		retainedSecrets[index] = d.bundle.DestinationAddressPolicies["default"][index].Secret
	}
	if err = d.UpdateDestinationAddressPolicies("default", policies); err != nil {
		t.Fatal(err)
	}
	for _, secret := range retainedSecrets {
		for _, value := range secret {
			if value != 0 {
				t.Fatal("successful policy replacement retained a superseded secret")
			}
		}
	}
	statePath := d.store.StatePath
	d.store.StatePath = t.TempDir()
	if err = d.UpdateDestinationAddressPolicies("default", nil); err == nil {
		t.Fatal("policy update unexpectedly survived durable Save failure")
	}
	d.store.StatePath = statePath
	if got := d.bundle.DestinationAddressPolicies["default"]; len(got) != len(policies) || got[1].DHPublic != public {
		t.Fatalf("failed durable update mutated active bundle = %#v", got)
	}
	invalid := cloneRemoteELSAuthorizations(policies)
	invalid[1].DHPublic[0] ^= 0x80
	if err = d.UpdateDestinationAddressPolicies("default", invalid); !errors.Is(err, dataplane.RouterErrDataPlaneConfig) {
		t.Fatalf("invalid DH binding = %v", err)
	}
	if got := d.bundle.DestinationAddressPolicies["default"]; len(got) != len(policies) || got[1].DHPublic != public {
		t.Fatalf("invalid update mutated durable policy = %#v", got)
	}
	if len(d.clientRuntimeSnapshot()) != 1 {
		t.Fatalf("client runtime count = %d", len(d.clientRuntimeSnapshot()))
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.bundle.DestinationAddressPolicies["default"]; len(got) != len(policies) || got[1].Kind != state.SecureStateRemoteELSAuthorizationDH || got[2].Kind != state.SecureStateRemoteELSAuthorizationPSK {
		t.Fatalf("reloaded policies = %#v", got)
	}
	none.ReleaseSensitive()
	dh.ReleaseSensitive()
	psk.ReleaseSensitive()
}
func TestDaemonNewProductionGraphPublicAndEncryptedDestinations(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	flood := daemonProductionFloodfill(t, now)
	network := newDaemonMemoryNetwork(flood, func() uint64 { return uint64(time.Now().UnixMilli()) })
	newProductionDaemon := func() *Controller {
		cfg := daemonTestConfig(t)
		cfg.StateDir = filepath.Dir(cfg.StatePath)
		cfg.Tunnel.Enabled = true
		cfg.NTCP2.Enabled = false
		cfg.Tunnel.MaintenanceInterval = time.Hour
		d, err := NewController(cfg, ControllerOptions{Transport: network.transport()})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	publicDaemon, encryptedDaemon, transitDaemon := newProductionDaemon(), newProductionDaemon(), newProductionDaemon()
	t.Cleanup(func() {
		_ = publicDaemon.Close()
		_ = encryptedDaemon.Close()
		_ = transitDaemon.Close()
		_ = publicDaemon.Wait()
		_ = encryptedDaemon.Wait()
		_ = transitDaemon.Wait()
	})
	if err := publicDaemon.DestroyDestination(context.Background(), "default"); err != nil {
		t.Fatal(err)
	}
	if err := encryptedDaemon.DestroyDestination(context.Background(), "default"); err != nil {
		t.Fatal(err)
	}
	if err := transitDaemon.DestroyDestination(context.Background(), "default"); err != nil {
		t.Fatal(err)
	}
	if _, err := publicDaemon.CreateDestination(context.Background(), "public", DestinationPolicy{Kind: DestinationPublicLS2}); err != nil {
		t.Fatal(err)
	}
	if _, err := encryptedDaemon.CreateDestination(context.Background(), "encrypted", DestinationPolicy{Kind: DestinationEncryptedNone, Secret: []byte("production-secret")}); err != nil {
		t.Fatal(err)
	}
	publicRuntime := publicDaemon.clientRuntimeSnapshot()[0]
	encryptedRuntime := encryptedDaemon.clientRuntimeSnapshot()[0]
	if publicRuntime.local.SigningKeyType() != foundation.SigningEdDSASHA512Ed25519 || encryptedRuntime.local.SigningKeyType() != foundation.SigningRedDSASHA512Ed25519 {
		t.Fatalf("destination signing types = %d/%d", publicRuntime.local.SigningKeyType(), encryptedRuntime.local.SigningKeyType())
	}
	if publicRuntime.pool == encryptedRuntime.pool || publicRuntime.pool.Owner() != publicRuntime.local.Hash() || encryptedRuntime.pool.Owner() != encryptedRuntime.local.Hash() {
		t.Fatal("destination factories did not create distinct owner-bound pools")
	}
	if err := publicDaemon.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := encryptedDaemon.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := transitDaemon.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = uint64(time.Now().UnixMilli())
	publicInfo, encryptedInfo, transitInfo := publicDaemon.localInfo.Snapshot(), encryptedDaemon.localInfo.Snapshot(), transitDaemon.localInfo.Snapshot()
	for _, admission := range []struct {
		database *netdb.Database
		infos    []foundation.NetworkDatabaseRouterInfo
	}{
		{publicDaemon.database, []foundation.NetworkDatabaseRouterInfo{encryptedInfo, transitInfo}},
		{encryptedDaemon.database, []foundation.NetworkDatabaseRouterInfo{publicInfo, transitInfo}},
		{transitDaemon.database, []foundation.NetworkDatabaseRouterInfo{publicInfo, encryptedInfo}},
	} {
		for _, info := range admission.infos {
			if err := admission.database.AdmitRouterInfo(info, false, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	var publicMaintainErr, encryptedMaintainErr error
	convergenceCtx, stopConvergence := context.WithTimeout(t.Context(), 5*time.Second)
	defer stopConvergence()
	for {
		publicMaintainErr = publicRuntime.maintain(convergenceCtx, uint64(time.Now().UnixMilli()))
		encryptedMaintainErr = encryptedRuntime.maintain(convergenceCtx, uint64(time.Now().UnixMilli()))
		for _, daemon := range []*Controller{publicDaemon, encryptedDaemon, transitDaemon} {
			if err := daemon.router.WaitControl(convergenceCtx); err != nil {
				t.Fatal(err)
			}
		}
		if publicRuntime.pool.Count(tunnel.Inbound, uint64(time.Now().UnixMilli())) > 0 &&
			publicRuntime.pool.Count(tunnel.Outbound, uint64(time.Now().UnixMilli())) > 0 &&
			encryptedRuntime.pool.Count(tunnel.Inbound, uint64(time.Now().UnixMilli())) > 0 &&
			encryptedRuntime.pool.Count(tunnel.Outbound, uint64(time.Now().UnixMilli())) > 0 {
			break
		}
	}
	now = uint64(time.Now().UnixMilli())
	publicEntries, encryptedEntries := publicRuntime.pool.Snapshot(now), encryptedRuntime.pool.Snapshot(now)
	if len(publicEntries) < 2 || len(encryptedEntries) < 2 {
		t.Fatalf("built destination circuit counts = %d/%d; errors=%v/%v", len(publicEntries), len(encryptedEntries), publicMaintainErr, encryptedMaintainErr)
	}
	for _, entry := range publicEntries {
		if entry.Owner != publicRuntime.local.Hash() {
			t.Fatalf("public circuit owner = %x", entry.Owner)
		}
	}
	for _, entry := range encryptedEntries {
		if entry.Owner != encryptedRuntime.local.Hash() {
			t.Fatalf("encrypted circuit owner = %x", entry.Owner)
		}
	}
	publicOutbound, publicOK := publicRuntime.pool.Select(tunnel.Outbound, now)
	encryptedOutbound, encryptedOK := encryptedRuntime.pool.Select(tunnel.Outbound, now)
	if !publicOK || !encryptedOK || publicOutbound.Owner == encryptedOutbound.Owner {
		t.Fatalf("selected circuits public=%#v encrypted=%#v", publicOutbound, encryptedOutbound)
	}
	if profile, ok := publicRuntime.profiles.Snapshot(encryptedDaemon.bundle.Router.Hash); !ok || profile.Successes == 0 {
		t.Fatalf("public build/health profile = %#v, %t", profile, ok)
	}
	if profile, ok := encryptedRuntime.profiles.Snapshot(publicDaemon.bundle.Router.Hash); !ok || profile.Successes == 0 {
		t.Fatalf("encrypted build/health profile = %#v, %t", profile, ok)
	}

	if err := publicDaemon.database.AdmitRouterInfo(flood, false, now); err != nil {
		t.Fatal(err)
	}
	if err := encryptedDaemon.database.AdmitRouterInfo(flood, false, now); err != nil {
		t.Fatal(err)
	}
	if _, err := publicDaemon.publication.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := encryptedDaemon.publication.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	network.mu.RLock()
	stores := append([]foundation.I2NPDatabaseStoreMessage(nil), network.stores...)
	network.mu.RUnlock()
	var publicStores, encryptedStores, tokens int
	for _, store := range stores {
		switch store.Type {
		case foundation.I2NPStoreLeaseSet2:
			publicStores++
		case foundation.I2NPStoreEncryptedLeaseSet:
			encryptedStores++
		}
		if store.ReplyToken != 0 {
			tokens++
		}
	}
	if publicStores == 0 || encryptedStores == 0 || tokens < 2 || publicRuntime.publisher == encryptedRuntime.publisher {
		t.Fatalf("publication objects public=%d encrypted=%d tokens=%d", publicStores, encryptedStores, tokens)
	}
	if policy, ok := encryptedDaemon.bundle.EncryptedLeaseSetPolicies["encrypted"]; !ok || string(policy.Secret) != "production-secret" {
		t.Fatalf("persisted ELS2 policy = %#v, %t", policy, ok)
	}
	encryptedIdentity, err := encryptedRuntime.local.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err = publicDaemon.UpdateDestinationAddressPolicies("public", []state.SecureStateRemoteELSAuthorization{{
		Identity: append([]byte(nil), encryptedIdentity.Bytes()...), Secret: []byte("production-secret"), Kind: state.SecureStateRemoteELSAuthorizationNone,
	}}); err != nil {
		t.Fatal(err)
	}

	publicSession, ok := publicDaemon.destinations.Session(publicRuntime.local.Hash())
	if !ok {
		t.Fatal("public production session missing")
	}
	encryptedSession, ok := encryptedDaemon.destinations.Session(encryptedRuntime.local.Hash())
	if !ok {
		t.Fatal("encrypted production session missing")
	}
	messageRoute := destination.DestinationRoute{Protocol: 17, ToPort: 4444}
	subscription, err := encryptedSession.Subscribe(messageRoute, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	messagePayload := []byte("authenticated-destination-garlic")
	if err = publicSession.SendMessage(context.Background(), dataplane.StreamingTunnelDelivery{
		From: publicRuntime.local.Hash(), To: encryptedRuntime.local.Hash(),
		Protocol: messageRoute.Protocol, FromPort: 3333, ToPort: messageRoute.ToPort, Payload: messagePayload,
	}); err != nil {
		t.Fatal(err)
	}
	messageCtx, cancelMessage := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelMessage()
	receivedMessage, err := subscription.Receive(messageCtx)
	if err != nil {
		t.Fatal(err)
	}
	daemonNewProductionGraphPublicAndEncryptedDestinationsRejected := receivedMessage.Delivery.From != publicRuntime.local.Hash() || receivedMessage.Delivery.To != encryptedRuntime.local.Hash() ||
		receivedMessage.Delivery.Protocol != messageRoute.Protocol || receivedMessage.Delivery.FromPort != 3333 ||
		receivedMessage.Delivery.ToPort != messageRoute.ToPort
	if !daemonNewProductionGraphPublicAndEncryptedDestinationsRejected {
		daemonNewProductionGraphPublicAndEncryptedDestinationsRejected = string(receivedMessage.Delivery.Payload) != string(messagePayload)
	}
	if daemonNewProductionGraphPublicAndEncryptedDestinationsRejected {
		t.Fatalf("authenticated destination message = %#v", receivedMessage.Delivery)
	}
	receivedMessage.Release()
	selfRoute := destination.DestinationRoute{Protocol: 17, ToPort: 5555}
	selfSubscription, err := publicSession.Subscribe(selfRoute, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer selfSubscription.Close()
	selfRatchetBefore := publicRuntime.ratchet.Stats()
	for sequence := range 4 {
		payload := []byte{byte(sequence), 0x53, 0x45, 0x4c, 0x46}
		if err = publicSession.SendMessage(context.Background(), dataplane.StreamingTunnelDelivery{
			To: publicRuntime.local.Hash(), Protocol: selfRoute.Protocol,
			FromPort: 3333, ToPort: selfRoute.ToPort, Payload: payload,
		}); err != nil {
			t.Fatalf("self message %d: %v", sequence, err)
		}
		receiveCtx, cancelReceive := context.WithTimeout(context.Background(), time.Second)
		message, receiveErr := selfSubscription.Receive(receiveCtx)
		cancelReceive()
		if receiveErr != nil {
			t.Fatalf("self message %d receive: %v", sequence, receiveErr)
		}
		daemonNewProductionGraphPublicAndEncryptedDestinationsRejected := message.Delivery.From != publicRuntime.local.Hash() || message.Delivery.To != publicRuntime.local.Hash() ||
			message.Delivery.Protocol != selfRoute.Protocol || message.Delivery.FromPort != 3333 ||
			message.Delivery.ToPort != selfRoute.ToPort
		if !daemonNewProductionGraphPublicAndEncryptedDestinationsRejected {
			daemonNewProductionGraphPublicAndEncryptedDestinationsRejected = string(message.Delivery.Payload) != string(payload)
		}
		if daemonNewProductionGraphPublicAndEncryptedDestinationsRejected {
			t.Fatalf("self message %d = %#v", sequence, message.Delivery)
		}
		message.Release()
	}
	if after := publicRuntime.ratchet.Stats(); after != selfRatchetBefore {
		t.Fatalf("self messages mutated ratchet state: before=%#v after=%#v", selfRatchetBefore, after)
	}
	exercise := func(source, target *dataplane.RouterDestinationSession, port string, request, response []byte) {
		listener, listenErr := target.ListenI2P(context.Background(), ":"+port)
		if listenErr != nil {
			t.Fatal(listenErr)
		}
		defer listener.Close()
		accepted := make(chan net.Conn, 1)
		acceptErr := make(chan error, 1)
		go func() {
			connection, err := listener.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			accepted <- connection
		}()
		dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		outbound, dialErr := source.DialI2P(dialCtx, target.B32()+":"+port)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		defer outbound.Close()
		var inbound net.Conn
		select {
		case inbound = <-accepted:
		case err := <-acceptErr:
			t.Fatal(err)
		case <-dialCtx.Done():
			t.Fatal(dialCtx.Err())
		}
		defer inbound.Close()
		_ = outbound.SetDeadline(time.Now().Add(5 * time.Second))
		_ = inbound.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := outbound.Write(request); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(request))
		if _, err := io.ReadFull(inbound, got); err != nil || string(got) != string(request) {
			t.Fatalf("stream request = %q, %v", got, err)
		}
		if _, err := inbound.Write(response); err != nil {
			t.Fatal(err)
		}
		got = make([]byte, len(response))
		if _, err := io.ReadFull(outbound, got); err != nil || string(got) != string(response) {
			t.Fatalf("stream response = %q, %v", got, err)
		}
		if _, err := outbound.Write(request); err != nil {
			t.Fatal(err)
		}
		got = make([]byte, len(request))
		if _, err := io.ReadFull(inbound, got); err != nil || string(got) != string(request) {
			t.Fatalf("existing-session request = %q, %v", got, err)
		}
		sourceStats, targetStats := source.StreamingStats(), target.StreamingStats()
		if sourceStats.CongestionWindow == 0 || targetStats.CongestionWindow == 0 {
			t.Fatalf("active congestion source=%#v target=%#v", sourceStats, targetStats)
		}
	}
	for _, stream := range []struct {
		port, request, response string
	}{
		{"80", "public-to-encrypted-0", "encrypted-to-public-0"},
		{"81", "public-to-encrypted-1", "encrypted-to-public-1"},
		{"82", "public-to-encrypted-2", "encrypted-to-public-2"},
		{"83", "public-to-encrypted-3", "encrypted-to-public-3"},
	} {
		exercise(publicSession, encryptedSession, stream.port, []byte(stream.request), []byte(stream.response))
	}
	exercise(encryptedSession, publicSession, "84", []byte("encrypted-to-public-new"), []byte("public-to-encrypted-reply"))
	network.mu.RLock()
	lookups := network.lookups
	network.mu.RUnlock()
	if lookups < 2 {
		t.Fatalf("RequestManager lookups = %d", lookups)
	}
	publicRatchet, encryptedRatchet := publicRuntime.ratchet.Stats(), encryptedRuntime.ratchet.Stats()
	daemonNewProductionGraphPublicAndEncryptedDestinationsRejected = publicRatchet.Sessions == 0 || encryptedRatchet.Sessions == 0 || publicRatchet.ExistingSessions == 0 || encryptedRatchet.ExistingSessions == 0 ||
		publicRatchet.InboundTags == 0
	if !daemonNewProductionGraphPublicAndEncryptedDestinationsRejected {
		daemonNewProductionGraphPublicAndEncryptedDestinationsRejected = encryptedRatchet.InboundTags == 0
	}
	if daemonNewProductionGraphPublicAndEncryptedDestinationsRejected {
		t.Fatalf("ratchet indexes public=%#v encrypted=%#v", publicRatchet, encryptedRatchet)
	}
	publicBandwidth, _ := publicDaemon.DestinationBandwidthSnapshot("public")
	encryptedBandwidth, _ := encryptedDaemon.DestinationBandwidthSnapshot("encrypted")
	if publicBandwidth.AcceptedBytes == 0 || encryptedBandwidth.AcceptedBytes == 0 || publicBandwidth.BurstBytes == 0 || encryptedBandwidth.BurstBytes == 0 {
		t.Fatalf("bandwidth public=%#v encrypted=%#v", publicBandwidth, encryptedBandwidth)
	}
	if err := encryptedDaemon.DestroyDestination(context.Background(), "encrypted"); err != nil {
		t.Fatal(err)
	}
	if encryptedRuntime.active() || len(encryptedRuntime.pool.Snapshot(uint64(time.Now().UnixMilli()))) != 0 {
		t.Fatal("destroyed encrypted runtime remained active")
	}
	if !publicRuntime.active() {
		t.Fatal("destroying encrypted destination released public runtime")
	}
	if selected, ok := publicRuntime.pool.Select(tunnel.Outbound, uint64(time.Now().UnixMilli())); !ok || selected.Owner != publicRuntime.local.Hash() {
		t.Fatalf("public circuit after sibling Destroy = %#v, %t", selected, ok)
	}
}

func TestDaemonProductionGraphEncryptedDHAndPSKStreaming(t *testing.T) {
	for _, authorization := range []string{"dh", "psk"} {
		t.Run(authorization, func(t *testing.T) { testDaemonProductionGraphEncryptedAuthorization(t, authorization) })
	}
}
func testDaemonProductionGraphEncryptedAuthorization(t *testing.T, authorization string) {
	now := uint64(time.Now().UnixMilli())
	flood := daemonProductionFloodfill(t, now)
	network := newDaemonMemoryNetwork(flood, func() uint64 { return uint64(time.Now().UnixMilli()) })
	newDaemon := func() *Controller {
		cfg := daemonTestConfig(t)
		cfg.StateDir = filepath.Dir(cfg.StatePath)
		cfg.Tunnel.Enabled = true
		cfg.NTCP2.Enabled = false
		cfg.Tunnel.MaintenanceInterval = time.Hour
		d, newErr := NewController(cfg, ControllerOptions{Transport: network.transport()})
		if newErr != nil {
			t.Fatal(newErr)
		}
		return d
	}
	sourceDaemon, targetDaemon, transitDaemon := newDaemon(), newDaemon(), newDaemon()
	t.Cleanup(func() {
		for _, d := range []*Controller{sourceDaemon, targetDaemon, transitDaemon} {
			_ = d.Close()
			_ = d.Wait()
		}
	})
	for _, d := range []*Controller{sourceDaemon, targetDaemon, transitDaemon} {
		if destroyErr := d.DestroyDestination(context.Background(), "default"); destroyErr != nil {
			t.Fatal(destroyErr)
		}
	}
	if _, err := sourceDaemon.CreateDestination(context.Background(), "source", DestinationPolicy{Kind: DestinationPublicLS2}); err != nil {
		t.Fatal(err)
	}

	secret := []byte("production-" + authorization)
	targetPolicy := DestinationPolicy{Secret: secret}
	remotePolicy := state.SecureStateRemoteELSAuthorization{Secret: append([]byte(nil), secret...)}
	switch authorization {
	case "dh":
		private, generateErr := ecdh.X25519().GenerateKey(cryptorand.Reader)
		if generateErr != nil {
			t.Fatal(generateErr)
		}
		var privateBytes, publicBytes [32]byte
		copy(privateBytes[:], private.Bytes())
		copy(publicBytes[:], private.PublicKey().Bytes())
		targetPolicy.Kind = DestinationEncryptedDH
		targetPolicy.DHClients = [][32]byte{publicBytes}
		remotePolicy.Kind = state.SecureStateRemoteELSAuthorizationDH
		remotePolicy.DHPrivate, remotePolicy.DHPublic = privateBytes, publicBytes
	case "psk":
		var psk [32]byte
		for index := range psk {
			psk[index] = byte(index + 1)
		}
		targetPolicy.Kind = DestinationEncryptedPSK
		targetPolicy.PSKClients = [][32]byte{psk}
		remotePolicy.Kind, remotePolicy.PSK = state.SecureStateRemoteELSAuthorizationPSK, psk
	}
	if _, err := targetDaemon.CreateDestination(context.Background(), "target", targetPolicy); err != nil {
		t.Fatal(err)
	}
	for _, d := range []*Controller{sourceDaemon, targetDaemon, transitDaemon} {
		if err := d.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	sourceRuntime, targetRuntime := sourceDaemon.clientRuntimeSnapshot()[0], targetDaemon.clientRuntimeSnapshot()[0]
	now = uint64(time.Now().UnixMilli())
	sourceInfo, targetInfo, transitInfo := sourceDaemon.localInfo.Snapshot(), targetDaemon.localInfo.Snapshot(), transitDaemon.localInfo.Snapshot()
	for _, admission := range []struct {
		database *netdb.Database
		infos    []foundation.NetworkDatabaseRouterInfo
	}{
		{sourceDaemon.database, []foundation.NetworkDatabaseRouterInfo{targetInfo, transitInfo}},
		{targetDaemon.database, []foundation.NetworkDatabaseRouterInfo{sourceInfo, transitInfo}},
		{transitDaemon.database, []foundation.NetworkDatabaseRouterInfo{sourceInfo, targetInfo}},
	} {
		for _, info := range admission.infos {
			if err := admission.database.AdmitRouterInfo(info, false, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	convergenceCtx, stopConvergence := context.WithTimeout(t.Context(), 5*time.Second)
	defer stopConvergence()
	for {
		_ = sourceRuntime.maintain(convergenceCtx, uint64(time.Now().UnixMilli()))
		_ = targetRuntime.maintain(convergenceCtx, uint64(time.Now().UnixMilli()))
		for _, daemon := range []*Controller{sourceDaemon, targetDaemon, transitDaemon} {
			if err := daemon.router.WaitControl(convergenceCtx); err != nil {
				t.Fatal(err)
			}
		}
		current := uint64(time.Now().UnixMilli())
		if sourceRuntime.pool.Count(tunnel.Inbound, current) > 0 && sourceRuntime.pool.Count(tunnel.Outbound, current) > 0 &&
			targetRuntime.pool.Count(tunnel.Inbound, current) > 0 && targetRuntime.pool.Count(tunnel.Outbound, current) > 0 {
			break
		}
	}
	now = uint64(time.Now().UnixMilli())
	if sourceRuntime.pool.Count(tunnel.Inbound, now) == 0 || sourceRuntime.pool.Count(tunnel.Outbound, now) == 0 ||
		targetRuntime.pool.Count(tunnel.Inbound, now) == 0 || targetRuntime.pool.Count(tunnel.Outbound, now) == 0 {
		t.Fatalf("owner pools were not built: source=%#v target=%#v", sourceRuntime.pool.Snapshot(now), targetRuntime.pool.Snapshot(now))
	}
	if err := sourceDaemon.database.AdmitRouterInfo(flood, false, now); err != nil {
		t.Fatal(err)
	}
	if err := targetDaemon.database.AdmitRouterInfo(flood, false, now); err != nil {
		t.Fatal(err)
	}
	if _, err := sourceDaemon.publication.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := targetDaemon.publication.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	targetIdentity, err := targetRuntime.local.Identity()
	if err != nil {
		t.Fatal(err)
	}
	remotePolicy.Identity = append([]byte(nil), targetIdentity.Bytes()...)
	if err = sourceDaemon.UpdateDestinationAddressPolicies("source", []state.SecureStateRemoteELSAuthorization{remotePolicy}); err != nil {
		t.Fatal(err)
	}
	persisted := sourceDaemon.bundle.DestinationAddressPolicies["source"]
	if len(persisted) != 1 || persisted[0].Kind != remotePolicy.Kind {
		t.Fatal("authorized remote ELS policy was not persisted")
	}

	sourceSession, sourceOK := sourceDaemon.destinations.Session(sourceRuntime.local.Hash())
	targetSession, targetOK := targetDaemon.destinations.Session(targetRuntime.local.Hash())
	if !sourceOK || !targetOK {
		t.Fatal("production destination session missing")
	}
	messageRoute := destination.DestinationRoute{Protocol: 18, ToPort: 9090}
	subscription, subscribeErr := targetSession.Subscribe(messageRoute, 1)
	if subscribeErr != nil {
		t.Fatal(subscribeErr)
	}
	defer subscription.Close()
	messagePayload := []byte("authorized-message-" + authorization)
	if err = sourceSession.SendMessage(context.Background(), dataplane.StreamingTunnelDelivery{
		From: sourceRuntime.local.Hash(), To: targetRuntime.local.Hash(),
		Protocol: messageRoute.Protocol, FromPort: 9091, ToPort: messageRoute.ToPort, Payload: messagePayload,
	}); err != nil {
		t.Fatal(err)
	}
	messageCtx, cancelMessage := context.WithTimeout(context.Background(), 5*time.Second)
	received, receiveErr := subscription.Receive(messageCtx)
	cancelMessage()
	if receiveErr != nil {
		t.Fatal(receiveErr)
	}
	daemonProductionGraphEncryptedDHAndPSKStreamingRejected := received.Delivery.From != (foundation.Hash{}) || received.Delivery.To != targetRuntime.local.Hash() ||
		received.Delivery.Protocol != messageRoute.Protocol || received.Delivery.FromPort != 9091 ||
		received.Delivery.ToPort != messageRoute.ToPort
	if !daemonProductionGraphEncryptedDHAndPSKStreamingRejected {
		daemonProductionGraphEncryptedDHAndPSKStreamingRejected = string(received.Delivery.Payload) != string(messagePayload)
	}
	if daemonProductionGraphEncryptedDHAndPSKStreamingRejected {
		t.Fatalf("authorized destination message = %#v", received.Delivery)
	}
	received.Release()
	listener, err := targetSession.ListenI2P(context.Background(), ":8080")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- connection
	}()
	streamCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	outbound, err := sourceSession.DialI2P(streamCtx, targetSession.B32()+":8080")
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.Close()
	var inbound net.Conn
	select {
	case inbound = <-accepted:
	case err = <-acceptErrors:
		t.Fatal(err)
	case <-streamCtx.Done():
		t.Fatal(streamCtx.Err())
	}
	defer inbound.Close()
	_ = outbound.SetDeadline(time.Now().Add(5 * time.Second))
	_ = inbound.SetDeadline(time.Now().Add(5 * time.Second))
	for _, payload := range [][]byte{[]byte("authorized-" + authorization), []byte("existing-" + authorization)} {
		if _, err = outbound.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err = io.ReadFull(inbound, got); err != nil || string(got) != string(payload) {
			t.Fatalf("authorized stream payload = %q, %v", got, err)
		}
	}
	reply := []byte("reply-" + authorization)
	if _, err = inbound.Write(reply); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(reply))
	if _, err = io.ReadFull(outbound, got); err != nil || string(got) != string(reply) {
		t.Fatalf("authorized stream reply = %q, %v", got, err)
	}
	if sourceRuntime.ratchet.Stats().ExistingSessions == 0 || targetRuntime.ratchet.Stats().ExistingSessions == 0 {
		t.Fatalf("authorized ratchet did not transition: source=%#v target=%#v", sourceRuntime.ratchet.Stats(), targetRuntime.ratchet.Stats())
	}
	if sourceSession.StreamingStats().CongestionWindow == 0 || targetSession.StreamingStats().CongestionWindow == 0 {
		t.Fatalf("authorized streaming congestion missing: source=%#v target=%#v", sourceSession.StreamingStats(), targetSession.StreamingStats())
	}
	network.mu.RLock()
	lookups := network.lookups
	encryptedStores := 0
	for _, store := range network.stores {
		if store.Type == foundation.I2NPStoreEncryptedLeaseSet {
			encryptedStores++
		}
	}
	network.mu.RUnlock()
	if lookups < 2 || encryptedStores == 0 {
		t.Fatalf("authorized graph lookups=%d encrypted_stores=%d", lookups, encryptedStores)
	}
}

func TestCreateDestinationPersistsPublicAndEncryptedPolicies(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Tunnel.Enabled = true
	d, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	var dhClient, pskClient [32]byte
	dhClient[0], pskClient[0] = 1, 2
	cases := []struct {
		name   string
		policy DestinationPolicy
		kind   foundation.SigningKeyType
	}{
		{name: "public", policy: DestinationPolicy{Kind: DestinationPublicLS2}, kind: foundation.SigningEdDSASHA512Ed25519},
		{name: "encrypted-none", policy: DestinationPolicy{Kind: DestinationEncryptedNone, Secret: []byte("none")}, kind: foundation.SigningRedDSASHA512Ed25519},
		{name: "encrypted-dh", policy: DestinationPolicy{Kind: DestinationEncryptedDH, Secret: []byte("dh"), DHClients: [][32]byte{dhClient}}, kind: foundation.SigningRedDSASHA512Ed25519},
		{name: "encrypted-psk", policy: DestinationPolicy{Kind: DestinationEncryptedPSK, Secret: []byte("psk"), PSKClients: [][32]byte{pskClient}}, kind: foundation.SigningRedDSASHA512Ed25519},
	}
	for _, test := range cases {
		retained := make([][]byte, 0, len(d.bundle.DestinationPrivate)+len(d.bundle.EncryptedLeaseSetPolicies))
		for _, private := range d.bundle.DestinationPrivate {
			retained = append(retained, private)
		}
		for _, policy := range d.bundle.EncryptedLeaseSetPolicies {
			retained = append(retained, policy.Secret)
		}
		created, createErr := d.CreateDestination(context.Background(), test.name, test.policy)
		if createErr != nil {
			t.Fatalf("CreateDestination(%q): %v", test.name, createErr)
		}
		if created.Name != test.name || created.Address == "" {
			t.Fatalf("created destination = %#v", created)
		}
		var found *destinationRuntime
		for _, runtime := range d.clientRuntimeSnapshot() {
			if runtime.name == test.name {
				found = runtime
				break
			}
		}
		if found == nil || found.local.SigningKeyType() != test.kind || found.publisher == nil || found.pool.Owner() != found.local.Hash() {
			t.Fatalf("runtime %q = %#v", test.name, found)
		}
		for _, sensitive := range retained {
			for _, value := range sensitive {
				if value != 0 {
					t.Fatalf("CreateDestination(%q) retained a superseded durable key or policy", test.name)
				}
			}
		}
	}
	if _, ok := d.bundle.EncryptedLeaseSetPolicies["public"]; ok {
		t.Fatal("public LS2 unexpectedly persisted an encrypted policy")
	}
	if policy, ok := d.bundle.EncryptedLeaseSetPolicies["encrypted-none"]; !ok || len(policy.DHClients)+len(policy.PSKClients) != 0 || string(policy.Secret) != "none" {
		t.Fatalf("no-auth ELS2 policy = %#v, %t", policy, ok)
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(reopened.clientRuntimeSnapshot()) != 5 {
		t.Fatalf("reloaded runtime count = %d", len(reopened.clientRuntimeSnapshot()))
	}
	for _, test := range cases {
		private := reopened.bundle.DestinationPrivate[test.name]
		imported, importErr := foundation.ImportLocalDestination(private)
		if importErr != nil {
			t.Fatal(importErr)
		}
		if imported.SigningKeyType() != test.kind {
			t.Fatalf("reloaded %q signing type = %d", test.name, imported.SigningKeyType())
		}
		imported.ReleaseSensitive()
	}
	if policy := reopened.bundle.EncryptedLeaseSetPolicies["encrypted-dh"]; len(policy.DHClients) != 1 || len(policy.PSKClients) != 0 || policy.DHClients[0] != dhClient {
		t.Fatalf("reloaded DH policy = %#v", policy)
	}
	if policy := reopened.bundle.EncryptedLeaseSetPolicies["encrypted-psk"]; len(policy.PSKClients) != 1 || len(policy.DHClients) != 0 || policy.PSKClients[0] != pskClient {
		t.Fatalf("reloaded PSK policy = %#v", policy)
	}
}

func TestCreateDestinationValidatesBeforeMutationAndDestroyIsIsolated(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Tunnel.Enabled = true
	d, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	before := len(d.bundle.DestinationPrivate)
	if _, err = d.CreateDestination(context.Background(), "invalid", DestinationPolicy{Kind: DestinationEncryptedDH}); !errors.Is(err, ErrDestinationPolicy) {
		t.Fatalf("invalid policy error = %v", err)
	}
	if len(d.bundle.DestinationPrivate) != before {
		t.Fatal("invalid policy mutated durable destinations")
	}
	first, err := d.CreateDestination(context.Background(), "first", DestinationPolicy{Kind: DestinationEncryptedNone, Secret: []byte("destroy-secret")})
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.CreateDestination(context.Background(), "second", DestinationPolicy{Kind: DestinationEncryptedNone})
	if err != nil {
		t.Fatal(err)
	}
	var secondRuntime *destinationRuntime
	for _, runtime := range d.clientRuntimeSnapshot() {
		if runtime.name == second.Name {
			secondRuntime = runtime
		}
	}
	if secondRuntime == nil {
		t.Fatal("second runtime missing")
	}
	removedPrivate := d.bundle.DestinationPrivate[first.Name]
	removedSecret := d.bundle.EncryptedLeaseSetPolicies[first.Name].Secret
	if err = d.DestroyDestination(context.Background(), first.Name); err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range [][]byte{removedPrivate, removedSecret} {
		for _, value := range sensitive {
			if value != 0 {
				t.Fatal("DestroyDestination retained removed private or ELS policy material")
			}
		}
	}
	if _, exists := d.bundle.DestinationPrivate[first.Name]; exists {
		t.Fatal("destroyed destination remained durable")
	}
	if _, exists := d.bundle.DestinationPrivate[second.Name]; !exists || !secondRuntime.active() {
		t.Fatal("destroying first destination affected second")
	}
	if _, ok := d.destinations.Session(secondRuntime.local.Hash()); !ok {
		t.Fatal("destroying first removed second session")
	}
}

func TestDestroyRemovesExactReleasedDestinationRuntime(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Tunnel.Enabled = true
	first, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		local, generateErr := foundation.GenerateLocalDestination()
		if generateErr != nil {
			t.Fatal(generateErr)
		}
		encoded, encodeErr := destinationPrivate(local)
		local.ReleaseSensitive()
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		first.bundle.DestinationPrivate[name] = encoded
	}
	if err = first.store.Save(first.bundle); err != nil {
		t.Fatal(err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	d, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	runtimes := d.clientRuntimeSnapshot()
	if len(runtimes) != 3 {
		t.Fatalf("initial runtimes = %d", len(runtimes))
	}
	var removed, retained, defaultRuntime *destinationRuntime
	for _, runtime := range runtimes {
		switch runtime.name {
		case "a":
			removed = runtime
		case "b":
			retained = runtime
		case "default":
			defaultRuntime = runtime
		}
	}
	if removed == nil || retained == nil || defaultRuntime == nil {
		t.Fatalf("runtimes = %#v", runtimes)
	}
	now := uint64(time.Now().UnixMilli())
	if err = d.database.AdmitRouterInfo(daemonProductionFloodfill(t, now), false, now); err != nil {
		t.Fatal(err)
	}
	blocking := &blockingRequestSender{entered: make(chan struct{})}
	requests, requestErr := netdb.NewRequestManager(
		d.database,
		blocking,
		daemonReplyRoute{local: d.bundle.Router.Hash, now: func() uint64 { return uint64(time.Now().UnixMilli()) }},
		netdb.RequestManagerConfig{Capacity: 2, TimeoutMillis: 60_000, Now: func() uint64 { return uint64(time.Now().UnixMilli()) }},
	)
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	if err = removed.requests.Close(); err != nil {
		t.Fatal(err)
	}
	removed.requests = requests
	type lookupReturn struct {
		waiter <-chan netdb.LookupResult
		err    error
	}
	lookupReturned := make(chan lookupReturn, 1)
	go func() {
		waiter, lookupErr := requests.LookupRouterInfo(context.Background(), foundation.Hash{99})
		lookupReturned <- lookupReturn{waiter: waiter, err: lookupErr}
	}()
	select {
	case <-blocking.entered:
	case <-time.After(time.Second):
		t.Fatal("destination RequestManager did not start its lookup send")
	}

	if err = d.destinations.Destroy(removed.local.Hash()); err != nil {
		t.Fatal(err)
	}
	lookup := <-lookupReturned
	if lookup.err != nil {
		t.Fatal(lookup.err)
	}
	result, open := <-lookup.waiter
	if !open || !errors.Is(result.Err, netdb.ErrRequestManagerClosed) {
		t.Fatalf("destroy lookup completion = %#v, open=%t", result, open)
	}
	runtimes = d.clientRuntimeSnapshot()
	if len(runtimes) != 2 || !removed.released.Load() || retained.released.Load() || defaultRuntime.released.Load() {
		t.Fatalf("destroyed runtime state = %#v", runtimes)
	}
	for _, runtime := range runtimes {
		if runtime != retained && runtime != defaultRuntime {
			t.Fatalf("unexpected retained runtime = %#v", runtime)
		}
	}
	if removed.requests.Pending() != 0 {
		t.Fatalf("destroy left %d request waiters", removed.requests.Pending())
	}
	if _, lookupErr := removed.requests.LookupRouterInfo(context.Background(), foundation.Hash{99}); !errors.Is(lookupErr, netdb.ErrRequestManagerClosed) {
		t.Fatalf("destroyed RequestManager accepted work: %v", lookupErr)
	}
	if removed.build.Pending() != 0 {
		t.Fatalf("destroy left %d pending builds", removed.build.Pending())
	}
	if expired, healthErr := removed.health.Expire(context.Background()); expired != 0 || !errors.Is(healthErr, tunnel.ErrHealthClosed) {
		t.Fatalf("destroyed Health accepted work: %d, %v", expired, healthErr)
	}
	if maintained, maintainErr := removed.maintainer.Maintain(context.Background()); maintained != 0 || !errors.Is(maintainErr, tunnel.ErrPairedMaintenanceClosed) {
		t.Fatalf("destroyed maintainer accepted work: %d, %v", maintained, maintainErr)
	}
	if senderErr := removed.sender.UpdateRemoteELS(nil); !errors.Is(senderErr, dataplane.RouterErrDataPlaneConfig) {
		t.Fatalf("destroyed sender accepted policy: %v", senderErr)
	}
}

func TestReseedOutcomesAreObservableWithoutMakingOptionalFailureFatal(t *testing.T) {
	newDaemon := func(t *testing.T, required bool) *Controller {
		t.Helper()
		cfg := daemonTestConfig(t)
		cfg.Reseed = state.ConfigurationReseed{
			Enabled: true, Required: required,
			Endpoints: []string{"http://reseed.example/i2p"},
		}
		d, err := NewController(cfg, ControllerOptions{SocketRuntime: loopbackSockets{}})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	t.Run("optional", func(t *testing.T) {
		d := newDaemon(t, false)
		parent, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := d.Start(parent); err != nil {
			t.Fatal(err)
		}
		deadline := time.After(time.Second)
		for d.registry.Snapshot().Reseed.Failures != 1 {
			select {
			case <-deadline:
				t.Fatalf("reseed metrics = %#v", d.registry.Snapshot().Reseed)
			case <-time.After(time.Millisecond):
			}
		}
		if !d.router.Running() || d.Status().Error != nil {
			t.Fatalf("optional reseed failure changed daemon status: %#v", d.Status())
		}
		if got := d.registry.Snapshot().Reseed; got.Attempts != 1 || got.Successes != 0 {
			t.Fatalf("reseed metrics = %#v", got)
		}
		cancel()
		if err := d.Wait(); err != nil {
			t.Fatalf("Wait after cancellation = %v, want nil", err)
		}
		if err := d.Close(); err != nil {
			t.Fatalf("Close after cancellation = %v, want nil", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		d := newDaemon(t, false)
		defer d.Close()
		d.recordReseedOutcome(nil)
		if got := d.registry.Snapshot().Reseed; got.Attempts != 1 || got.Successes != 1 || got.Failures != 0 {
			t.Fatalf("reseed metrics = %#v", got)
		}
	})

	t.Run("required", func(t *testing.T) {
		d := newDaemon(t, true)
		if err := d.Start(context.Background()); err == nil {
			t.Fatal("Start succeeded after required reseed failure")
		}
		if got := d.registry.Snapshot().Reseed; got.Attempts != 1 || got.Failures != 1 || got.Successes != 0 {
			t.Fatalf("reseed metrics = %#v", got)
		}
		if err := d.Wait(); err == nil {
			t.Fatal("Wait = nil after required reseed failure")
		}
	})
}

func TestMaintenancePreflightErrorsDoNotDistortTunnelBuildRate(t *testing.T) {
	registry := observability.NewRegistry()
	daemon := &Controller{
		registry: registry,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	daemon.recordMaintenanceError(tunnel.ErrNoEligiblePeers)
	daemon.recordMaintenanceError(router.ErrTransportUnavailable)
	snapshot := registry.Snapshot().Tunnel
	if snapshot.Builds != 0 || snapshot.BuildFailures != 0 {
		t.Fatalf("preflight build metrics = builds %d, failures %d", snapshot.Builds, snapshot.BuildFailures)
	}
}

func TestRemoteELSContextFailureAndReleaseCleanup(t *testing.T) {
	destination, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	identity, err := destination.Identity()
	if err != nil {
		t.Fatal(err)
	}
	invalid := []state.SecureStateRemoteELSAuthorization{
		{Identity: append([]byte(nil), identity.Bytes()...), Secret: []byte("first"), Kind: state.SecureStateRemoteELSAuthorizationNone},
		{Identity: append([]byte(nil), identity.Bytes()...), Secret: []byte("second"), Kind: state.SecureStateRemoteELSAuthorizationKind(99)},
	}
	if contexts, err := remoteELSContexts(invalid); !errors.Is(err, dataplane.RouterErrDataPlaneConfig) || contexts != nil {
		t.Fatalf("remoteELSContexts partial failure = %#v, %v", contexts, err)
	}
	secret := []byte("retained")
	contexts := map[foundation.Hash]router.RemoteELSContext{
		identity.Hash(): {Identity: identity, Secret: secret, Authorization: netdb.ELSClientAuthorization{UsePSK: true, PSK: [32]byte{1}}},
	}
	releaseRemoteELSContexts(contexts)
	if len(contexts) != 0 {
		t.Fatal("remote ELS context cleanup retained map entries")
	}
	for _, value := range secret {
		if value != 0 {
			t.Fatal("remote ELS context cleanup retained secret bytes")
		}
	}
}
