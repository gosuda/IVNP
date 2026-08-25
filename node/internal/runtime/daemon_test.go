package noderuntime

import (
	"gosuda.org/ivnp/state"

	"gosuda.org/ivnp/client"

	"gosuda.org/ivnp/networking"

	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"

	"gosuda.org/ivnp/foundation"

	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type recordingSockets struct{ calls int }

func (s *recordingSockets) ListenStream(context.Context, networking.RouterEndpoint) (net.Listener, error) {
	s.calls++
	return nil, errors.New("unexpected socket")
}
func (s *recordingSockets) DialStream(context.Context, networking.RouterEndpoint) (net.Conn, error) {
	s.calls++
	return nil, errors.New("unexpected socket")
}
func (s *recordingSockets) ListenUDP(context.Context, networking.RouterEndpoint) (*net.UDPConn, error) {
	s.calls++
	return nil, errors.New("unexpected socket")
}

type blockingRequestSender struct {
	entered chan struct{}
	once    sync.Once
}

func (s *blockingRequestSender) Send(ctx context.Context, _ networking.NetworkDatabaseRouterRef, _ networking.I2NPMessage) error {
	s.once.Do(func() { close(s.entered) })
	<-ctx.Done()
	return ctx.Err()
}

type requestDirectCapture struct {
	calls  int
	target foundation.Hash
}

func (s *requestDirectCapture) Send(_ context.Context, target foundation.Hash, _ networking.I2NPMessage) error {
	s.calls++
	s.target = target
	return nil
}

type requestTunnelCapture struct {
	calls int
	id    uint32
	block networking.TunnelBlock
	err   error
}

func (s *requestTunnelCapture) SendBlock(_ context.Context, id uint32, block networking.TunnelBlock) error {
	s.calls++
	s.id = id
	s.block = block
	s.block.Data = append([]byte(nil), block.Data...)
	return s.err
}

type requestPairCapture struct{ pair networking.TunnelCircuitPair }

func (s requestPairCapture) Pair(uint64) (networking.TunnelCircuitPair, bool) { return s.pair, true }

type requestReplyRouteCapture struct {
	gateway foundation.Hash
	tunnel  uint32
}

func (r requestReplyRouteCapture) DatabaseLookupReplyRoute() (foundation.Hash, uint32, bool) {
	return r.gateway, r.tunnel, true
}

type loopbackSockets struct{}

func (loopbackSockets) ListenStream(context.Context, networking.RouterEndpoint) (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}
func (loopbackSockets) DialStream(ctx context.Context, endpoint networking.RouterEndpoint) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, endpoint.Network, endpoint.Address)
}
func (loopbackSockets) ListenUDP(context.Context, networking.RouterEndpoint) (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

type defaultTransportSockets struct {
	streams int
	packets int
}

func (s *defaultTransportSockets) ListenStream(context.Context, networking.RouterEndpoint) (net.Listener, error) {
	s.streams++
	return net.Listen("tcp", "127.0.0.1:0")
}
func (s *defaultTransportSockets) DialStream(ctx context.Context, endpoint networking.RouterEndpoint) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, endpoint.Network, endpoint.Address)
}
func (s *defaultTransportSockets) ListenUDP(context.Context, networking.RouterEndpoint) (*net.UDPConn, error) {
	s.packets++
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

type daemonMemoryNetwork struct {
	mu        sync.RWMutex
	endpoints map[foundation.Hash]*daemonMemoryTransport
	flood     foundation.Hash
	floodDB   *networking.NetworkDatabase
	now       func() uint64
	stores    []networking.I2NPDatabaseStoreMessage
	lookups   int
	nextID    uint32
}

type daemonMemoryTransport struct {
	network  *daemonMemoryNetwork
	local    foundation.Hash
	bindings networking.RouterTransportBindings
	done     chan struct{}
	once     sync.Once
	running  bool
}

func newDaemonMemoryNetwork(flood networking.NetworkDatabaseRouterInfo, now func() uint64) *daemonMemoryNetwork {
	return &daemonMemoryNetwork{
		endpoints: make(map[foundation.Hash]*daemonMemoryTransport), flood: flood.Hash(),
		floodDB: networking.NetworkDatabaseNewDatabase(flood.Hash(), networking.NetworkDatabaseDefaultBucketCapacity), now: now,
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

func (t *daemonMemoryTransport) Start(_ context.Context, bindings networking.RouterTransportBindings) error {
	t.local, t.bindings, t.running = bindings.LocalInfo.Hash(), bindings, true
	t.network.mu.Lock()
	t.network.endpoints[t.local] = t
	t.network.mu.Unlock()
	return nil
}

func (t *daemonMemoryTransport) Send(ctx context.Context, target foundation.Hash, message networking.I2NPMessage) error {
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

func (t *daemonMemoryTransport) Status() networking.RouterTransportStatus {
	return networking.RouterTransportStatus{Running: t.running}
}

func (n *daemonMemoryNetwork) route(from, target foundation.Hash, message networking.I2NPMessage) error {
	if target == n.flood {
		return n.handleFlood(from, message)
	}
	if message.Header.Type == networking.I2NPShortTunnelBuild {
		if _, err := networking.I2NPParseBuildRecords(networking.I2NPShortTunnelBuild, message.Payload); err != nil {
			return err
		}
	}
	n.mu.RLock()
	endpoint := n.endpoints[target]
	n.mu.RUnlock()
	if endpoint == nil {
		return networking.RouterErrTransportUnavailable
	}
	return endpoint.bindings.HandleI2NPFrom(from, message, n.now(), false)
}

func (n *daemonMemoryNetwork) handleFlood(from foundation.Hash, message networking.I2NPMessage) error {
	switch message.Header.Type {
	case networking.I2NPDatabaseStore:
		store, err := networking.I2NPParseDatabaseStore(message.Payload)
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
			status := networking.I2NPMessage{Header: networking.I2NPHeader{Type: networking.I2NPDeliveryStatus, ID: n.messageID(), Expiration: n.now() + 60_000}, Payload: payload[:]}
			return n.reply(n.flood, store.ReplyGateway, store.ReplyTunnelID, status)
		}
		return nil
	case networking.I2NPDatabaseLookup:
		lookup, err := networking.I2NPParseDatabaseLookup(message.Payload)
		if err != nil {
			return err
		}
		n.mu.Lock()
		n.lookups++
		n.mu.Unlock()
		typeID, data, found := n.floodDB.StoredLeaseSet(lookup.Key)
		if !found {
			return networking.NetworkDatabaseErrNoFloodfill
		}
		payload, err := networking.NetworkDatabaseMarshalDatabaseStore(lookup.Key, typeID, data, 0, foundation.Hash{}, 0)
		if err != nil {
			return err
		}
		reply := networking.I2NPMessage{Header: networking.I2NPHeader{Type: networking.I2NPDatabaseStore, ID: n.messageID(), Expiration: n.now() + 60_000}, Payload: payload}
		return n.reply(n.flood, lookup.From, lookup.ReplyTunnelID, reply)
	default:
		return n.route(from, from, message)
	}
}

func (n *daemonMemoryNetwork) reply(from, gateway foundation.Hash, tunnelID uint32, message networking.I2NPMessage) error {
	if tunnelID == 0 {
		return n.route(from, gateway, message)
	}
	frame := make([]byte, message.EncodedLen())
	if _, err := message.MarshalTo(frame); err != nil {
		return err
	}
	payload := make([]byte, networking.I2NPTunnelGatewayHeaderLen+len(frame))
	binary.BigEndian.PutUint32(payload[:4], tunnelID)
	binary.BigEndian.PutUint16(payload[4:6], uint16(len(frame)))
	copy(payload[6:], frame)
	gatewayMessage := networking.I2NPMessage{Header: networking.I2NPHeader{Type: networking.I2NPTunnelGateway, ID: n.messageID(), Expiration: message.Header.Expiration}, Payload: payload}
	return n.route(from, gateway, gatewayMessage)
}

func daemonProductionFloodfill(t *testing.T, now uint64) networking.NetworkDatabaseRouterInfo {
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
	info, err := networking.NetworkDatabaseParseRouterInfo(append(unsigned, ed25519.Sign(private, unsigned)...))
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
	d, err := New(cfg, Options{SocketRuntime: sockets, Logger: discardNATLogger()})
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

func daemonTestConfig(t *testing.T) state.ConfigurationOperating {
	t.Helper()
	base := t.TempDir()
	return state.ConfigurationOperating{
		StatePath: filepath.Join(base, "router.state"),
		KeyPath:   filepath.Join(base, "router.keys"),
		Network:   state.ConfigurationNetwork{ID: 2, IPv4: true},
		Router:    state.ConfigurationRouter{Version: "0.0.0"},
		State:     state.ConfigurationState{MaxBytes: 1 << 20, MaxDestinations: 16, MaxNameBytes: 64},
		NetDB:     state.ConfigurationNetDB{BucketCapacity: 4},
		Tunnel: state.ConfigurationTunnel{
			Hops: 1, InboundTarget: 1, OutboundTarget: 1, PoolCapacity: 4, BuildPendingCapacity: 4,
			Lifetime: 10 * time.Minute, RenewBefore: 10 * time.Second, MaintenanceInterval: time.Minute,
		},
		NTCP2: state.ConfigurationTransport{Enabled: true, Bind: state.ConfigurationEndpoint{Host: "127.0.0.1", Port: 12345}, MaxSessions: 4},
	}
}

func TestNewDoesNotOpenSocketsAndReloadsState(t *testing.T) {
	cfg := daemonTestConfig(t)
	sockets := new(recordingSockets)
	first, err := New(cfg, Options{SocketRuntime: sockets})
	if err != nil {
		t.Fatal(err)
	}
	if sockets.calls != 0 {
		t.Fatalf("New opened %d sockets", sockets.calls)
	}
	if _, err := New(cfg, Options{SocketRuntime: sockets}); !errors.Is(err, state.SecureStateErrStateLocked) {
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
	second, err := New(cfg, Options{SocketRuntime: sockets})
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
	if _, err := New(cfg, Options{SocketRuntime: new(recordingSockets)}); err == nil {
		t.Fatal("New accepted a configuration without transports")
	}
	cfg.NTCP2.Enabled = true
	d, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
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
			if _, err := New(cfg, Options{SocketRuntime: new(recordingSockets)}); !errors.Is(err, state.ConfigurationErrInvalidOperating) {
				t.Fatalf("New lifetime %s error = %v, want invalid operating config", lifetime, err)
			}
		})
	}
}

func TestNewRejectsDestinationBoundsAndDuplicateIdentities(t *testing.T) {
	t.Run("duplicate", func(t *testing.T) {
		cfg := daemonTestConfig(t)
		d, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
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
		if _, err := New(cfg, Options{SocketRuntime: new(recordingSockets)}); !errors.Is(err, ErrDuplicateDestination) {
			t.Fatalf("duplicate destinations error = %v", err)
		}
	})

	t.Run("bound", func(t *testing.T) {
		cfg := daemonTestConfig(t)
		cfg.State.MaxDestinations = 65
		d, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
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
		if _, err := New(cfg, Options{SocketRuntime: new(recordingSockets)}); !errors.Is(err, ErrTooManyDestinations) {
			t.Fatalf("too many destinations error = %v", err)
		}
	})
}

func TestTunnelCompositionUsesLiveInboundGatewayRoute(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Tunnel.Enabled = true
	d, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	tunnelCompositionUsesLiveInboundGatewayRouteRejected := d.service == nil || d.tunnels == nil || d.pool == nil || d.buildManager == nil || d.requests == nil || d.replyKeys == nil
	if !tunnelCompositionUsesLiveInboundGatewayRouteRejected {
		tunnelCompositionUsesLiveInboundGatewayRouteRejected = d.maintainer == nil
	}
	if tunnelCompositionUsesLiveInboundGatewayRouteRejected {
		t.Fatal("native tunnel data plane is incomplete")
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
	if err := d.pool.Add(networking.TunnelEntry{ID: 1, Direction: networking.TunnelOutbound, Expires: now + 30_000}, now); err != nil {
		t.Fatal(err)
	}
	if err := d.pool.Add(networking.TunnelEntry{ID: 2, Direction: networking.TunnelInbound, Gateway: gateway, GatewayTunnelID: 77, Expires: now + 30_000}, now); err != nil {
		t.Fatal(err)
	}
	clientRuntime := d.clientRuntimeSnapshot()[0]
	owner := clientRuntime.local.Hash()
	if err := clientRuntime.pool.Add(networking.TunnelEntry{ID: 3, Direction: networking.TunnelOutbound, Expires: now + 30_000, Owner: owner}, now); err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.pool.Add(networking.TunnelEntry{ID: 4, Direction: networking.TunnelInbound, Expires: now + 30_000, Owner: owner}, now); err != nil {
		t.Fatal(err)
	}
	d.refreshObservability()
	tunnels := d.registry.Snapshot().Tunnel
	if tunnels.ExploratoryInboundActive != 1 || tunnels.ExploratoryOutboundActive != 1 || tunnels.ClientInboundActive != 1 || tunnels.ClientOutboundActive != 1 {
		t.Fatalf("pool-owned active tunnel metrics = %+v", tunnels)
	}
	gotGateway, gotTunnel, viaTunnel := (daemonReplyRoute{local: d.bundle.Router.Hash, maintainer: d.maintainer, now: func() uint64 { return now }}).DatabaseLookupReplyRoute()
	if !viaTunnel || gotGateway != gateway || gotTunnel != 77 {
		t.Fatalf("reply route = %x/%d/%t, want gateway tunnel 77", gotGateway, gotTunnel, viaTunnel)
	}
}

func TestMuxRequestSenderUsesEstablishedOutboundTunnel(t *testing.T) {
	target, replyGateway := foundation.Hash{1}, foundation.Hash{2}
	payload, err := networking.NetworkDatabaseBuildDatabaseLookup(foundation.Hash{3}, networking.NetworkDatabaseLeaseSetLookup, requestReplyRouteCapture{
		gateway: replyGateway, tunnel: 7,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	direct := new(requestDirectCapture)
	throughTunnel := new(requestTunnelCapture)
	replyKeys := networking.GarlicNewReplyKeyRegistry(2)
	private, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var staticKey [32]byte
	copy(staticKey[:], private.PublicKey().Bytes())
	sender := muxRequestSender{
		sender: direct, tunnels: throughTunnel,
		pairs: requestPairCapture{pair: networking.TunnelCircuitPair{OutboundID: 11}},
		now:   func() uint64 { return 100 }, replyKeys: replyKeys,
		staticKeyLookup: func(hash foundation.Hash) ([32]byte, bool) {
			return staticKey, hash == target
		},
	}
	message := networking.I2NPMessage{Header: networking.I2NPHeader{Type: networking.I2NPDatabaseLookup, ID: 9, Expiration: 1_000}, Payload: payload}
	if err = sender.Send(context.Background(), networking.NetworkDatabaseRouterRef{Hash: target}, message); err != nil {
		t.Fatal(err)
	}
	if direct.calls != 0 || throughTunnel.calls != 1 || throughTunnel.id != 11 {
		t.Fatalf("send paths direct=%d tunnel=%d/%d", direct.calls, throughTunnel.calls, throughTunnel.id)
	}
	if throughTunnel.block.Delivery != networking.TunnelDeliveryRouter || throughTunnel.block.Gateway != target || !throughTunnel.block.Last {
		t.Fatalf("tunnel block = %#v", throughTunnel.block)
	}
	decoded, used, err := networking.I2NPParse(throughTunnel.block.Data)
	if err != nil || used != len(throughTunnel.block.Data) || decoded.Header.Type != networking.I2NPGarlic {
		t.Fatalf("embedded wrapper = %#v/%d, %v", decoded.Header, used, err)
	}
	if len(decoded.Payload) < 4 || int(binary.BigEndian.Uint32(decoded.Payload[:4])) != len(decoded.Payload)-4 {
		t.Fatalf("garlic payload length = %d", len(decoded.Payload))
	}
	inner, err := networking.GarlicECIESOpenRouterMessage(make([]byte, len(decoded.Payload)), private.Bytes(), decoded.Payload[4:], 100)
	if err != nil || inner.Header != message.Header {
		t.Fatalf("embedded lookup = %#v, %v", inner.Header, err)
	}
	lookup, err := networking.I2NPParseDatabaseLookup(inner.Payload)
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
	throughTunnel.err = errors.New("tunnel send failed")
	if err = sender.Send(context.Background(), networking.NetworkDatabaseRouterRef{Hash: target}, message); !errors.Is(err, throughTunnel.err) || replyKeys.Len() != 0 {
		t.Fatalf("failed send = %v, reply_keys=%d", err, replyKeys.Len())
	}
}

func TestMuxLeaseSetSenderUsesOutboundTunnelAndSeedsBothRoutes(t *testing.T) {
	target, replyGateway, outboundEndpoint := foundation.Hash{1}, foundation.Hash{2}, foundation.Hash{3}
	payload, err := networking.NetworkDatabaseMarshalDatabaseStore(foundation.Hash{4}, networking.I2NPStoreLeaseSet2, []byte{1}, 5, replyGateway, 7)
	if err != nil {
		t.Fatal(err)
	}
	direct := new(requestDirectCapture)
	throughTunnel := new(requestTunnelCapture)
	var seeded [][2]foundation.Hash
	sender := muxLeaseSetSender{
		sender: direct, tunnels: throughTunnel,
		pairs: requestPairCapture{pair: networking.TunnelCircuitPair{OutboundID: 11, OutboundEndpoint: outboundEndpoint}},
		now:   func() uint64 { return 100 },
		seedReplyRouterInfo: func(_ context.Context, endpoint, reply foundation.Hash) error {
			seeded = append(seeded, [2]foundation.Hash{endpoint, reply})
			return nil
		},
	}
	message := networking.I2NPMessage{Header: networking.I2NPHeader{Type: networking.I2NPDatabaseStore, ID: 9, Expiration: 1_000}, Payload: payload}
	if err = sender.Send(context.Background(), networking.NetworkDatabaseRouterRef{Hash: target}, message); err != nil {
		t.Fatal(err)
	}
	if direct.calls != 0 || throughTunnel.calls != 1 || throughTunnel.id != 11 {
		t.Fatalf("send paths direct=%d tunnel=%d/%d", direct.calls, throughTunnel.calls, throughTunnel.id)
	}
	if throughTunnel.block.Delivery != networking.TunnelDeliveryRouter || throughTunnel.block.Gateway != target || !throughTunnel.block.Last {
		t.Fatalf("tunnel block = %#v", throughTunnel.block)
	}
	if len(seeded) != 2 || seeded[0] != [2]foundation.Hash{target, replyGateway} || seeded[1] != [2]foundation.Hash{outboundEndpoint, target} {
		t.Fatalf("RouterInfo seeds = %#v", seeded)
	}
	decoded, used, err := networking.I2NPParse(throughTunnel.block.Data)
	if err != nil || used != len(throughTunnel.block.Data) || decoded.Header != message.Header {
		t.Fatalf("embedded store = %#v/%d, %v", decoded.Header, used, err)
	}
	store, err := networking.I2NPParseDatabaseStore(decoded.Payload)
	if err != nil || store.ReplyGateway != replyGateway || store.ReplyTunnelID != 7 || store.ReplyToken != 5 {
		t.Fatalf("embedded store route = %#v, %v", store, err)
	}
}

func TestProxyRequiresTunnelAndPersistsDefaultDestination(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.HTTPProxy.Enabled = true
	cfg.HTTPProxy.Address = state.ConfigurationEndpoint{Host: "127.0.0.1"}
	if _, err := New(cfg, Options{}); !errors.Is(err, ErrProxyWithoutTunnels) {
		t.Fatalf("New without tunnels error = %v", err)
	}
	cfg.Tunnel.Enabled = true
	first, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.bundle.DestinationPrivate["default"]) == 0 {
		t.Fatal("default ECIES destination was not persisted")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
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
	d, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
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

func TestStartServesAllLocalListenersAndCloses(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Tunnel.Enabled = true
	cfg.Control = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, BearerToken: "test-token", MaxConnections: 4}
	cfg.HTTPProxy = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, MaxConnections: 4}
	cfg.SOCKS5 = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, MaxConnections: 4}
	cfg.Metrics = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, MaxConnections: 4}
	d, err := New(cfg, Options{SocketRuntime: loopbackSockets{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !d.router.Running() || d.control == nil || d.httpProxy == nil || d.socks5 == nil || d.metricsListener == nil {
		t.Fatal("router and configured local listeners were not all started")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestStartRollsBackWhenMetricsListenerFails(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Metrics = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, MaxConnections: 4}
	listenErr := errors.New("metrics listener failed")
	d, err := New(cfg, Options{
		SocketRuntime: loopbackSockets{},
		Listener: ListenerFunc(func(context.Context, string, string) (net.Listener, error) {
			return nil, listenErr
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(context.Background()); !errors.Is(err, listenErr) {
		t.Fatalf("Start error = %v, want %v", err, listenErr)
	}
	status := d.Status()
	if d.router.Running() || !errors.Is(status.Error, listenErr) {
		t.Fatal("failed Start left router running or did not retain the listener error")
	}
	if err := d.Wait(); !errors.Is(err, listenErr) {
		t.Fatalf("Wait error = %v, want %v", err, listenErr)
	}
}
func TestDestinationAddressPoliciesPersistAndWireRemoteELS(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Tunnel.Enabled = true
	first, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
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

	d, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
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
	if err = d.UpdateDestinationAddressPolicies("default", invalid); !errors.Is(err, networking.RouterErrDataPlaneConfig) {
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
	reopened, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
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
	newProductionDaemon := func() *Daemon {
		cfg := daemonTestConfig(t)
		cfg.StateDir = filepath.Dir(cfg.StatePath)
		cfg.Tunnel.Enabled = true
		cfg.NTCP2.Enabled = false
		cfg.Tunnel.MaintenanceInterval = time.Hour
		d, err := New(cfg, Options{Transport: network.transport()})
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
		database *networking.NetworkDatabase
		infos    []networking.NetworkDatabaseRouterInfo
	}{
		{publicDaemon.database, []networking.NetworkDatabaseRouterInfo{encryptedInfo, transitInfo}},
		{encryptedDaemon.database, []networking.NetworkDatabaseRouterInfo{publicInfo, transitInfo}},
		{transitDaemon.database, []networking.NetworkDatabaseRouterInfo{publicInfo, encryptedInfo}},
	} {
		for _, info := range admission.infos {
			if err := admission.database.AdmitRouterInfo(info, false, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	var publicMaintainErr, encryptedMaintainErr error
	for range 8 {
		publicMaintainErr = publicRuntime.maintain(context.Background(), uint64(time.Now().UnixMilli()))
		encryptedMaintainErr = encryptedRuntime.maintain(context.Background(), uint64(time.Now().UnixMilli()))
		if publicRuntime.pool.Count(networking.TunnelInbound, uint64(time.Now().UnixMilli())) > 0 &&
			publicRuntime.pool.Count(networking.TunnelOutbound, uint64(time.Now().UnixMilli())) > 0 &&
			encryptedRuntime.pool.Count(networking.TunnelInbound, uint64(time.Now().UnixMilli())) > 0 &&
			encryptedRuntime.pool.Count(networking.TunnelOutbound, uint64(time.Now().UnixMilli())) > 0 {
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
	publicOutbound, publicOK := publicRuntime.pool.Select(networking.TunnelOutbound, now)
	encryptedOutbound, encryptedOK := encryptedRuntime.pool.Select(networking.TunnelOutbound, now)
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
	stores := append([]networking.I2NPDatabaseStoreMessage(nil), network.stores...)
	network.mu.RUnlock()
	var publicStores, encryptedStores, tokens int
	for _, store := range stores {
		switch store.Type {
		case networking.I2NPStoreLeaseSet2:
			publicStores++
		case networking.I2NPStoreEncryptedLeaseSet:
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
	messageRoute := client.ClientDestinationRoute{Protocol: 17, ToPort: 4444}
	subscription, err := encryptedSession.Subscribe(messageRoute, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	messagePayload := []byte("authenticated-destination-garlic")
	if err = publicSession.SendMessage(context.Background(), networking.StreamingTunnelDelivery{
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
	selfRoute := client.ClientDestinationRoute{Protocol: 17, ToPort: 5555}
	selfSubscription, err := publicSession.Subscribe(selfRoute, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer selfSubscription.Close()
	selfRatchetBefore := publicRuntime.ratchet.Stats()
	for sequence := range 4 {
		payload := []byte{byte(sequence), 0x53, 0x45, 0x4c, 0x46}
		if err = publicSession.SendMessage(context.Background(), networking.StreamingTunnelDelivery{
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
	exercise := func(source, target *networking.RouterDestinationSession, port string, request, response []byte) {
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
	if selected, ok := publicRuntime.pool.Select(networking.TunnelOutbound, uint64(time.Now().UnixMilli())); !ok || selected.Owner != publicRuntime.local.Hash() {
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
	newDaemon := func() *Daemon {
		cfg := daemonTestConfig(t)
		cfg.StateDir = filepath.Dir(cfg.StatePath)
		cfg.Tunnel.Enabled = true
		cfg.NTCP2.Enabled = false
		cfg.Tunnel.MaintenanceInterval = time.Hour
		d, newErr := New(cfg, Options{Transport: network.transport()})
		if newErr != nil {
			t.Fatal(newErr)
		}
		return d
	}
	sourceDaemon, targetDaemon, transitDaemon := newDaemon(), newDaemon(), newDaemon()
	t.Cleanup(func() {
		for _, d := range []*Daemon{sourceDaemon, targetDaemon, transitDaemon} {
			_ = d.Close()
			_ = d.Wait()
		}
	})
	for _, d := range []*Daemon{sourceDaemon, targetDaemon, transitDaemon} {
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
	for _, d := range []*Daemon{sourceDaemon, targetDaemon, transitDaemon} {
		if err := d.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	sourceRuntime, targetRuntime := sourceDaemon.clientRuntimeSnapshot()[0], targetDaemon.clientRuntimeSnapshot()[0]
	now = uint64(time.Now().UnixMilli())
	sourceInfo, targetInfo, transitInfo := sourceDaemon.localInfo.Snapshot(), targetDaemon.localInfo.Snapshot(), transitDaemon.localInfo.Snapshot()
	for _, admission := range []struct {
		database *networking.NetworkDatabase
		infos    []networking.NetworkDatabaseRouterInfo
	}{
		{sourceDaemon.database, []networking.NetworkDatabaseRouterInfo{targetInfo, transitInfo}},
		{targetDaemon.database, []networking.NetworkDatabaseRouterInfo{sourceInfo, transitInfo}},
		{transitDaemon.database, []networking.NetworkDatabaseRouterInfo{sourceInfo, targetInfo}},
	} {
		for _, info := range admission.infos {
			if err := admission.database.AdmitRouterInfo(info, false, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	for range 8 {
		_ = sourceRuntime.maintain(context.Background(), uint64(time.Now().UnixMilli()))
		_ = targetRuntime.maintain(context.Background(), uint64(time.Now().UnixMilli()))
		current := uint64(time.Now().UnixMilli())
		if sourceRuntime.pool.Count(networking.TunnelInbound, current) > 0 && sourceRuntime.pool.Count(networking.TunnelOutbound, current) > 0 &&
			targetRuntime.pool.Count(networking.TunnelInbound, current) > 0 && targetRuntime.pool.Count(networking.TunnelOutbound, current) > 0 {
			break
		}
	}
	now = uint64(time.Now().UnixMilli())
	if sourceRuntime.pool.Count(networking.TunnelInbound, now) == 0 || sourceRuntime.pool.Count(networking.TunnelOutbound, now) == 0 ||
		targetRuntime.pool.Count(networking.TunnelInbound, now) == 0 || targetRuntime.pool.Count(networking.TunnelOutbound, now) == 0 {
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
	messageRoute := client.ClientDestinationRoute{Protocol: 18, ToPort: 9090}
	subscription, subscribeErr := targetSession.Subscribe(messageRoute, 1)
	if subscribeErr != nil {
		t.Fatal(subscribeErr)
	}
	defer subscription.Close()
	messagePayload := []byte("authorized-message-" + authorization)
	if err = sourceSession.SendMessage(context.Background(), networking.StreamingTunnelDelivery{
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
		if store.Type == networking.I2NPStoreEncryptedLeaseSet {
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
	d, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
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
	reopened, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
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
	d, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
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
	first, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
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
	d, err := New(cfg, Options{SocketRuntime: new(recordingSockets)})
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
	requests, requestErr := networking.NetworkDatabaseNewRequestManager(
		d.database,
		blocking,
		daemonReplyRoute{local: d.bundle.Router.Hash, now: func() uint64 { return uint64(time.Now().UnixMilli()) }},
		networking.NetworkDatabaseRequestManagerConfig{Capacity: 2, TimeoutMillis: 60_000, Now: func() uint64 { return uint64(time.Now().UnixMilli()) }},
	)
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	if err = removed.requests.Close(); err != nil {
		t.Fatal(err)
	}
	removed.requests = requests
	type lookupReturn struct {
		waiter <-chan networking.NetworkDatabaseLookupResult
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
	if !open || !errors.Is(result.Err, networking.NetworkDatabaseErrRequestManagerClosed) {
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
	if _, lookupErr := removed.requests.LookupRouterInfo(context.Background(), foundation.Hash{99}); !errors.Is(lookupErr, networking.NetworkDatabaseErrRequestManagerClosed) {
		t.Fatalf("destroyed RequestManager accepted work: %v", lookupErr)
	}
	if removed.build.Pending() != 0 {
		t.Fatalf("destroy left %d pending builds", removed.build.Pending())
	}
	if expired, healthErr := removed.health.Expire(context.Background()); expired != 0 || !errors.Is(healthErr, networking.TunnelErrHealthClosed) {
		t.Fatalf("destroyed Health accepted work: %d, %v", expired, healthErr)
	}
	if maintained, maintainErr := removed.maintainer.Maintain(context.Background()); maintained != 0 || !errors.Is(maintainErr, networking.TunnelErrPairedMaintenanceClosed) {
		t.Fatalf("destroyed maintainer accepted work: %d, %v", maintained, maintainErr)
	}
	if senderErr := removed.sender.UpdateRemoteELS(nil); !errors.Is(senderErr, networking.RouterErrDataPlaneConfig) {
		t.Fatalf("destroyed sender accepted policy: %v", senderErr)
	}
}

func TestWaitDoesNotRaceStartRegistration(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Metrics = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, MaxConnections: 1}
	entered := make(chan struct{})
	release := make(chan struct{})
	d, err := New(cfg, Options{
		SocketRuntime: loopbackSockets{},
		Listener: ListenerFunc(func(context.Context, string, string) (net.Listener, error) {
			close(entered)
			<-release
			return net.Listen("tcp", "127.0.0.1:0")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Wait(); err != nil {
		t.Fatalf("Wait before Start = %v", err)
	}
	started := make(chan error, 1)
	go func() { started <- d.Start(context.Background()) }()
	<-entered
	waited := make(chan error, 1)
	go func() { waited <- d.Wait() }()
	select {
	case err := <-waited:
		t.Fatalf("Wait returned before Start registered workers: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-waited; err != nil {
		t.Fatal(err)
	}
}

func TestCloseWaitsForStartupBeforeReleasingResources(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Metrics = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, MaxConnections: 1}
	entered := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	var returned net.Listener
	d, err := New(cfg, Options{
		SocketRuntime: loopbackSockets{},
		Listener: ListenerFunc(func(ctx context.Context, _, _ string) (net.Listener, error) {
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-release
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err == nil {
				returned = listener
			}
			return listener, err
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan error, 1)
	go func() { started <- d.Start(context.Background()) }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	<-canceled
	select {
	case err := <-closed:
		t.Fatalf("Close returned before Start completed registration: %v", err)
	default:
	}
	close(release)
	if err := <-started; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Start error = %v, want closed", err)
	}
	if err := <-closed; err != nil {
		t.Fatalf("Close error = %v", err)
	}
	if returned == nil {
		t.Fatal("Listen did not return its tracked listener")
	}
	if err := returned.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("returned listener remained open: Close() = %v", err)
	}
	if d.metrics != nil || d.metricsListener != nil || d.router.Running() {
		t.Fatal("canceled startup left a listener or server running")
	}
	second, err := New(cfg, Options{SocketRuntime: loopbackSockets{}})
	if err != nil {
		t.Fatalf("New after concurrent Close error = %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOptionsListenOwnsEveryClientListener(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Tunnel.Enabled = true
	cfg.Control = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, BearerToken: "control-token", MaxConnections: 1}
	cfg.HTTPProxy = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, MaxConnections: 1}
	cfg.SOCKS5 = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, MaxConnections: 1}
	cfg.Metrics = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, MaxConnections: 1}
	var calls int
	d, err := New(cfg, Options{
		SocketRuntime: loopbackSockets{},
		Listener: ListenerFunc(func(_ context.Context, network, address string) (net.Listener, error) {
			if network != "tcp" || address != "127.0.0.1:0" {
				t.Fatalf("Listen(%q, %q)", network, address)
			}
			calls++
			return net.Listen(network, address)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 4 {
		t.Fatalf("Listen calls = %d, want 4", calls)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestOptionsListenerInjectsSAMPacketListener(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Tunnel.Enabled = true
	cfg.SAM = state.ConfigurationListener{
		Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, UDPAddress: state.ConfigurationEndpoint{Host: "127.0.0.1"},
		MaxConnections: 4, ReadinessTimeout: time.Second, SessionQueue: 4,
	}
	var streamCalls, packetCalls int
	listener := ListenerFuncs{
		Stream: func(_ context.Context, network, address string) (net.Listener, error) {
			if network != "tcp" || address != "127.0.0.1:0" {
				t.Fatalf("Listen(%q, %q)", network, address)
			}
			streamCalls++
			return net.Listen(network, address)
		},
		Packet: func(_ context.Context, network, address string) (net.PacketConn, error) {
			if network != "udp" || address != "127.0.0.1:0" {
				t.Fatalf("ListenPacket(%q, %q)", network, address)
			}
			packetCalls++
			return net.ListenPacket(network, address)
		},
	}
	d, err := New(cfg, Options{SocketRuntime: loopbackSockets{}, Listener: listener})
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if streamCalls != 1 || packetCalls != 1 || d.samServer == nil || d.samServer.UDPAddr() == nil {
		t.Fatalf("listener calls stream=%d packet=%d UDP=%v", streamCalls, packetCalls, d.samServer.UDPAddr())
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	if err = d.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestMetricsBearerAuthentication(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Metrics = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, BearerToken: "metrics-token", MaxConnections: 1}
	d, err := New(cfg, Options{SocketRuntime: loopbackSockets{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.metrics.ReadHeaderTimeout != 10*time.Second || d.metrics.ReadTimeout != 30*time.Second || d.metrics.WriteTimeout != 30*time.Second || d.metrics.IdleTimeout != 30*time.Second || d.metrics.MaxHeaderBytes != 32<<10 {
		t.Fatalf("metrics server bounds = %#v", d.metrics)
	}
	t.Cleanup(func() {
		_ = d.Close()
		_ = d.Wait()
	})
	url := "http://" + d.metricsListener.Addr().String() + "/metrics"
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated metrics status = %d", response.StatusCode)
	}
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer metrics-token")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authenticated metrics status = %d", response.StatusCode)
	}
}

func TestReseedOutcomesAreObservableWithoutMakingOptionalFailureFatal(t *testing.T) {
	newDaemon := func(t *testing.T, required bool) *Daemon {
		t.Helper()
		cfg := daemonTestConfig(t)
		cfg.Reseed = state.ConfigurationReseed{
			Enabled: true, Required: required,
			Endpoints: []string{"http://reseed.example/i2p"},
		}
		d, err := New(cfg, Options{SocketRuntime: loopbackSockets{}})
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
	if contexts, err := remoteELSContexts(invalid); !errors.Is(err, networking.RouterErrDataPlaneConfig) || contexts != nil {
		t.Fatalf("remoteELSContexts partial failure = %#v, %v", contexts, err)
	}
	secret := []byte("retained")
	contexts := map[foundation.Hash]networking.RouterRemoteELSContext{
		identity.Hash(): {Identity: identity, Secret: secret, Authorization: networking.NetworkDatabaseELSClientAuthorization{UsePSK: true, PSK: [32]byte{1}}},
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
