package ivnp_test

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking"
)

var errMemoryTransportUnavailable = errors.New("memory transport: target unavailable")

const embeddedTestTimeout = 20 * time.Second

type embeddedMemoryNetwork struct {
	mu        sync.RWMutex
	endpoints map[foundation.Hash]*embeddedMemoryTransport
	flood     foundation.Hash
	floodDB   *networking.NetworkDatabase
	nextID    uint32
}

type embeddedMemoryTransport struct {
	network  *embeddedMemoryNetwork
	local    foundation.Hash
	bindings networking.RouterTransportBindings
	done     chan struct{}
	once     sync.Once
	running  bool
}

func newEmbeddedMemoryNetwork(flood networking.NetworkDatabaseRouterInfo) *embeddedMemoryNetwork {
	return &embeddedMemoryNetwork{
		endpoints: make(map[foundation.Hash]*embeddedMemoryTransport),
		flood:     flood.Hash(),
		floodDB:   networking.NetworkDatabaseNewDatabase(flood.Hash(), 16),
	}
}

func (n *embeddedMemoryNetwork) transport() *embeddedMemoryTransport {
	return &embeddedMemoryTransport{network: n, done: make(chan struct{})}
}

func (n *embeddedMemoryNetwork) messageID() uint32 {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nextID++
	if n.nextID == 0 {
		n.nextID++
	}
	return n.nextID
}

func (t *embeddedMemoryTransport) Start(ctx context.Context, bindings networking.RouterTransportBindings) error {
	bindings.LocalInfo.SetReachability(networking.RouterReachabilityReachable)
	if err := bindings.LocalInfo.Publish(ctx); err != nil {
		return err
	}
	t.network.mu.Lock()
	t.local = bindings.LocalInfo.Hash()
	t.bindings = bindings
	t.running = true
	t.network.endpoints[t.local] = t
	t.network.mu.Unlock()
	return nil
}

func (t *embeddedMemoryTransport) Send(ctx context.Context, target foundation.Hash, message networking.I2NPMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return t.network.route(t.localHash(), target, message)
}

func (t *embeddedMemoryTransport) Close() error {
	t.once.Do(func() {
		t.network.mu.Lock()
		delete(t.network.endpoints, t.local)
		t.running = false
		t.network.mu.Unlock()
		close(t.done)
	})
	return nil
}

func (t *embeddedMemoryTransport) Wait() error {
	<-t.done
	return nil
}

func (t *embeddedMemoryTransport) Status() networking.RouterTransportStatus {
	t.network.mu.RLock()
	status := networking.RouterTransportStatus{Running: t.running}
	t.network.mu.RUnlock()
	return status
}

func (t *embeddedMemoryTransport) localHash() foundation.Hash {
	t.network.mu.RLock()
	local := t.local
	t.network.mu.RUnlock()
	return local
}

func (t *embeddedMemoryTransport) routerInfo() networking.NetworkDatabaseRouterInfo {
	t.network.mu.RLock()
	localInfo := t.bindings.LocalInfo
	t.network.mu.RUnlock()
	if localInfo == nil {
		return networking.NetworkDatabaseRouterInfo{}
	}
	return localInfo.Snapshot()
}

func (n *embeddedMemoryNetwork) route(from, target foundation.Hash, message networking.I2NPMessage) error {
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
		return errMemoryTransportUnavailable
	}
	return endpoint.bindings.HandleI2NPFrom(from, message, uint64(time.Now().UnixMilli()), false)
}

func (n *embeddedMemoryNetwork) handleFlood(from foundation.Hash, message networking.I2NPMessage) error {
	now := uint64(time.Now().UnixMilli())
	switch message.Header.Type {
	case networking.I2NPDatabaseStore:
		store, err := networking.I2NPParseDatabaseStore(message.Payload)
		if err != nil {
			return err
		}
		if err = n.floodDB.HandleDatabaseStore(store, false, now); err != nil {
			return err
		}
		if store.ReplyToken == 0 {
			return nil
		}
		var payload [12]byte
		binary.BigEndian.PutUint32(payload[:4], store.ReplyToken)
		binary.BigEndian.PutUint64(payload[4:], now)
		status := networking.I2NPMessage{
			Header: networking.I2NPHeader{
				Type:       networking.I2NPDeliveryStatus,
				ID:         n.messageID(),
				Expiration: now + 60_000,
			},
			Payload: payload[:],
		}
		return n.reply(n.flood, store.ReplyGateway, store.ReplyTunnelID, status)
	case networking.I2NPDatabaseLookup:
		lookup, err := networking.I2NPParseDatabaseLookup(message.Payload)
		if err != nil {
			return err
		}
		typeID, data, found := n.floodDB.StoredLeaseSet(lookup.Key)
		if !found {
			return networking.NetworkDatabaseErrNoFloodfill
		}
		payload := marshalEmbeddedDatabaseStore(lookup.Key, typeID, data)
		reply := networking.I2NPMessage{
			Header: networking.I2NPHeader{
				Type:       networking.I2NPDatabaseStore,
				ID:         n.messageID(),
				Expiration: now + 60_000,
			},
			Payload: payload,
		}
		return n.reply(n.flood, lookup.From, lookup.ReplyTunnelID, reply)
	default:
		return n.route(from, from, message)
	}
}

func marshalEmbeddedDatabaseStore(key foundation.Hash, typeID networking.I2NPStoreType, data []byte) []byte {
	payload := make([]byte, 37+len(data))
	copy(payload[:foundation.HashLength], key[:])
	payload[foundation.HashLength] = byte(typeID)
	copy(payload[37:], data)
	return payload
}

func (n *embeddedMemoryNetwork) reply(from, gateway foundation.Hash, tunnelID uint32, message networking.I2NPMessage) error {
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
	gatewayMessage := networking.I2NPMessage{
		Header: networking.I2NPHeader{
			Type:       networking.I2NPTunnelGateway,
			ID:         n.messageID(),
			Expiration: message.Header.Expiration,
		},
		Payload: payload,
	}
	return n.route(from, gateway, gatewayMessage)
}

func embeddedTestFloodfill(t *testing.T) networking.NetworkDatabaseRouterInfo {
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
	now := uint64(time.Now().UnixMilli())
	unsigned := append(identity, make([]byte, 10)...)
	binary.BigEndian.PutUint64(unsigned[len(identity):len(identity)+8], now)
	unsigned = append(unsigned, options[:optionLen]...)
	info, err := networking.NetworkDatabaseParseRouterInfo(append(unsigned, ed25519.Sign(private, unsigned)...))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func embeddedTestConfig(t *testing.T) ivnp.Config {
	t.Helper()
	base := t.TempDir()
	var cfg ivnp.Config
	cfg.DataDir = base
	cfg.StateDir = base
	cfg.StatePath = filepath.Join(base, "router.state")
	cfg.KeyPath = filepath.Join(base, "router.keys")
	cfg.Network.ID = 2
	cfg.Network.IPv4 = true
	cfg.Router.Version = "0.9.70"
	cfg.State.MaxBytes = 1 << 20
	cfg.State.MaxDestinations = 16
	cfg.State.MaxNameBytes = 64
	cfg.Tunnel.ExploratoryInboundTarget = 1
	cfg.Tunnel.ExploratoryOutboundTarget = 1
	cfg.Tunnel.ExploratoryPoolCapacity = 2
	cfg.NetDB.BucketCapacity = 16
	cfg.NetDB.LookupCapacity = 32
	cfg.Tunnel.Enabled = true
	cfg.Tunnel.Hops = 1
	cfg.Tunnel.ClientInboundTarget = 1
	cfg.Tunnel.ClientOutboundTarget = 1
	cfg.Tunnel.ClientPoolCapacity = 2
	cfg.Tunnel.BuildPendingCapacity = 4
	cfg.Tunnel.Lifetime = 10 * time.Minute
	cfg.Tunnel.RenewBefore = 10 * time.Second
	cfg.Tunnel.MaintenanceInterval = 100 * time.Millisecond
	cfg.Tunnel.BandwidthRateBytesPerSecond = 64 * 1024
	return cfg
}

func captureEmbeddedRouterInfo(t *testing.T, cfg ivnp.Config, network *embeddedMemoryNetwork) []byte {
	t.Helper()
	transport := network.transport()
	router, err := ivnp.New(cfg, ivnp.Options{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if err = router.DestroyDestination(context.Background(), "default"); err != nil {
		t.Fatal(err)
	}
	if err = router.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	info := transport.routerInfo()
	encoded := append([]byte(nil), info.Bytes()...)
	if len(encoded) == 0 {
		t.Fatal("started node did not expose its local RouterInfo to the transport")
	}
	if err = router.Close(); err != nil {
		t.Fatal(err)
	}
	if err = router.Wait(); err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestEmbeddedDestinationLifecycle(t *testing.T) {
	flood := embeddedTestFloodfill(t)
	network := newEmbeddedMemoryNetwork(flood)
	configs := []ivnp.Config{embeddedTestConfig(t), embeddedTestConfig(t), embeddedTestConfig(t)}
	routerInfos := make([][]byte, len(configs))
	for index := range configs {
		routerInfos[index] = captureEmbeddedRouterInfo(t, configs[index], network)
	}

	bootstrapDir := t.TempDir()
	bootstrapPaths := make([]string, 0, len(routerInfos)+1)
	for index, info := range routerInfos {
		path := filepath.Join(bootstrapDir, "router-"+string(rune('a'+index))+".dat")
		if err := os.WriteFile(path, info, 0o600); err != nil {
			t.Fatal(err)
		}
		bootstrapPaths = append(bootstrapPaths, path)
	}
	floodPath := filepath.Join(bootstrapDir, "floodfill.dat")
	if err := os.WriteFile(floodPath, flood.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	for index := range configs {
		paths := make([]string, 0, len(configs))
		for peerIndex, path := range bootstrapPaths {
			if peerIndex != index {
				paths = append(paths, path)
			}
		}
		configs[index].NetDB.BootstrapRouterInfoPaths = append(paths, floodPath)
	}

	routers := make([]*ivnp.Node, 0, len(configs))
	for _, cfg := range configs {
		router, err := ivnp.New(cfg, ivnp.Options{Transport: network.transport()})
		if err != nil {
			t.Fatal(err)
		}
		if err = router.DestroyDestination(context.Background(), "default"); err != nil {
			t.Fatal(err)
		}
		routers = append(routers, router)
	}
	t.Cleanup(func() {
		for _, router := range routers {
			_ = router.Close()
			_ = router.Wait()
		}
	})
	for _, router := range routers {
		if err := router.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), embeddedTestTimeout)
	defer cancel()
	source, err := routers[0].DestinationController().CreateDestination(ctx, ivnp.DestinationSpec{})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := routers[1].DestinationController().CreateDestination(ctx, ivnp.DestinationSpec{})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	for _, endpoint := range []ivnp.DestinationEndpoint{source, target} {
		ready, ok := endpoint.(ivnp.ReadyDestinationEndpoint)
		if !ok {
			t.Fatalf("endpoint %T does not implement ivnp.ReadyDestinationEndpoint", endpoint)
		}
		if err = ready.WaitReady(ctx); err != nil {
			t.Fatal(err)
		}
	}

	listener, err := target.ListenI2P(ctx, ":8080")
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
	outbound, err := source.DialI2P(ctx, target.B32()+":8080")
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.Close()
	var inbound net.Conn
	select {
	case inbound = <-accepted:
	case err = <-acceptErrors:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer inbound.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err = outbound.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err = inbound.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	payload := []byte("embedded-router-round-trip")
	if _, err = outbound.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(inbound, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("received %q, want %q", got, payload)
	}

	if err = source.Close(); err != nil {
		t.Fatal(err)
	}
	if err = target.Close(); err != nil {
		t.Fatal(err)
	}
	for _, router := range routers {
		if err = router.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, router := range routers {
		if err = router.Wait(); err != nil {
			t.Fatal(err)
		}
	}
}
