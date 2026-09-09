package ivnp

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

const embeddedTestTimeout = 20 * time.Second

type embeddedMemoryNetwork struct {
	mu        sync.RWMutex
	endpoints map[foundation.Hash]*embeddedMemoryTransport
	flood     foundation.Hash
	floodDB   *controlplane.NetworkDatabase
	nextID    uint32
}

type embeddedMemoryTransport struct {
	network  *embeddedMemoryNetwork
	local    foundation.Hash
	bindings dataplane.RouterTransportBindings
	done     chan struct{}
	once     sync.Once
	running  bool
}

func newEmbeddedMemoryNetwork(flood foundation.NetworkDatabaseRouterInfo) *embeddedMemoryNetwork {
	return &embeddedMemoryNetwork{
		endpoints: make(map[foundation.Hash]*embeddedMemoryTransport),
		flood:     flood.Hash(),
		floodDB:   controlplane.NetworkDatabaseNewDatabase(flood.Hash(), 16),
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

func (t *embeddedMemoryTransport) Start(ctx context.Context, bindings dataplane.RouterTransportBindings) error {
	localInfo, ok := bindings.LocalInfo.(controlplane.RouterLocalInfo)
	if !ok {
		return errors.New("memory network requires control-plane identity publication")
	}
	localInfo.SetReachability(controlplane.RouterReachabilityReachable)
	if err := localInfo.Publish(ctx); err != nil {
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

func (t *embeddedMemoryTransport) Send(ctx context.Context, target foundation.Hash, message foundation.I2NPMessage) error {
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

func (t *embeddedMemoryTransport) Status() dataplane.RouterTransportStatus {
	t.network.mu.RLock()
	status := dataplane.RouterTransportStatus{Running: t.running}
	t.network.mu.RUnlock()
	return status
}

func (t *embeddedMemoryTransport) localHash() foundation.Hash {
	t.network.mu.RLock()
	local := t.local
	t.network.mu.RUnlock()
	return local
}

func (t *embeddedMemoryTransport) routerInfo() foundation.NetworkDatabaseRouterInfo {
	t.network.mu.RLock()
	localInfo := t.bindings.LocalInfo
	t.network.mu.RUnlock()
	if localInfo == nil {
		return foundation.NetworkDatabaseRouterInfo{}
	}
	return localInfo.Snapshot()
}

func (n *embeddedMemoryNetwork) route(from, target foundation.Hash, message foundation.I2NPMessage) error {
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
		return dataplane.RouterErrSessionUnavailable
	}
	return endpoint.bindings.HandleI2NPFrom(from, message, uint64(time.Now().UnixMilli()), false)
}

func (n *embeddedMemoryNetwork) handleFlood(from foundation.Hash, message foundation.I2NPMessage) error {
	now := uint64(time.Now().UnixMilli())
	switch message.Header.Type {
	case foundation.I2NPDatabaseStore:
		store, err := foundation.I2NPParseDatabaseStore(message.Payload)
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
		status := foundation.I2NPMessage{
			Header: foundation.I2NPHeader{
				Type:       foundation.I2NPDeliveryStatus,
				ID:         n.messageID(),
				Expiration: now + 60_000,
			},
			Payload: payload[:],
		}
		return n.reply(n.flood, store.ReplyGateway, store.ReplyTunnelID, status)
	case foundation.I2NPDatabaseLookup:
		lookup, err := foundation.I2NPParseDatabaseLookup(message.Payload)
		if err != nil {
			return err
		}
		typeID, data, found := n.floodDB.StoredLeaseSet(lookup.Key)
		if !found {
			return controlplane.NetworkDatabaseErrNoFloodfill
		}
		payload := marshalEmbeddedDatabaseStore(lookup.Key, typeID, data)
		reply := foundation.I2NPMessage{
			Header: foundation.I2NPHeader{
				Type:       foundation.I2NPDatabaseStore,
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

func marshalEmbeddedDatabaseStore(key foundation.Hash, typeID foundation.I2NPStoreType, data []byte) []byte {
	payload := make([]byte, 37+len(data))
	copy(payload[:foundation.HashLength], key[:])
	payload[foundation.HashLength] = byte(typeID)
	copy(payload[37:], data)
	return payload
}

func (n *embeddedMemoryNetwork) reply(from, gateway foundation.Hash, tunnelID uint32, message foundation.I2NPMessage) error {
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
	gatewayMessage := foundation.I2NPMessage{
		Header: foundation.I2NPHeader{
			Type:       foundation.I2NPTunnelGateway,
			ID:         n.messageID(),
			Expiration: message.Header.Expiration,
		},
		Payload: payload,
	}
	return n.route(from, gateway, gatewayMessage)
}

func embeddedTestFloodfill(t *testing.T) foundation.NetworkDatabaseRouterInfo {
	t.Helper()
	public, private, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	identity := make([]byte, foundation.IdentityBaseLength+7)
	copy(identity[352:384], public)
	identity[384] = byte(foundation.CertificateKey)
	identity[385], identity[386] = 0, 4
	identity[387], identity[388] = 0, byte(foundation.SigningEdDSASHA512Ed25519)
	identity[389], identity[390] = 0, byte(foundation.CryptoElGamal)
	local := foundation.LocalAddress{
		Destination: []byte(foundation.EncodeI2PBase64(identity)), Hash: foundation.Sum(identity),
		SigningPublic: public, SigningPrivate: private,
	}
	var static [32]byte
	var iv [16]byte
	if _, err = cryptorand.Read(static[:]); err != nil {
		t.Fatal(err)
	}
	if _, err = cryptorand.Read(iv[:]); err != nil {
		t.Fatal(err)
	}
	builder, err := controlplane.NetworkDatabaseNewLocalRouterInfo(controlplane.NetworkDatabaseLocalRouterInfoConfig{
		Local: local,
		Contacts: controlplane.NetworkDatabaseRouterInfoContacts{
			Addresses: []controlplane.NetworkDatabaseLocalRouterAddress{{
				Cost: 3, TransportStyle: []byte("NTCP2"),
				Options: []foundation.MappingEntry{
					{Key: []byte("host"), Value: []byte("192.0.2.254")},
					{Key: []byte("i"), Value: []byte(foundation.EncodeI2PBase64(iv[:]))},
					{Key: []byte("port"), Value: []byte("12345")},
					{Key: []byte("s"), Value: []byte(foundation.EncodeI2PBase64(static[:]))},
					{Key: []byte("v"), Value: []byte("2")},
				},
			}},
			Options: []foundation.MappingEntry{
				{Key: []byte("caps"), Value: []byte("f")},
				{Key: []byte("netId"), Value: []byte("2")},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.ReleaseSensitive()
	info, err := builder.Publish(uint64(time.Now().UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func embeddedTestConfig(t *testing.T) RouterConfig {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultRouterConfig()
	cfg.Persistence = &PersistenceConfig{Directory: base}
	cfg.NTCP2.Advertised = netip.MustParseAddrPort("192.0.2.1:12345")
	cfg.Bootstrap = BootstrapConfig{}
	cfg.Exploratory = TunnelPoolConfig{
		Inbound:     TunnelDirectionConfig{Hops: 1, Count: 1},
		Outbound:    TunnelDirectionConfig{Hops: 1, Count: 1},
		RenewBefore: 10 * time.Second,
	}
	return cfg
}

func newEmbeddedTestRouter(t *testing.T, cfg RouterConfig, transport *embeddedMemoryTransport) *Router {
	t.Helper()
	settings, options, err := routerSettings(cfg)
	if err != nil {
		t.Fatal(err)
	}
	options.Transport = transport
	router, err := newRouter(t.Context(), cfg, settings, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := router.Close(); err != nil {
			t.Errorf("close embedded router: %v", err)
		}
	})
	return router
}

func captureEmbeddedRouterInfo(t *testing.T, cfg RouterConfig, network *embeddedMemoryNetwork) []byte {
	t.Helper()
	transport := network.transport()
	router := newEmbeddedTestRouter(t, cfg, transport)
	info := transport.routerInfo()
	encoded := append([]byte(nil), info.Bytes()...)
	if len(encoded) == 0 {
		t.Fatal("started node did not expose its local RouterInfo to the transport")
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestEmbeddedDestinationLifecycle(t *testing.T) {
	flood := embeddedTestFloodfill(t)
	network := newEmbeddedMemoryNetwork(flood)
	configs := []RouterConfig{embeddedTestConfig(t), embeddedTestConfig(t), embeddedTestConfig(t)}
	routerInfos := make([][]byte, len(configs))
	for index := range configs {
		routerInfos[index] = captureEmbeddedRouterInfo(t, configs[index], network)
	}

	for index := range configs {
		for peerIndex, info := range routerInfos {
			if peerIndex != index {
				configs[index].Bootstrap.RouterInfos = append(configs[index].Bootstrap.RouterInfos, info)
			}
		}
		configs[index].Bootstrap.RouterInfos = append(configs[index].Bootstrap.RouterInfos, flood.Bytes())
	}

	routers := make([]*Router, 0, len(configs))
	for _, cfg := range configs {
		routers = append(routers, newEmbeddedTestRouter(t, cfg, network.transport()))
	}

	ctx, cancel := context.WithTimeout(context.Background(), embeddedTestTimeout)
	defer cancel()
	destinationConfig := DefaultDestinationConfig()
	destinationConfig.Tunnels = configs[0].Exploratory
	source, err := routers[0].NewDestination(ctx, destinationConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := routers[1].NewDestination(ctx, destinationConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	listener, err := target.Listen("i2p", ":8080")
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
	outbound, err := source.DialContext(ctx, "i2p", net.JoinHostPort(target.B32(), "8080"))
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

	t.Run("HTTP transport over B32", func(t *testing.T) {
		httpListener, err := target.Listen("i2p", ":8082")
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, err := io.WriteString(w, "embedded HTTP response"); err != nil {
				t.Error(err)
			}
		})}
		served := make(chan error, 1)
		go func() { served <- server.Serve(httpListener) }()
		t.Cleanup(func() {
			if err := server.Close(); err != nil {
				t.Error(err)
			}
			if err := <-served; !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("HTTP server shutdown: %v", err)
			}
		})
		transport := &http.Transport{DialContext: source.DialContext}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		response, err := client.Get("http://" + net.JoinHostPort(target.B32(), "8082") + "/")
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK || string(body) != "embedded HTTP response" {
			t.Fatalf("HTTP response = %d %q", response.StatusCode, body)
		}
	})

	t.Run("signed datagram round trip", func(t *testing.T) {
		sender, err := source.ListenPacket("i2p-datagram2", ":0")
		if err != nil {
			t.Fatal(err)
		}
		defer sender.Close()
		receiver, err := target.ListenPacket("i2p-datagram2", ":8081")
		if err != nil {
			t.Fatal(err)
		}
		defer receiver.Close()
		packetDeadline := time.Now().Add(5 * time.Second)
		if err = sender.SetDeadline(packetDeadline); err != nil {
			t.Fatal(err)
		}
		if err = receiver.SetDeadline(packetDeadline); err != nil {
			t.Fatal(err)
		}
		sourceAddress := sender.LocalAddr().(Addr)
		if sourceAddress.Port < 49152 {
			t.Fatalf("ephemeral source port = %d, want dynamic port", sourceAddress.Port)
		}
		request := []byte("signed request")
		if n, err := sender.WriteTo(request, receiver.LocalAddr()); err != nil || n != len(request) {
			t.Fatalf("send signed request: bytes=%d error=%v", n, err)
		}
		buffer := make([]byte, 128)
		n, from, err := receiver.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if string(buffer[:n]) != string(request) {
			t.Fatalf("signed request = %q, want %q", buffer[:n], request)
		}
		if address, ok := from.(Addr); !ok || address.Hash != source.Hash() || address.Port != sourceAddress.Port {
			t.Fatalf("verified source = %v, want %v", from, sourceAddress)
		}
		reply := []byte("signed reply")
		if n, err := receiver.WriteTo(reply, from); err != nil || n != len(reply) {
			t.Fatalf("send signed reply: bytes=%d error=%v", n, err)
		}
		n, from, err = sender.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if string(buffer[:n]) != string(reply) {
			t.Fatalf("signed reply = %q, want %q", buffer[:n], reply)
		}
		if address, ok := from.(Addr); !ok || address.Hash != target.Hash() || address.Port != 8081 {
			t.Fatalf("verified reply source = %v, want %v", from, receiver.LocalAddr())
		}
	})

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
}
