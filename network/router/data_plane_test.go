package router

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	ivnp "gosuda.org/ivnp"
	"gosuda.org/ivnp/network/tunnel"
	"gosuda.org/ivnp/protocol/garlic"
	"gosuda.org/ivnp/protocol/i2np"
	"gosuda.org/ivnp/protocol/netdb"
	"gosuda.org/ivnp/protocol/streaming"
	streamtunnel "gosuda.org/ivnp/protocol/streaming/tunnel"
)

type dataPlaneTunnelSender struct {
	mu       sync.Mutex
	handle   func(context.Context, i2np.Message) error
	messages []i2np.Message
}

func (s *dataPlaneTunnelSender) Send(ctx context.Context, _ ivnp.Hash, message i2np.Message) error {
	copyMessage := i2np.Message{Header: message.Header, Payload: append([]byte(nil), message.Payload...)}
	s.mu.Lock()
	s.messages = append(s.messages, copyMessage)
	handle := s.handle
	s.mu.Unlock()
	if handle == nil {
		return nil
	}
	return handle(ctx, copyMessage)
}

type dataPlaneRequestSender struct{}

func (dataPlaneRequestSender) Send(context.Context, netdb.RouterRef, i2np.Message) error {
	return errors.New("unexpected LeaseSet lookup")
}

type dataPlaneReplyRoute struct{}

func (dataPlaneReplyRoute) DatabaseLookupReplyRoute() (ivnp.Hash, uint32, bool) {
	return ivnp.Hash{}, 1, true
}

type dataPlaneDirectSender func(context.Context, streamtunnel.Delivery) error

func (f dataPlaneDirectSender) SendTunnel(ctx context.Context, delivery streamtunnel.Delivery) error {
	return f(ctx, delivery)
}

func TestRatchetGarlicClovesMatchI2PDCompactBlocks(t *testing.T) {
	const fixtureHex = "0b000d0001010203040000000aaabbcc" +
		"0b002c20" +
		"1111111111111111111111111111111111111111111111111111111111111111" +
		"14050607080000000bddee"
	fixture, err := hex.DecodeString(fixtureHex)
	if err != nil {
		t.Fatal(err)
	}
	cloves, err := parseRatchetGarlicCloves(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(cloves) != 2 || cloves[0].Delivery.Type != garlic.DeliveryLocal ||
		cloves[0].Message.Header.Type != i2np.DatabaseStore || cloves[0].Message.Header.ID != 0x01020304 ||
		cloves[0].Message.Header.Expiration != 10_000 || !bytes.Equal(cloves[0].Message.Payload, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("LeaseSet clove = %#v", cloves[0])
	}
	var destination ivnp.Hash
	for index := range destination {
		destination[index] = 0x11
	}
	if cloves[1].Delivery.Type != garlic.DeliveryDestination || cloves[1].Delivery.To != destination ||
		cloves[1].Message.Header.Type != i2np.Data || cloves[1].Message.Header.ID != 0x05060708 ||
		cloves[1].Message.Header.Expiration != 11_000 || !bytes.Equal(cloves[1].Message.Payload, []byte{0xdd, 0xee}) {
		t.Fatalf("Data clove = %#v", cloves[1])
	}

	encoded := make([]byte, len(fixture))
	first, err := appendRatchetGarlicClove(encoded, garlic.Delivery{Type: garlic.DeliveryLocal}, cloves[0].Message)
	if err != nil {
		t.Fatal(err)
	}
	second, err := appendRatchetGarlicClove(encoded[len(first):], garlic.Delivery{Type: garlic.DeliveryDestination, To: destination}, cloves[1].Message)
	if err != nil {
		t.Fatal(err)
	}
	if got := encoded[:len(first)+len(second)]; !bytes.Equal(got, fixture) {
		t.Fatalf("compact blocks = %x, want %x", got, fixture)
	}
}
func TestDestinationDataUsesI2CPGzipHeader(t *testing.T) {
	payload := []byte("native-streaming-payload")
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	gzipPayload := compressed.Bytes()
	binary.BigEndian.PutUint16(gzipPayload[4:6], 1234)
	binary.BigEndian.PutUint16(gzipPayload[6:8], 5678)
	gzipPayload[9] = streamtunnel.ProtocolStreaming
	data := make([]byte, 4+len(gzipPayload))
	binary.BigEndian.PutUint32(data[:4], uint32(len(gzipPayload)))
	copy(data[4:], gzipPayload)
	protocol, fromPort, toPort, decoded, err := parseDestinationData(data)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != streamtunnel.ProtocolStreaming || fromPort != 1234 || toPort != 5678 || !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded Data = protocol %d ports %d/%d payload %q", protocol, fromPort, toPort, decoded)
	}

	encoded, err := marshalDestinationDataTo(make([]byte, 256), streamtunnel.Delivery{
		Protocol: streamtunnel.ProtocolStreaming, FromPort: 1234, ToPort: 5678, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded[4:8], []byte{0x1f, 0x8b, 0x08, 0x00}) || encoded[13] != streamtunnel.ProtocolStreaming {
		t.Fatalf("I2CP gzip header = %x", encoded[4:14])
	}
	_, _, _, roundTrip, err := parseDestinationData(encoded)
	if err != nil || !bytes.Equal(roundTrip, payload) {
		t.Fatalf("stored-block round trip = %q, %v", roundTrip, err)
	}
}

func TestStreamingTunnelSenderLeaseSetGarlicTunnelDestination(t *testing.T) {
	const now = uint64(1_000)
	clientDestination, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	serverDestination, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	clientAddress, err := ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	serverAddress, err := ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}

	serverDestinations := NewDestinationManager()
	clientDestinations := NewDestinationManager()
	t.Cleanup(func() {
		_ = serverDestinations.Close()
		_ = clientDestinations.Close()
	})
	serverService := NewService(netdb.NewDatabase(ivnp.Hash{}, netdb.DefaultBucketCapacity))
	serverGarlic := garlic.NewSessionManager(garlic.SessionManagerConfig{})
	receiver, err := NewGarlicReceiver(GarlicReceiverConfig{
		Service: serverService,
		Destinations: map[ivnp.Hash]GarlicDestination{
			serverAddress.Hash: {Private: serverAddress.EncryptionPrivate, Sessions: serverGarlic},
		},
		ReplyKeys: garlic.NewReplyKeyRegistry(1),
		Now:       func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	serverService.SetGarlicSink(receiver.HandleGarlicFrom)
	serverService.SetDestinationSink(func(from, to ivnp.Hash, message i2np.Message) error {
		return receiver.HandleDestinationData(from, to, message, serverDestinations)
	})

	// The receiver's streaming reply takes the in-memory return path. The
	// forward packet below remains a complete LeaseSet -> Garlic -> tunnel path.
	serverSession, err := serverDestinations.Create(DestinationSessionConfig{Default: true, Streaming: streamtunnel.TunnelNetworkConfig{
		Destination: serverDestination,
		Sender: dataPlaneDirectSender(func(ctx context.Context, delivery streamtunnel.Delivery) error {
			return clientDestinations.HandleStreaming(ctx, delivery)
		}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverSession.ListenI2P(context.Background(), ":80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	leaseID, exitID, endpointID := uint32(71), uint32(72), uint32(73)
	finalRuntime := tunnel.NewRuntime(tunnel.RuntimeConfig{Now: func() uint64 { return now }})
	if err = finalRuntime.RegisterInbound(tunnel.InboundCircuit{
		ID: endpointID, Endpoint: tunnel.NewEndpoint(8, i2np.I2PDMaxFrame),
		Local: func(i2np.Message) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	finalBridge := &dataPlaneTunnelSender{handle: func(_ context.Context, message i2np.Message) error {
		return finalRuntime.Handle(message)
	}}
	destinationRuntime := tunnel.NewRuntime(tunnel.RuntimeConfig{Sender: finalBridge, Now: func() uint64 { return now }})
	if err = destinationRuntime.RegisterOutbound(tunnel.OutboundCircuit{ID: leaseID, FirstHop: ivnp.Hash{2}, NextTunnelID: endpointID}); err != nil {
		t.Fatal(err)
	}
	exitBridge := &dataPlaneTunnelSender{handle: func(_ context.Context, message i2np.Message) error {
		gateway, parseErr := i2np.ParseTunnelGateway(message.Payload)
		if parseErr != nil {
			return parseErr
		}
		return destinationRuntime.HandleGateway(gateway.TunnelID, gateway.Embedded)
	}}
	exitRuntime := tunnel.NewRuntime(tunnel.RuntimeConfig{Sender: exitBridge, Now: func() uint64 { return now }})
	if err = exitRuntime.RegisterInbound(tunnel.InboundCircuit{ID: exitID, Endpoint: tunnel.NewEndpoint(8, i2np.I2PDMaxFrame)}); err != nil {
		t.Fatal(err)
	}
	bridge := &dataPlaneTunnelSender{handle: func(_ context.Context, message i2np.Message) error {
		return exitRuntime.Handle(message)
	}}
	sourceRuntime := tunnel.NewRuntime(tunnel.RuntimeConfig{Sender: bridge, Now: func() uint64 { return now }})
	outboundID := uint32(74)
	if err = sourceRuntime.RegisterOutbound(tunnel.OutboundCircuit{ID: outboundID, FirstHop: ivnp.Hash{1}, NextTunnelID: exitID}); err != nil {
		t.Fatal(err)
	}
	pool := tunnel.NewPool(1)
	endpoint := ivnp.Hash{9}
	outboundEntry := tunnel.Entry{ID: outboundID, Direction: tunnel.Outbound, Expires: now + 120_000, HopCount: 1}
	outboundEntry.Hops[0] = endpoint
	if err = pool.Add(outboundEntry, now); err != nil {
		t.Fatal(err)
	}

	database := netdb.NewDatabase(clientAddress.Hash, netdb.DefaultBucketCapacity)
	storeLegacyLeaseSet(t, database, serverAddress, netdb.Lease{Gateway: ivnp.Hash{1}, TunnelID: leaseID, EndDate: now + 120_000})
	requests, err := netdb.NewRequestManager(database, dataPlaneRequestSender{}, dataPlaneReplyRoute{}, netdb.RequestManagerConfig{Capacity: 16, TimeoutMillis: 60_000, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	var nextID, seedCalls uint32
	var seededEndpoint, seededGateway ivnp.Hash
	sender, err := NewStreamingTunnelSender(StreamingTunnelSenderConfig{
		Database: database, Requests: requests, Garlic: garlic.NewSessionManager(garlic.SessionManagerConfig{}),
		Tunnels: sourceRuntime, Pool: pool, Now: func() uint64 { return now },
		SeedRouterInfo: func(_ context.Context, endpoint, gateway ivnp.Hash) error {
			seededEndpoint, seededGateway = endpoint, gateway
			seedCalls++
			return nil
		},
		NextID: func() (uint32, error) { nextID++; return nextID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery := streamtunnel.Delivery{
		From: clientDestination.Hash(), To: serverAddress.Hash, Protocol: streamtunnel.ProtocolStreaming, Payload: []byte("streaming"),
	}
	if err := sender.SendTunnel(context.Background(), delivery); err != nil {
		t.Fatal(err)
	}
	if err := sender.SendTunnel(context.Background(), delivery); err != nil {
		t.Fatal(err)
	}
	if seedCalls != 1 || seededEndpoint != endpoint || seededGateway != (ivnp.Hash{1}) {
		t.Fatalf("RouterInfo seed calls/endpoint/gateway = %d/%x/%x", seedCalls, seededEndpoint, seededGateway)
	}
	bridge.mu.Lock()
	decrypted := len(bridge.messages)
	bridge.mu.Unlock()
	if decrypted == 0 {
		t.Fatal("outbound tunnel did not carry the encrypted Garlic frame")
	}
}

func TestGarlicReceiverDeliversNewSessionReplyAndEstablishesExistingSession(t *testing.T) {
	const now = uint64(1_000_000)
	initiator, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	responder, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	initiatorHash, responderHash := initiator.Hash(), responder.Hash()
	responderKey := responder.X25519Public()
	left, err := garlic.NewRatchetManager(initiator, garlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	right, err := garlic.NewRatchetManager(responder, garlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		left.ReleaseSensitive()
		right.ReleaseSensitive()
		initiator.ReleaseSensitive()
		responder.ReleaseSensitive()
	})
	data, err := marshalDestinationDataTo(make([]byte, 256), streamtunnel.Delivery{
		From: initiatorHash, To: responderHash, Protocol: streamtunnel.ProtocolStreaming,
	})
	if err != nil {
		t.Fatal(err)
	}
	message := i2np.Message{Header: i2np.Header{Type: i2np.Data, ID: 1, Expiration: now + 1_000}, Payload: data}
	local, err := netdb.NewLocalLeaseSet2(initiator)
	if err != nil {
		t.Fatal(err)
	}
	if err = local.ReplaceInboundLeases([]netdb.Lease{{Gateway: ivnp.Hash{1}, TunnelID: 1, EndDate: now + 60_000}}); err != nil {
		t.Fatal(err)
	}
	set := make([]byte, netdb.MaxLeaseSetBytes)
	setLen, err := local.MarshalTo(set, now, initiator.Sign)
	if err != nil {
		t.Fatal(err)
	}
	storePayload, err := netdb.MarshalDatabaseStore(initiatorHash, i2np.StoreLeaseSet2, set[:setLen], 0, ivnp.Hash{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := i2np.Message{Header: i2np.Header{Type: i2np.DatabaseStore, ID: 2, Expiration: now + 1_000}, Payload: storePayload}
	static := initiator.X25519Public()
	observed := ivnp.Sum(static[:])
	if target, targetErr := ratchetReplyTarget([]garlic.Clove{{Delivery: garlic.Delivery{Type: garlic.DeliveryLocal}, Message: store}}, observed); targetErr != nil || target != initiatorHash {
		t.Fatalf("valid LS2 binding target = %x, %v", target, targetErr)
	}
	forgedPayload := append([]byte(nil), store.Payload...)
	forgedPayload[len(forgedPayload)-1] ^= 1
	forged := store
	forged.Payload = forgedPayload
	if _, targetErr := ratchetReplyTarget([]garlic.Clove{{Delivery: garlic.Delivery{Type: garlic.DeliveryLocal}, Message: forged}}, observed); !errors.Is(targetErr, ErrGarlicPacket) {
		t.Fatalf("forged LS2 binding error = %v, want %v", targetErr, ErrGarlicPacket)
	}
	payload := make([]byte, 2*netdb.MaxLeaseSetBytes)
	first, err := appendRatchetGarlicClove(payload, garlic.Delivery{Type: garlic.DeliveryLocal}, store)
	if err != nil {
		t.Fatal(err)
	}
	second, err := appendRatchetGarlicClove(payload[len(first):], garlic.Delivery{Type: garlic.DeliveryDestination, To: responderHash}, message)
	if err != nil {
		t.Fatal(err)
	}
	payload = payload[:len(first)+len(second)]

	packet, err := left.Encrypt(make([]byte, i2np.I2PDMaxPayload-4), responderHash, responderKey[:], uint16(ivnp.CryptoX25519), payload, now)
	if err != nil {
		t.Fatal(err)
	}
	outer := make([]byte, 4+len(packet))
	binary.BigEndian.PutUint32(outer[:4], uint32(len(packet)))
	copy(outer[4:], packet)
	service := NewService(netdb.NewDatabase(ivnp.Hash{}, netdb.DefaultBucketCapacity))
	service.SetDestinationSink(func(ivnp.Hash, ivnp.Hash, i2np.Message) error { return nil })
	var replyTarget ivnp.Hash
	var reply []byte
	receiver, err := NewGarlicReceiver(GarlicReceiverConfig{
		Service: service, ReplyKeys: garlic.NewReplyKeyRegistry(1), Now: func() uint64 { return now },
		Destinations: map[ivnp.Hash]GarlicDestination{responderHash: {
			Ratchet: right,
			SendRatchetReply: func(_ context.Context, target ivnp.Hash, packet []byte) error {
				replyTarget, reply = target, append([]byte(nil), packet...)
				return nil
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = receiver.HandleGarlic(i2np.Message{Header: i2np.Header{Type: i2np.Garlic}, Payload: outer}); err != nil {
		t.Fatal(err)
	}
	if replyTarget != initiatorHash || len(reply) == 0 {
		t.Fatal("authenticated New Session Reply was not routed to the initiator")
	}
	if _, err = left.Receive(make([]byte, len(reply)), make([]byte, len(reply)), reply, now); err != nil {
		t.Fatalf("initiator did not transition to Existing Session: %v", err)
	}
	existing, err := left.EncryptExisting(make([]byte, i2np.I2PDMaxPayload-4), responderHash, []byte{11, 0, 0}, garlic.RatchetOptions{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = right.Receive(make([]byte, len(existing)), make([]byte, len(existing)), existing, now); err != nil {
		t.Fatalf("responder rejected Existing Session: %v", err)
	}
}
func storeLegacyLeaseSet(t *testing.T, database *netdb.Database, address ivnp.LocalAddress, lease netdb.Lease) {
	t.Helper()
	raw, err := ivnp.DecodeI2PBase64(address.Destination)
	if err != nil {
		t.Fatal(err)
	}
	identity, used, err := ivnp.ParseIdentity(raw)
	if err != nil || used != len(raw) {
		t.Fatalf("parse destination identity = %v, used %d", err, used)
	}
	local, err := netdb.NewLocalLeaseSet(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = local.ReplaceInboundLeases([]netdb.Lease{lease}); err != nil {
		t.Fatal(err)
	}
	snapshot, ok := local.Snapshot(0)
	if !ok {
		t.Fatal("LeaseSet snapshot failed")
	}
	signingKey, rest := identity.SigningKeyParts()
	if len(rest) != 0 {
		t.Fatal("legacy LeaseSet test identity has split signing key")
	}
	payload := make([]byte, netdb.MaxLeaseSetBytes)
	n, err := snapshot.MarshalLegacy(payload, address.EncryptionPublic[:], signingKey, func(unsigned []byte) ([]byte, error) {
		return ed25519.Sign(address.SigningPrivate, unsigned), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	store := i2np.DatabaseStoreMessage{Key: address.Hash, Type: i2np.StoreLeaseSet, Data: payload[:n]}
	if err = database.HandleDatabaseStore(store, false, 1); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyGarlicSYNTeachesReceiverSenderLeaseSet(t *testing.T) {
	const now = uint64(1_000)
	senderAddress, err := ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	senderDatabase := netdb.NewDatabase(ivnp.Hash{}, netdb.DefaultBucketCapacity)
	storeLegacyLeaseSet(t, senderDatabase, senderAddress, netdb.Lease{
		Gateway: ivnp.Hash{1}, TunnelID: 7, EndDate: now + 120_000,
	})
	var nextID uint32
	sender := &StreamingTunnelSender{
		database: senderDatabase,
		nextID: func() (uint32, error) {
			nextID++
			return nextID, nil
		},
	}
	syn := make([]byte, streaming.HeaderLen)
	binary.BigEndian.PutUint16(syn[18:20], streamtunnel.FlagSynchronize)
	wire, err := sender.destinationCloveSetTo(make([]byte, i2np.I2PDMaxPayload), make([]byte, i2np.I2PDMaxPayload), streamtunnel.Delivery{
		From: senderAddress.Hash, To: ivnp.Hash{2}, Protocol: streamtunnel.ProtocolStreaming, Payload: syn,
	}, now+60_000)
	if err != nil {
		t.Fatal(err)
	}
	set, err := garlic.ParseCloveSet(wire)
	if err != nil {
		t.Fatal(err)
	}
	cloves := set.Cloves()
	first, ok, err := cloves.Next()
	if err != nil || !ok || first.Delivery.Type != garlic.DeliveryLocal || first.Message.Header.Type != i2np.DatabaseStore {
		t.Fatalf("first legacy SYN clove = %#v, %t, %v", first, ok, err)
	}

	receiverDatabase := netdb.NewDatabase(ivnp.Hash{}, netdb.DefaultBucketCapacity)
	service := NewService(receiverDatabase)
	service.SetDestinationSink(func(ivnp.Hash, ivnp.Hash, i2np.Message) error { return nil })
	if err = service.HandleGarlicCloveSet(set, now, false); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := receiverDatabase.StoredLeaseSet(senderAddress.Hash); !ok {
		t.Fatal("receiver did not learn the sender LeaseSet from legacy SYN")
	}
}

type dataPlaneSenderRef struct {
	target *StreamingTunnelSender
}

func (r *dataPlaneSenderRef) SendTunnel(ctx context.Context, delivery streamtunnel.Delivery) error {
	if r == nil || r.target == nil {
		return errors.New("streaming sender is not ready")
	}
	return r.target.SendTunnel(ctx, delivery)
}

type dataPlanePublicationLoop struct {
	mu       sync.Mutex
	database *netdb.Database
	now      uint64
	owner    *netdb.LeaseSetPublisher
	stores   []i2np.DatabaseStoreMessage
}

func (l *dataPlanePublicationLoop) Send(_ context.Context, _ netdb.RouterRef, message i2np.Message) error {
	store, err := i2np.ParseDatabaseStore(message.Payload)
	if err != nil {
		return err
	}
	if err = l.database.HandleDatabaseStore(store, false, l.now); err != nil {
		return err
	}
	l.mu.Lock()
	l.stores = append(l.stores, store)
	l.mu.Unlock()
	if l.owner == nil || !l.owner.HandleDeliveryStatus(i2np.DeliveryStatusMessage{MessageID: store.ReplyToken, Timestamp: l.now}) {
		return errors.New("publication confirmation was not correlated")
	}
	return nil
}

type dataPlaneReplyPath struct {
	gateway ivnp.Hash
	tunnel  uint32
}

func (r dataPlaneReplyPath) NetDBReplyPath() (ivnp.Hash, uint32, bool) {
	return r.gateway, r.tunnel, true
}

func TestProductionDestinationDataPlaneOverConfirmedLS2(t *testing.T) {
	const now = uint64(1_000_000)
	aDestination, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	bDestination, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		aDestination.ReleaseSensitive()
		bDestination.ReleaseSensitive()
	})

	aHash, bHash := aDestination.Hash(), bDestination.Hash()
	aRatchet, err := garlic.NewRatchetManager(aDestination, garlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	bRatchet, err := garlic.NewRatchetManager(bDestination, garlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		aRatchet.ReleaseSensitive()
		bRatchet.ReleaseSensitive()
	})

	aDestinations, bDestinations := NewDestinationManager(), NewDestinationManager()
	t.Cleanup(func() {
		_ = aDestinations.Close()
		_ = bDestinations.Close()
	})
	aService := NewService(netdb.NewDatabase(aHash, netdb.DefaultBucketCapacity))
	bService := NewService(netdb.NewDatabase(bHash, netdb.DefaultBucketCapacity))
	var aReceiver, bReceiver *GarlicReceiver
	aService.SetGarlicSink(func(_ I2NPSource, message i2np.Message) error { return aReceiver.HandleGarlic(message) })
	bService.SetGarlicSink(func(_ I2NPSource, message i2np.Message) error { return bReceiver.HandleGarlic(message) })
	aService.SetDestinationSink(func(from, to ivnp.Hash, message i2np.Message) error {
		return aReceiver.HandleDestinationData(from, to, message, aDestinations)
	})
	bService.SetDestinationSink(func(from, to ivnp.Hash, message i2np.Message) error {
		return bReceiver.HandleDestinationData(from, to, message, bDestinations)
	})

	aRuntime, bRuntime := tunnel.NewRuntime(tunnel.RuntimeConfig{Now: func() uint64 { return now }}), tunnel.NewRuntime(tunnel.RuntimeConfig{Now: func() uint64 { return now }})
	aPool, bPool := tunnel.NewOwnedPool(aHash, 2), tunnel.NewOwnedPool(bHash, 2)
	const (
		aOutbound = uint32(101)
		aExit     = uint32(102)
		aLease    = uint32(103)
		aFinal    = uint32(104)
		bOutbound = uint32(201)
		bExit     = uint32(202)
		bLease    = uint32(203)
		bFinal    = uint32(204)
	)
	aWire := &dataPlaneTunnelSender{}
	bWire := &dataPlaneTunnelSender{}
	aRuntime.SetSender(aWire)
	bRuntime.SetSender(bWire)
	aWire.handle = func(ctx context.Context, message i2np.Message) error {
		switch message.Header.Type {
		case i2np.TunnelData:
			return aRuntime.HandleContext(ctx, message)
		case i2np.TunnelGateway:
			gateway, parseErr := i2np.ParseTunnelGateway(message.Payload)
			if parseErr != nil {
				return parseErr
			}
			switch gateway.TunnelID {
			case aLease:
				return aRuntime.HandleGateway(gateway.TunnelID, gateway.Embedded)
			case bLease:
				return bRuntime.HandleGateway(gateway.TunnelID, gateway.Embedded)
			default:
				return errors.New("unknown A loopback lease")
			}
		default:
			return errors.New("unexpected A tunnel message")
		}
	}
	bWire.handle = func(ctx context.Context, message i2np.Message) error {
		switch message.Header.Type {
		case i2np.TunnelData:
			return bRuntime.HandleContext(ctx, message)
		case i2np.TunnelGateway:
			gateway, parseErr := i2np.ParseTunnelGateway(message.Payload)
			if parseErr != nil {
				return parseErr
			}
			switch gateway.TunnelID {
			case aLease:
				return aRuntime.HandleGateway(gateway.TunnelID, gateway.Embedded)
			case bLease:
				return bRuntime.HandleGateway(gateway.TunnelID, gateway.Embedded)
			default:
				return errors.New("unknown B loopback lease")
			}
		default:
			return errors.New("unexpected B tunnel message")
		}
	}
	for _, circuit := range []tunnel.OutboundCircuit{
		{ID: aOutbound, Owner: aHash, FirstHop: ivnp.Hash{1}, NextTunnelID: aExit},
		{ID: aLease, Owner: aHash, FirstHop: ivnp.Hash{2}, NextTunnelID: aFinal},
	} {
		if err := aRuntime.RegisterOutbound(circuit); err != nil {
			t.Fatal(err)
		}
	}
	for _, circuit := range []tunnel.OutboundCircuit{
		{ID: bOutbound, Owner: bHash, FirstHop: ivnp.Hash{3}, NextTunnelID: bExit},
		{ID: bLease, Owner: bHash, FirstHop: ivnp.Hash{4}, NextTunnelID: bFinal},
	} {
		if err := bRuntime.RegisterOutbound(circuit); err != nil {
			t.Fatal(err)
		}
	}
	for _, circuit := range []tunnel.InboundCircuit{
		{ID: aExit, Owner: aHash, Endpoint: tunnel.NewEndpoint(8, i2np.I2PDMaxFrame)},
		{ID: aFinal, Owner: aHash, Endpoint: tunnel.NewEndpoint(8, i2np.I2PDMaxFrame), Local: func(message i2np.Message) error { return aReceiver.HandleGarlic(message) }},
	} {
		if err := aRuntime.RegisterInbound(circuit); err != nil {
			t.Fatal(err)
		}
	}
	for _, circuit := range []tunnel.InboundCircuit{
		{ID: bExit, Owner: bHash, Endpoint: tunnel.NewEndpoint(8, i2np.I2PDMaxFrame)},
		{ID: bFinal, Owner: bHash, Endpoint: tunnel.NewEndpoint(8, i2np.I2PDMaxFrame), Local: func(message i2np.Message) error { return bReceiver.HandleGarlic(message) }},
	} {
		if err := bRuntime.RegisterInbound(circuit); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []tunnel.Entry{
		{ID: aOutbound, Direction: tunnel.Outbound, Expires: now + 60_000, Owner: aHash},
		{ID: aLease, Direction: tunnel.Inbound, Expires: now + 60_000, Owner: aHash},
	} {
		if err := aPool.Add(entry, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []tunnel.Entry{
		{ID: bOutbound, Direction: tunnel.Outbound, Expires: now + 60_000, Owner: bHash},
		{ID: bLease, Direction: tunnel.Inbound, Expires: now + 60_000, Owner: bHash},
	} {
		if err := bPool.Add(entry, now); err != nil {
			t.Fatal(err)
		}
	}

	aDatabase := netdb.NewDatabase(aHash, netdb.DefaultBucketCapacity)
	bDatabase := netdb.NewDatabase(bHash, netdb.DefaultBucketCapacity)
	for range netdb.PublicationFloodfillK {
		if err := aDatabase.AdmitRouterInfo(dataPlaneFloodfill(t), true, now); err != nil {
			t.Fatal(err)
		}
		if err := bDatabase.AdmitRouterInfo(dataPlaneFloodfill(t), true, now); err != nil {
			t.Fatal(err)
		}
	}

	aLocal, err := netdb.NewLocalLeaseSet2(aDestination)
	if err != nil {
		t.Fatal(err)
	}
	bLocal, err := netdb.NewLocalLeaseSet2(bDestination)
	if err != nil {
		t.Fatal(err)
	}
	aPublication := &dataPlanePublicationLoop{database: bDatabase, now: now}
	bPublication := &dataPlanePublicationLoop{database: aDatabase, now: now}
	aPublisher, err := netdb.NewLeaseSetPublisher(netdb.LeaseSetPublisherConfig{
		Local2: aLocal, Database: aDatabase, InboundLeases: netdb.InboundLeaseSourceFunc(func(uint64) []netdb.Lease {
			return []netdb.Lease{{Gateway: ivnp.Hash{2}, TunnelID: aLease, EndDate: now + 60_000}}
		}), Sender: aPublication, Sign: aDestination.Sign, Now: func() uint64 { return now }, Random: func() uint32 { return 11 },
		FloodfillLimit: netdb.PublicationFloodfillK, ReplyPath: dataPlaneReplyPath{gateway: aHash, tunnel: aLease},
	})
	if err != nil {
		t.Fatal(err)
	}
	bPublisher, err := netdb.NewLeaseSetPublisher(netdb.LeaseSetPublisherConfig{
		Local2: bLocal, Database: bDatabase, InboundLeases: netdb.InboundLeaseSourceFunc(func(uint64) []netdb.Lease {
			return []netdb.Lease{{Gateway: ivnp.Hash{4}, TunnelID: bLease, EndDate: now + 60_000}}
		}), Sender: bPublication, Sign: bDestination.Sign, Now: func() uint64 { return now }, Random: func() uint32 { return 21 },
		FloodfillLimit: netdb.PublicationFloodfillK, ReplyPath: dataPlaneReplyPath{gateway: bHash, tunnel: bLease},
	})
	if err != nil {
		t.Fatal(err)
	}
	aPublication.owner, bPublication.owner = aPublisher, bPublisher
	t.Cleanup(func() {
		aPublisher.Close()
		bPublisher.Close()
	})
	if sent, err := aPublisher.Publish(context.Background()); err != nil || sent != netdb.PublicationFloodfillK {
		t.Fatalf("publish A = %d, %v", sent, err)
	}
	if sent, err := bPublisher.Publish(context.Background()); err != nil || sent != netdb.PublicationFloodfillK {
		t.Fatalf("publish B = %d, %v", sent, err)
	}
	for _, publication := range []struct {
		hash   ivnp.Hash
		stores []i2np.DatabaseStoreMessage
	}{{aHash, aPublication.stores}, {bHash, bPublication.stores}} {
		if len(publication.stores) != netdb.PublicationFloodfillK {
			t.Fatalf("publication count = %d", len(publication.stores))
		}
		for _, store := range publication.stores {
			if store.Key != publication.hash || store.Type != i2np.StoreLeaseSet2 || store.ReplyToken == 0 || store.ReplyToken&(uint32(1)<<31) != 0 {
				t.Fatalf("uncorrelated LS2 publication = %#v", store)
			}
		}
	}
	if _, ok := aDatabase.LeaseSet2(bHash); !ok {
		t.Fatal("A NetDB did not resolve B signed LS2")
	}
	if _, ok := bDatabase.LeaseSet2(aHash); !ok {
		t.Fatal("B NetDB did not resolve A signed LS2")
	}

	aRequests, err := netdb.NewRequestManager(aDatabase, dataPlaneRequestSender{}, dataPlaneReplyRoute{}, netdb.RequestManagerConfig{Capacity: 4, TimeoutMillis: 60_000, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	bRequests, err := netdb.NewRequestManager(bDatabase, dataPlaneRequestSender{}, dataPlaneReplyRoute{}, netdb.RequestManagerConfig{Capacity: 4, TimeoutMillis: 60_000, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	aSender, err := NewStreamingTunnelSender(StreamingTunnelSenderConfig{Database: aDatabase, Requests: aRequests, Ratchet: aRatchet, Tunnels: aRuntime, Pool: aPool, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	bSender, err := NewStreamingTunnelSender(StreamingTunnelSenderConfig{Database: bDatabase, Requests: bRequests, Ratchet: bRatchet, Tunnels: bRuntime, Pool: bPool, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	aRef, bRef := &dataPlaneSenderRef{target: aSender}, &dataPlaneSenderRef{target: bSender}
	aSession, err := aDestinations.Create(DestinationSessionConfig{Default: true, Streaming: streamtunnel.TunnelNetworkConfig{Destination: aDestination, Sender: aRef}})
	if err != nil {
		t.Fatal(err)
	}
	bSession, err := bDestinations.Create(DestinationSessionConfig{Default: true, Streaming: streamtunnel.TunnelNetworkConfig{Destination: bDestination, Sender: bRef}})
	if err != nil {
		t.Fatal(err)
	}
	aReceiver, err = NewGarlicReceiver(GarlicReceiverConfig{Service: aService, ReplyKeys: garlic.NewReplyKeyRegistry(4), Now: func() uint64 { return now }, Destinations: map[ivnp.Hash]GarlicDestination{
		aHash: {Ratchet: aRatchet, SendRatchetReply: aSender.SendRatchetReply},
	}})
	if err != nil {
		t.Fatal(err)
	}
	bReceiver, err = NewGarlicReceiver(GarlicReceiverConfig{Service: bService, ReplyKeys: garlic.NewReplyKeyRegistry(4), Now: func() uint64 { return now }, Destinations: map[ivnp.Hash]GarlicDestination{
		bHash: {Ratchet: bRatchet, SendRatchetReply: bSender.SendRatchetReply},
	}})
	if err != nil {
		t.Fatal(err)
	}

	listener, err := bSession.ListenI2P(context.Background(), ":80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	aConnection, err := aSession.DialI2P(ctx, bSession.B32()+":80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aConnection.Close() })
	var bConnection net.Conn
	select {
	case bConnection = <-accepted:
	case <-ctx.Done():
		t.Fatal("B did not accept A streaming connection")
	}
	t.Cleanup(func() { _ = bConnection.Close() })
	if _, err = aConnection.Write([]byte("A-to-B")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("A-to-B"))
	if _, err = io.ReadFull(bConnection, got); err != nil || !bytes.Equal(got, []byte("A-to-B")) {
		t.Fatalf("B application bytes = %q, %v", got, err)
	}
	if _, err = bConnection.Write([]byte("B-to-A")); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len("B-to-A"))
	if _, err = io.ReadFull(aConnection, got); err != nil || !bytes.Equal(got, []byte("B-to-A")) {
		t.Fatalf("A application bytes = %q, %v", got, err)
	}
	aRatchetState, bRatchetState := aRatchet.Stats(), bRatchet.Stats()
	if aRatchetState.Sessions != 1 || aRatchetState.Pending != 0 || aRatchetState.NewSessionReplies != 1 || aRatchetState.ExistingSessions == 0 || aRatchetState.InboundTags == 0 {
		t.Fatalf("A ratchet did not complete NS/NSR/Existing transition: %#v", aRatchetState)
	}
	if bRatchetState.Sessions != 1 || bRatchetState.Pending != 0 || bRatchetState.NewSessions != 1 || bRatchetState.ExistingSessions == 0 || bRatchetState.InboundTags == 0 {
		t.Fatalf("B ratchet did not complete NS/NSR/Existing transition: %#v", bRatchetState)
	}
	aStreaming, bStreaming := aSession.StreamingStats(), bSession.StreamingStats()
	if aStreaming.Connections != 1 || aStreaming.CongestionWindow == 0 || bStreaming.Connections != 1 || bStreaming.CongestionWindow == 0 {
		t.Fatalf("streaming congestion state A=%#v B=%#v", aStreaming, bStreaming)
	}
	aWire.mu.Lock()
	aTunnelMessages := len(aWire.messages)
	aWire.mu.Unlock()
	bWire.mu.Lock()
	bTunnelMessages := len(bWire.messages)
	bWire.mu.Unlock()
	if aTunnelMessages == 0 || bTunnelMessages == 0 {
		t.Fatalf("bidirectional Garlic traffic was not tunneled: A=%d B=%d", aTunnelMessages, bTunnelMessages)
	}
	if owner, ok := aRuntime.CircuitOwner(aOutbound); !ok || owner != aHash {
		t.Fatalf("A outbound owner = %x, %t", owner, ok)
	}
	if owner, ok := bRuntime.CircuitOwner(bOutbound); !ok || owner != bHash {
		t.Fatalf("B outbound owner = %x, %t", owner, ok)
	}
	if _, ok := bRuntime.CircuitOwner(aOutbound); ok || aPool.Owner() != aHash || bPool.Owner() != bHash {
		t.Fatal("destination tunnel ownership is not isolated")
	}

	if err := aDestinations.Destroy(aHash); err != nil {
		t.Fatal(err)
	}
	if cleared := aPool.Clear(); len(cleared) != 2 {
		t.Fatalf("A pool clear = %v", cleared)
	}
	aRuntime.RemoveOwner(aHash)
	if aPool.Count(tunnel.Outbound, now) != 0 {
		t.Fatal("destroyed A retained an outbound tunnel")
	}
	if _, ok := aRuntime.CircuitOwner(aOutbound); ok {
		t.Fatal("destroyed A retained a runtime circuit")
	}
	if bPool.Count(tunnel.Outbound, now) != 1 {
		t.Fatal("destroying A changed B's pool")
	}
	if owner, ok := bRuntime.CircuitOwner(bOutbound); !ok || owner != bHash {
		t.Fatalf("destroying A changed B's runtime circuit owner = %x, %t", owner, ok)
	}
	if live, ok := bDestinations.Session(bHash); !ok || live != bSession {
		t.Fatal("destroying A removed B's streaming endpoint")
	}
	if state := bSession.StreamingStats(); state.Connections != 1 || state.CongestionWindow == 0 {
		t.Fatalf("destroying A changed B's live send/receive congestion state: %#v", state)
	}
}

func dataPlaneFloodfill(t *testing.T) netdb.RouterInfo {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := make([]byte, ivnp.IdentityBaseLength+7)
	copy(identity[352:384], public)
	identity[384] = byte(ivnp.CertificateKey)
	identity[385], identity[386] = 0, 4
	identity[387], identity[388] = 0, byte(ivnp.SigningEdDSASHA512Ed25519)
	identity[389], identity[390] = 0, byte(ivnp.CryptoElGamal)
	options := make([]byte, 16)
	optionLen, err := ivnp.MarshalMappingTo(options, []ivnp.MappingEntry{{Key: []byte("caps"), Value: []byte("f")}})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := append(identity, make([]byte, 10)...)
	unsigned = append(unsigned, options[:optionLen]...)
	info, err := netdb.ParseRouterInfo(append(unsigned, ed25519.Sign(private, unsigned)...))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestGarlicReceiverConstructorFailureDoesNotReturnSensitiveOwner(t *testing.T) {
	hash := ivnp.Sum([]byte("invalid-garlic-destination"))
	receiver, err := NewGarlicReceiver(GarlicReceiverConfig{
		Service: NewWithSinks(nil, Sinks{}), ReplyKeys: garlic.NewReplyKeyRegistry(1),
		Now: func() uint64 { return 1 }, StaticPrivate: bytes.Repeat([]byte{0x42}, 32),
		Destinations: map[ivnp.Hash]GarlicDestination{hash: {}},
	})
	if !errors.Is(err, ErrDataPlaneConfig) || receiver != nil {
		t.Fatalf("NewGarlicReceiver partial failure = %#v, %v", receiver, err)
	}
}
func TestGarlicReceiverUnregisterWaitsForInflightAndReleasesStaticKey(t *testing.T) {
	local, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer local.ReleaseSensitive()
	ratchet, err := garlic.NewRatchetManager(local, garlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer ratchet.ReleaseSensitive()
	static := bytes.Repeat([]byte{0x42}, 32)
	receiver, err := NewGarlicReceiver(GarlicReceiverConfig{
		Service: NewWithSinks(nil, Sinks{}), ReplyKeys: garlic.NewReplyKeyRegistry(1),
		Now: func() uint64 { return 1_800_000_000_000 }, StaticPrivate: static,
	})
	if err != nil {
		t.Fatal(err)
	}
	remove, err := receiver.RegisterDestination(local.Hash(), GarlicDestination{Ratchet: ratchet})
	if err != nil {
		t.Fatal(err)
	}
	receiver.destinationsMu.RLock()
	state := receiver.destinations[local.Hash()]
	receiver.destinationsMu.RUnlock()
	heldScratch := make([]*garlicReceiveScratch, 0, cap(state.scratch))
	for range cap(state.scratch) {
		heldScratch = append(heldScratch, <-state.scratch)
	}
	payload := make([]byte, 4+64)
	binary.BigEndian.PutUint32(payload[:4], 64)
	handleDone := make(chan struct{})
	go func() {
		_ = receiver.HandleGarlic(i2np.Message{Header: i2np.Header{Type: i2np.Garlic}, Payload: payload})
		close(handleDone)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		state.inFlightMu.Lock()
		inFlight := state.inFlight
		state.inFlightMu.Unlock()
		if inFlight == 1 {
			break
		}
		if time.Now().After(deadline) {
			for _, scratch := range heldScratch {
				state.scratch <- scratch
			}
			t.Fatal("garlic handler never acquired its destination snapshot")
		}
		time.Sleep(time.Millisecond)
	}
	removeDone := make(chan struct{})
	go func() {
		remove()
		close(removeDone)
	}()
	select {
	case <-removeDone:
		for _, scratch := range heldScratch {
			state.scratch <- scratch
		}
		t.Fatal("destination unregister returned during in-flight receive")
	case <-time.After(20 * time.Millisecond):
	}
	for _, scratch := range heldScratch {
		state.scratch <- scratch
	}
	select {
	case <-handleDone:
	case <-time.After(time.Second):
		t.Fatal("garlic receive did not finish")
	}
	select {
	case <-removeDone:
	case <-time.After(time.Second):
		t.Fatal("destination unregister did not pass its in-flight barrier")
	}
	receiver.ReleaseSensitive()
	receiver.ReleaseSensitive()
	if !receiver.released || receiver.hasStatic || receiver.staticPrivate != ([32]byte{}) || len(receiver.destinations) != 0 {
		t.Fatal("garlic receiver retained sensitive static or destination state")
	}
}

func TestStreamingTunnelSenderReleaseClearsRemoteELSContext(t *testing.T) {
	remote, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer remote.ReleaseSensitive()
	identity, err := remote.Identity()
	if err != nil {
		t.Fatal(err)
	}
	hash := identity.Hash()
	var psk [32]byte
	psk[0] = 7
	sender := new(StreamingTunnelSender)
	if err = sender.UpdateRemoteELS(map[ivnp.Hash]RemoteELSContext{
		hash: {Identity: identity, Secret: []byte("remote-secret"), Authorization: netdb.ELSClientAuthorization{UsePSK: true, PSK: psk}},
	}); err != nil {
		t.Fatal(err)
	}
	secret := sender.remoteELS[hash].Secret
	sender.ReleaseSensitive()
	sender.ReleaseSensitive()
	for _, value := range secret {
		if value != 0 {
			t.Fatal("streaming sender retained remote ELS secret")
		}
	}
	if !sender.released || sender.remoteELS != nil {
		t.Fatal("streaming sender retained remote ELS policy table")
	}
	if err = sender.UpdateRemoteELS(nil); !errors.Is(err, ErrDataPlaneConfig) {
		t.Fatalf("UpdateRemoteELS after release = %v", err)
	}
}
