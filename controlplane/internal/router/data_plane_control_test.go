package router

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	controlplanetunnel "gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

type controlPlaneTunnelSender struct {
	mu       sync.Mutex
	handle   func(context.Context, foundation.I2NPMessage) error
	messages []foundation.I2NPMessage
}

func (s *controlPlaneTunnelSender) Send(ctx context.Context, _ foundation.Hash, message foundation.I2NPMessage) error {
	copyMessage := foundation.I2NPMessage{Header: message.Header, Payload: append([]byte(nil), message.Payload...)}
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

func (dataPlaneRequestSender) Send(context.Context, controlplanenetdb.RouterRef, foundation.I2NPMessage) error {
	return errors.New("unexpected LeaseSet lookup")
}

type dataPlaneReplyRoute struct{}

func (dataPlaneReplyRoute) DatabaseLookupReplyRoute() (foundation.Hash, uint32, bool) {
	return foundation.Hash{1}, 1, true
}

type controlPlaneDirectSender func(context.Context, dataplane.StreamingTunnelDelivery) error

func (f controlPlaneDirectSender) SendTunnel(ctx context.Context, delivery dataplane.StreamingTunnelDelivery) error {
	return f(ctx, delivery)
}
func TestSelectLease2RotatesAcrossUsableLeases(t *testing.T) {
	const now = uint64(1_750_000_000_000)
	destination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()

	local, err := controlplanenetdb.NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err = local.ReplaceInboundLeases([]foundation.NetworkDatabaseLease{
		{Gateway: foundation.Hash{1}, TunnelID: 11, EndDate: now + 60_000},
		{Gateway: foundation.Hash{2}, TunnelID: 22, EndDate: now - 1_000},
		{Gateway: foundation.Hash{3}, TunnelID: 33, EndDate: now + 120_000},
	}); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, foundation.NetworkDatabaseMaxLeaseSetBytes)
	n, err := local.MarshalTo(wire, now-60_000, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	set, err := foundation.NetworkDatabaseParseLeaseSet2(wire[:n])
	if err != nil {
		t.Fatal(err)
	}

	for pick, want := range []uint32{11, 33, 11} {
		lease, selectErr := selectLease2(set, now, uint64(pick))
		if selectErr != nil {
			t.Fatal(selectErr)
		}
		if lease.TunnelID != want {
			t.Fatalf("pick %d selected tunnel %d, want %d", pick, lease.TunnelID, want)
		}
	}
}
func TestStreamingTunnelSenderLeaseSetGarlicTunnelDestination(t *testing.T) {
	const now = uint64(1_000)
	clientDestination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	serverDestination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	clientAddress, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	serverAddress, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}

	serverDestinations := dataplane.RouterNewDestinationManager()
	clientDestinations := dataplane.RouterNewDestinationManager()
	t.Cleanup(func() {
		_ = serverDestinations.Close()
		_ = clientDestinations.Close()
	})
	serverService, _ := newControlTestService(t, controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity))
	serverGarlic := dataplane.GarlicNewSessionManager(dataplane.GarlicSessionManagerConfig{})
	receiver, err := dataplane.RouterNewGarlicReceiver(dataplane.RouterGarlicReceiverConfig{
		Service: serverService,
		Destinations: map[foundation.Hash]dataplane.RouterGarlicDestination{
			serverAddress.Hash: {Private: serverAddress.EncryptionPrivate, Sessions: serverGarlic},
		},
		ReplyKeys: dataplane.GarlicNewReplyKeyRegistry(1),
		Now:       func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	serverService.SetGarlicSink(receiver.HandleGarlicFrom)
	serverService.SetDestinationSink(func(from, to foundation.Hash, message foundation.I2NPMessage) error {
		return receiver.HandleDestinationData(from, to, message, serverDestinations)
	})

	// The receiver's streaming reply takes the in-memory return path. The
	// forward packet below remains a complete LeaseSet -> Garlic -> tunnel path.
	serverSession, err := serverDestinations.Create(dataplane.RouterDestinationSessionConfig{Default: true, Streaming: dataplane.StreamingTunnelTunnelNetworkConfig{
		Destination: serverDestination,
		Sender: controlPlaneDirectSender(func(ctx context.Context, delivery dataplane.StreamingTunnelDelivery) error {
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
	finalRuntime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Now: func() uint64 { return now }})
	if _, err = finalRuntime.RegisterInbound(dataplane.TunnelInboundCircuit{
		ID: endpointID, Endpoint: dataplane.TunnelNewEndpoint(8, foundation.I2NPI2PDMaxFrame),
		Local: func(foundation.I2NPMessage) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	finalBridge := &controlPlaneTunnelSender{handle: func(_ context.Context, message foundation.I2NPMessage) error {
		return finalRuntime.Handle(message)
	}}
	destinationRuntime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: finalBridge, Now: func() uint64 { return now }})
	if _, err = destinationRuntime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: leaseID, FirstHop: foundation.Hash{2}, NextTunnelID: endpointID}); err != nil {
		t.Fatal(err)
	}
	exitBridge := &controlPlaneTunnelSender{handle: func(_ context.Context, message foundation.I2NPMessage) error {
		gateway, parseErr := foundation.I2NPParseTunnelGateway(message.Payload)
		if parseErr != nil {
			return parseErr
		}
		return destinationRuntime.HandleGateway(gateway.TunnelID, gateway.Embedded)
	}}
	exitRuntime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: exitBridge, Now: func() uint64 { return now }})
	if _, err = exitRuntime.RegisterInbound(dataplane.TunnelInboundCircuit{ID: exitID, Endpoint: dataplane.TunnelNewEndpoint(8, foundation.I2NPI2PDMaxFrame)}); err != nil {
		t.Fatal(err)
	}
	bridge := &controlPlaneTunnelSender{handle: func(_ context.Context, message foundation.I2NPMessage) error {
		return exitRuntime.Handle(message)
	}}
	sourceRuntime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: bridge, Now: func() uint64 { return now }})
	outboundID := uint32(74)
	sourceToken, err := sourceRuntime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: outboundID, Owner: clientDestination.Hash(), FirstHop: foundation.Hash{1}, NextTunnelID: exitID})
	if err != nil {
		t.Fatal(err)
	}
	pool := controlplanetunnel.NewOwnedPool(clientDestination.Hash(), 1)
	endpoint := foundation.Hash{9}
	outboundEntry := controlplanetunnel.Entry{ID: outboundID, Circuit: sourceToken, Owner: clientDestination.Hash(), Direction: controlplanetunnel.Outbound, Expires: now + 120_000, HopCount: 1}
	outboundEntry.Hops[0] = endpoint
	if err = pool.Add(outboundEntry, now); err != nil {
		t.Fatal(err)
	}

	database := controlplanenetdb.NewDatabase(clientAddress.Hash, controlplanenetdb.DefaultBucketCapacity)
	storeControlLegacyLeaseSet(t, database, serverAddress, foundation.NetworkDatabaseLease{Gateway: foundation.Hash{1}, TunnelID: leaseID, EndDate: now + 120_000})
	requests, err := controlplanenetdb.NewRequestManager(database, dataPlaneRequestSender{}, dataPlaneReplyRoute{}, controlplanenetdb.RequestManagerConfig{Capacity: 16, TimeoutMillis: 60_000, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	var nextID, seedCalls uint32
	var seededEndpoint, seededGateway foundation.Hash
	sender, err := NewStreamingTunnelSender(StreamingTunnelSenderConfig{
		Owner:    clientDestination.Hash(),
		Database: database, Requests: requests, Garlic: dataplane.GarlicNewSessionManager(dataplane.GarlicSessionManagerConfig{}),
		Tunnels: sourceRuntime, Pool: pool, Now: func() uint64 { return now },
		SeedRouterInfo: func(_ context.Context, endpoint, gateway foundation.Hash) error {
			seededEndpoint, seededGateway = endpoint, gateway
			seedCalls++
			return nil
		},
		NextID: func() (uint32, error) { nextID++; return nextID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery := dataplane.StreamingTunnelDelivery{
		From: clientDestination.Hash(), To: serverAddress.Hash, Protocol: dataplane.StreamingTunnelProtocolStreaming, Payload: []byte("streaming"),
	}
	if err := sender.SendTunnel(context.Background(), delivery); err != nil {
		t.Fatal(err)
	}
	if err := sender.SendTunnel(context.Background(), delivery); err != nil {
		t.Fatal(err)
	}
	if seedCalls != 1 || seededEndpoint != endpoint || seededGateway != (foundation.Hash{1}) {
		t.Fatalf("RouterInfo seed calls/endpoint/gateway = %d/%x/%x", seedCalls, seededEndpoint, seededGateway)
	}
	bridge.mu.Lock()
	decrypted := len(bridge.messages)
	bridge.mu.Unlock()
	if decrypted == 0 {
		t.Fatal("outbound tunnel did not carry the encrypted Garlic frame")
	}
}
func storeControlLegacyLeaseSet(t *testing.T, database *controlplanenetdb.Database, address foundation.LocalAddress, leases ...foundation.NetworkDatabaseLease) {
	t.Helper()
	raw, err := foundation.DecodeI2PBase64(address.Destination)
	if err != nil {
		t.Fatal(err)
	}
	identity, used, err := foundation.ParseIdentity(raw)
	if err != nil || used != len(raw) {
		t.Fatalf("parse destination identity = %v, used %d", err, used)
	}
	local, err := controlplanenetdb.NewLocalLeaseSet(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = local.ReplaceInboundLeases(leases); err != nil {
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
	payload := make([]byte, foundation.NetworkDatabaseMaxLeaseSetBytes)
	n, err := snapshot.MarshalLegacy(payload, address.EncryptionPublic[:], signingKey, func(unsigned []byte) ([]byte, error) {
		return ed25519.Sign(address.SigningPrivate, unsigned), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	store := foundation.I2NPDatabaseStoreMessage{Key: address.Hash, Type: foundation.I2NPStoreLeaseSet, Data: payload[:n]}
	if err = database.HandleDatabaseStore(store, false, 1); err != nil {
		t.Fatal(err)
	}
}

type dataPlaneSenderRef struct {
	target *StreamingTunnelSender
}

func (r *dataPlaneSenderRef) SendTunnel(ctx context.Context, delivery dataplane.StreamingTunnelDelivery) error {
	if r == nil || r.target == nil {
		return errors.New("streaming sender is not ready")
	}
	return r.target.SendTunnel(ctx, delivery)
}

type dataPlanePublicationLoop struct {
	mu       sync.Mutex
	database *controlplanenetdb.Database
	now      uint64
	owner    *controlplanenetdb.LeaseSetPublisher
	stores   []foundation.I2NPDatabaseStoreMessage
}

func (l *dataPlanePublicationLoop) Send(_ context.Context, _ controlplanenetdb.RouterRef, message foundation.I2NPMessage) error {
	store, err := foundation.I2NPParseDatabaseStore(message.Payload)
	if err != nil {
		return err
	}
	if err = l.database.HandleDatabaseStore(store, false, l.now); err != nil {
		return err
	}
	l.mu.Lock()
	l.stores = append(l.stores, store)
	l.mu.Unlock()
	if l.owner == nil || !l.owner.HandleDeliveryStatus(foundation.I2NPDeliveryStatusMessage{MessageID: store.ReplyToken, Timestamp: l.now}) {
		return errors.New("publication confirmation was not correlated")
	}
	return nil
}

type dataPlaneReplyPath struct {
	gateway foundation.Hash
	tunnel  uint32
}

func (r dataPlaneReplyPath) NetDBReplyPath() (foundation.Hash, uint32, bool) {
	return r.gateway, r.tunnel, true
}

func TestProductionDestinationDataPlaneOverConfirmedLS2(t *testing.T) {
	const now = uint64(1_000_000)
	aDestination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	bDestination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		aDestination.ReleaseSensitive()
		bDestination.ReleaseSensitive()
	})

	aHash, bHash := aDestination.Hash(), bDestination.Hash()
	aRatchet, err := dataplane.GarlicNewRatchetManager(aDestination, dataplane.GarlicRatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	bRatchet, err := dataplane.GarlicNewRatchetManager(bDestination, dataplane.GarlicRatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		aRatchet.ReleaseSensitive()
		bRatchet.ReleaseSensitive()
	})

	aDestinations, bDestinations := dataplane.RouterNewDestinationManager(), dataplane.RouterNewDestinationManager()
	t.Cleanup(func() {
		_ = aDestinations.Close()
		_ = bDestinations.Close()
	})
	aService, aControl := newControlTestService(t, controlplanenetdb.NewDatabase(aHash, controlplanenetdb.DefaultBucketCapacity))
	bService, bControl := newControlTestService(t, controlplanenetdb.NewDatabase(bHash, controlplanenetdb.DefaultBucketCapacity))
	var aReceiver, bReceiver *dataplane.RouterGarlicReceiver
	aService.SetGarlicSink(func(_ dataplane.RouterI2NPSource, message foundation.I2NPMessage) error {
		return aReceiver.HandleGarlic(message)
	})
	bService.SetGarlicSink(func(_ dataplane.RouterI2NPSource, message foundation.I2NPMessage) error {
		return bReceiver.HandleGarlic(message)
	})
	aService.SetDestinationSink(func(from, to foundation.Hash, message foundation.I2NPMessage) error {
		return aReceiver.HandleDestinationData(from, to, message, aDestinations)
	})
	bService.SetDestinationSink(func(from, to foundation.Hash, message foundation.I2NPMessage) error {
		return bReceiver.HandleDestinationData(from, to, message, bDestinations)
	})

	aRuntime, bRuntime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Now: func() uint64 { return now }}), dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Now: func() uint64 { return now }})
	aPool, bPool := controlplanetunnel.NewOwnedPool(aHash, 2), controlplanetunnel.NewOwnedPool(bHash, 2)
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
	aWire := &controlPlaneTunnelSender{}
	bWire := &controlPlaneTunnelSender{}
	aRuntime.SetSender(aWire)
	bRuntime.SetSender(bWire)
	aWire.handle = func(ctx context.Context, message foundation.I2NPMessage) error {
		switch message.Header.Type {
		case foundation.I2NPTunnelData:
			return aRuntime.HandleContext(ctx, message)
		case foundation.I2NPTunnelGateway:
			gateway, parseErr := foundation.I2NPParseTunnelGateway(message.Payload)
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
	bWire.handle = func(ctx context.Context, message foundation.I2NPMessage) error {
		switch message.Header.Type {
		case foundation.I2NPTunnelData:
			return bRuntime.HandleContext(ctx, message)
		case foundation.I2NPTunnelGateway:
			gateway, parseErr := foundation.I2NPParseTunnelGateway(message.Payload)
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
	for _, circuit := range []dataplane.TunnelOutboundCircuit{
		{ID: aOutbound, Owner: aHash, FirstHop: foundation.Hash{1}, NextTunnelID: aExit},
		{ID: aLease, Owner: aHash, FirstHop: foundation.Hash{2}, NextTunnelID: aFinal},
	} {
		if _, err := aRuntime.RegisterOutbound(circuit); err != nil {
			t.Fatal(err)
		}
	}
	for _, circuit := range []dataplane.TunnelOutboundCircuit{
		{ID: bOutbound, Owner: bHash, FirstHop: foundation.Hash{3}, NextTunnelID: bExit},
		{ID: bLease, Owner: bHash, FirstHop: foundation.Hash{4}, NextTunnelID: bFinal},
	} {
		if _, err := bRuntime.RegisterOutbound(circuit); err != nil {
			t.Fatal(err)
		}
	}
	for _, circuit := range []dataplane.TunnelInboundCircuit{
		{ID: aExit, Owner: aHash, Endpoint: dataplane.TunnelNewEndpoint(8, foundation.I2NPI2PDMaxFrame)},
		{ID: aFinal, Owner: aHash, Endpoint: dataplane.TunnelNewEndpoint(8, foundation.I2NPI2PDMaxFrame), Local: func(message foundation.I2NPMessage) error { return aReceiver.HandleGarlic(message) }},
	} {
		if _, err := aRuntime.RegisterInbound(circuit); err != nil {
			t.Fatal(err)
		}
	}
	for _, circuit := range []dataplane.TunnelInboundCircuit{
		{ID: bExit, Owner: bHash, Endpoint: dataplane.TunnelNewEndpoint(8, foundation.I2NPI2PDMaxFrame)},
		{ID: bFinal, Owner: bHash, Endpoint: dataplane.TunnelNewEndpoint(8, foundation.I2NPI2PDMaxFrame), Local: func(message foundation.I2NPMessage) error { return bReceiver.HandleGarlic(message) }},
	} {
		if _, err := bRuntime.RegisterInbound(circuit); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []controlplanetunnel.Entry{
		{ID: aOutbound, Direction: controlplanetunnel.Outbound, Expires: now + 60_000, Owner: aHash},
		{ID: aLease, Direction: controlplanetunnel.Inbound, Expires: now + 60_000, Owner: aHash},
	} {
		installed, ok := aRuntime.InspectCircuit(entry.ID)
		if !ok {
			t.Fatal("missing A circuit installation")
		}
		entry.Circuit = installed.Token
		if err := aPool.Add(entry, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []controlplanetunnel.Entry{
		{ID: bOutbound, Direction: controlplanetunnel.Outbound, Expires: now + 60_000, Owner: bHash},
		{ID: bLease, Direction: controlplanetunnel.Inbound, Expires: now + 60_000, Owner: bHash},
	} {
		installed, ok := bRuntime.InspectCircuit(entry.ID)
		if !ok {
			t.Fatal("missing B circuit installation")
		}
		entry.Circuit = installed.Token
		if err := bPool.Add(entry, now); err != nil {
			t.Fatal(err)
		}
	}

	aDatabase := controlplanenetdb.NewDatabase(aHash, controlplanenetdb.DefaultBucketCapacity)
	bDatabase := controlplanenetdb.NewDatabase(bHash, controlplanenetdb.DefaultBucketCapacity)
	for range controlplanenetdb.PublicationFloodfillK {
		if err := aDatabase.AdmitRouterInfo(dataPlaneFloodfill(t), true, now); err != nil {
			t.Fatal(err)
		}
		if err := bDatabase.AdmitRouterInfo(dataPlaneFloodfill(t), true, now); err != nil {
			t.Fatal(err)
		}
	}

	aLocal, err := controlplanenetdb.NewLocalLeaseSet2(aDestination)
	if err != nil {
		t.Fatal(err)
	}
	bLocal, err := controlplanenetdb.NewLocalLeaseSet2(bDestination)
	if err != nil {
		t.Fatal(err)
	}
	aPublication := &dataPlanePublicationLoop{database: bDatabase, now: now}
	bPublication := &dataPlanePublicationLoop{database: aDatabase, now: now}
	aPublisher, err := controlplanenetdb.NewLeaseSetPublisher(controlplanenetdb.LeaseSetPublisherConfig{
		Local2: aLocal, Database: aDatabase, InboundLeases: controlplanenetdb.InboundLeaseSourceFunc(func(uint64) []foundation.NetworkDatabaseLease {
			return []foundation.NetworkDatabaseLease{{Gateway: foundation.Hash{2}, TunnelID: aLease, EndDate: now + 60_000}}
		}), Sender: aPublication, Sign: aDestination.Sign, Now: func() uint64 { return now }, Random: func() uint32 { return 11 },
		FloodfillLimit: controlplanenetdb.PublicationFloodfillK, ReplyPath: dataPlaneReplyPath{gateway: aHash, tunnel: aLease},
	})
	if err != nil {
		t.Fatal(err)
	}
	bPublisher, err := controlplanenetdb.NewLeaseSetPublisher(controlplanenetdb.LeaseSetPublisherConfig{
		Local2: bLocal, Database: bDatabase, InboundLeases: controlplanenetdb.InboundLeaseSourceFunc(func(uint64) []foundation.NetworkDatabaseLease {
			return []foundation.NetworkDatabaseLease{{Gateway: foundation.Hash{4}, TunnelID: bLease, EndDate: now + 60_000}}
		}), Sender: bPublication, Sign: bDestination.Sign, Now: func() uint64 { return now }, Random: func() uint32 { return 21 },
		FloodfillLimit: controlplanenetdb.PublicationFloodfillK, ReplyPath: dataPlaneReplyPath{gateway: bHash, tunnel: bLease},
	})
	if err != nil {
		t.Fatal(err)
	}
	aPublication.owner, bPublication.owner = aPublisher, bPublisher
	t.Cleanup(func() {
		aPublisher.Close()
		bPublisher.Close()
	})
	if sent, err := aPublisher.Publish(context.Background()); err != nil || sent != controlplanenetdb.PublicationFloodfillK {
		t.Fatalf("publish A = %d, %v", sent, err)
	}
	if sent, err := bPublisher.Publish(context.Background()); err != nil || sent != controlplanenetdb.PublicationFloodfillK {
		t.Fatalf("publish B = %d, %v", sent, err)
	}
	for _, publication := range []struct {
		hash   foundation.Hash
		stores []foundation.I2NPDatabaseStoreMessage
	}{{aHash, aPublication.stores}, {bHash, bPublication.stores}} {
		if len(publication.stores) != controlplanenetdb.PublicationFloodfillK {
			t.Fatalf("publication count = %d", len(publication.stores))
		}
		for _, store := range publication.stores {
			if store.Key != publication.hash || store.Type != foundation.I2NPStoreLeaseSet2 || store.ReplyToken == 0 || store.ReplyToken&(uint32(1)<<31) != 0 {
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

	aRequests, err := controlplanenetdb.NewRequestManager(aDatabase, dataPlaneRequestSender{}, dataPlaneReplyRoute{}, controlplanenetdb.RequestManagerConfig{Capacity: 4, TimeoutMillis: 60_000, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	bRequests, err := controlplanenetdb.NewRequestManager(bDatabase, dataPlaneRequestSender{}, dataPlaneReplyRoute{}, controlplanenetdb.RequestManagerConfig{Capacity: 4, TimeoutMillis: 60_000, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	aSender, err := NewStreamingTunnelSender(StreamingTunnelSenderConfig{Owner: aHash, Database: aDatabase, Requests: aRequests, Ratchet: aRatchet, Tunnels: aRuntime, Pool: aPool, AwaitControl: aControl.WaitIdle, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	bSender, err := NewStreamingTunnelSender(StreamingTunnelSenderConfig{Owner: bHash, Database: bDatabase, Requests: bRequests, Ratchet: bRatchet, Tunnels: bRuntime, Pool: bPool, AwaitControl: bControl.WaitIdle, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	aRef, bRef := &dataPlaneSenderRef{target: aSender}, &dataPlaneSenderRef{target: bSender}
	aSession, err := aDestinations.Create(dataplane.RouterDestinationSessionConfig{Default: true, Streaming: dataplane.StreamingTunnelTunnelNetworkConfig{Destination: aDestination, Sender: aRef}})
	if err != nil {
		t.Fatal(err)
	}
	bSession, err := bDestinations.Create(dataplane.RouterDestinationSessionConfig{Default: true, Streaming: dataplane.StreamingTunnelTunnelNetworkConfig{Destination: bDestination, Sender: bRef}})
	if err != nil {
		t.Fatal(err)
	}
	aReceiver, err = dataplane.RouterNewGarlicReceiver(dataplane.RouterGarlicReceiverConfig{Service: aService, ReplyKeys: dataplane.GarlicNewReplyKeyRegistry(4), Now: func() uint64 { return now }, Destinations: map[foundation.Hash]dataplane.RouterGarlicDestination{
		aHash: {Ratchet: aRatchet, ReserveRatchetReply: aSender.ReserveRatchetReply},
	}})
	if err != nil {
		t.Fatal(err)
	}
	bReceiver, err = dataplane.RouterNewGarlicReceiver(dataplane.RouterGarlicReceiverConfig{Service: bService, ReplyKeys: dataplane.GarlicNewReplyKeyRegistry(4), Now: func() uint64 { return now }, Destinations: map[foundation.Hash]dataplane.RouterGarlicDestination{
		bHash: {Ratchet: bRatchet, ReserveRatchetReply: bSender.ReserveRatchetReply},
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
	if aPool.Count(controlplanetunnel.Outbound, now) != 0 {
		t.Fatal("destroyed A retained an outbound tunnel")
	}
	if _, ok := aRuntime.CircuitOwner(aOutbound); ok {
		t.Fatal("destroyed A retained a runtime circuit")
	}
	if bPool.Count(controlplanetunnel.Outbound, now) != 1 {
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

func dataPlaneFloodfill(t *testing.T) foundation.NetworkDatabaseRouterInfo {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
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
	unsigned = append(unsigned, options[:optionLen]...)
	info, err := foundation.NetworkDatabaseParseRouterInfo(append(unsigned, ed25519.Sign(private, unsigned)...))
	if err != nil {
		t.Fatal(err)
	}
	return info
}
func TestStreamingTunnelSenderReleaseClearsRemoteELSContext(t *testing.T) {
	remote, err := foundation.GenerateLegacyLocalDestination()
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
	sender := &StreamingTunnelSender{execution: &dataplane.RouterPreparedRouteSender{}}
	if err = sender.UpdateRemoteELS(map[foundation.Hash]RemoteELSContext{
		hash: {Identity: identity, Secret: []byte("remote-secret"), Authorization: controlplanenetdb.ELSClientAuthorization{UsePSK: true, PSK: psk}},
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
	if err = sender.UpdateRemoteELS(nil); !errors.Is(err, dataplane.RouterErrDataPlaneConfig) {
		t.Fatalf("UpdateRemoteELS after release = %v", err)
	}
}

func newControlTestService(t *testing.T, database *controlplanenetdb.Database) (*dataplane.RouterService, *ControlDispatcher) {
	t.Helper()
	queue, err := NewControlDispatcher(database, ControlSinks{}, ControlDispatcherConfig{QueueLimits: dataplane.RouterDefaultControlQueueLimits()})
	if err != nil {
		t.Fatal(err)
	}
	if err = queue.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := queue.Close(); err != nil {
			t.Error(err)
		}
	})
	return dataplane.RouterNewService(dataplane.RouterSinks{Control: queue}), queue
}
