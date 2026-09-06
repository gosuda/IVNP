//go:build integration

package router

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	controlplanetunnel "gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

// TestI2PDNTCP2Interop proves an explicit DatabaseLookup round trip with a
// native i2pd floodfill peer. It is opt-in because it needs that peer's current
// RouterInfo; Alice is intentionally non-published for the local test fixture.
func TestI2PDNTCP2Interop(t *testing.T) {
	if os.Getenv("IVNP_I2PD_INTEGRATION") != "1" {
		t.Skip("set IVNP_I2PD_INTEGRATION=1 to run against native i2pd")
	}
	path := os.Getenv("IVNP_I2PD_ROUTER_INFO")
	if path == "" {
		t.Skip("set IVNP_I2PD_ROUTER_INFO to the native i2pd router.info path")
	}

	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read native i2pd RouterInfo: %v", err)
	}
	peer, err := foundation.NetworkDatabaseParseRouterInfo(wire)
	if err != nil {
		t.Fatalf("parse native i2pd RouterInfo: %v", err)
	}
	valid, err := peer.Verify()
	if err != nil || !valid {
		t.Fatalf("verify native i2pd RouterInfo: valid=%t err=%v", valid, err)
	}
	if !dataplane.RouterNTCP2PeerCapable(peer, uint64(time.Now().UnixMilli())) {
		t.Fatal("native i2pd peer has no current NTCP2 address")
	}
	if !foundation.NetworkDatabaseIsFloodfill(peer) {
		t.Fatal("native i2pd peer is not floodfill and cannot prove direct DatabaseLookup handling")
	}

	alice, aliceStatic, aliceIV := newI2PDInteropLocal(t)
	database := controlplanenetdb.NewDatabase(alice.Hash(), 16)
	if err = database.AdmitRouterInfo(peer, false, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatalf("admit native i2pd RouterInfo: %v", err)
	}
	manager, err := dataplane.RouterNewNTCP2Manager(dataplane.RouterNTCP2ManagerConfig{
		Peers:            NewTransportPeerSource(database),
		StaticPrivate:    aliceStatic,
		StaticIV:         aliceIV,
		HandshakeTimeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: manager})
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan foundation.I2NPDatabaseStoreMessage, 2)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	service, control := newI2PDControlService(t, ctx, database, ControlSinks{DatabaseStoreCompleted: func(_ context.Context, store foundation.I2NPDatabaseStoreMessage) {
		select {
		case received <- store:
		default:
		}
	}})
	if err = transport.Start(ctx, dataplane.RouterTransportBindings{
		LocalInfo:         alice,
		Clock:             dataplane.RouterWallClock{},
		HandleI2NP:        service.HandleI2NP,
		HandleI2NPFrom:    service.HandleI2NPFrom,
		HandleI2NPContext: service.HandleI2NPFromContext,
	}); err != nil {
		cancel()
		t.Fatalf("start native I2PD NTCP2 client: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		if err := transport.Close(); err != nil {
			t.Errorf("close native I2PD NTCP2 client: %v", err)
		}
		if err := transport.Wait(); err != nil {
			t.Errorf("wait for native I2PD NTCP2 client: %v", err)
		}
	})

	peerHash := peer.Hash()
	openCtx, openCancel := context.WithTimeout(ctx, 30*time.Second)
	defer openCancel()
	if err = transport.EnsureSession(openCtx, peerHash); err != nil {
		t.Fatalf("open native i2pd NTCP2 session: %v", err)
	}

	lookupPayload := make([]byte, 67)
	aliceHash := alice.Hash()
	copy(lookupPayload[:32], peerHash[:])
	copy(lookupPayload[32:64], aliceHash[:])
	if _, err = foundation.I2NPParseDatabaseLookup(lookupPayload); err != nil {
		t.Fatalf("build direct native i2pd database lookup: %v", err)
	}
	message := foundation.I2NPMessage{
		Header: foundation.I2NPHeader{
			Type:       foundation.I2NPDatabaseLookup,
			ID:         1,
			Expiration: uint64(time.Now().Add(time.Minute).UnixMilli()),
		},
		Payload: lookupPayload,
	}
	sendCtx, sendCancel := context.WithTimeout(ctx, 30*time.Second)
	defer sendCancel()
	if err = transport.Send(sendCtx, peerHash, message); err != nil {
		t.Fatalf("send database lookup over native i2pd NTCP2: %v", err)
	}
	requireNativeI2PDRouterInfoStore(t, received, peerHash, "DatabaseLookup response")
	waitI2PDControl(t, control)
	if !manager.Status().Running {
		t.Fatal("native I2PD NTCP2 client stopped after a RouterInfo round trip")
	}
}

func requireNativeI2PDRouterInfoStore(t *testing.T, received <-chan foundation.I2NPDatabaseStoreMessage, peerHash [32]byte, phase string) {
	t.Helper()
	select {
	case store := <-received:
		if store.Type != foundation.I2NPStoreRouterInfo || store.Key != peerHash {
			t.Fatalf("%s = type %d, key %s; want RouterInfo for %s", phase, store.Type, store.Key, peerHash)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("native i2pd did not send %s", phase)
	}
}

func newI2PDInteropLocal(t *testing.T) (*LocalRouterInfo, []byte, []byte) {
	t.Helper()
	local, err := foundation.GenerateLocalRouterAddress()
	if err != nil {
		t.Fatal(err)
	}
	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	if _, err = rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{
		Local:         local,
		RouterVersion: "0.9.70",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.ReplaceAddresses([]PublishedAddress{{
		Transport: "NTCP2",
		Cost:      14,
		Options: []MappingOption{
			{Key: "caps", Value: "4"},
			{Key: "s", Value: foundation.EncodeI2PBase64(static.PublicKey().Bytes())},
			{Key: "v", Value: "2"},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	owner.SetReachability(ReachabilityFirewalled)
	if err = owner.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot := owner.Snapshot()
	if snapshot.Identity.CryptoKeyType() != foundation.CryptoX25519 || snapshot.Identity.SigningKeyType() != foundation.SigningEdDSASHA512Ed25519 {
		t.Fatalf("local RouterInfo identity = crypto %d signing %d", snapshot.Identity.CryptoKeyType(), snapshot.Identity.SigningKeyType())
	}
	return owner, static.Bytes(), iv
}

// TestI2PDShortTunnelBuildDiagnostic sends the production BuildManager's
// bootstrap inbound and paired outbound builds through two signed native i2pd
// RouterInfos. Before each NTCP2 send it opens the initiator-created ECIES
// record and checks every defined request field. Native rejection is reported
// by BuildManager; silence remains a timeout so an ignored request cannot look
// successful.
func TestI2PDShortTunnelBuildDiagnostic(t *testing.T) {
	if os.Getenv("IVNP_I2PD_INTEGRATION") != "1" {
		t.Skip("set IVNP_I2PD_INTEGRATION=1 to run against native i2pd")
	}
	goDebug := os.Getenv("GODEBUG")
	if goDebug != "" {
		goDebug += ","
	}
	t.Setenv("GODEBUG", goDebug+"cryptocustomrand=1")
	path := os.Getenv("IVNP_I2PD_ROUTER_INFO")
	if path == "" {
		t.Skip("set IVNP_I2PD_ROUTER_INFO to the native i2pd router.info path")
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read native i2pd RouterInfo: %v", err)
	}
	peer, err := foundation.NetworkDatabaseParseRouterInfo(wire)
	if err != nil {
		t.Fatalf("parse native i2pd RouterInfo: %v", err)
	}
	valid, err := peer.Verify()
	if err != nil || !valid {
		t.Fatalf("verify native i2pd RouterInfo: valid=%t err=%v", valid, err)
	}
	if !dataplane.RouterNTCP2PeerCapable(peer, uint64(time.Now().UnixMilli())) {
		t.Fatal("native i2pd peer has no current NTCP2 address")
	}
	buildKeyBytes, trailingKeyBytes := peer.Identity.CryptoKeyParts()
	if peer.Identity.CryptoKeyType() != foundation.CryptoX25519 || len(buildKeyBytes) != 32 || len(trailingKeyBytes) != 0 {
		t.Fatalf("native i2pd identity encryption key type=%d lengths=%d/%d", peer.Identity.CryptoKeyType(), len(buildKeyBytes), len(trailingKeyBytes))
	}
	var buildStatic [32]byte
	copy(buildStatic[:], buildKeyBytes)
	replyPath := os.Getenv("IVNP_I2PD_REPLY_ROUTER_INFO")
	if replyPath == "" {
		t.Skip("set IVNP_I2PD_REPLY_ROUTER_INFO to a distinct native i2pd router.info path")
	}
	replyWire, err := os.ReadFile(replyPath)
	if err != nil {
		t.Fatalf("read native reply-gateway i2pd RouterInfo: %v", err)
	}
	replyPeer, err := foundation.NetworkDatabaseParseRouterInfo(replyWire)
	if err != nil {
		t.Fatalf("parse native reply-gateway i2pd RouterInfo: %v", err)
	}
	valid, err = replyPeer.Verify()
	if err != nil || !valid {
		t.Fatalf("verify native reply-gateway i2pd RouterInfo: valid=%t err=%v", valid, err)
	}
	if !dataplane.RouterNTCP2PeerCapable(replyPeer, uint64(time.Now().UnixMilli())) {
		t.Fatal("native reply-gateway i2pd peer has no current NTCP2 address")
	}
	replyBuildKeyBytes, replyTrailingKeyBytes := replyPeer.Identity.CryptoKeyParts()
	if replyPeer.Identity.CryptoKeyType() != foundation.CryptoX25519 || len(replyBuildKeyBytes) != 32 || len(replyTrailingKeyBytes) != 0 {
		t.Fatalf("native reply-gateway identity encryption key type=%d lengths=%d/%d", replyPeer.Identity.CryptoKeyType(), len(replyBuildKeyBytes), len(replyTrailingKeyBytes))
	}
	var replyBuildStatic [32]byte
	copy(replyBuildStatic[:], replyBuildKeyBytes)

	alice, aliceStatic, aliceIV := newI2PDInteropLocal(t)
	database := controlplanenetdb.NewDatabase(alice.Hash(), 16)
	now := func() uint64 { return uint64(time.Now().UnixMilli()) }
	if err = database.AdmitRouterInfo(peer, false, now()); err != nil {
		t.Fatalf("admit native endpoint i2pd RouterInfo: %v", err)
	}
	if err = database.AdmitRouterInfo(replyPeer, false, now()); err != nil {
		t.Fatalf("admit native reply-gateway i2pd RouterInfo: %v", err)
	}
	transportManager, err := dataplane.RouterNewNTCP2Manager(dataplane.RouterNTCP2ManagerConfig{
		Peers:            NewTransportPeerSource(database),
		StaticPrivate:    aliceStatic,
		StaticIV:         aliceIV,
		HandshakeTimeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: transportManager})
	if err != nil {
		t.Fatal(err)
	}
	random := new(i2pdBuildDiagnosticRandom)
	sender := &i2pdBuildDiagnosticSender{
		next: transport, random: random,
		statics: map[foundation.Hash][32]byte{peer.Hash(): buildStatic, replyPeer.Hash(): replyBuildStatic},
	}
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: transport.DataSender(), Now: now})
	replyKeys := dataplane.GarlicNewReplyKeyRegistry(4)
	var service *dataplane.RouterService
	deliveryStatuses := make(chan foundation.I2NPDeliveryStatusMessage, 1)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	var buildManager *controlplanetunnel.BuildManager
	inboundResults := make(chan error, 1)
	outboundResults := make(chan error, 1)
	transportErrors := make(chan error, 4)
	buildManager, err = controlplanetunnel.NewBuildManager(controlplanetunnel.BuildManagerConfig{
		Runtime: runtime, Sender: sender, ReplyKeys: replyKeys,
		LocalRouter: alice.Hash(), StaticPrivate: aliceStatic,
		LocalDelivery: func(message foundation.I2NPMessage) error {
			return service.HandleI2NP(message, now(), false)
		},
		Now: now, Random: random,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := buildManager.Close(); err != nil {
			t.Error(err)
		}
	})
	service, control := newI2PDControlService(t, ctx, database, ControlSinks{
		DeliveryStatus: func(status foundation.I2NPDeliveryStatusMessage) error {
			select {
			case deliveryStatuses <- status:
			default:
			}
			return nil
		},
		TunnelBuild: func(_ context.Context, _ dataplane.RouterI2NPSource, _ foundation.I2NPBuildRecords, message foundation.I2NPMessage) error {
			result := buildManager.HandleInboundReply(message)
			select {
			case inboundResults <- result:
			default:
			}
			return result
		},
		OutboundTunnelBuildReply: func(message foundation.I2NPMessage) error {
			result := buildManager.HandleReply(message)
			select {
			case outboundResults <- result:
			default:
			}
			return result
		},
	})
	service.SetTunnelDataSink(runtime.Handle)
	garlicReceiver, err := dataplane.RouterNewGarlicReceiver(dataplane.RouterGarlicReceiverConfig{Service: service, ReplyKeys: replyKeys, Now: now, StaticPrivate: aliceStatic})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(garlicReceiver.ReleaseSensitive)
	service.SetGarlicSink(garlicReceiver.HandleGarlicFrom)
	handleIncoming := func(handlerCtx context.Context, from foundation.Hash, message foundation.I2NPMessage, nowMillis uint64, fromFloodfill bool) error {
		t.Logf("incoming_i2np_type=%d id=%d payload_len=%d", message.Header.Type, message.Header.ID, len(message.Payload))
		// Direct DeliveryStatus must not satisfy the reply-tunnel assertion.
		switch message.Header.Type {
		case foundation.I2NPShortTunnelBuild, foundation.I2NPTunnelData, foundation.I2NPGarlic, foundation.I2NPOutboundTunnelBuildReply:
		default:
			return nil
		}
		handleErr := service.HandleI2NPFromContext(handlerCtx, from, message, nowMillis, fromFloodfill)
		if handleErr != nil {
			select {
			case transportErrors <- fmt.Errorf("incoming I2NP type %d: %w", message.Header.Type, handleErr):
			default:
			}
		}
		return handleErr
	}
	if err = transport.Start(ctx, dataplane.RouterTransportBindings{
		LocalInfo: alice,
		Clock:     dataplane.RouterWallClock{},
		HandleI2NP: func(message foundation.I2NPMessage, nowMillis uint64, fromFloodfill bool) error {
			return handleIncoming(ctx, foundation.Hash{}, message, nowMillis, fromFloodfill)
		},
		HandleI2NPContext: handleIncoming,
		HandleI2NPFrom: func(from foundation.Hash, message foundation.I2NPMessage, nowMillis uint64, fromFloodfill bool) error {
			return handleIncoming(ctx, from, message, nowMillis, fromFloodfill)
		},
	}); err != nil {
		cancel()
		t.Fatalf("start native i2pd NTCP2 client: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		if closeErr := transport.Close(); closeErr != nil {
			t.Errorf("close native i2pd NTCP2 client: %v", closeErr)
		}
		if waitErr := transport.Wait(); waitErr != nil {
			t.Errorf("wait for native i2pd NTCP2 client: %v", waitErr)
		}
	})
	peerHash := peer.Hash()
	replyPeerHash := replyPeer.Hash()
	openCtx, openCancel := context.WithTimeout(ctx, 30*time.Second)
	defer openCancel()
	if err = transport.EnsureSession(openCtx, replyPeerHash); err != nil {
		t.Fatalf("open native reply-gateway i2pd NTCP2 session: %v", err)
	}
	if err = transport.EnsureSession(openCtx, peerHash); err != nil {
		t.Fatalf("open native endpoint i2pd NTCP2 session: %v", err)
	}

	circuitID := uint32(now()) | 1
	receiveID := circuitID ^ 0x50607080
	if receiveID ==
		0 {
		receiveID = 1
	}

	inboundCtx, inboundCancel := context.WithTimeout(ctx, 30*time.Second)
	defer inboundCancel()
	replyID, err := buildManager.StartInbound(inboundCtx, controlplanetunnel.InboundBuild{
		CircuitID: circuitID,
		Hops: []controlplanetunnel.ShortBuildHop{{
			Router: replyPeerHash, StaticKey: replyBuildStatic, ReceiveTunnelID: receiveID,
		}},
		ExpiresAt: now() + 10*60_000,
	})
	if err != nil {
		t.Fatalf("send production ShortTunnelBuild: %v", err)
	}
	inspected, inspectErr := sender.inspection()
	if inspectErr != nil {
		t.Fatalf("inspect outbound ShortTunnelBuild: %v", inspectErr)
	}
	if inspected.ReceiveTunnelID != receiveID || inspected.NextTunnelID != circuitID ||
		inspected.NextRouter != alice.Hash() || !inspected.Gateway || inspected.Endpoint ||
		inspected.LifetimeSeconds != 600 || inspected.NextMessageID != replyID ||
		inspected.Options.EncodedLen() != 2 {
		t.Fatalf("decrypted outbound request = %+v, reply ID %d", inspected, replyID)
	}
	t.Logf("signed_router_hash=%s record_count=4 receive_tunnel_id=%d next_tunnel_id=%d next_router=%s gateway=%t endpoint=%t request_minutes=%d lifetime_seconds=%d next_message_id=%d options_len=%d",
		foundation.EncodeI2PBase64(replyPeerHash[:]), inspected.ReceiveTunnelID, inspected.NextTunnelID,
		foundation.EncodeI2PBase64(inspected.NextRouter[:]), inspected.Gateway, inspected.Endpoint,
		inspected.RequestMinutes, inspected.LifetimeSeconds, inspected.NextMessageID, inspected.Options.EncodedLen())
	select {
	case result := <-inboundResults:
		if result != nil {
			t.Fatalf("native i2pd inbound ShortTunnelBuild reply: %v", result)
		}
		t.Log("native i2pd accepted the inbound ShortTunnelBuild")
	case <-time.After(15 * time.Second):
		t.Fatal("native i2pd ignored the inbound ShortTunnelBuild for 15 seconds")
	}
	waitI2PDControl(t, control)

	outboundCircuitID := circuitID ^ 0x90a0b0c0
	outboundReceiveID := receiveID ^ 0xd0e0f001
	if outboundCircuitID ==
		0 {
		outboundCircuitID = 1
	}

	if outboundReceiveID == 0 || outboundReceiveID == receiveID {
		outboundReceiveID++
	}
	outboundCtx, outboundCancel := context.WithTimeout(ctx, 30*time.Second)
	defer outboundCancel()
	outboundReplyID, err := buildManager.StartOutbound(outboundCtx, controlplanetunnel.OutboundBuild{
		CircuitID: outboundCircuitID,
		Hops: []controlplanetunnel.ShortBuildHop{{
			Router: peerHash, StaticKey: buildStatic, ReceiveTunnelID: outboundReceiveID,
		}},
		ReplyRouter: replyPeerHash, ReplyTunnelID: receiveID, ExpiresAt: now() + 10*60_000,
	})
	if err != nil {
		t.Fatalf("send production outbound ShortTunnelBuild: %v", err)
	}
	inspected, inspectErr = sender.inspection()
	if inspectErr != nil {
		t.Fatalf("inspect outbound-tunnel ShortTunnelBuild: %v", inspectErr)
	}
	if inspected.ReceiveTunnelID != outboundReceiveID || inspected.NextTunnelID != receiveID ||
		inspected.NextRouter != replyPeerHash || inspected.Gateway || !inspected.Endpoint ||
		inspected.LifetimeSeconds != 600 || inspected.NextMessageID != outboundReplyID ||
		inspected.Options.EncodedLen() != 2 {
		t.Fatalf("decrypted outbound-tunnel request = %+v, reply ID %d", inspected, outboundReplyID)
	}
	t.Logf("outbound_tunnel receive_tunnel_id=%d next_tunnel_id=%d next_router=%s gateway=%t endpoint=%t request_minutes=%d lifetime_seconds=%d next_message_id=%d options_len=%d",
		inspected.ReceiveTunnelID, inspected.NextTunnelID, foundation.EncodeI2PBase64(inspected.NextRouter[:]),
		inspected.Gateway, inspected.Endpoint, inspected.RequestMinutes, inspected.LifetimeSeconds,
		inspected.NextMessageID, inspected.Options.EncodedLen())
	select {
	case result := <-outboundResults:
		if result != nil {
			t.Fatalf("native i2pd outbound ShortTunnelBuild reply: %v", result)
		}
		t.Log("native i2pd accepted the outbound ShortTunnelBuild")
	case transportErr := <-transportErrors:
		t.Fatalf("native i2pd outbound ShortTunnelBuild reply delivery: %v", transportErr)
	case <-time.After(15 * time.Second):
		t.Fatal("native i2pd ignored the outbound ShortTunnelBuild reply for 15 seconds")
	}
	waitI2PDControl(t, control)
	if _, ok := runtime.CircuitOwner(outboundCircuitID); !ok {
		t.Fatal("native i2pd reply did not install the outbound circuit")
	}
	if replyKeys.Len() != 0 {
		t.Fatalf("native i2pd reply left %d one-time keys", replyKeys.Len())
	}

	compressed, err := foundation.NetworkDatabaseCompressRouterInfo(alice.Snapshot().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	const publicationToken = uint32(0x10203040)
	storePayload, err := foundation.NetworkDatabaseMarshalDatabaseStore(alice.Hash(), foundation.I2NPStoreRouterInfo, compressed, publicationToken, replyPeerHash, receiveID)
	if err != nil {
		t.Fatal(err)
	}
	storeMessage := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: 0x50607080, Expiration: now() + 60_000},
		Payload: storePayload,
	}
	storeFrame := make([]byte, storeMessage.EncodedLen())
	if _, err = storeMessage.MarshalTo(storeFrame); err != nil {
		t.Fatal(err)
	}
	if err = runtime.SendBlock(ctx, outboundCircuitID, dataplane.TunnelBlock{
		Delivery: dataplane.TunnelDeliveryRouter, Gateway: peerHash, Last: true, Data: storeFrame,
	}); err != nil {
		t.Fatalf("send DatabaseStore through native outbound tunnel: %v", err)
	}
	select {
	case status := <-deliveryStatuses:
		if status.MessageID != publicationToken {
			t.Fatalf("DatabaseStore reply token = %d, want %d", status.MessageID, publicationToken)
		}
		t.Log("native i2pd returned DatabaseStore confirmation through the inbound tunnel")
	case transportErr := <-transportErrors:
		t.Fatalf("native i2pd DatabaseStore reply delivery: %v", transportErr)
	case <-time.After(15 * time.Second):
		t.Fatal("native i2pd ignored the DatabaseStore reply tunnel for 15 seconds")
	}
	waitI2PDControl(t, control)
}

type i2pdBuildDiagnosticRandom struct {
	mu     sync.Mutex
	stream []byte
}

func (r *i2pdBuildDiagnosticRandom) Read(dst []byte) (int, error) {
	if _, err := rand.Read(dst); err != nil {
		return 0, err
	}
	r.mu.Lock()
	r.stream = append(r.stream, dst...)
	r.mu.Unlock()
	return len(dst), nil
}

func (r *i2pdBuildDiagnosticRandom) snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.stream...)
}

type i2pdBuildDiagnosticSender struct {
	next    *TransportMux
	random  *i2pdBuildDiagnosticRandom
	statics map[foundation.Hash][32]byte

	mu      sync.Mutex
	request controlplanetunnel.ShortBuildRequest
	err     error
}

func (s *i2pdBuildDiagnosticSender) Send(ctx context.Context, peer foundation.Hash, message foundation.I2NPMessage) error {
	if message.Header.Type == foundation.I2NPShortTunnelBuild {
		static, ok := s.statics[peer]
		if !ok {
			return fmt.Errorf("missing signed identity build key for %s", foundation.EncodeI2PBase64(peer[:]))
		}
		request, err := inspectI2PDOutboundShortRecord(message, peer, static, s.random.snapshot())
		s.mu.Lock()
		s.request, s.err = request, err
		s.mu.Unlock()
		if err != nil {
			return err
		}
	}
	return s.next.Send(ctx, peer, message)
}

func (s *i2pdBuildDiagnosticSender) EnsureSession(ctx context.Context, peer foundation.Hash) error {
	return s.next.EnsureSession(ctx, peer)
}

func (s *i2pdBuildDiagnosticSender) inspection() (controlplanetunnel.ShortBuildRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.request, s.err
}

func inspectI2PDOutboundShortRecord(message foundation.I2NPMessage, peer foundation.Hash, static [32]byte, randomStream []byte) (controlplanetunnel.ShortBuildRequest, error) {
	records, err := foundation.I2NPParseBuildRecords(foundation.I2NPShortTunnelBuild, message.Payload)
	if err != nil {
		return controlplanetunnel.ShortBuildRequest{}, err
	}
	if records.Count != 4 {
		return controlplanetunnel.ShortBuildRequest{}, fmt.Errorf("record count = %d, want 4", records.Count)
	}
	var record []byte
	for index := range int(records.Count) {
		candidate := records.Records[index*controlplanetunnel.ShortBuildRecordSize : (index+1)*controlplanetunnel.ShortBuildRecordSize]
		if bytes.Equal(candidate[:16], peer[:16]) {
			if record != nil {
				return controlplanetunnel.ShortBuildRequest{}, fmt.Errorf("duplicate peer prefix")
			}
			record = candidate
		}
	}
	if record == nil {
		return controlplanetunnel.ShortBuildRequest{}, fmt.Errorf("peer record not found")
	}
	curve := ecdh.X25519()
	var private *ecdh.PrivateKey
	for offset := range len(randomStream) - 31 {
		candidate, keyErr := curve.NewPrivateKey(randomStream[offset : offset+32])
		if keyErr == nil && bytes.Equal(record[16:48], candidate.PublicKey().Bytes()) {
			private = candidate
			break
		}
	}
	if private == nil {
		return controlplanetunnel.ShortBuildRequest{}, fmt.Errorf("record ephemeral key differs from BuildManager random source")
	}
	remote, err := curve.NewPublicKey(static[:])
	if err != nil {
		return controlplanetunnel.ShortBuildRequest{}, err
	}
	shared, err := private.ECDH(remote)
	if err != nil {
		return controlplanetunnel.ShortBuildRequest{}, err
	}
	defer clear(shared)
	state := dataplane.NoiseInitialize("Noise_N_25519_ChaChaPoly_SHA256")
	defer state.ReleaseSensitive()
	if err = state.MixHash(nil); err != nil {
		return controlplanetunnel.ShortBuildRequest{}, err
	}
	if err = state.MixHash(static[:]); err != nil {
		return controlplanetunnel.ShortBuildRequest{}, err
	}
	if err = state.MixHash(record[16:48]); err != nil {
		return controlplanetunnel.ShortBuildRequest{}, err
	}
	if err = state.MixKey(shared); err != nil {
		return controlplanetunnel.ShortBuildRequest{}, err
	}
	var plaintext [controlplanetunnel.ShortBuildRequestPlainSize]byte
	if _, err = state.DecryptAndHash(plaintext[:], record[48:]); err != nil {
		return controlplanetunnel.ShortBuildRequest{}, err
	}
	if plaintext[40]&^byte(0xc0) != 0 || plaintext[40]&0xc0 == 0xc0 ||
		plaintext[41] != 0 || plaintext[42] != 0 || plaintext[43] != 0 ||
		binary.BigEndian.Uint16(plaintext[56:58]) != 0 {
		return controlplanetunnel.ShortBuildRequest{}, fmt.Errorf("flags/reserved/options prefix = %x/%x/%x", plaintext[40:44], plaintext[41:44], plaintext[56:58])
	}
	return controlplanetunnel.ParseShortBuildRequest(plaintext[:])
}

func newI2PDControlService(t *testing.T, ctx context.Context, database *controlplanenetdb.Database, sinks ControlSinks) (*dataplane.RouterService, *ControlDispatcher) {
	t.Helper()
	control, err := NewControlDispatcher(database, sinks, ControlDispatcherConfig{QueueLimits: dataplane.RouterDefaultControlQueueLimits()})
	if err != nil {
		t.Fatal(err)
	}
	if err = control.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := control.Close(); err != nil {
			t.Error(err)
		}
	})
	return dataplane.RouterNewService(dataplane.RouterSinks{Control: control}), control
}

func waitI2PDControl(t *testing.T, control *ControlDispatcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if err := control.Barrier(ctx); err != nil {
		t.Fatalf("native i2pd control completion: %v", err)
	}
}
