//go:build integration

package router

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	ivnp "gosuda.org/ivnp/i2p"
	"gosuda.org/ivnp/network/transport/noise"
	"gosuda.org/ivnp/network/tunnel"
	"gosuda.org/ivnp/protocol/garlic"
	"gosuda.org/ivnp/protocol/i2np"
	"gosuda.org/ivnp/protocol/netdb"
	"os"
	"sync"
	"testing"
	"time"
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
	peer, err := netdb.ParseRouterInfo(wire)
	if err != nil {
		t.Fatalf("parse native i2pd RouterInfo: %v", err)
	}
	valid, err := peer.Verify()
	if err != nil || !valid {
		t.Fatalf("verify native i2pd RouterInfo: valid=%t err=%v", valid, err)
	}
	if _, err = selectNTCP2Address(peer); err != nil {
		t.Fatalf("select native i2pd NTCP2 address: %v", err)
	}
	if !netdb.IsFloodfill(peer) {
		t.Fatal("native i2pd peer is not floodfill and cannot prove direct DatabaseLookup handling")
	}

	alice, aliceStatic, aliceIV := newI2PDInteropLocal(t)
	database := netdb.NewDatabase(alice.Hash(), 16)
	if err = database.AdmitRouterInfo(peer, false, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatalf("admit native i2pd RouterInfo: %v", err)
	}
	manager, err := NewNTCP2Manager(NTCP2ManagerConfig{
		Database:         database,
		StaticPrivate:    aliceStatic,
		StaticIV:         aliceIV,
		HandshakeTimeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan i2np.Message, 2)
	ctx, cancel := context.WithCancel(context.Background())
	if err = manager.Start(ctx, TransportBindings{
		LocalInfo: alice,
		Clock:     WallClock{},
		HandleI2NP: func(message i2np.Message, _ uint64, _ bool) error {
			select {
			case received <- message:
			default:
			}
			return nil
		},
	}); err != nil {
		cancel()
		t.Fatalf("start native I2PD NTCP2 client: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = manager.Close()
		if err := manager.Wait(); err != nil {
			t.Errorf("wait for native I2PD NTCP2 client: %v", err)
		}
	})

	peerHash := peer.Hash()
	openCtx, openCancel := context.WithTimeout(ctx, 30*time.Second)
	defer openCancel()
	if err = manager.openOutbound(openCtx, peerHash); err != nil {
		t.Fatalf("open native i2pd NTCP2 session: %v", err)
	}

	lookupPayload := make([]byte, 67)
	aliceHash := alice.Hash()
	copy(lookupPayload[:32], peerHash[:])
	copy(lookupPayload[32:64], aliceHash[:])
	if _, err = i2np.ParseDatabaseLookup(lookupPayload); err != nil {
		t.Fatalf("build direct native i2pd database lookup: %v", err)
	}
	message := i2np.Message{
		Header: i2np.Header{
			Type:       i2np.DatabaseLookup,
			ID:         1,
			Expiration: uint64(time.Now().Add(time.Minute).UnixMilli()),
		},
		Payload: lookupPayload,
	}
	sendCtx, sendCancel := context.WithTimeout(ctx, 30*time.Second)
	defer sendCancel()
	if err = manager.Send(sendCtx, peerHash, message); err != nil {
		t.Fatalf("send database lookup over native i2pd NTCP2: %v", err)
	}
	requireNativeI2PDRouterInfoStore(t, received, peerHash, "DatabaseLookup response")
	if !manager.Status().Running {
		t.Fatal("native I2PD NTCP2 client stopped after a RouterInfo round trip")
	}
}

func requireNativeI2PDRouterInfoStore(t *testing.T, received <-chan i2np.Message, peerHash [32]byte, phase string) {
	t.Helper()
	select {
	case reply := <-received:
		if reply.Header.Type != i2np.DatabaseStore {
			t.Fatalf("%s type = %d, want DatabaseStore", phase, reply.Header.Type)
		}
		store, err := i2np.ParseDatabaseStore(reply.Payload)
		if err != nil {
			t.Fatalf("parse %s: %v", phase, err)
		}
		if store.Type != i2np.StoreRouterInfo || store.Key != peerHash {
			t.Fatalf("%s = type %d, key %s; want RouterInfo for %s", phase, store.Type, store.Key, peerHash)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("native i2pd did not send %s", phase)
	}
}

func newI2PDInteropLocal(t *testing.T) (*LocalRouterInfo, []byte, []byte) {
	t.Helper()
	local, err := ivnp.GenerateLocalRouterAddress()
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
			{Key: "s", Value: ivnp.EncodeI2PBase64(static.PublicKey().Bytes())},
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
	if snapshot.Identity.CryptoKeyType() != ivnp.CryptoX25519 || snapshot.Identity.SigningKeyType() != ivnp.SigningEdDSASHA512Ed25519 {
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
	peer, err := netdb.ParseRouterInfo(wire)
	if err != nil {
		t.Fatalf("parse native i2pd RouterInfo: %v", err)
	}
	valid, err := peer.Verify()
	if err != nil || !valid {
		t.Fatalf("verify native i2pd RouterInfo: valid=%t err=%v", valid, err)
	}
	if _, err = selectNTCP2Address(peer); err != nil {
		t.Fatalf("select native i2pd NTCP2 address: %v", err)
	}
	buildKeyBytes, trailingKeyBytes := peer.Identity.CryptoKeyParts()
	if peer.Identity.CryptoKeyType() != ivnp.CryptoX25519 || len(buildKeyBytes) != 32 || len(trailingKeyBytes) != 0 {
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
	replyPeer, err := netdb.ParseRouterInfo(replyWire)
	if err != nil {
		t.Fatalf("parse native reply-gateway i2pd RouterInfo: %v", err)
	}
	valid, err = replyPeer.Verify()
	if err != nil || !valid {
		t.Fatalf("verify native reply-gateway i2pd RouterInfo: valid=%t err=%v", valid, err)
	}
	if _, err = selectNTCP2Address(replyPeer); err != nil {
		t.Fatalf("select native reply-gateway i2pd NTCP2 address: %v", err)
	}
	replyBuildKeyBytes, replyTrailingKeyBytes := replyPeer.Identity.CryptoKeyParts()
	if replyPeer.Identity.CryptoKeyType() != ivnp.CryptoX25519 || len(replyBuildKeyBytes) != 32 || len(replyTrailingKeyBytes) != 0 {
		t.Fatalf("native reply-gateway identity encryption key type=%d lengths=%d/%d", replyPeer.Identity.CryptoKeyType(), len(replyBuildKeyBytes), len(replyTrailingKeyBytes))
	}
	var replyBuildStatic [32]byte
	copy(replyBuildStatic[:], replyBuildKeyBytes)

	alice, aliceStatic, aliceIV := newI2PDInteropLocal(t)
	database := netdb.NewDatabase(alice.Hash(), 16)
	now := func() uint64 { return uint64(time.Now().UnixMilli()) }
	if err = database.AdmitRouterInfo(peer, false, now()); err != nil {
		t.Fatalf("admit native endpoint i2pd RouterInfo: %v", err)
	}
	if err = database.AdmitRouterInfo(replyPeer, false, now()); err != nil {
		t.Fatalf("admit native reply-gateway i2pd RouterInfo: %v", err)
	}
	transportManager, err := NewNTCP2Manager(NTCP2ManagerConfig{
		Database:         database,
		StaticPrivate:    aliceStatic,
		StaticIV:         aliceIV,
		HandshakeTimeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	random := new(i2pdBuildDiagnosticRandom)
	sender := &i2pdBuildDiagnosticSender{
		next: transportManager, random: random,
		statics: map[ivnp.Hash][32]byte{peer.Hash(): buildStatic, replyPeer.Hash(): replyBuildStatic},
	}
	runtime := tunnel.NewRuntime(tunnel.RuntimeConfig{Sender: sender, Now: now})
	replyKeys := garlic.NewReplyKeyRegistry(4)
	service := NewService(nil)
	deliveryStatuses := make(chan i2np.DeliveryStatusMessage, 1)
	service.SetDeliveryStatusSink(func(status i2np.DeliveryStatusMessage) error {
		select {
		case deliveryStatuses <- status:
		default:
		}
		return nil
	})
	var buildManager *tunnel.BuildManager
	inboundResults := make(chan error, 1)
	outboundResults := make(chan error, 1)
	transportErrors := make(chan error, 4)
	buildManager, err = tunnel.NewBuildManager(tunnel.BuildManagerConfig{
		Runtime: runtime, Sender: sender, ReplyKeys: replyKeys,
		LocalRouter: alice.Hash(), StaticPrivate: aliceStatic,
		SeedReplyRouterInfo: func(seedCtx context.Context, endpoint, replyRouter ivnp.Hash) error {
			if endpoint != peer.Hash() || replyRouter != replyPeer.Hash() {
				return fmt.Errorf("unexpected reply RouterInfo seed endpoint=%s reply=%s", endpoint, replyRouter)
			}
			compressed, compressErr := netdb.CompressRouterInfo(replyWire)
			if compressErr != nil {
				return compressErr
			}
			payload, marshalErr := netdb.MarshalDatabaseStore(replyRouter, i2np.StoreRouterInfo, compressed, 0, ivnp.Hash{}, 0)
			if marshalErr != nil {
				return marshalErr
			}
			return transportManager.Send(seedCtx, endpoint, i2np.Message{
				Header:  i2np.Header{Type: i2np.DatabaseStore, ID: 0x31415926, Expiration: now() + 60_000},
				Payload: payload,
			})
		},
		LocalDelivery: func(message i2np.Message) error {
			return service.HandleI2NP(message, now(), false)
		},
		Now: now, Random: random,
	})
	if err != nil {
		t.Fatal(err)
	}
	service.SetTunnelBuildSink(func(_ I2NPSource, _ i2np.BuildRecords, message i2np.Message) error {
		result := buildManager.HandleInboundReply(message)
		select {
		case inboundResults <- result:
		default:
		}
		return result
	})
	service.SetOutboundTunnelBuildReplySink(func(message i2np.Message) error {
		result := buildManager.HandleReply(message)
		select {
		case outboundResults <- result:
		default:
		}
		return result
	})
	service.SetTunnelDataSink(runtime.Handle)
	garlicReceiver, err := NewGarlicReceiver(GarlicReceiverConfig{Service: service, ReplyKeys: replyKeys, Now: now, StaticPrivate: aliceStatic})
	if err != nil {
		t.Fatal(err)
	}
	service.SetGarlicSink(garlicReceiver.HandleGarlicFrom)
	ctx, cancel := context.WithCancel(context.Background())
	if err = transportManager.Start(ctx, TransportBindings{
		LocalInfo: alice,
		Clock:     WallClock{},
		HandleI2NP: func(message i2np.Message, _ uint64, _ bool) error {
			t.Logf("incoming_i2np_type=%d id=%d payload_len=%d", message.Header.Type, message.Header.ID, len(message.Payload))
			switch message.Header.Type {
			case i2np.ShortTunnelBuild, i2np.TunnelData, i2np.Garlic, i2np.OutboundTunnelBuildReply:
				if handleErr := service.HandleI2NP(message, now(), false); handleErr != nil {
					select {
					case transportErrors <- fmt.Errorf("incoming I2NP type %d: %w", message.Header.Type, handleErr):
					default:
					}
				}
			}
			return nil
		},
	}); err != nil {
		cancel()
		t.Fatalf("start native i2pd NTCP2 client: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = transportManager.Close()
		if waitErr := transportManager.Wait(); waitErr != nil {
			t.Errorf("wait for native i2pd NTCP2 client: %v", waitErr)
		}
	})
	peerHash := peer.Hash()
	replyPeerHash := replyPeer.Hash()
	openCtx, openCancel := context.WithTimeout(ctx, 30*time.Second)
	defer openCancel()
	if err = transportManager.openOutbound(openCtx, replyPeerHash); err != nil {
		t.Fatalf("open native reply-gateway i2pd NTCP2 session: %v", err)
	}
	if err = transportManager.openOutbound(openCtx, peerHash); err != nil {
		t.Fatalf("open native endpoint i2pd NTCP2 session: %v", err)
	}

	circuitID := uint32(now()) | 1
	receiveID := circuitID ^ 0x50607080
	if receiveID ==
		0 {
		receiveID = 1
	}

	replyID, err := buildManager.StartInbound(ctx, tunnel.InboundBuild{
		CircuitID: circuitID,
		Hops: []tunnel.ShortBuildHop{{
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
		ivnp.EncodeI2PBase64(replyPeerHash[:]), inspected.ReceiveTunnelID, inspected.NextTunnelID,
		ivnp.EncodeI2PBase64(inspected.NextRouter[:]), inspected.Gateway, inspected.Endpoint,
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

	outboundCircuitID := circuitID ^ 0x90a0b0c0
	outboundReceiveID := receiveID ^ 0xd0e0f001
	if outboundCircuitID ==
		0 {
		outboundCircuitID = 1
	}

	if outboundReceiveID == 0 || outboundReceiveID == receiveID {
		outboundReceiveID++
	}
	outboundReplyID, err := buildManager.StartOutbound(ctx, tunnel.OutboundBuild{
		CircuitID: outboundCircuitID,
		Hops: []tunnel.ShortBuildHop{{
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
		inspected.ReceiveTunnelID, inspected.NextTunnelID, ivnp.EncodeI2PBase64(inspected.NextRouter[:]),
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

	compressed, err := netdb.CompressRouterInfo(alice.Snapshot().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	const publicationToken = uint32(0x10203040)
	storePayload, err := netdb.MarshalDatabaseStore(alice.Hash(), i2np.StoreRouterInfo, compressed, publicationToken, replyPeerHash, receiveID)
	if err != nil {
		t.Fatal(err)
	}
	storeMessage := i2np.Message{
		Header:  i2np.Header{Type: i2np.DatabaseStore, ID: 0x50607080, Expiration: now() + 60_000},
		Payload: storePayload,
	}
	storeFrame := make([]byte, storeMessage.EncodedLen())
	if _, err = storeMessage.MarshalTo(storeFrame); err != nil {
		t.Fatal(err)
	}
	if err = runtime.SendBlock(ctx, outboundCircuitID, tunnel.Block{
		Delivery: tunnel.DeliveryRouter, Gateway: peerHash, Last: true, Data: storeFrame,
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
	next    *NTCP2Manager
	random  *i2pdBuildDiagnosticRandom
	statics map[ivnp.Hash][32]byte

	mu      sync.Mutex
	request tunnel.ShortBuildRequest
	err     error
}

func (s *i2pdBuildDiagnosticSender) Send(ctx context.Context, peer ivnp.Hash, message i2np.Message) error {
	if message.Header.Type == i2np.ShortTunnelBuild {
		static, ok := s.statics[peer]
		if !ok {
			return fmt.Errorf("missing signed identity build key for %s", ivnp.EncodeI2PBase64(peer[:]))
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

func (s *i2pdBuildDiagnosticSender) inspection() (tunnel.ShortBuildRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.request, s.err
}

func inspectI2PDOutboundShortRecord(message i2np.Message, peer ivnp.Hash, static [32]byte, randomStream []byte) (tunnel.ShortBuildRequest, error) {
	records, err := i2np.ParseBuildRecords(i2np.ShortTunnelBuild, message.Payload)
	if err != nil {
		return tunnel.ShortBuildRequest{}, err
	}
	if records.Count != 4 {
		return tunnel.ShortBuildRequest{}, fmt.Errorf("record count = %d, want 4", records.Count)
	}
	var record []byte
	for index := range int(records.Count) {
		candidate := records.Records[index*tunnel.ShortBuildRecordSize : (index+1)*tunnel.ShortBuildRecordSize]
		if bytes.Equal(candidate[:16], peer[:16]) {
			if record != nil {
				return tunnel.ShortBuildRequest{}, fmt.Errorf("duplicate peer prefix")
			}
			record = candidate
		}
	}
	if record == nil {
		return tunnel.ShortBuildRequest{}, fmt.Errorf("peer record not found")
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
		return tunnel.ShortBuildRequest{}, fmt.Errorf("record ephemeral key differs from BuildManager random source")
	}
	remote, err := curve.NewPublicKey(static[:])
	if err != nil {
		return tunnel.ShortBuildRequest{}, err
	}
	shared, err := private.ECDH(remote)
	if err != nil {
		return tunnel.ShortBuildRequest{}, err
	}
	defer clear(shared)
	state := noise.Initialize("Noise_N_25519_ChaChaPoly_SHA256")
	defer state.ReleaseSensitive()
	if err = state.MixHash(nil); err != nil {
		return tunnel.ShortBuildRequest{}, err
	}
	if err = state.MixHash(static[:]); err != nil {
		return tunnel.ShortBuildRequest{}, err
	}
	if err = state.MixHash(record[16:48]); err != nil {
		return tunnel.ShortBuildRequest{}, err
	}
	if err = state.MixKey(shared); err != nil {
		return tunnel.ShortBuildRequest{}, err
	}
	var plaintext [tunnel.ShortBuildRequestPlainSize]byte
	if _, err = state.DecryptAndHash(plaintext[:], record[48:]); err != nil {
		return tunnel.ShortBuildRequest{}, err
	}
	if plaintext[40]&^byte(0xc0) != 0 || plaintext[40]&0xc0 == 0xc0 ||
		plaintext[41] != 0 || plaintext[42] != 0 || plaintext[43] != 0 ||
		binary.BigEndian.Uint16(plaintext[56:58]) != 0 {
		return tunnel.ShortBuildRequest{}, fmt.Errorf("flags/reserved/options prefix = %x/%x/%x", plaintext[40:44], plaintext[41:44], plaintext[56:58])
	}
	return tunnel.ParseShortBuildRequest(plaintext[:])
}
