package router

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/garlic"
	garlicecies "gosuda.org/ivnp/networking/internal/garlic/ecies"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/tunnel"
)

type buildReplyCaptureSender struct {
	peer    foundation.Hash
	message i2np.Message
	handle  func(i2np.Message) error
}

func (s *buildReplyCaptureSender) Send(_ context.Context, peer foundation.Hash, message i2np.Message) error {
	s.peer = peer
	s.message = i2np.Message{Header: message.Header, Payload: append([]byte(nil), message.Payload...)}
	if s.handle != nil {
		return s.handle(s.message)
	}
	return nil
}

func TestBuildReplySenderSendsTunnelGatewayDirectlyToIBGW(t *testing.T) {
	const now = uint64(1_000)
	local, gateway := foundation.Hash{1}, foundation.Hash{2}
	var received i2np.Message
	destinationSender := &buildReplyCaptureSender{}
	service := NewWithSinks(nil, Sinks{OutboundTunnelBuildReply: func(message i2np.Message) error {
		received = message
		return nil
	}})
	sender, err := NewBuildReplySender(BuildReplySenderConfig{
		Sender: destinationSender, Service: service, LocalRouter: local, Now: func() uint64 { return now },
		NextID: buildReplyIDSource(8, 9),
	})
	if err != nil {
		t.Fatal(err)
	}
	key := testRouterReplyKey()
	reply := testRouterBuildReply()
	if err = sender.SendBuildReply(context.Background(), gateway, 42, key, reply); err != nil {
		t.Fatal(err)
	}
	if destinationSender.peer != gateway || destinationSender.message.Header.Type != i2np.TunnelGateway {
		t.Fatalf("tunnel delivery = peer %x message %#v", destinationSender.peer, destinationSender.message.Header)
	}
	tunnelGateway, err := i2np.ParseTunnelGateway(destinationSender.message.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if tunnelGateway.TunnelID != 42 || tunnelGateway.Embedded.Header.Type != i2np.Garlic {
		t.Fatalf("reply route = %#v", tunnelGateway)
	}
	if destinationSender.message.Header.ID != 9 || tunnelGateway.Embedded.Header.ID != 8 || destinationSender.message.Header.ID == reply.Header.ID || tunnelGateway.Embedded.Header.ID == reply.Header.ID {
		t.Fatalf("envelope IDs = gateway %d garlic %d reply %d", destinationSender.message.Header.ID, tunnelGateway.Embedded.Header.ID, reply.Header.ID)
	}
	garlicMessage, err := i2np.ParseGarlic(tunnelGateway.Embedded.Payload)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := garlicecies.OpenOneTimeReplyExistingSession(make([]byte, len(garlicMessage.Encrypted)-8-16), key.Key, key.Tag, garlicMessage.Encrypted)
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := javaTransportHeader(t, reply.Header)
	if opened.Header != wantHeader || string(opened.Payload) != string(reply.Payload) {
		t.Fatalf("opened reply = %#v, want header %#v", opened, wantHeader)
	}
	if received.Header.Type != 0 {
		t.Fatal("remote reply was delivered to local Service")
	}
}

func TestOutboundBuildReplyTraversesInboundTunnelDataPlane(t *testing.T) {
	const (
		now                  = uint64(1_700_000_000_000)
		replyGatewayTunnelID = uint32(42)
		replyEndpointID      = uint32(43)
		outboundCircuitID    = uint32(44)
		outboundReceiveID    = uint32(45)
	)
	creatorHash := foundation.Hash{1}
	gatewayHash := foundation.Hash{2}
	obepHash := foundation.Hash{3}
	ownerHash := foundation.Hash{9}
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logOutput, nil))

	var layerKey, ivKey [32]byte
	for index := range layerKey {
		layerKey[index] = byte(index + 1)
		ivKey[index] = byte(index + 33)
	}
	gatewayEncryptor, err := tunnel.NewLayerEncryptor(layerKey[:], ivKey[:])
	if err != nil {
		t.Fatal(err)
	}
	creatorDecryptor, err := tunnel.NewLayerDecryptor(layerKey[:], ivKey[:])
	if err != nil {
		t.Fatal(err)
	}

	creatorService := NewService(nil)
	var obepService *Service
	creatorSender := &buildReplyCaptureSender{handle: func(message i2np.Message) error {
		return obepService.HandleI2NPFrom(creatorHash, message, now, false)
	}}
	creatorRuntime := tunnel.NewRuntime(tunnel.RuntimeConfig{Sender: creatorSender, Now: func() uint64 { return now }})
	replyKeys := garlic.NewReplyKeyRegistry(4)
	creatorManager, err := tunnel.NewBuildManager(tunnel.BuildManagerConfig{
		Runtime: creatorRuntime, Pool: tunnel.NewOwnedPool(ownerHash, 4), Sender: creatorSender, ReplyKeys: replyKeys,
		LocalRouter: creatorHash, Now: func() uint64 { return now }, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	creatorService.SetTunnelDataSink(creatorRuntime.Handle)
	creatorService.SetOutboundTunnelBuildReplySink(creatorManager.HandleReply)
	creatorReceiver, err := NewGarlicReceiver(GarlicReceiverConfig{
		Service: creatorService, ReplyKeys: replyKeys, Now: func() uint64 { return now }, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	creatorService.SetGarlicSink(creatorReceiver.HandleGarlicFrom)
	if err = creatorRuntime.RegisterInbound(tunnel.InboundCircuit{
		ID: replyEndpointID, Transforms: []tunnel.LayerCipher{creatorDecryptor},
		Endpoint: tunnel.NewEndpoint(8, i2np.I2PDMaxPayload),
		Local: func(message i2np.Message) error {
			return creatorService.HandleI2NP(message, now, false)
		},
		ExpiresAt: now + 600_000,
	}); err != nil {
		t.Fatal(err)
	}

	gatewaySender := &buildReplyCaptureSender{handle: func(message i2np.Message) error {
		return creatorService.HandleI2NPFrom(gatewayHash, message, now, false)
	}}
	gatewayRuntime := tunnel.NewRuntime(tunnel.RuntimeConfig{Sender: gatewaySender, Now: func() uint64 { return now }})
	gatewayService := NewWithSinks(nil, Sinks{TunnelGateway: gatewayRuntime.HandleGateway})
	if err = gatewayRuntime.RegisterOutbound(tunnel.OutboundCircuit{
		ID: replyGatewayTunnelID, FirstHop: creatorHash, NextTunnelID: replyEndpointID,
		Transforms: []tunnel.LayerCipher{gatewayEncryptor}, ExpiresAt: now + 600_000,
	}); err != nil {
		t.Fatal(err)
	}

	obepService = NewService(nil)
	obepSender := &buildReplyCaptureSender{handle: func(message i2np.Message) error {
		return gatewayService.HandleI2NPFrom(obepHash, message, now, false)
	}}
	obepRuntime := tunnel.NewRuntime(tunnel.RuntimeConfig{Sender: obepSender, Now: func() uint64 { return now }})
	replySender, err := NewBuildReplySender(BuildReplySenderConfig{
		Sender: obepSender, Service: obepService, LocalRouter: obepHash, Now: func() uint64 { return now },
		NextID: buildReplyIDSource(50, 51), Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	obepPrivateBytes := make([]byte, 32)
	for index := range obepPrivateBytes {
		obepPrivateBytes[index] = byte(index + 65)
	}
	obepPrivate, err := ecdh.X25519().NewPrivateKey(obepPrivateBytes)
	if err != nil {
		t.Fatal(err)
	}
	obepManager, err := tunnel.NewBuildManager(tunnel.BuildManagerConfig{
		Runtime: obepRuntime, Sender: obepSender, ReplyKeys: garlic.NewReplyKeyRegistry(1),
		ReplySender: replySender, LocalRouter: obepHash, StaticPrivate: obepPrivateBytes,
		LocalDelivery: func(i2np.Message) error { return nil }, Now: func() uint64 { return now }, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	obepService.SetTunnelBuildSink(func(source I2NPSource, _ i2np.BuildRecords, message i2np.Message) error {
		if !source.Direct {
			return errors.New("outbound build was not delivered by direct transport")
		}
		return obepManager.HandleBuildFrom(source.Peer, message)
	})

	hop := tunnel.ShortBuildHop{Router: obepHash, ReceiveTunnelID: outboundReceiveID}
	copy(hop.StaticKey[:], obepPrivate.PublicKey().Bytes())
	if _, err = creatorManager.StartOutbound(context.Background(), tunnel.OutboundBuild{
		CircuitID: outboundCircuitID, Hops: []tunnel.ShortBuildHop{hop},
		ReplyRouter: gatewayHash, ReplyTunnelID: replyGatewayTunnelID, ExpiresAt: now + 600_000,
	}); err != nil {
		t.Fatal(err)
	}
	if owner, ok := creatorRuntime.CircuitOwner(outboundCircuitID); !ok || owner != ownerHash {
		t.Fatalf("outbound circuit owner = %x, %t; want %x", owner, ok, ownerHash)
	}
	if replyKeys.Len() != 0 {
		t.Fatalf("reply key count = %d, want 0 after one-time delivery", replyKeys.Len())
	}
	if creatorSender.peer != obepHash || obepSender.peer != gatewayHash || gatewaySender.peer != creatorHash {
		t.Fatalf("reply path creator=%x endpoint=%x gateway=%x", creatorSender.peer, obepSender.peer, gatewaySender.peer)
	}
	for _, stage := range []string{
		"creator_registered", "obep_wrapped", "obep_sent", "creator_key_matched",
		"creator_decrypted", "creator_received", "creator_authenticated",
	} {
		if !strings.Contains(logOutput.String(), `"stage":"`+stage+`"`) {
			t.Fatalf("reply logs omit stage %q:\n%s", stage, logOutput.String())
		}
	}
	wantOwnerLog := `"owner_kind":"client","owner":"` + foundation.EncodeI2PBase64(ownerHash[:]) + `"`
	if !strings.Contains(logOutput.String(), wantOwnerLog) {
		t.Fatalf("reply logs omit stable owner fields %q:\n%s", wantOwnerLog, logOutput.String())
	}
}

func TestBuildReplySenderInjectsRawReplyForSameRouterGateway(t *testing.T) {
	const now = uint64(1_000)
	local := foundation.Hash{1}
	calls := 0
	var tunnelID uint32
	var received i2np.Message
	service := NewWithSinks(nil, Sinks{TunnelGateway: func(id uint32, message i2np.Message) error {
		calls++
		tunnelID = id
		received = message
		return nil
	}})
	destinationSender := &buildReplyCaptureSender{}
	sender, err := NewBuildReplySender(BuildReplySenderConfig{
		Sender: destinationSender, Service: service, LocalRouter: local, Now: func() uint64 { return now },
		NextID: buildReplyIDSource(8),
	})
	if err != nil {
		t.Fatal(err)
	}
	reply := testRouterBuildReply()
	if err = sender.SendBuildReply(context.Background(), local, 42, testRouterReplyKey(), reply); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || tunnelID != 42 || received.Header != reply.Header || string(received.Payload) != string(reply.Payload) {
		t.Fatalf("local injection = calls %d tunnel %d reply %#v", calls, tunnelID, received)
	}
	if destinationSender.message.Header.Type != 0 {
		t.Fatal("same-router reply was sent remotely")
	}
}

func TestBuildReplySenderGarlicSurvivesServiceAdmissionWithoutReplayCollision(t *testing.T) {
	const now = uint64(1_000)
	local, gateway := foundation.Hash{1}, foundation.Hash{2}
	var received i2np.Message
	service := NewWithSinks(nil, Sinks{OutboundTunnelBuildReply: func(message i2np.Message) error {
		received = i2np.Message{Header: message.Header, Payload: append([]byte(nil), message.Payload...)}
		return nil
	}})
	key := testRouterReplyKey()
	registry := garlic.NewReplyKeyRegistry(1)
	if err := registry.RegisterGarlicReplyKey(key); err != nil {
		t.Fatal(err)
	}
	receiver, err := NewGarlicReceiver(GarlicReceiverConfig{
		Service: service, ReplyKeys: registry, Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	service.SetGarlicSink(receiver.HandleGarlicFrom)
	destinationSender := &buildReplyCaptureSender{}
	sender, err := NewBuildReplySender(BuildReplySenderConfig{
		Sender: destinationSender, Service: service, LocalRouter: local, Now: func() uint64 { return now },
		NextID: buildReplyIDSource(8, 9),
	})
	if err != nil {
		t.Fatal(err)
	}
	reply := testRouterBuildReply()
	if err = sender.SendBuildReply(context.Background(), gateway, 42, key, reply); err != nil {
		t.Fatal(err)
	}
	tunnelGateway, err := i2np.ParseTunnelGateway(destinationSender.message.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.HandleI2NP(tunnelGateway.Embedded, now, false); err != nil {
		t.Fatal(err)
	}
	wantHeader := javaTransportHeader(t, reply.Header)
	if received.Header != wantHeader || string(received.Payload) != string(reply.Payload) {
		t.Fatalf("admitted reply = %#v, want header %#v", received, wantHeader)
	}
}

func TestGarlicReceiverConsumesShortBuildReplyTagBeforeAuthentication(t *testing.T) {
	const now = uint64(1_000)
	key := testRouterReplyKey()
	registry := garlic.NewReplyKeyRegistry(1)
	if err := registry.RegisterGarlicReplyKey(key); err != nil {
		t.Fatal(err)
	}
	calls := 0
	service := NewWithSinks(nil, Sinks{OutboundTunnelBuildReply: func(i2np.Message) error { calls++; return nil }})
	receiver, err := NewGarlicReceiver(GarlicReceiverConfig{Service: service, ReplyKeys: registry, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	reply := testRouterBuildReply()
	ciphertext := make([]byte, 8+13+len(reply.Payload)+16)
	ciphertext, err = garlicecies.SealOneTimeReplyExistingSession(ciphertext, key.Key, key.Tag, reply, nil)
	if err != nil {
		t.Fatal(err)
	}
	outer := i2np.Message{Header: i2np.Header{Type: i2np.Garlic}, Payload: make([]byte, 4+len(ciphertext))}
	copy(outer.Payload[4:], ciphertext)
	outer.Payload[0] = byte(len(ciphertext) >> 24)
	outer.Payload[1] = byte(len(ciphertext) >> 16)
	outer.Payload[2] = byte(len(ciphertext) >> 8)
	outer.Payload[3] = byte(len(ciphertext))
	if err = receiver.HandleGarlic(outer); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || registry.Len() != 0 {
		t.Fatalf("authenticated calls = %d, retained keys = %d", calls, registry.Len())
	}
	if err = registry.RegisterGarlicReplyKey(key); err != nil {
		t.Fatal(err)
	}
	outer.Payload[len(outer.Payload)-1] ^= 1
	if err = receiver.HandleGarlic(outer); !errors.Is(err, garlicecies.ErrOneTimeReplyExistingSession) || registry.Len() != 0 {
		t.Fatalf("tampered one-use reply error = %v, retained keys = %d", err, registry.Len())
	}
}

func testRouterReplyKey() (key tunnel.GarlicReplyKey) {
	for index := range key.Key {
		key.Key[index] = byte(index + 1)
	}
	for index := range key.Tag {
		key.Tag[index] = byte(index + 8)
	}
	key.ExpiresAt = 10_000
	return key
}

func testRouterBuildReply() i2np.Message {
	return i2np.Message{Header: i2np.Header{Type: i2np.OutboundTunnelBuildReply, ID: 7, Expiration: 10_000}, Payload: append([]byte{1}, make([]byte, i2np.ShortBuildRecordLen)...)}
}

func buildReplyIDSource(ids ...uint32) MessageIDSource {
	index := 0
	return func() (uint32, error) {
		if index == len(ids) {
			return 0, errors.New("exhausted build reply IDs")
		}
		id := ids[index]
		index++
		return id, nil
	}
}

func javaTransportHeader(t testing.TB, header i2np.Header) i2np.Header {
	t.Helper()
	seconds, ok := i2np.EncodeTransportExpiration(header.Expiration)
	if !ok {
		t.Fatal("test expiration is not encodable")
	}
	header.Expiration = i2np.DecodeTransportExpiration(seconds)
	return header
}
