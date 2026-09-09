package router

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"errors"
	"testing"
	"time"

	controlplanetunnel "gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

var (
	errOutboundBuildNotDirect = errors.New("outbound build was not delivered by direct transport")
	errBuildReplyIDsExhausted = errors.New("exhausted build reply IDs")
)

type buildReplyCaptureSender struct {
	peer    foundation.Hash
	message foundation.I2NPMessage
	handle  func(foundation.I2NPMessage) error
}

func (s *buildReplyCaptureSender) Send(_ context.Context, peer foundation.Hash, message foundation.I2NPMessage) error {
	s.peer = peer
	s.message = foundation.I2NPMessage{Header: message.Header, Payload: append([]byte(nil), message.Payload...)}
	if s.handle != nil {
		return s.handle(s.message)
	}
	return nil
}

func TestBuildReplySenderSendsTunnelGatewayDirectlyToIBGW(t *testing.T) {
	const now = uint64(1_000)
	local, gateway := foundation.Hash{1}, foundation.Hash{2}
	var received foundation.I2NPMessage
	destinationSender := &buildReplyCaptureSender{}
	service, control := newControlServiceForTest(t, nil, ControlSinks{OutboundTunnelBuildReply: func(message foundation.I2NPMessage) error {
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
	if destinationSender.peer != gateway || destinationSender.message.Header.Type != foundation.I2NPTunnelGateway {
		t.Fatalf("tunnel delivery = peer %x message %#v", destinationSender.peer, destinationSender.message.Header)
	}
	tunnelGateway, err := foundation.I2NPParseTunnelGateway(destinationSender.message.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if tunnelGateway.TunnelID != 42 || tunnelGateway.Embedded.Header.Type != foundation.I2NPGarlic {
		t.Fatalf("reply route = %#v", tunnelGateway)
	}
	if destinationSender.message.Header.ID != 9 || tunnelGateway.Embedded.Header.ID != 8 || destinationSender.message.Header.ID == reply.Header.ID || tunnelGateway.Embedded.Header.ID == reply.Header.ID {
		t.Fatalf("envelope IDs = gateway %d garlic %d reply %d", destinationSender.message.Header.ID, tunnelGateway.Embedded.Header.ID, reply.Header.ID)
	}
	garlicMessage, err := foundation.I2NPParseGarlic(tunnelGateway.Embedded.Payload)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := dataplane.GarlicECIESOpenOneTimeReplyExistingSession(make([]byte, len(garlicMessage.Encrypted)-8-16), key.Key, key.Tag, garlicMessage.Encrypted)
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := javaTransportHeader(t, reply.Header)
	if opened.Header != wantHeader || !bytes.Equal(opened.Payload, reply.Payload) {
		t.Fatalf("opened reply = %#v, want header %#v", opened, wantHeader)
	}
	waitBuildReplyControl(t, control)
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

	var layerKey, ivKey [32]byte
	for index := range layerKey {
		layerKey[index] = byte(index + 1)
		ivKey[index] = byte(index + 33)
	}
	gatewayEncryptor, err := dataplane.TunnelNewLayerEncryptor(layerKey[:], ivKey[:])
	if err != nil {
		t.Fatal(err)
	}
	creatorDecryptor, err := dataplane.TunnelNewLayerDecryptor(layerKey[:], ivKey[:])
	if err != nil {
		t.Fatal(err)
	}

	var creatorService *dataplane.RouterService
	var obepService *dataplane.RouterService
	creatorSender := &buildReplyCaptureSender{handle: func(message foundation.I2NPMessage) error {
		return obepService.HandleI2NPFrom(creatorHash, message, now, false)
	}}
	creatorRuntime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: creatorSender, Now: func() uint64 { return now }})
	replyKeys := dataplane.GarlicNewReplyKeyRegistry(4)
	creatorManager, err := controlplanetunnel.NewBuildManager(controlplanetunnel.BuildManagerConfig{
		Runtime: creatorRuntime, Pool: controlplanetunnel.NewOwnedPool(ownerHash, 4), Sender: creatorSender, ReplyKeys: replyKeys,
		LocalRouter: creatorHash, Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := creatorManager.Close(); err != nil {
			t.Error(err)
		}
	})
	creatorService, creatorControl := newControlServiceForTest(t, nil, ControlSinks{OutboundTunnelBuildReply: creatorManager.HandleReply})
	creatorService.SetTunnelDataSink(creatorRuntime.Handle)
	creatorReceiver, err := dataplane.RouterNewGarlicReceiver(dataplane.RouterGarlicReceiverConfig{
		Service: creatorService, ReplyKeys: replyKeys, Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(creatorReceiver.ReleaseSensitive)
	creatorService.SetGarlicSink(creatorReceiver.HandleGarlicFrom)
	creatorInbound, err := creatorRuntime.RegisterInbound(dataplane.TunnelInboundCircuit{
		ID: replyEndpointID, Transforms: []dataplane.TunnelLayerCipher{creatorDecryptor},
		Endpoint: dataplane.TunnelNewEndpoint(8, foundation.I2NPI2PDMaxPayload),
		Local: func(message foundation.I2NPMessage) error {
			return creatorService.HandleI2NP(message, now, false)
		},
		ExpiresAt: now + 600_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { creatorRuntime.RemoveCircuit(creatorInbound) })

	gatewaySender := &buildReplyCaptureSender{handle: func(message foundation.I2NPMessage) error {
		return creatorService.HandleI2NPFrom(gatewayHash, message, now, false)
	}}
	gatewayRuntime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: gatewaySender, Now: func() uint64 { return now }})
	gatewayService := dataplane.RouterNewService(dataplane.RouterSinks{TunnelGateway: gatewayRuntime.HandleGateway})
	gatewayOutbound, err := gatewayRuntime.RegisterOutbound(dataplane.TunnelOutboundCircuit{
		ID: replyGatewayTunnelID, FirstHop: creatorHash, NextTunnelID: replyEndpointID,
		Transforms: []dataplane.TunnelLayerCipher{gatewayEncryptor}, ExpiresAt: now + 600_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gatewayRuntime.RemoveCircuit(gatewayOutbound) })

	var obepManager *controlplanetunnel.BuildManager
	obepService, obepControl := newControlServiceForTest(t, nil, ControlSinks{TunnelBuild: func(ctx context.Context, source dataplane.RouterI2NPSource, _ foundation.I2NPBuildRecords, message foundation.I2NPMessage) error {
		if !source.Direct {
			return errOutboundBuildNotDirect
		}
		return obepManager.HandleBuildContext(ctx, controlplanetunnel.BuildSource{Router: source.Peer, Direct: source.Direct}, message)
	}})
	obepSender := &buildReplyCaptureSender{handle: func(message foundation.I2NPMessage) error {
		return gatewayService.HandleI2NPFrom(obepHash, message, now, false)
	}}
	obepRuntime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: obepSender, Now: func() uint64 { return now }})
	replySender, err := NewBuildReplySender(BuildReplySenderConfig{
		Sender: obepSender, Service: obepService, LocalRouter: obepHash, Now: func() uint64 { return now },
		NextID: buildReplyIDSource(50, 51),
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
	obepManager, err = controlplanetunnel.NewBuildManager(controlplanetunnel.BuildManagerConfig{
		Runtime: obepRuntime, Sender: obepSender, ReplyKeys: dataplane.GarlicNewReplyKeyRegistry(1),
		ReplySender: replySender, LocalRouter: obepHash, StaticPrivate: obepPrivateBytes,
		LocalDelivery: func(foundation.I2NPMessage) error { return nil }, Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := obepManager.Close(); err != nil {
			t.Error(err)
		}
	})

	hop := controlplanetunnel.ShortBuildHop{Router: obepHash, ReceiveTunnelID: outboundReceiveID}
	copy(hop.StaticKey[:], obepPrivate.PublicKey().Bytes())
	if _, err = creatorManager.StartOutbound(context.Background(), controlplanetunnel.OutboundBuild{
		CircuitID: outboundCircuitID, Hops: []controlplanetunnel.ShortBuildHop{hop},
		ReplyRouter: gatewayHash, ReplyTunnelID: replyGatewayTunnelID, ExpiresAt: now + 600_000,
	}); err != nil {
		t.Fatal(err)
	}
	waitBuildReplyControl(t, obepControl)
	waitBuildReplyControl(t, creatorControl)
	if owner, ok := creatorRuntime.CircuitOwner(outboundCircuitID); !ok || owner != ownerHash {
		t.Fatalf("outbound circuit owner = %x, %t; want %x", owner, ok, ownerHash)
	}
	if replyKeys.Len() != 0 {
		t.Fatalf("reply key count = %d, want 0 after one-time delivery", replyKeys.Len())
	}
	if creatorSender.peer != obepHash || obepSender.peer != gatewayHash || gatewaySender.peer != creatorHash {
		t.Fatalf("reply path creator=%x endpoint=%x gateway=%x", creatorSender.peer, obepSender.peer, gatewaySender.peer)
	}
}

func TestBuildReplySenderInjectsRawReplyForSameRouterGateway(t *testing.T) {
	const now = uint64(1_000)
	local := foundation.Hash{1}
	calls := 0
	var tunnelID uint32
	var received foundation.I2NPMessage
	service := dataplane.RouterNewService(dataplane.RouterSinks{TunnelGateway: func(id uint32, message foundation.I2NPMessage) error {
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
	if calls != 1 || tunnelID != 42 || received.Header != reply.Header || !bytes.Equal(received.Payload, reply.Payload) {
		t.Fatalf("local injection = calls %d tunnel %d reply %#v", calls, tunnelID, received)
	}
	if destinationSender.message.Header.Type != 0 {
		t.Fatal("same-router reply was sent remotely")
	}
}

func TestBuildReplySenderGarlicSurvivesServiceAdmissionWithoutReplayCollision(t *testing.T) {
	const now = uint64(1_000)
	local, gateway := foundation.Hash{1}, foundation.Hash{2}
	var received foundation.I2NPMessage
	service, control := newControlServiceForTest(t, nil, ControlSinks{OutboundTunnelBuildReply: func(message foundation.I2NPMessage) error {
		received = foundation.I2NPMessage{Header: message.Header, Payload: append([]byte(nil), message.Payload...)}
		return nil
	}})
	key := testRouterReplyKey()
	registry := dataplane.GarlicNewReplyKeyRegistry(1)
	if err := registry.RegisterGarlicReplyKey(key); err != nil {
		t.Fatal(err)
	}
	receiver, err := dataplane.RouterNewGarlicReceiver(dataplane.RouterGarlicReceiverConfig{
		Service: service, ReplyKeys: registry, Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(receiver.ReleaseSensitive)
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
	tunnelGateway, err := foundation.I2NPParseTunnelGateway(destinationSender.message.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.HandleI2NP(tunnelGateway.Embedded, now, false); err != nil {
		t.Fatal(err)
	}
	waitBuildReplyControl(t, control)
	wantHeader := javaTransportHeader(t, reply.Header)
	if received.Header != wantHeader || !bytes.Equal(received.Payload, reply.Payload) {
		t.Fatalf("admitted reply = %#v, want header %#v", received, wantHeader)
	}
}

func TestGarlicReceiverConsumesShortBuildReplyTagBeforeAuthentication(t *testing.T) {
	const now = uint64(1_000)
	key := testRouterReplyKey()
	registry := dataplane.GarlicNewReplyKeyRegistry(1)
	if err := registry.RegisterGarlicReplyKey(key); err != nil {
		t.Fatal(err)
	}
	calls := 0
	service, control := newControlServiceForTest(t, nil, ControlSinks{OutboundTunnelBuildReply: func(foundation.I2NPMessage) error { calls++; return nil }})
	receiver, err := dataplane.RouterNewGarlicReceiver(dataplane.RouterGarlicReceiverConfig{Service: service, ReplyKeys: registry, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(receiver.ReleaseSensitive)
	reply := testRouterBuildReply()
	ciphertext := make([]byte, 8+13+len(reply.Payload)+16)
	ciphertext, err = dataplane.GarlicECIESSealOneTimeReplyExistingSession(ciphertext, key.Key, key.Tag, reply, nil)
	if err != nil {
		t.Fatal(err)
	}
	outer := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPGarlic}, Payload: make([]byte, 4+len(ciphertext))}
	copy(outer.Payload[4:], ciphertext)
	outer.Payload[0] = byte(len(ciphertext) >> 24)
	outer.Payload[1] = byte(len(ciphertext) >> 16)
	outer.Payload[2] = byte(len(ciphertext) >> 8)
	outer.Payload[3] = byte(len(ciphertext))
	if err = receiver.HandleGarlic(outer); err != nil {
		t.Fatal(err)
	}
	waitBuildReplyControl(t, control)
	if calls != 1 || registry.Len() != 0 {
		t.Fatalf("authenticated calls = %d, retained keys = %d", calls, registry.Len())
	}
	if err = registry.RegisterGarlicReplyKey(key); err != nil {
		t.Fatal(err)
	}
	outer.Payload[len(outer.Payload)-1] ^= 1
	if err = receiver.HandleGarlic(outer); !errors.Is(err, dataplane.GarlicECIESErrOneTimeReplyExistingSession) || registry.Len() != 0 {
		t.Fatalf("tampered one-use reply error = %v, retained keys = %d", err, registry.Len())
	}
}

func testRouterReplyKey() (key dataplane.GarlicReplyKey) {
	for index := range key.Key {
		key.Key[index] = byte(index + 1)
	}
	for index := range key.Tag {
		key.Tag[index] = byte(index + 8)
	}
	key.ExpiresAt = 10_000
	return key
}

func testRouterBuildReply() foundation.I2NPMessage {
	return foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPOutboundTunnelBuildReply, ID: 7, Expiration: 10_000}, Payload: append([]byte{1}, make([]byte, foundation.I2NPShortBuildRecordLen)...)}
}

func buildReplyIDSource(ids ...uint32) dataplane.RouterMessageIDSource {
	index := 0
	return func() (uint32, error) {
		if index == len(ids) {
			return 0, errBuildReplyIDsExhausted
		}
		id := ids[index]
		index++
		return id, nil
	}
}

func javaTransportHeader(t testing.TB, header foundation.I2NPHeader) foundation.I2NPHeader {
	t.Helper()
	seconds, ok := foundation.I2NPEncodeTransportExpiration(header.Expiration)
	if !ok {
		t.Fatal("test expiration is not encodable")
	}
	header.Expiration = foundation.I2NPDecodeTransportExpiration(seconds)
	return header
}

func waitBuildReplyControl(t *testing.T, control *ControlDispatcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := control.WaitIdle(ctx); err != nil {
		t.Fatalf("build reply control completion = %v", err)
	}
}
