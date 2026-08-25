package router

import (
	"context"
	"errors"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/garlic"
	"gosuda.org/ivnp/networking/internal/garlic/ecies"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/tunnel"
	"testing"
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
	if opened.Header != reply.Header || string(opened.Payload) != string(reply.Payload) {
		t.Fatalf("opened reply = %#v", opened)
	}
	if received.Header.Type != 0 {
		t.Fatal("remote reply was delivered to local Service")
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
	if received.Header != reply.Header || string(received.Payload) != string(reply.Payload) {
		t.Fatalf("admitted reply = %#v", received)
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
