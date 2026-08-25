package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"errors"
	ivnp "gosuda.org/ivnp"
	"gosuda.org/ivnp/crypto/cryptx"
	eciesgarlic "gosuda.org/ivnp/protocol/garlic/ecies"
	"gosuda.org/ivnp/protocol/i2np"
	"sync"
	"testing"
	"time"
)

type buildCounterReader struct{ value byte }

func (r *buildCounterReader) Read(dst []byte) (int, error) {
	for index := range dst {
		r.value++
		dst[index] = r.value
	}
	return len(dst), nil
}

type buildReplyRegistry struct {
	entries map[[8]byte]GarlicReplyKey
	removed [][8]byte
}

func newBuildReplyRegistry() *buildReplyRegistry {
	return &buildReplyRegistry{entries: make(map[[8]byte]GarlicReplyKey)}
}

func (r *buildReplyRegistry) RegisterGarlicReplyKey(key GarlicReplyKey) error {
	r.entries[key.Tag] = key
	return nil
}

func (r *buildReplyRegistry) RemoveGarlicReplyKey(tag [8]byte) {
	delete(r.entries, tag)
	r.removed = append(r.removed, tag)
}

func (r *buildReplyRegistry) consume(tag [8]byte) (GarlicReplyKey, error) {
	key, ok := r.entries[tag]
	if !ok {
		return GarlicReplyKey{}, ErrBuildPending
	}
	delete(r.entries, tag)
	return key, nil
}

type captureBuildReplySender struct {
	peer   ivnp.Hash
	tunnel uint32
	key    GarlicReplyKey
	reply  i2np.Message
}

func (s *captureBuildReplySender) SendBuildReply(_ context.Context, peer ivnp.Hash, tunnelID uint32, key GarlicReplyKey, reply i2np.Message) error {
	s.peer, s.tunnel, s.key, s.reply = peer, tunnelID, key, reply
	s.reply.Payload = append([]byte(nil), reply.Payload...)
	return nil
}

type cancelingBuildSender struct {
	entered chan struct{}
	once    sync.Once
}

func (s *cancelingBuildSender) Send(ctx context.Context, _ ivnp.Hash, _ i2np.Message) error {
	s.once.Do(func() { close(s.entered) })
	<-ctx.Done()
	return ctx.Err()
}

func TestBuildManagerCreatesAndInstallsOutboundTunnel(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	replyKeys := newBuildReplyRegistry()
	var seededEndpoint, seededReply ivnp.Hash
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Sender: sender, ReplyKeys: replyKeys, Now: func() uint64 { return now }, Random: new(buildCounterReader),
		SeedReplyRouterInfo: func(_ context.Context, endpoint, reply ivnp.Hash) error {
			seededEndpoint, seededReply = endpoint, reply
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	build := OutboundBuild{
		CircuitID: 91, ReplyRouter: sha256.Sum256([]byte("reply-router")), ReplyTunnelID: 92,
		ExpiresAt: now + 10*60*1000,
		Hops:      make([]ShortBuildHop, 3),
	}
	privateKeys := make([][]byte, len(build.Hops))
	for index := range build.Hops {
		privateKeys[index] = make([]byte, 32)
		for offset := range privateKeys[index] {
			privateKeys[index][offset] = byte(1 + index*32 + offset)
		}
		private, keyErr := ecdh.X25519().NewPrivateKey(privateKeys[index])
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		build.Hops[index] = ShortBuildHop{
			Router: sha256.Sum256([]byte{byte(index + 1)}), ReceiveTunnelID: uint32(100 + index),
		}
		copy(build.Hops[index].StaticKey[:], private.PublicKey().Bytes())
	}

	replyID, err := manager.StartOutbound(context.Background(), build)
	if err != nil {
		t.Fatal(err)
	}
	if seededEndpoint != build.Hops[len(build.Hops)-1].Router || seededReply != build.ReplyRouter {
		t.Fatalf("reply RouterInfo seed = endpoint %s reply %s", seededEndpoint, seededReply)
	}
	sent := sender.take()
	if len(sent) != 1 || sent[0].peer != build.Hops[0].Router || sent[0].message.Header.Type != i2np.ShortTunnelBuild {
		t.Fatalf("initial build message = %#v", sent)
	}
	records, err := i2np.ParseBuildRecords(i2np.ShortTunnelBuild, sent[0].message.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if records.Count != 4 || len(records.Records) != 4*ShortBuildRecordSize {
		t.Fatalf("three-hop build encoded %d records (%d bytes), want four padded records", records.Count, len(records.Records))
	}
	participantKeys := make([]ShortBuildKeys, len(build.Hops))
	for index, hop := range build.Hops {
		var plaintext [ShortBuildRequestPlainSize]byte
		request, derived, _, processErr := ProcessShortBuildRecords(records.Records, plaintext[:], hop.Router, privateKeys[index], true, new(buildCounterReader))
		if processErr != nil {
			t.Fatalf("process hop %d: %v", index, processErr)
		}
		if request.ReceiveTunnelID != hop.ReceiveTunnelID || request.Gateway || request.Endpoint != (index+1 == len(build.Hops)) {
			t.Fatalf("hop %d request = %#v", index, request)
		}
		participantKeys[index] = derived
	}
	reply := i2np.Message{
		Header:  i2np.Header{Type: i2np.OutboundTunnelBuildReply, ID: replyID, Expiration: now + buildMessageLifetime},
		Payload: sent[0].message.Payload,
	}
	endpointKeys := participantKeys[len(participantKeys)-1]
	registered, ok := replyKeys.entries[endpointKeys.GarlicTag]
	if !ok || registered.Key != endpointKeys.GarlicKey || registered.ExpiresAt != now+buildRequestTimeout {
		t.Fatalf("registered endpoint reply key = %#v, found %t", registered, ok)
	}
	consumed, consumeErr := replyKeys.consume(endpointKeys.GarlicTag)
	if consumeErr != nil || consumed.Key != endpointKeys.GarlicKey {
		t.Fatalf("consumed endpoint reply key = %#v, %v", consumed, consumeErr)
	}
	if err = manager.HandleReply(reply); err != nil {
		t.Fatal(err)
	}
	if len(replyKeys.entries) != 0 {
		t.Fatalf("unconsumed reply keys = %d", len(replyKeys.entries))
	}
	expected := deliveryStatusFrame(t, 7)
	if err = runtime.SendBlock(context.Background(), build.CircuitID, Block{Delivery: DeliveryLocal, Last: true, Data: expected}); err != nil {
		t.Fatal(err)
	}
	sent = sender.take()
	if len(sent) != 1 || sent[0].peer != build.Hops[0].Router || sent[0].message.Header.Type != i2np.TunnelData {
		t.Fatalf("installed tunnel message = %#v", sent)
	}
	current := sent[0].message
	var delivered i2np.Message
	for index, hop := range build.Hops {
		hopSender := new(captureTunnelSender)
		hopRuntime := NewRuntime(RuntimeConfig{Sender: hopSender, Now: func() uint64 { return now }})
		encryptor, cipherErr := NewLayerEncryptor(participantKeys[index].LayerKey[:], participantKeys[index].IVKey[:])
		if cipherErr != nil {
			t.Fatal(cipherErr)
		}
		circuit := InboundCircuit{ID: hop.ReceiveTunnelID, Transforms: []LayerCipher{encryptor}}
		if index+1 < len(build.Hops) {
			circuit.Forward = &Forward{Peer: build.Hops[index+1].Router, TunnelID: build.Hops[index+1].ReceiveTunnelID}
		} else {
			circuit.Endpoint = NewEndpoint(8, 4096)
			circuit.Local = func(message i2np.Message) error {
				delivered = message
				return nil
			}
		}
		if err = hopRuntime.RegisterInbound(circuit); err != nil {
			t.Fatal(err)
		}
		if err = hopRuntime.Handle(current); err != nil {
			t.Fatalf("hop %d tunnel data: %v", index, err)
		}
		if index+1 < len(build.Hops) {
			forwarded := hopSender.take()
			if len(forwarded) != 1 || forwarded[0].peer != build.Hops[index+1].Router {
				t.Fatalf("hop %d forwarding = %#v", index, forwarded)
			}
			current = forwarded[0].message
		}
	}
	if delivered.Header.Type != i2np.DeliveryStatus || delivered.Header.ID != 7 {
		t.Fatalf("delivered message = %#v", delivered)
	}
}

func TestBuildManagerRejectsExpiredAndUnknownReplies(t *testing.T) {
	now := uint64(1_700_000_000_000)
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	replyKeys := newBuildReplyRegistry()
	manager, err := NewBuildManager(BuildManagerConfig{Runtime: runtime, Sender: sender, ReplyKeys: replyKeys, Now: func() uint64 { return now }, Random: new(buildCounterReader)})
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.HandleReply(i2np.Message{Header: i2np.Header{Type: i2np.OutboundTunnelBuildReply, ID: 1}, Payload: append([]byte{1}, make([]byte, ShortBuildRecordSize)...)}); err != ErrBuildPending {
		t.Fatalf("unknown reply error = %v, want %v", err, ErrBuildPending)
	}
	if _, err = manager.StartOutbound(context.Background(), OutboundBuild{CircuitID: 1, ReplyTunnelID: 2, ExpiresAt: now - 1, Hops: []ShortBuildHop{{Router: ivnp.Hash{1}, StaticKey: [32]byte{1}, ReceiveTunnelID: 3}}}); err != ErrBuildConfig {
		t.Fatalf("expired build error = %v, want %v", err, ErrBuildConfig)
	}
}

func TestBuildManagerClearsReplyRegistryAfterReplyErrorAndExpiry(t *testing.T) {
	replyKeys := newBuildReplyRegistry()
	profiles := NewPeerProfiles(PeerProfilesConfig{})
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: NewRuntime(RuntimeConfig{}), Sender: discardTunnelSender{}, ReplyKeys: replyKeys, Profiles: profiles, Now: func() uint64 { return 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	var errorTag, expiryTag [8]byte
	errorTag[0], expiryTag[0] = 1, 2
	if err = replyKeys.RegisterGarlicReplyKey(GarlicReplyKey{Tag: errorTag, ExpiresAt: 2}); err != nil {
		t.Fatal(err)
	}
	failedPeer := ivnp.Hash{9}
	manager.pending[1] = &pendingOutboundBuild{replyTag: errorTag, deadline: 2, build: OutboundBuild{Hops: []ShortBuildHop{{Router: failedPeer}}}}
	if err = manager.HandleReply(i2np.Message{Header: i2np.Header{Type: i2np.OutboundTunnelBuildReply, ID: 1}}); err == nil {
		t.Fatal("accepted malformed reply")
	}
	if _, ok := replyKeys.entries[errorTag]; ok {
		t.Fatal("reply key retained after malformed reply")
	}
	if profile, ok := profiles.Snapshot(failedPeer); ok {
		t.Fatalf("unauthenticated malformed reply poisoned peer profile: %#v", profile)
	}
	manager.pending[3] = &pendingOutboundBuild{
		deadline: 2, recordCount: 1, keys: make([]ShortBuildKeys, 1), positions: []uint8{0},
		build: OutboundBuild{Hops: []ShortBuildHop{{Router: failedPeer}}},
	}
	invalidAuthenticatedRecords := append([]byte{1}, make([]byte, ShortBuildRecordSize)...)
	if err = manager.HandleReply(i2np.Message{Header: i2np.Header{Type: i2np.OutboundTunnelBuildReply, ID: 3}, Payload: invalidAuthenticatedRecords}); err == nil {
		t.Fatal("accepted reply with invalid authenticated records")
	}
	if profile, ok := profiles.Snapshot(failedPeer); !ok || profile.Failures != 1 || profiles.Eligible(failedPeer) {
		t.Fatalf("invalid authenticated reply profile = %#v, present=%t eligible=%t", profile, ok, profiles.Eligible(failedPeer))
	}
	if err = replyKeys.RegisterGarlicReplyKey(GarlicReplyKey{Tag: expiryTag, ExpiresAt: 2}); err != nil {
		t.Fatal(err)
	}
	manager.pending[2] = &pendingOutboundBuild{replyTag: expiryTag, deadline: 2}
	if expired := manager.Expire(2); expired != 1 {
		t.Fatalf("expired builds = %d, want 1", expired)
	}
	if _, ok := replyKeys.entries[expiryTag]; ok {
		t.Fatal("reply key retained after expiry")
	}
}

func TestBuildManagerRollsBackPoolWhenRuntimeInstallFails(t *testing.T) {
	const (
		managerNow = uint64(100)
		expiresAt  = uint64(101)
		replyID    = uint32(7)
		circuitID  = uint32(8)
	)
	runtime := NewRuntime(RuntimeConfig{Now: func() uint64 { return expiresAt }})
	pool := NewPool(1)
	replyKeys := newBuildReplyRegistry()
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: discardTunnelSender{}, ReplyKeys: replyKeys, Now: func() uint64 { return managerNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	var keys ShortBuildKeys
	manager.pending[replyID] = &pendingOutboundBuild{
		build:       OutboundBuild{CircuitID: circuitID, Hops: []ShortBuildHop{{Router: ivnp.Hash{1}, ReceiveTunnelID: 9}}, ExpiresAt: expiresAt},
		keys:        []ShortBuildKeys{keys},
		positions:   []uint8{0},
		recordCount: 1,
		deadline:    expiresAt,
	}
	payload := make([]byte, 1+ShortBuildRecordSize)
	payload[0] = 1
	if _, err = SealShortBuildReply(payload[1:], make([]byte, ShortBuildReplyPlainSize), keys, 0); err != nil {
		t.Fatal(err)
	}
	reply := i2np.Message{Header: i2np.Header{Type: i2np.OutboundTunnelBuildReply, ID: replyID}, Payload: payload}
	if err = manager.HandleReply(reply); err != ErrCircuitExpired {
		t.Fatalf("install error = %v, want %v", err, ErrCircuitExpired)
	}
	if manager.Pending() != 0 || pool.Count(Outbound, 0) != 0 {
		t.Fatalf("failed install retained pending=%d pool=%d", manager.Pending(), pool.Count(Outbound, 0))
	}
	if err = runtime.SendBlock(context.Background(), circuitID, Block{Delivery: DeliveryLocal, Last: true, Data: []byte{1}}); err != ErrCircuitNotFound {
		t.Fatalf("rolled-back circuit error = %v, want %v", err, ErrCircuitNotFound)
	}
}

func TestBuildManagerRestoresRetiredTunnelWhenRuntimeInstallFails(t *testing.T) {
	const (
		managerNow = uint64(100)
		runtimeNow = uint64(101)
		replyID    = uint32(7)
		oldID      = uint32(8)
		newID      = uint32(9)
	)
	runtime := NewRuntime(RuntimeConfig{Sender: discardTunnelSender{}, Now: func() uint64 { return runtimeNow }})
	pool := NewPool(1)
	old := Entry{ID: oldID, Direction: Outbound, Expires: runtimeNow + 1}
	if err := pool.Add(old, managerNow); err != nil {
		t.Fatal(err)
	}
	if err := runtime.RegisterOutbound(OutboundCircuit{ID: old.ID, NextTunnelID: 10, ExpiresAt: old.Expires}); err != nil {
		t.Fatal(err)
	}
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: discardTunnelSender{}, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return managerNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	var keys ShortBuildKeys
	manager.pending[replyID] = &pendingOutboundBuild{
		build:       OutboundBuild{CircuitID: newID, Hops: []ShortBuildHop{{Router: ivnp.Hash{1}, ReceiveTunnelID: 11}}, ExpiresAt: runtimeNow, retireID: old.ID},
		keys:        []ShortBuildKeys{keys},
		positions:   []uint8{0},
		recordCount: 1,
		deadline:    runtimeNow,
	}
	payload := make([]byte, 1+ShortBuildRecordSize)
	payload[0] = 1
	if _, err = SealShortBuildReply(payload[1:], make([]byte, ShortBuildReplyPlainSize), keys, 0); err != nil {
		t.Fatal(err)
	}
	reply := i2np.Message{Header: i2np.Header{Type: i2np.OutboundTunnelBuildReply, ID: replyID}, Payload: payload}
	if err = manager.HandleReply(reply); err != ErrCircuitExpired {
		t.Fatalf("install error = %v, want %v", err, ErrCircuitExpired)
	}
	if entry, ok := pool.Get(old.ID, managerNow); !ok || entry != old {
		t.Fatalf("restored pool entry = %#v, %t", entry, ok)
	}
	if _, ok := pool.Get(newID, managerNow); ok {
		t.Fatal("failed replacement retained")
	}
	if err = runtime.SendBlock(context.Background(), old.ID, Block{Delivery: DeliveryLocal, Last: true, Data: []byte{1}}); err != nil {
		t.Fatalf("retained runtime circuit error = %v", err)
	}
}

func TestBuildManagerBuildsInboundAcrossTransitAndRejectsStaleRequests(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	creator := sha256.Sum256([]byte("inbound-creator"))
	outerPeer := sha256.Sum256([]byte("outer-obep"))
	carrier := new(captureTunnelSender)
	var inboundDelivered i2np.Message
	creatorRuntime := NewRuntime(RuntimeConfig{Sender: carrier, Now: func() uint64 { return now }})
	if err := creatorRuntime.RegisterOutbound(OutboundCircuit{ID: 500, FirstHop: outerPeer, NextTunnelID: 501}); err != nil {
		t.Fatal(err)
	}
	creatorManager, err := NewBuildManager(BuildManagerConfig{
		Runtime: creatorRuntime, Sender: carrier, ReplyKeys: newBuildReplyRegistry(), LocalRouter: creator,
		LocalDelivery: func(message i2np.Message) error { inboundDelivered = message; return nil }, Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	build := InboundBuild{CircuitID: 700, OutboundTunnelID: 500, ExpiresAt: now + 600_000, Hops: make([]ShortBuildHop, 3)}
	privateKeys := make([][]byte, len(build.Hops))
	for index := range build.Hops {
		privateKeys[index] = make([]byte, 32)
		for offset := range privateKeys[index] {
			privateKeys[index][offset] = byte(1 + index*32 + offset)
		}
		private, keyErr := ecdh.X25519().NewPrivateKey(privateKeys[index])
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		build.Hops[index] = ShortBuildHop{
			Router: sha256.Sum256([]byte{byte(index + 21)}), ReceiveTunnelID: uint32(600 + index),
		}
		copy(build.Hops[index].StaticKey[:], private.PublicKey().Bytes())
	}
	build.CarrierEndpoint = build.Hops[0].Router
	replyID, err := creatorManager.StartInbound(context.Background(), build)
	if err != nil {
		t.Fatal(err)
	}
	carried := carrier.take()
	if len(carried) != 1 || carried[0].message.Header.Type != i2np.TunnelData {
		t.Fatalf("inbound carrier message = %#v", carried)
	}
	blocks := make([]Block, 1)
	count, err := NewEndpoint(1, i2np.I2PDMaxPayload).Parse(carried[0].message.Payload, blocks)
	if err != nil || count != 1 || blocks[0].Delivery != DeliveryRouter || blocks[0].Gateway != build.Hops[0].Router {
		t.Fatalf("carrier blocks = %d, %#v, %v", count, blocks[0], err)
	}
	current, used, err := i2np.ParseUnchecked(blocks[0].Data)
	if err != nil || used != len(blocks[0].Data) || current.Header.Type != i2np.ShortTunnelBuild {
		t.Fatalf("carrier build = %#v, %d, %v", current, used, err)
	}
	for index, hop := range build.Hops {
		next := new(captureTunnelSender)
		hopRuntime := NewRuntime(RuntimeConfig{Sender: next, Now: func() uint64 { return now }})
		hopManager, managerErr := NewBuildManager(BuildManagerConfig{
			Runtime: hopRuntime, Sender: next, ReplyKeys: newBuildReplyRegistry(), LocalRouter: hop.Router,
			StaticPrivate: privateKeys[index], LocalDelivery: func(i2np.Message) error { return nil },
			Now: func() uint64 { return now }, Random: new(buildCounterReader),
		})
		if managerErr != nil {
			t.Fatal(managerErr)
		}
		predecessor := outerPeer
		if index != 0 {
			predecessor = build.Hops[index-1].Router
		}
		if managerErr = hopManager.HandleBuildFrom(predecessor, current); managerErr != nil {
			t.Fatalf("hop %d build: %v", index, managerErr)
		}
		forwarded := next.take()
		if len(forwarded) != 1 {
			t.Fatalf("hop %d forwarded = %#v", index, forwarded)
		}
		wantPeer := creator
		if index+1 < len(build.Hops) {
			wantPeer = build.Hops[index+1].Router
		}
		if forwarded[0].peer != wantPeer || forwarded[0].message.Header.Type != i2np.ShortTunnelBuild {
			t.Fatalf("hop %d route = %#v", index, forwarded[0])
		}
		current = forwarded[0].message
	}
	if current.Header.ID != replyID {
		t.Fatalf("inbound reply ID = %d, want %d", current.Header.ID, replyID)
	}
	pendingKeys := append([]ShortBuildKeys(nil), creatorManager.pendingInbound[replyID].keys...)
	if err = creatorManager.HandleBuild(current); err != nil {
		t.Fatal(err)
	}
	producerSender := new(captureTunnelSender)
	producer := NewRuntime(RuntimeConfig{Sender: producerSender, Now: func() uint64 { return now }})
	if err = producer.RegisterOutbound(OutboundCircuit{ID: 1, FirstHop: ivnp.Hash{1}, NextTunnelID: build.CircuitID}); err != nil {
		t.Fatal(err)
	}
	if err = producer.SendBlock(context.Background(), 1, Block{Delivery: DeliveryLocal, Last: true, Data: deliveryStatusFrame(t, 55)}); err != nil {
		t.Fatal(err)
	}
	layered := producerSender.take()
	if len(layered) != 1 {
		t.Fatalf("layered inbound source = %#v", layered)
	}
	for hop := range pendingKeys {
		encryptor, cipherErr := NewLayerEncryptor(pendingKeys[hop].LayerKey[:], pendingKeys[hop].IVKey[:])
		if cipherErr != nil {
			t.Fatal(cipherErr)
		}
		if cipherErr = encryptor.Transform(layered[0].message.Payload[4:], layered[0].message.Payload[4:]); cipherErr != nil {
			t.Fatal(cipherErr)
		}
	}
	if err = creatorRuntime.Handle(layered[0].message); err != nil {
		t.Fatalf("layered inbound tunnel data: %v", err)
	}
	if inboundDelivered.Header.Type != i2np.DeliveryStatus || inboundDelivered.Header.ID != 55 {
		t.Fatalf("layered inbound delivery = %#v", inboundDelivered)
	}
	if creatorManager.Pending() != 0 {
		t.Fatalf("pending inbound builds = %d", creatorManager.Pending())
	}
	if err = creatorRuntime.RegisterInbound(InboundCircuit{ID: build.CircuitID, Endpoint: NewEndpoint(1, 1)}); err != ErrCircuitExists {
		t.Fatalf("inbound circuit collision = %v, want %v", err, ErrCircuitExists)
	}

	staleSender := new(captureTunnelSender)
	staleRuntime := NewRuntime(RuntimeConfig{Sender: staleSender, Now: func() uint64 { return now }})
	staleManager, err := NewBuildManager(BuildManagerConfig{
		Runtime: staleRuntime, Sender: staleSender, ReplyKeys: newBuildReplyRegistry(), LocalRouter: build.Hops[0].Router,
		StaticPrivate: privateKeys[0], Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	var plaintext [ShortBuildRequestPlainSize]byte
	request := ShortBuildRequest{
		ReceiveTunnelID: 900, NextTunnelID: 901, NextRouter: sha256.Sum256([]byte("stale-next")),
		RequestMinutes: uint32(now/60_000 - 9), LifetimeSeconds: shortBuildLifetime, NextMessageID: 902,
	}
	if err = MarshalShortBuildRequest(plaintext[:], request, nil); err != nil {
		t.Fatal(err)
	}
	var record [ShortBuildRecordSize]byte
	if _, err = EncryptShortBuildRequest(record[:], build.Hops[0].Router, build.Hops[0].StaticKey[:], plaintext[:]); err != nil {
		t.Fatal(err)
	}
	stale := i2np.Message{Header: i2np.Header{Type: i2np.ShortTunnelBuild, ID: 903, Expiration: now + buildMessageLifetime}, Payload: append([]byte{1}, record[:]...)}
	if err = staleManager.HandleBuildFrom(ivnp.Hash{9}, stale); err != ErrBuildRejected {
		t.Fatalf("stale request error = %v, want %v", err, ErrBuildRejected)
	}
	if err = staleRuntime.RegisterInbound(InboundCircuit{ID: request.ReceiveTunnelID, Endpoint: NewEndpoint(1, 1)}); err != nil {
		t.Fatalf("stale request installed a circuit: %v", err)
	}
}

func TestBuildManagerRoutesOBEPReplyWithDerivedGarlicKey(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	privateBytes := make([]byte, 32)
	for index := range privateBytes {
		privateBytes[index] = byte(index + 1)
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	hop := ShortBuildHop{Router: sha256.Sum256([]byte("obep")), ReceiveTunnelID: 41}
	copy(hop.StaticKey[:], private.PublicKey().Bytes())
	replyRouter := sha256.Sum256([]byte("reply-gateway"))
	replyKeys := newBuildReplyRegistry()
	creatorSender := new(captureTunnelSender)
	creatorRuntime := NewRuntime(RuntimeConfig{Sender: creatorSender, Now: func() uint64 { return now }})
	creator, err := NewBuildManager(BuildManagerConfig{
		Runtime: creatorRuntime, Sender: creatorSender, ReplyKeys: replyKeys, Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	replyID, err := creator.StartOutbound(context.Background(), OutboundBuild{
		CircuitID: 40, Hops: []ShortBuildHop{hop}, ReplyRouter: replyRouter, ReplyTunnelID: 42, ExpiresAt: now + 600_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	requests := creatorSender.take()
	if len(requests) != 1 {
		t.Fatalf("outbound request = %#v", requests)
	}
	replies := new(captureBuildReplySender)
	obepSender := new(captureTunnelSender)
	obep, err := NewBuildManager(BuildManagerConfig{
		Runtime: NewRuntime(RuntimeConfig{Sender: obepSender, Now: func() uint64 { return now }}), Sender: obepSender,
		ReplyKeys: newBuildReplyRegistry(), ReplySender: replies, LocalRouter: hop.Router, StaticPrivate: privateBytes,
		LocalDelivery: func(i2np.Message) error { return nil }, Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = obep.HandleBuildFrom(ivnp.Hash{7}, requests[0].message); err != nil {
		t.Fatal(err)
	}
	if replies.peer != replyRouter || replies.tunnel != 42 || replies.reply.Header.Type != i2np.OutboundTunnelBuildReply || replies.reply.Header.ID != replyID {
		t.Fatalf("OBEP garlic route = %#v", replies)
	}
	registered, ok := replyKeys.entries[replies.key.Tag]
	if !ok || registered.Key != replies.key.Key || registered.ExpiresAt != now+buildRequestTimeout {
		t.Fatalf("derived garlic key = %#v, found %t", registered, ok)
	}
	if _, err = replyKeys.consume(replies.key.Tag); err != nil {
		t.Fatal(err)
	}
	if err = creator.HandleReply(replies.reply); err != nil {
		t.Fatal(err)
	}
}

func TestBuildManagerAllowsLocalEndpointTransitOnly(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	local := sha256.Sum256([]byte("local-endpoint"))
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: NewRuntime(RuntimeConfig{Now: func() uint64 { return now }}), Sender: discardTunnelSender{},
		ReplyKeys: newBuildReplyRegistry(), ReplySender: new(captureBuildReplySender), LocalRouter: local,
		LocalDelivery: func(i2np.Message) error { return nil }, Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := ShortBuildRequest{
		ReceiveTunnelID: 1, NextTunnelID: 2, NextRouter: local, Endpoint: true,
		RequestMinutes: uint32(now / 60_000), LifetimeSeconds: shortBuildLifetime, NextMessageID: 3,
	}
	if !manager.validTransitRequest(request, ShortBuildKeys{HasGarlicKeys: true}, now, BuildSource{Router: ivnp.Hash{1}, Direct: true}) {
		t.Fatal("endpoint request to local router rejected")
	}
	request.Endpoint = false
	if manager.validTransitRequest(request, ShortBuildKeys{}, now, BuildSource{Router: ivnp.Hash{1}, Direct: true}) {
		t.Fatal("non-endpoint loop request accepted")
	}
}

func TestBuildManagerGatewayTransitInjectsTunnelGateway(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Sender: sender, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	next := sha256.Sum256([]byte("gateway-next"))
	request := ShortBuildRequest{
		ReceiveTunnelID: 11, NextTunnelID: 12, NextRouter: next, Gateway: true,
		RequestMinutes: uint32(now / 60_000), LifetimeSeconds: shortBuildLifetime, NextMessageID: 13,
	}
	var keys ShortBuildKeys
	for index := range keys.LayerKey {
		keys.LayerKey[index] = byte(index + 1)
		keys.IVKey[index] = byte(255 - index)
	}
	if err = manager.installTransitCircuit(request, keys, now); err != nil {
		t.Fatal(err)
	}
	statusPayload := make([]byte, 12)
	status := i2np.Message{Header: i2np.Header{Type: i2np.DeliveryStatus, ID: 77, Expiration: now + 1}, Payload: statusPayload}
	if err = runtime.HandleGateway(request.ReceiveTunnelID, status); err != nil {
		t.Fatal(err)
	}
	sent := sender.take()
	if len(sent) != 1 || sent[0].peer != next || sent[0].message.Header.Type != i2np.TunnelData {
		t.Fatalf("gateway injection = %#v", sent)
	}
	payload := append([]byte(nil), sent[0].message.Payload...)
	if err = func() error {
		decryptor, cipherErr := NewLayerDecryptor(keys.LayerKey[:], keys.IVKey[:])
		if cipherErr != nil {
			return cipherErr
		}
		return decryptor.Transform(payload[4:], payload[4:])
	}(); err != nil {
		t.Fatal(err)
	}
	blocks := make([]Block, 1)
	count, err := NewEndpoint(1, i2np.I2PDMaxPayload).Parse(payload, blocks)
	if err != nil || count != 1 || blocks[0].Delivery != DeliveryLocal {
		t.Fatalf("gateway payload blocks = %d, %#v, %v", count, blocks[0], err)
	}
	delivered, used, err := i2np.ParseUnchecked(blocks[0].Data)
	if err != nil || used != len(blocks[0].Data) || delivered.Header.Type != i2np.DeliveryStatus || delivered.Header.ID != status.Header.ID {
		t.Fatalf("gateway payload delivery = %#v, %d, %v", delivered, used, err)
	}
}

func TestBuildManagerAuthenticatesTransitBeforeReservation(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	privateBytes := make([]byte, 32)
	for index := range privateBytes {
		privateBytes[index] = byte(index + 1)
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	local := sha256.Sum256([]byte("transit-local"))
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Sender: sender,
		ReplyKeys: newBuildReplyRegistry(), LocalRouter: local, StaticPrivate: privateBytes, Now: func() uint64 { return now }, MaxPending: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := ShortBuildRequest{
		ReceiveTunnelID: 101, NextTunnelID: 102, NextRouter: sha256.Sum256([]byte("transit-next")),
		RequestMinutes: uint32(now / 60_000), LifetimeSeconds: shortBuildLifetime, NextMessageID: 103,
	}
	var plaintext [ShortBuildRequestPlainSize]byte
	if err = MarshalShortBuildRequest(plaintext[:], request, nil); err != nil {
		t.Fatal(err)
	}
	var record [ShortBuildRecordSize]byte
	if _, err = EncryptShortBuildRequest(record[:], local, private.PublicKey().Bytes(), plaintext[:]); err != nil {
		t.Fatal(err)
	}
	malformed := record
	malformed[len(malformed)-1] ^= 1
	if err = manager.HandleBuildFrom(ivnp.Hash{7}, i2np.Message{Header: i2np.Header{Type: i2np.ShortTunnelBuild, ID: 201}, Payload: append([]byte{1}, malformed[:]...)}); err == nil {
		t.Fatal("malformed transit accepted")
	}
	if len(manager.transit) != 0 {
		t.Fatalf("malformed transit reserved slots = %#v", manager.transit)
	}
	message := i2np.Message{Header: i2np.Header{Type: i2np.ShortTunnelBuild, ID: 202}, Payload: append([]byte{1}, record[:]...)}
	if err = runtime.RegisterInbound(InboundCircuit{ID: request.ReceiveTunnelID, Endpoint: NewEndpoint(1, 1)}); err != nil {
		t.Fatal(err)
	}
	if err = manager.HandleBuildFrom(ivnp.Hash{7}, i2np.Message{Header: i2np.Header{Type: i2np.ShortTunnelBuild, ID: 203}, Payload: append([]byte(nil), message.Payload...)}); err != ErrBuildRejected {
		t.Fatalf("colliding transit error = %v, want %v", err, ErrBuildRejected)
	}
	if len(manager.transit) != 0 {
		t.Fatalf("colliding transit reserved slots = %#v", manager.transit)
	}
	runtime.RemoveCircuit(request.ReceiveTunnelID)
	results := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			duplicate := message
			duplicate.Payload = append([]byte(nil), message.Payload...)
			results <- manager.HandleBuildFrom(ivnp.Hash{7}, duplicate)
		}()
	}
	group.Wait()
	close(results)
	var accepted, rejected int
	for result := range results {
		if result == nil {
			accepted++
		} else if result == ErrBuildTransit {
			rejected++
		} else {
			t.Fatalf("concurrent transit error = %v", result)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("concurrent transit results accepted=%d rejected=%d", accepted, rejected)
	}
}

func TestBuildManagerModernPendingAccountsForVariableBuilds(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	privateBytes := make([]byte, 32)
	for index := range privateBytes {
		privateBytes[index] = byte(index + 1)
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	hop := ShortBuildHop{Router: sha256.Sum256([]byte("pending-hop")), ReceiveTunnelID: 11}
	copy(hop.StaticKey[:], private.PublicKey().Bytes())
	outbound := OutboundBuild{CircuitID: 12, Hops: []ShortBuildHop{hop}, ReplyRouter: sha256.Sum256([]byte("pending-reply")), ReplyTunnelID: 13, ExpiresAt: now + 1}
	inbound := InboundBuild{CircuitID: 14, ExpiresAt: now + 1, Hops: []ShortBuildHop{hop}}
	newManager := func(limit int) *BuildManager {
		manager, managerErr := NewBuildManager(BuildManagerConfig{
			Runtime: NewRuntime(RuntimeConfig{Now: func() uint64 { return now }}), Sender: discardTunnelSender{}, ReplyKeys: newBuildReplyRegistry(),
			LocalRouter: sha256.Sum256([]byte("pending-local")), LocalDelivery: func(i2np.Message) error { return nil },
			Now: func() uint64 { return now }, Random: new(buildCounterReader), MaxPending: limit,
		})
		if managerErr != nil {
			t.Fatal(managerErr)
		}
		return manager
	}
	fullOutbound := newManager(1)
	fullOutbound.pendingVariable[99] = &pendingVariableBuild{}
	if _, err = fullOutbound.StartOutbound(context.Background(), outbound); err != ErrBuildPending {
		t.Fatalf("outbound ignored variable pending count: %v", err)
	}
	fullInbound := newManager(1)
	fullInbound.pendingVariable[99] = &pendingVariableBuild{}
	if _, err = fullInbound.StartInbound(context.Background(), inbound); err != ErrBuildPending {
		t.Fatalf("inbound ignored variable pending count: %v", err)
	}
	const replyID = uint32(0x05060708)
	collidingOutbound := newManager(2)
	collidingOutbound.pendingVariable[replyID] = &pendingVariableBuild{}
	if _, err = collidingOutbound.StartOutbound(context.Background(), outbound); err != ErrBuildPending {
		t.Fatalf("outbound ignored variable reply ID collision: %v", err)
	}
	collidingInbound := newManager(2)
	collidingInbound.pendingVariable[replyID] = &pendingVariableBuild{}
	if _, err = collidingInbound.StartInbound(context.Background(), inbound); err != ErrBuildPending {
		t.Fatalf("inbound ignored variable reply ID collision: %v", err)
	}
}

func testShortBuildHop(t *testing.T, label string, tunnelID uint32) (ShortBuildHop, []byte) {
	t.Helper()
	privateBytes := sha256.Sum256([]byte("private-" + label))
	private, err := ecdh.X25519().NewPrivateKey(privateBytes[:])
	if err != nil {
		t.Fatal(err)
	}
	hop := ShortBuildHop{Router: sha256.Sum256([]byte("router-" + label)), ReceiveTunnelID: tunnelID}
	copy(hop.StaticKey[:], private.PublicKey().Bytes())
	return hop, append([]byte(nil), privateBytes[:]...)
}

func TestInboundCreatorFakeRecordIsRealAndTamperChecked(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	local := sha256.Sum256([]byte("fake-record-creator"))
	hop, private := testShortBuildHop(t, "fake-record-hop", 101)
	sender := new(captureTunnelSender)
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }}),
		Sender:  sender, ReplyKeys: newBuildReplyRegistry(), LocalRouter: local,
		LocalDelivery: func(i2np.Message) error { return nil }, Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	replyID, err := manager.StartInbound(context.Background(), InboundBuild{
		CircuitID: 102, Hops: []ShortBuildHop{hop}, ExpiresAt: now + 600_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := sender.take()[0].message
	pending := manager.pendingInbound[replyID]
	if pending == nil || pending.recordCount != 4 || pending.fakePosition == pending.positions[0] {
		t.Fatalf("pending fake metadata = %#v", pending)
	}
	records, err := i2np.ParseBuildRecords(i2np.ShortTunnelBuild, request.Payload)
	if err != nil {
		t.Fatal(err)
	}
	fake := records.Records[int(pending.fakePosition)*ShortBuildRecordSize : (int(pending.fakePosition)+1)*ShortBuildRecordSize]
	if !bytes.Equal(fake[:shortBuildPeerSize], local[:shortBuildPeerSize]) || bytes.Equal(fake[shortBuildPeerSize:shortBuildCipherOffset], make([]byte, 32)) {
		t.Fatalf("creator fake prefix/ephemeral = %x / %x", fake[:16], fake[16:48])
	}
	if _, err = ecdh.X25519().NewPublicKey(fake[shortBuildPeerSize:shortBuildCipherOffset]); err != nil {
		t.Fatalf("creator fake ephemeral: %v", err)
	}
	next := new(captureTunnelSender)
	participant, err := NewBuildManager(BuildManagerConfig{
		Runtime: NewRuntime(RuntimeConfig{Sender: next, Now: func() uint64 { return now }}),
		Sender:  next, ReplyKeys: newBuildReplyRegistry(), LocalRouter: hop.Router, StaticPrivate: private,
		Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = participant.HandleBuildFrom(ivnp.Hash{9}, request); err != nil {
		t.Fatal(err)
	}
	reply := next.take()[0].message
	tampered := reply
	tampered.Payload = append([]byte(nil), reply.Payload...)
	tampered.Payload[1+int(pending.fakePosition)*ShortBuildRecordSize+100] ^= 1
	if err = manager.HandleBuild(tampered); !errors.Is(err, ErrBuildFakeRecord) {
		t.Fatalf("tampered creator fake error = %v", err)
	}
}

func TestInboundBuildGarlicWrapsAcrossDifferentCarrierEndpoint(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	local := sha256.Sum256([]byte("wrapped-inbound-creator"))
	hop, private := testShortBuildHop(t, "wrapped-ibgw", 201)
	carrierEndpoint := sha256.Sum256([]byte("carrier-obep"))
	firstHop := sha256.Sum256([]byte("carrier-first"))
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	if err := runtime.RegisterOutbound(OutboundCircuit{ID: 202, FirstHop: firstHop, NextTunnelID: 203}); err != nil {
		t.Fatal(err)
	}
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Sender: sender, ReplyKeys: newBuildReplyRegistry(), LocalRouter: local,
		LocalDelivery: func(i2np.Message) error { return nil }, Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.StartInbound(context.Background(), InboundBuild{
		CircuitID: 204, OutboundTunnelID: 202, CarrierEndpoint: carrierEndpoint,
		Hops: []ShortBuildHop{hop}, ExpiresAt: now + 600_000,
	}); err != nil {
		t.Fatal(err)
	}
	carried := sender.take()
	if len(carried) != 1 || carried[0].peer != firstHop || carried[0].message.Header.Type != i2np.TunnelData {
		t.Fatalf("carrier output = %#v", carried)
	}
	blocks := make([]Block, 1)
	count, err := NewEndpoint(1, i2np.I2PDMaxPayload).Parse(carried[0].message.Payload, blocks)
	if err != nil || count != 1 {
		t.Fatalf("carrier parse = %d, %v", count, err)
	}
	outer, used, err := i2np.ParseUnchecked(blocks[0].Data)
	if err != nil || used != len(blocks[0].Data) || outer.Header.Type != i2np.Garlic {
		t.Fatalf("outer = %#v, %d, %v", outer, used, err)
	}
	garlicMessage, err := i2np.ParseGarlic(outer.Payload)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := eciesgarlic.OpenRouterMessage(make([]byte, len(garlicMessage.Encrypted)), private, garlicMessage.Encrypted, now)
	if err != nil || inner.Header.Type != i2np.ShortTunnelBuild {
		t.Fatalf("wrapped inner = %#v, %v", inner, err)
	}
}

func TestTransitBandwidthOptionsReplyAndReceiptLifetime(t *testing.T) {
	const now = uint64(1_700_000_059_000)
	localHop, private := testShortBuildHop(t, "bandwidth-transit", 301)
	nextRouter := sha256.Sum256([]byte("bandwidth-next"))
	request := ShortBuildRequest{
		ReceiveTunnelID: localHop.ReceiveTunnelID, NextTunnelID: 302, NextRouter: nextRouter,
		RequestMinutes: uint32(now/60_000 - 7), LifetimeSeconds: shortBuildLifetime, NextMessageID: 303,
	}
	options := ShortBuildOptions{Minimum: 32, Requested: 48}
	var plaintext [ShortBuildRequestPlainSize]byte
	if err := MarshalShortBuildRequest(plaintext[:], request, marshalShortBuildOptions(options)); err != nil {
		t.Fatal(err)
	}
	parsedRequest, err := ParseShortBuildRequest(plaintext[:])
	if err != nil {
		t.Fatal(err)
	}
	if parsedOptions, ok := parseShortBuildOptions(parsedRequest.Options, false); !ok || parsedOptions != options {
		t.Fatalf("parsed bandwidth options = %#v, %t", parsedOptions, ok)
	}
	var record [ShortBuildRecordSize]byte
	keys, err := EncryptShortBuildRequest(record[:], localHop.Router, localHop.StaticKey[:], plaintext[:])
	if err != nil {
		t.Fatal(err)
	}
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Sender: sender, ReplyKeys: newBuildReplyRegistry(), LocalRouter: localHop.Router,
		StaticPrivate: private, Bandwidth: func(ShortBuildRequest) uint32 { return 64 },
		Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !manager.validTransitRequest(parsedRequest, keys, now, BuildSource{Router: ivnp.Hash{8}, Direct: true}) {
		t.Fatalf("bandwidth transit request rejected before admission: %+v", parsedRequest)
	}
	message := i2np.Message{Header: i2np.Header{Type: i2np.ShortTunnelBuild, ID: 304}, Payload: append([]byte{1}, record[:]...)}
	originalPayload := append([]byte(nil), message.Payload...)
	if err = manager.HandleBuildFrom(ivnp.Hash{8}, message); err != nil {
		t.Fatal(err)
	}
	forwarded := sender.take()[0].message
	var reply [ShortBuildReplyPlainSize]byte
	if _, err = OpenShortBuildReply(reply[:], forwarded.Payload[1:], keys, 0); err != nil {
		t.Fatal(err)
	}
	mapping, _, err := ivnp.ParseMapping(reply[:])
	if err != nil {
		t.Fatal(err)
	}
	it := mapping.Iterator()
	key, value, ok, err := it.Next()
	if err != nil || !ok || string(key) != "b" || string(value) != "64" || reply[len(reply)-1] != 0 {
		t.Fatalf("bandwidth reply = %q=%q ok=%t code=%d err=%v", key, value, ok, reply[len(reply)-1], err)
	}
	shard := runtime.shard(request.ReceiveTunnelID)
	shard.mu.RLock()
	installed := shard.inbound[request.ReceiveTunnelID]
	shard.mu.RUnlock()
	if installed.expiresAt != now+600_000 {
		t.Fatalf("transit expiration = %d, want %d", installed.expiresAt, now+600_000)
	}
	message.Payload = originalPayload
	if err = manager.HandleBuildFrom(nextRouter, message); !errors.Is(err, ErrBuildRejected) {
		t.Fatalf("predecessor/next loop error = %v", err)
	}
}

func TestBuildManagerRejectsInvalidOptionsCoalescingAndStaticKeyMisuse(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	hop, _ := testShortBuildHop(t, "validation-hop", 401)
	identityKey := hop.StaticKey
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: NewRuntime(RuntimeConfig{Now: func() uint64 { return now }}), Sender: discardTunnelSender{},
		ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now },
		StaticKeyLookup: func(ivnp.Hash) ([32]byte, bool) { return identityKey, true },
	})
	if err != nil {
		t.Fatal(err)
	}
	build := OutboundBuild{CircuitID: 402, Hops: []ShortBuildHop{hop}, ReplyRouter: ivnp.Hash{4}, ReplyTunnelID: 403, ExpiresAt: now + 600_000}
	build.Hops[0].StaticKey[0] ^= 1
	if _, err = manager.StartOutbound(context.Background(), build); !errors.Is(err, ErrBuildConfig) {
		t.Fatalf("transport/static key misuse error = %v", err)
	}
	build.Hops[0] = hop
	build.ReplyRouter = hop.Router
	if _, err = manager.StartOutbound(context.Background(), build); !errors.Is(err, ErrBuildConfig) {
		t.Fatalf("coalesced endpoint/reply gateway error = %v", err)
	}
	for _, options := range []ShortBuildOptions{
		{Minimum: 2, Requested: 1}, {Requested: 2, Limit: 1}, {Minimum: 2, Limit: 1},
	} {
		if validShortBuildOptions(options, true) {
			t.Fatalf("invalid ordered options accepted: %#v", options)
		}
	}
	if validShortBuildOptions(ShortBuildOptions{Limit: 1}, false) {
		t.Fatal("limit option accepted for non-IBGW")
	}
}

func TestTransitTimestampWindowMatchesJavaBounds(t *testing.T) {
	const now = uint64(1_700_000_059_000)
	local := sha256.Sum256([]byte("timestamp-local"))
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: NewRuntime(RuntimeConfig{Now: func() uint64 { return now }}), Sender: discardTunnelSender{},
		ReplyKeys: newBuildReplyRegistry(), LocalRouter: local, Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	source := BuildSource{Router: ivnp.Hash{9}, Direct: true}
	request := ShortBuildRequest{ReceiveTunnelID: 1, NextTunnelID: 2, NextRouter: ivnp.Hash{8}, LifetimeSeconds: shortBuildLifetime, NextMessageID: 3}
	rounded := now / 60_000
	for _, vector := range []struct {
		minutes uint32
		want    bool
	}{
		{uint32(rounded - 8), true},
		{uint32(rounded - 9), false},
		{uint32(rounded + 5), true},
		{uint32(rounded + 6), false},
	} {
		request.RequestMinutes = vector.minutes
		if got := manager.validTransitRequest(request, ShortBuildKeys{}, now, source); got != vector.want {
			t.Fatalf("request minute %d validity = %t, want %t", vector.minutes, got, vector.want)
		}
	}
}

func TestBuildManagerCloseCancelsActiveSendAndClearsPending(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	sender := &cancelingBuildSender{entered: make(chan struct{})}
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Sender: sender, ReplyKeys: newBuildReplyRegistry(),
		Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	scalar := make([]byte, 32)
	scalar[0] = 1
	private, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	hop := ShortBuildHop{Router: sha256.Sum256([]byte("close-hop")), ReceiveTunnelID: 7}
	copy(hop.StaticKey[:], private.PublicKey().Bytes())
	build := OutboundBuild{
		CircuitID: 8, ReplyRouter: sha256.Sum256([]byte("close-reply")), ReplyTunnelID: 9,
		ExpiresAt: now + 60_000, Hops: []ShortBuildHop{hop},
	}
	sendResult := make(chan error, 1)
	go func() {
		_, startErr := manager.StartOutbound(context.Background(), build)
		sendResult <- startErr
	}()
	select {
	case <-sender.entered:
	case <-time.After(time.Second):
		t.Fatal("build sender did not enter")
	}
	if err = manager.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-sendResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("active build result = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join active build")
	}
	if manager.Pending() != 0 {
		t.Fatalf("pending after Close = %d", manager.Pending())
	}
}

func TestBuildManagerReleaseSensitiveClearsOwnedKeys(t *testing.T) {
	static := make([]byte, 32)
	static[0] = 1
	legacy := bytes.Repeat([]byte{0x5a}, cryptx.ElGamalPrivateKeySize)
	sender := new(captureTunnelSender)
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return 1 }}),
		Sender:  sender, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return 1 },
		StaticPrivate: static, LegacyPrivate: legacy,
	})
	if err != nil {
		t.Fatal(err)
	}
	shortKeys := []ShortBuildKeys{{ReplyKey: [32]byte{1}, LayerKey: [32]byte{2}, IVKey: [32]byte{3}}}
	variableKeys := []VariableBuildKeys{{LayerKey: [32]byte{4}, IVKey: [32]byte{5}}}
	manager.pending[1] = &pendingOutboundBuild{keys: shortKeys, positions: []uint8{1}, replyTag: [8]byte{1}}
	manager.pendingVariable[2] = &pendingVariableBuild{keys: variableKeys, positions: []uint8{2}}
	if err = manager.Close(); err != nil {
		t.Fatal(err)
	}
	manager.ReleaseSensitive()
	if !manager.released || manager.staticPrivateKey != nil || manager.legacyEnabled || manager.legacyPrivate != (cryptx.ElGamalPrivateKey{}) || manager.random != nil {
		t.Fatal("build manager retained static private state")
	}
	if len(manager.pending) != 0 || len(manager.pendingInbound) != 0 || len(manager.pendingVariable) != 0 || len(manager.transit) != 0 || len(manager.transitRecords) != 0 {
		t.Fatal("build manager retained lifecycle state")
	}
	if shortKeys[0] != (ShortBuildKeys{}) || variableKeys[0] != (VariableBuildKeys{}) {
		t.Fatal("build manager retained pending build keys")
	}
	if _, err = manager.StartOutbound(context.Background(), OutboundBuild{}); !errors.Is(err, ErrBuildConfig) {
		t.Fatalf("StartOutbound after release = %v", err)
	}
}
