package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/observability"
)

type buildCounterReader struct{ value byte }

func (r *buildCounterReader) Read(dst []byte) (int, error) {
	for index := range dst {
		r.value++
		dst[index] = r.value
	}
	return len(dst), nil
}

type buildXorShiftReader struct{ state uint64 }

func (r *buildXorShiftReader) Read(dst []byte) (int, error) {
	for index := range dst {
		r.state ^= r.state << 13
		r.state ^= r.state >> 7
		r.state ^= r.state << 17
		dst[index] = byte(r.state >> 56)
	}
	return len(dst), nil
}

type buildReplyRegistry struct {
	mu      sync.Mutex
	entries map[[8]byte]dataplane.GarlicReplyKey
	removed [][8]byte
}

func newBuildReplyRegistry() *buildReplyRegistry {
	return &buildReplyRegistry{entries: make(map[[8]byte]dataplane.GarlicReplyKey)}
}

func (r *buildReplyRegistry) RegisterGarlicReplyKey(key dataplane.GarlicReplyKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[key.Tag] = key
	return nil
}

func (r *buildReplyRegistry) RemoveGarlicReplyKey(tag [8]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, tag)
	r.removed = append(r.removed, tag)
}

func (r *buildReplyRegistry) consume(tag [8]byte) (dataplane.GarlicReplyKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key, ok := r.entries[tag]
	if !ok {
		return dataplane.GarlicReplyKey{}, ErrBuildPending
	}
	delete(r.entries, tag)
	return key, nil
}

type captureBuildReplySender struct {
	peer   foundation.Hash
	tunnel uint32
	key    dataplane.GarlicReplyKey
	reply  foundation.I2NPMessage
}

func (s *captureBuildReplySender) SendBuildReply(_ context.Context, peer foundation.Hash, tunnelID uint32, key dataplane.GarlicReplyKey, reply foundation.I2NPMessage) error {
	s.peer, s.tunnel, s.key, s.reply = peer, tunnelID, key, reply
	s.reply.Payload = append([]byte(nil), reply.Payload...)
	return nil
}

type cancelingBuildSender struct {
	entered chan struct{}
	once    sync.Once
}

func (s *cancelingBuildSender) Send(ctx context.Context, _ foundation.Hash, _ foundation.I2NPMessage) error {
	s.once.Do(func() { close(s.entered) })
	<-ctx.Done()
	return ctx.Err()
}

type failingSessionBuildSender struct{ err error }

func (s failingSessionBuildSender) Send(context.Context, foundation.Hash, foundation.I2NPMessage) error {
	return s.err
}

func (s failingSessionBuildSender) EnsureSession(context.Context, foundation.Hash) error {
	return s.err
}

type sessionCaptureTunnelSender struct {
	buildCaptureSender
	sessions []foundation.Hash
}

func (s *sessionCaptureTunnelSender) EnsureSession(_ context.Context, peer foundation.Hash) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = append(s.sessions, peer)
	return nil
}

type replyReadyBuildSender struct {
	buildCaptureSender
	replyPeer  foundation.Hash
	replyErr   error
	replyReady bool
}

func (s *replyReadyBuildSender) EnsureSession(_ context.Context, peer foundation.Hash) error {
	if peer == s.replyPeer {
		if s.replyErr != nil {
			return s.replyErr
		}
		s.replyReady = true
	}
	return nil
}

func (s *replyReadyBuildSender) Send(ctx context.Context, peer foundation.Hash, message foundation.I2NPMessage) error {
	if !s.replyReady {
		return errors.New("creator has no inbound build return session")
	}
	return s.buildCaptureSender.Send(ctx, peer, message)
}

func TestBootstrapInboundEstablishesReturnSessionBeforeSending(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "reachable", true: "unavailable"}[unavailable], func(t *testing.T) {
			const now = uint64(1_700_000_000_000)
			first, _ := testShortBuildHop(t, "bootstrap-first", 1)
			last, _ := testShortBuildHop(t, "bootstrap-last", 2)
			sender := &replyReadyBuildSender{replyPeer: last.Router}
			if unavailable {
				sender.replyErr = errors.New("reply transport unavailable")
			}
			profiles := NewPeerProfiles(PeerProfilesConfig{})
			manager, err := NewBuildManager(BuildManagerConfig{
				Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender}),
				Sender:  sender, ReplyKeys: newBuildReplyRegistry(), Profiles: profiles,
				LocalRouter: foundation.Hash{9}, LocalDelivery: func(foundation.I2NPMessage) error { return nil },
				Now: func() uint64 { return now }, Random: new(buildCounterReader),
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(manager.ReleaseSensitive)
			_, err = manager.StartInbound(t.Context(), InboundBuild{
				CircuitID: 3, Hops: []ShortBuildHop{first, last}, ExpiresAt: now + 600_000,
			})
			if unavailable {
				if !errors.Is(err, sender.replyErr) || manager.Pending() != 0 || len(sender.take()) != 0 {
					t.Fatalf("unreachable return path admitted a build: %v", err)
				}
				if profiles.EligibleAt(last.Router, now) || !profiles.EligibleAt(first.Router, now) {
					t.Fatal("return transport failure was not isolated to its peer")
				}
				return
			}
			if err != nil || len(sender.take()) != 1 {
				t.Fatalf("prepared return path did not permit the bootstrap build: %v", err)
			}
		})
	}
}

func TestBuildManagerSeparatesTransportFailureFromBuildHistory(t *testing.T) {
	now := uint64(1_000)
	sessionErr := errors.New("session failed")
	profiles := NewPeerProfiles(PeerProfilesConfig{})
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{}), Sender: failingSessionBuildSender{err: sessionErr},
		ReplyKeys: newBuildReplyRegistry(), Profiles: profiles, Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	hops := []ShortBuildHop{{Router: foundation.Hash{1}}, {Router: foundation.Hash{2}}, {Router: foundation.Hash{3}}}
	if err = manager.ensureBuildSession(context.Background(), hops[0].Router, hops, "inbound", "first_hop"); !errors.Is(err, sessionErr) {
		t.Fatalf("session error = %v, want %v", err, sessionErr)
	}
	if profiles.EligibleAt(hops[0].Router, now) {
		t.Fatal("failed transport peer skipped its cooldown")
	}
	for _, hop := range hops {
		if _, ok := profiles.Snapshot(hop.Router); ok {
			t.Fatalf("transport preflight created build history for %x", hop.Router)
		}
	}
	if !profiles.EligibleAt(hops[1].Router, now) || !profiles.EligibleAt(hops[2].Router, now) {
		t.Fatal("one transport failure quarantined unrelated path peers")
	}
}

func TestBuildManagerAttributesAuthenticatedRejectionToOnePeer(t *testing.T) {
	now := uint64(2_000)
	profiles := NewPeerProfiles(PeerProfilesConfig{})
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{}), Sender: buildDiscardSender{},
		ReplyKeys: newBuildReplyRegistry(), Profiles: profiles, Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	peers := []foundation.Hash{{1}, {2}, {3}}
	manager.recordBuildPeer(peers[1], false, 0, now)
	for index, peer := range peers {
		profile, ok := profiles.Snapshot(peer)
		if index == 1 {
			if !ok || profile.Failures != 1 {
				t.Fatalf("rejected peer profile = %#v, %t", profile, ok)
			}
		} else if ok {
			t.Fatalf("authenticated rejection poisoned peer %d: %#v", index, profile)
		}
	}
}

func TestBuildManagerCreatesAndInstallsOutboundTunnel(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	sender := new(buildCaptureSender)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	replyKeys := newBuildReplyRegistry()
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Sender: sender, ReplyKeys: replyKeys, Now: func() uint64 { return now }, Random: new(buildCounterReader),
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
	sent := sender.take()
	if len(sent) != 1 || sent[0].peer != build.Hops[0].Router || sent[0].message.Header.Type != foundation.I2NPShortTunnelBuild ||
		sent[0].message.Header.Expiration < now+buildMessageLifetime || sent[0].message.Header.Expiration >= now+buildMessageLifetime+buildMessageFuzz {
		t.Fatalf("initial build message = %#v", sent)
	}
	records, err := foundation.I2NPParseBuildRecords(foundation.I2NPShortTunnelBuild, sent[0].message.Payload)
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
	reply := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPOutboundTunnelBuildReply, ID: replyID, Expiration: now + buildMessageLifetime},
		Payload: sent[0].message.Payload,
	}
	endpointKeys := participantKeys[len(participantKeys)-1]
	registered, ok := replyKeys.entries[endpointKeys.GarlicTag]
	if !ok || registered.Key != endpointKeys.GarlicKey || registered.ExpiresAt != now+2*buildMessageLifetime {
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
	expected := buildStatusFrame(t, 7)
	if err = runtime.SendBlock(context.Background(), build.CircuitID, dataplane.TunnelBlock{Delivery: dataplane.TunnelDeliveryLocal, Last: true, Data: expected}); err != nil {
		t.Fatal(err)
	}
	sent = sender.take()
	if len(sent) != 1 || sent[0].peer != build.Hops[0].Router || sent[0].message.Header.Type != foundation.I2NPTunnelData {
		t.Fatalf("installed tunnel message = %#v", sent)
	}
	current := sent[0].message
	var delivered foundation.I2NPMessage
	for index, hop := range build.Hops {
		hopSender := new(buildCaptureSender)
		hopRuntime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: hopSender, Now: func() uint64 { return now }})
		encryptor, cipherErr := dataplane.TunnelNewLayerEncryptor(participantKeys[index].LayerKey[:], participantKeys[index].IVKey[:])
		if cipherErr != nil {
			t.Fatal(cipherErr)
		}
		circuit := dataplane.TunnelInboundCircuit{ID: hop.ReceiveTunnelID, Transforms: []dataplane.TunnelLayerCipher{encryptor}}
		if index+1 < len(build.Hops) {
			circuit.Forward = &dataplane.TunnelForward{Peer: build.Hops[index+1].Router, TunnelID: build.Hops[index+1].ReceiveTunnelID}
		} else {
			circuit.Endpoint = dataplane.TunnelNewEndpoint(8, 4096)
			circuit.Local = func(message foundation.I2NPMessage) error {
				delivered = message
				return nil
			}
		}
		if _, err = hopRuntime.RegisterInbound(circuit); err != nil {
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
	if delivered.Header.Type != foundation.I2NPDeliveryStatus || delivered.Header.ID != 7 {
		t.Fatalf("delivered message = %#v", delivered)
	}
}

func TestBuildManagerRejectsExpiredAndUnknownReplies(t *testing.T) {
	now := uint64(1_700_000_000_000)
	sender := new(buildCaptureSender)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	replyKeys := newBuildReplyRegistry()
	manager, err := NewBuildManager(BuildManagerConfig{Runtime: runtime, Sender: sender, ReplyKeys: replyKeys, Now: func() uint64 { return now }, Random: new(buildCounterReader)})
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.HandleReply(foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPOutboundTunnelBuildReply, ID: 1}, Payload: append([]byte{1}, make([]byte, ShortBuildRecordSize)...)}); err != ErrBuildPending {
		t.Fatalf("unknown reply error = %v, want %v", err, ErrBuildPending)
	}
	if _, err = manager.StartOutbound(context.Background(), OutboundBuild{CircuitID: 1, ReplyTunnelID: 2, ExpiresAt: now - 1, Hops: []ShortBuildHop{{Router: foundation.Hash{1}, StaticKey: [32]byte{1}, ReceiveTunnelID: 3}}}); err != ErrBuildConfig {
		t.Fatalf("expired build error = %v, want %v", err, ErrBuildConfig)
	}
}

func TestBuildManagerAcceptsAuthenticatedReplyDuringJavaGracePeriod(t *testing.T) {
	now := uint64(1_700_000_000_000)
	privateBytes := make([]byte, 32)
	for index := range privateBytes {
		privateBytes[index] = byte(index + 1)
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	hop := ShortBuildHop{Router: sha256.Sum256([]byte("late-obep")), ReceiveTunnelID: 41}
	copy(hop.StaticKey[:], private.PublicKey().Bytes())
	sender := new(buildCaptureSender)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	replyKeys := newBuildReplyRegistry()
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Sender: sender, ReplyKeys: replyKeys,
		Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	startedAt := now
	replyID, err := manager.StartOutbound(context.Background(), OutboundBuild{
		CircuitID: 40, Hops: []ShortBuildHop{hop}, ReplyRouter: foundation.Hash{2},
		ReplyTunnelID: 42, ExpiresAt: now + 30_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	sent := sender.take()
	if len(sent) != 1 {
		t.Fatalf("outbound request count = %d, want 1", len(sent))
	}
	records, err := foundation.I2NPParseBuildRecords(foundation.I2NPShortTunnelBuild, sent[0].message.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var plaintext [ShortBuildRequestPlainSize]byte
	_, endpointKeys, _, err := ProcessShortBuildRecords(
		records.Records, plaintext[:], hop.Router, privateBytes, true, new(buildCounterReader),
	)
	if err != nil {
		t.Fatal(err)
	}

	now += buildRequestTimeout()
	if expired := manager.Expire(now); expired != 1 {
		t.Fatalf("timed out builds = %d, want 1", expired)
	}
	now += 1
	registered, ok := replyKeys.entries[endpointKeys.GarlicTag]
	if !ok || registered.ExpiresAt != startedAt+2*buildMessageLifetime {
		t.Fatalf("late reply key expiry = %#v, found %t", registered, ok)
	}
	if _, err = replyKeys.consume(endpointKeys.GarlicTag); err != nil {
		t.Fatalf("late reply key was not retained: %v", err)
	}
	reply := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPOutboundTunnelBuildReply, ID: replyID, Expiration: now + buildMessageLifetime},
		Payload: sent[0].message.Payload,
	}
	if err = manager.HandleReply(reply); err != nil {
		t.Fatalf("authenticated late reply: %v", err)
	}
	if _, ok := runtime.CircuitOwner(40); !ok {
		t.Fatal("late authenticated reply did not install the outbound circuit")
	}
}

func TestBuildManagerRetainsEveryTimedOutBuildUntilJavaGraceExpires(t *testing.T) {
	const start = uint64(1_700_000_000_000)
	now := start
	privateBytes := make([]byte, 32)
	for index := range privateBytes {
		privateBytes[index] = byte(index + 1)
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	hop := ShortBuildHop{Router: sha256.Sum256([]byte("time-bounded-grace-obep"))}
	copy(hop.StaticKey[:], private.PublicKey().Bytes())
	replyKeys := newBuildReplyRegistry()
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{}), Sender: buildDiscardSender{}, ReplyKeys: replyKeys,
		Now: func() uint64 { return now }, Random: &buildXorShiftReader{state: 1}, MaxPending: 2,
		Schedule: func(time.Duration, func()) func() { return func() {} },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.ReleaseSensitive)

	var retained []*pendingOutboundBuild
	var retainedTags [][8]byte
	for batch := range 6 {
		for slot := range manager.maxPending {
			hop.ReceiveTunnelID = uint32(100 + batch*manager.maxPending + slot)
			replyID, startErr := manager.StartOutbound(context.Background(), OutboundBuild{
				CircuitID: uint32(200 + batch*manager.maxPending + slot), Hops: []ShortBuildHop{hop},
				ReplyRouter: foundation.Hash{9}, ReplyTunnelID: 10, ExpiresAt: now + 600_000,
			})
			if startErr != nil {
				t.Fatalf("batch %d retry %d: %v", batch, slot, startErr)
			}
			pending := manager.pending[replyID]
			retained = append(retained, pending)
			retainedTags = append(retainedTags, pending.replyTag)
		}
		now += buildRequestTimeout()
		if expired := manager.Expire(now); expired != manager.maxPending {
			t.Fatalf("batch %d expired builds = %d, want %d", batch, expired, manager.maxPending)
		}
		if active := manager.Pending(); active != 0 {
			t.Fatalf("batch %d active builds = %d, want 0 before retry", batch, active)
		}
		manager.mu.Lock()
		recent := len(manager.recent)
		manager.mu.Unlock()
		wantRecent := (batch + 1) * manager.maxPending
		if recent != wantRecent {
			t.Fatalf("batch %d grace builds = %d, want %d", batch, recent, wantRecent)
		}
		if len(replyKeys.entries) != wantRecent {
			t.Fatalf("batch %d retained reply keys = %d, want %d", batch, len(replyKeys.entries), wantRecent)
		}
	}
	if len(retained) <= manager.maxPending {
		t.Fatalf("grace state did not grow beyond active capacity: %d", len(retained))
	}
	for index, pending := range retained {
		if pending.keys[0] == (ShortBuildKeys{}) {
			t.Fatalf("retained reply %d lost key material before grace expiry", index)
		}
	}

	now = start + buildRequestTimeout() + buildReplyGracePeriod
	manager.Expire(now)
	if retained[0].keys[0] != (ShortBuildKeys{}) || retained[1].keys[0] != (ShortBuildKeys{}) {
		t.Fatal("oldest grace batch retained key material at expiry")
	}
	for _, tag := range retainedTags[:manager.maxPending] {
		if _, ok := replyKeys.entries[tag]; ok {
			t.Fatalf("expired grace reply tag %x remained registered", tag)
		}
	}
	if retained[manager.maxPending].keys[0] == (ShortBuildKeys{}) {
		t.Fatal("younger grace batch expired with oldest batch")
	}

	now = start + 6*buildRequestTimeout() + buildReplyGracePeriod
	manager.Expire(now)
	manager.mu.Lock()
	recent := len(manager.recent)
	manager.mu.Unlock()
	if recent != 0 || len(replyKeys.entries) != 0 {
		t.Fatalf("expired grace state: recent=%d reply_keys=%d", recent, len(replyKeys.entries))
	}
}

func TestBuildManagerRetainsInboundAndVariableCreatorsDuringJavaGrace(t *testing.T) {
	now := uint64(100)
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{}), Sender: buildDiscardSender{}, ReplyKeys: newBuildReplyRegistry(),
		Now: func() uint64 { return now }, Schedule: func(time.Duration, func()) func() { return func() {} },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.ReleaseSensitive)
	inbound := &pendingInboundBuild{deadline: now, keys: []ShortBuildKeys{{LayerKey: [32]byte{1}}}}
	variable := &pendingVariableBuild{deadline: now, keys: []VariableBuildKeys{{LayerKey: [32]byte{2}}}}
	manager.pendingInbound[11] = inbound
	manager.pendingVariable[12] = variable

	if expired := manager.Expire(now); expired != 2 {
		t.Fatalf("timed-out creator builds = %d, want 2", expired)
	}
	if manager.Pending() != 0 || !manager.hasInboundPending(11) {
		t.Fatalf("grace state was counted active or inbound reply was unroutable: pending=%d", manager.Pending())
	}
	if got := manager.takeVariablePending(12); got != variable || got.keys[0].LayerKey[0] != 2 {
		t.Fatalf("late variable pending = %#v, want retained build", got)
	}
	clearVariableBuildKeys(variable.keys)
	now += buildReplyGracePeriod
	manager.Expire(now)
	if inbound.keys[0] != (ShortBuildKeys{}) || manager.hasInboundPending(11) {
		t.Fatal("inbound creator state survived the Java grace deadline")
	}
}

func TestBuildManagerDelayedSweepDoesNotExtendJavaGrace(t *testing.T) {
	const activeDeadline = uint64(100)
	now := activeDeadline + buildReplyGracePeriod + 1
	replyKeys := newBuildReplyRegistry()
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{}), Sender: buildDiscardSender{}, ReplyKeys: replyKeys,
		Now: func() uint64 { return now }, Schedule: func(time.Duration, func()) func() { return func() {} },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.ReleaseSensitive)
	tag := [8]byte{1}
	if err = replyKeys.RegisterGarlicReplyKey(dataplane.GarlicReplyKey{Tag: tag, ExpiresAt: now + 1}); err != nil {
		t.Fatal(err)
	}
	outbound := &pendingOutboundBuild{deadline: activeDeadline, replyTag: tag, keys: []ShortBuildKeys{{LayerKey: [32]byte{1}}}}
	inbound := &pendingInboundBuild{deadline: activeDeadline, keys: []ShortBuildKeys{{LayerKey: [32]byte{2}}}}
	variable := &pendingVariableBuild{deadline: activeDeadline, keys: []VariableBuildKeys{{LayerKey: [32]byte{3}}}}
	manager.pending[1] = outbound
	manager.pendingInbound[2] = inbound
	manager.pendingVariable[3] = variable

	if expired := manager.Expire(now); expired != 3 {
		t.Fatalf("delayed sweep expired builds = %d, want 3", expired)
	}
	manager.mu.Lock()
	recent := len(manager.recent)
	manager.mu.Unlock()
	if recent != 0 {
		t.Fatalf("delayed sweep retained %d builds past anchored grace", recent)
	}
	if outbound.keys[0] != (ShortBuildKeys{}) || inbound.keys[0] != (ShortBuildKeys{}) || variable.keys[0] != (VariableBuildKeys{}) {
		t.Fatal("delayed sweep retained creator key material past anchored grace")
	}
	if _, ok := replyKeys.entries[tag]; ok {
		t.Fatal("delayed sweep retained garlic reply key past anchored grace")
	}
}

func TestBuildRequestTimeoutMatchesApplicableJavaSlowSystemRules(t *testing.T) {
	tests := []struct {
		name         string
		goos, goarch string
		cores        int
		want         uint64
	}{
		{name: "Apple M1", goos: "darwin", goarch: "arm64", cores: 4, want: normalBuildRequestTimeout},
		{name: "Linux ARM server", goos: "linux", goarch: "arm64", cores: 5, want: normalBuildRequestTimeout},
		{name: "Raspberry Pi", goos: "linux", goarch: "arm64", cores: 4, want: slowBuildRequestTimeout},
		{name: "32-bit ARM", goos: "linux", goarch: "arm", cores: 8, want: slowBuildRequestTimeout},
		{name: "Android", goos: "android", goarch: "amd64", cores: 8, want: slowBuildRequestTimeout},
		{name: "x86", goos: "linux", goarch: "amd64", cores: 2, want: normalBuildRequestTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := buildRequestTimeoutForSystem(test.goos, test.goarch, test.cores); got != test.want {
				t.Fatalf("build timeout = %d, want %d", got, test.want)
			}
		})
	}
}

func TestRandomizedBuildMessageDeadlineUsesJavaFuzzRange(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	deadline, err := randomizedBuildMessageDeadline(now, bytes.NewReader([]byte{0, 0, 0x4e, 0x1f}))
	if err != nil {
		t.Fatal(err)
	}
	if want := now + buildMessageLifetime + buildMessageFuzz - 1; deadline != want {
		t.Fatalf("randomized build deadline = %d, want %d", deadline, want)
	}
}

func TestBuildManagerClearsReplyRegistryAfterReplyErrorAndExpiry(t *testing.T) {
	replyKeys := newBuildReplyRegistry()
	profiles := NewPeerProfiles(PeerProfilesConfig{})
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{}), Sender: buildDiscardSender{}, ReplyKeys: replyKeys, Profiles: profiles, Now: func() uint64 { return 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	var errorTag, expiryTag [8]byte
	errorTag[0], expiryTag[0] = 1, 2
	if err = replyKeys.RegisterGarlicReplyKey(dataplane.GarlicReplyKey{Tag: errorTag, ExpiresAt: 2}); err != nil {
		t.Fatal(err)
	}
	failedPeer := foundation.Hash{9}
	manager.pending[1] = &pendingOutboundBuild{replyTag: errorTag, deadline: 2, build: OutboundBuild{Hops: []ShortBuildHop{{Router: failedPeer}}}}
	if err = manager.HandleReply(foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPOutboundTunnelBuildReply, ID: 1}}); err == nil {
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
	if err = manager.HandleReply(foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPOutboundTunnelBuildReply, ID: 3}, Payload: invalidAuthenticatedRecords}); err == nil {
		t.Fatal("accepted reply with invalid authenticated records")
	}
	if profile, ok := profiles.Snapshot(failedPeer); ok {
		t.Fatalf("unattributable authenticated reply error poisoned peer profile: %#v", profile)
	}
	if err = replyKeys.RegisterGarlicReplyKey(dataplane.GarlicReplyKey{Tag: expiryTag, ExpiresAt: 2 + 2*buildMessageLifetime}); err != nil {
		t.Fatal(err)
	}
	manager.pending[2] = &pendingOutboundBuild{replyTag: expiryTag, deadline: 2, build: OutboundBuild{Hops: []ShortBuildHop{{Router: failedPeer}}}}
	if expired := manager.Expire(2); expired != 1 {
		t.Fatalf("expired builds = %d, want 1", expired)
	}
	if _, ok := replyKeys.entries[expiryTag]; !ok {
		t.Fatal("reply key was not retained during the late-reply grace period")
	}
	if expired := manager.Expire(2 + buildReplyGracePeriod); expired != 0 {
		t.Fatalf("newly timed out builds during grace cleanup = %d, want 0", expired)
	}
	if _, ok := replyKeys.entries[expiryTag]; ok {
		t.Fatal("reply key retained after the late-reply grace period")
	}
	profile, ok := profiles.Snapshot(failedPeer)
	if !ok || profile.Failures != 1 || profile.Successes != 0 {
		t.Fatalf("build timeout profile = %#v, %t", profile, ok)
	}
}

func TestBuildManagerMultiHopTimeoutRecordsEveryPeer(t *testing.T) {
	profiles := NewPeerProfiles(PeerProfilesConfig{})
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{}), Sender: buildDiscardSender{}, ReplyKeys: newBuildReplyRegistry(),
		Profiles: profiles, Now: func() uint64 { return 10 },
	})
	if err != nil {
		t.Fatal(err)
	}
	peers := []foundation.Hash{{1}, {2}, {3}}
	hops := make([]ShortBuildHop, len(peers))
	for index, peer := range peers {
		hops[index].Router = peer
	}
	manager.pending[1] = &pendingOutboundBuild{deadline: 10, build: OutboundBuild{Hops: hops}}
	if expired := manager.Expire(10); expired != 1 {
		t.Fatalf("expired builds = %d, want 1", expired)
	}
	for _, peer := range peers {
		profile, ok := profiles.Snapshot(peer)
		if !ok || profile.Failures != 1 || profile.Successes != 0 {
			t.Fatalf("timeout profile for %x = %#v, %t", peer, profile, ok)
		}
	}
}

func TestBuildManagerDeadlineExpiresAndWakesOwnerImmediately(t *testing.T) {
	now := uint64(1)
	var (
		scheduledDurations []time.Duration
		scheduledCallbacks []func()
	)
	wake := make(chan struct{}, 1)
	metrics := observability.NewRegistry()
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{}), Sender: buildDiscardSender{}, ReplyKeys: newBuildReplyRegistry(),
		Now: func() uint64 { return now },
		Schedule: func(duration time.Duration, callback func()) func() {
			scheduledDurations = append(scheduledDurations, duration)
			scheduledCallbacks = append(scheduledCallbacks, callback)
			return func() {}
		},
		OnBuildEvent: func() { wake <- struct{}{} }, Metrics: metrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending := &pendingOutboundBuild{deadline: 2}
	pending.cancelDeadline = manager.scheduleBuildDeadline(now, pending.deadline)
	manager.pending[1] = pending
	now = 2
	scheduledCallbacks[0]()
	if manager.Pending() != 0 {
		t.Fatalf("expired pending builds = %d, want 0", manager.Pending())
	}
	wantDurations := []time.Duration{time.Millisecond, time.Minute}
	if !slices.Equal(scheduledDurations, wantDurations) {
		t.Fatalf("deadline schedules = %v, want %v", scheduledDurations, wantDurations)
	}
	select {
	case <-wake:
	default:
		t.Fatal("build deadline did not wake owner immediately")
	}
	if got := metrics.Snapshot().Tunnel.ExploratoryOutboundTimeouts; got != 1 {
		t.Fatalf("exploratory outbound timeouts = %d, want 1", got)
	}
}
func TestBuildManagerRollsBackPoolWhenRuntimeInstallFails(t *testing.T) {
	const (
		managerNow = uint64(100)
		expiresAt  = uint64(101)
		replyID    = uint32(7)
		circuitID  = uint32(8)
	)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Now: func() uint64 { return expiresAt }})
	pool := NewPool(1)
	replyKeys := newBuildReplyRegistry()
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: buildDiscardSender{}, ReplyKeys: replyKeys, Now: func() uint64 { return managerNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	var keys ShortBuildKeys
	manager.pending[replyID] = &pendingOutboundBuild{
		build:       OutboundBuild{CircuitID: circuitID, Hops: []ShortBuildHop{{Router: foundation.Hash{1}, ReceiveTunnelID: 9}}, ExpiresAt: expiresAt},
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
	reply := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPOutboundTunnelBuildReply, ID: replyID}, Payload: payload}
	if err = manager.HandleReply(reply); err != dataplane.TunnelErrCircuitExpired {
		t.Fatalf("install error = %v, want %v", err, dataplane.TunnelErrCircuitExpired)
	}
	if manager.Pending() != 0 || pool.Count(Outbound, 0) != 0 {
		t.Fatalf("failed install retained pending=%d pool=%d", manager.Pending(), pool.Count(Outbound, 0))
	}
	if err = runtime.SendBlock(context.Background(), circuitID, dataplane.TunnelBlock{Delivery: dataplane.TunnelDeliveryLocal, Last: true, Data: []byte{1}}); err != dataplane.TunnelErrCircuitNotFound {
		t.Fatalf("rolled-back circuit error = %v, want %v", err, dataplane.TunnelErrCircuitNotFound)
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
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: buildDiscardSender{}, Now: func() uint64 { return runtimeNow }})
	pool := NewPool(1)
	old := Entry{ID: oldID, Direction: Outbound, Expires: runtimeNow + 1}
	if _, err := runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: old.ID, NextTunnelID: 10, ExpiresAt: old.Expires}); err != nil {
		t.Fatal(err)
	}
	old.Circuit = buildCircuitToken(t, runtime, old.ID)
	if err := pool.Add(old, managerNow); err != nil {
		t.Fatal(err)
	}
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: buildDiscardSender{}, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return managerNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	var keys ShortBuildKeys
	manager.pending[replyID] = &pendingOutboundBuild{
		build:       OutboundBuild{CircuitID: newID, Hops: []ShortBuildHop{{Router: foundation.Hash{1}, ReceiveTunnelID: 11}}, ExpiresAt: runtimeNow, retireID: old.ID},
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
	reply := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPOutboundTunnelBuildReply, ID: replyID}, Payload: payload}
	if err = manager.HandleReply(reply); err != dataplane.TunnelErrCircuitExpired {
		t.Fatalf("install error = %v, want %v", err, dataplane.TunnelErrCircuitExpired)
	}
	if entry, ok := pool.Get(old.ID, managerNow); !ok || entry != old {
		t.Fatalf("restored pool entry = %#v, %t", entry, ok)
	}
	if _, ok := pool.Get(newID, managerNow); ok {
		t.Fatal("failed replacement retained")
	}
	if err = runtime.SendBlock(context.Background(), old.ID, dataplane.TunnelBlock{Delivery: dataplane.TunnelDeliveryLocal, Last: true, Data: []byte{1}}); err != nil {
		t.Fatalf("retained runtime circuit error = %v", err)
	}
}

func TestBuildManagerBuildsInboundAcrossTransitAndRejectsStaleRequests(t *testing.T) {
	now := uint64(1_700_000_000_000)
	creator := sha256.Sum256([]byte("inbound-creator"))
	outerPeer := sha256.Sum256([]byte("outer-obep"))
	carrier := new(buildCaptureSender)
	var inboundDelivered foundation.I2NPMessage
	creatorRuntime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: carrier, Now: func() uint64 { return now }})
	if _, err := creatorRuntime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 500, FirstHop: outerPeer, NextTunnelID: 501}); err != nil {
		t.Fatal(err)
	}
	creatorManager, err := NewBuildManager(BuildManagerConfig{
		Runtime: creatorRuntime, Sender: carrier, ReplyKeys: newBuildReplyRegistry(), LocalRouter: creator,
		LocalDelivery: func(message foundation.I2NPMessage) error { inboundDelivered = message; return nil }, Now: func() uint64 { return now }, Random: new(buildCounterReader),
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
	if len(carried) != 1 || carried[0].message.Header.Type != foundation.I2NPTunnelData {
		t.Fatalf("inbound carrier message = %#v", carried)
	}
	blocks := make([]dataplane.TunnelBlock, 1)
	count, err := dataplane.TunnelNewEndpoint(1, foundation.I2NPI2PDMaxPayload).Parse(carried[0].message.Payload, blocks, 0)
	if err != nil || count != 1 || blocks[0].Delivery != dataplane.TunnelDeliveryRouter || blocks[0].Gateway != build.Hops[0].Router {
		t.Fatalf("carrier blocks = %d, %#v, %v", count, blocks[0], err)
	}
	current, used, err := foundation.I2NPParseUnchecked(blocks[0].Data)
	if err != nil || used != len(blocks[0].Data) || current.Header.Type != foundation.I2NPShortTunnelBuild {
		t.Fatalf("carrier build = %#v, %d, %v", current, used, err)
	}
	for index, hop := range build.Hops {
		next := new(buildCaptureSender)
		hopRuntime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: next, Now: func() uint64 { return now }})
		hopManager, managerErr := NewBuildManager(BuildManagerConfig{
			Runtime: hopRuntime, Sender: next, ReplyKeys: newBuildReplyRegistry(), LocalRouter: hop.Router,
			StaticPrivate: privateKeys[index], LocalDelivery: func(foundation.I2NPMessage) error { return nil },
			Now: func() uint64 { return now }, Random: new(buildCounterReader),
		})
		if managerErr != nil {
			t.Fatal(managerErr)
		}
		predecessor := outerPeer
		if index != 0 {
			predecessor = build.Hops[index-1].Router
		}
		if managerErr = hopManager.HandleBuildContext(context.Background(), BuildSource{Router: predecessor, Direct: true}, current); managerErr != nil {
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
		if forwarded[0].peer != wantPeer || forwarded[0].message.Header.Type != foundation.I2NPShortTunnelBuild || forwarded[0].message.Header.Expiration != now+nextHopSendTimeout {
			t.Fatalf("hop %d route = %#v", index, forwarded[0])
		}
		current = forwarded[0].message
	}
	if current.Header.ID != replyID {
		t.Fatalf("inbound reply ID = %d, want %d", current.Header.ID, replyID)
	}
	pendingKeys := append([]ShortBuildKeys(nil), creatorManager.pendingInbound[replyID].keys...)
	now += buildRequestTimeout()
	if expired := creatorManager.Expire(now); expired != 1 {
		t.Fatalf("timed out inbound builds = %d, want 1", expired)
	}
	if !creatorManager.hasInboundPending(replyID) {
		t.Fatal("timed-out inbound build was not retained during Java grace")
	}
	now++
	if err = creatorManager.HandleBuildContext(context.Background(), BuildSource{}, current); err != nil {
		t.Fatal(err)
	}
	producerSender := new(buildCaptureSender)
	producer := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: producerSender, Now: func() uint64 { return now }})
	if _, err = producer.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 1, FirstHop: foundation.Hash{1}, NextTunnelID: build.CircuitID}); err != nil {
		t.Fatal(err)
	}
	if err = producer.SendBlock(context.Background(), 1, dataplane.TunnelBlock{Delivery: dataplane.TunnelDeliveryLocal, Last: true, Data: buildStatusFrame(t, 55)}); err != nil {
		t.Fatal(err)
	}
	layered := producerSender.take()
	if len(layered) != 1 {
		t.Fatalf("layered inbound source = %#v", layered)
	}
	for hop := range pendingKeys {
		encryptor, cipherErr := dataplane.TunnelNewLayerEncryptor(pendingKeys[hop].LayerKey[:], pendingKeys[hop].IVKey[:])
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
	if inboundDelivered.Header.Type != foundation.I2NPDeliveryStatus || inboundDelivered.Header.ID != 55 {
		t.Fatalf("layered inbound delivery = %#v", inboundDelivered)
	}
	if creatorManager.Pending() != 0 {
		t.Fatalf("pending inbound builds = %d", creatorManager.Pending())
	}
	if _, err = creatorRuntime.RegisterInbound(dataplane.TunnelInboundCircuit{ID: build.CircuitID, Endpoint: dataplane.TunnelNewEndpoint(1, 1)}); err != dataplane.TunnelErrCircuitExists {
		t.Fatalf("inbound circuit collision = %v, want %v", err, dataplane.TunnelErrCircuitExists)
	}

	staleSender := new(buildCaptureSender)
	staleRuntime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: staleSender, Now: func() uint64 { return now }})
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
	stale := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPShortTunnelBuild, ID: 903, Expiration: now + buildMessageLifetime}, Payload: append([]byte{1}, record[:]...)}
	if err = staleManager.HandleBuildContext(context.Background(), BuildSource{Router: foundation.Hash{9}, Direct: true}, stale); err != ErrBuildRejected {
		t.Fatalf("stale request error = %v, want %v", err, ErrBuildRejected)
	}
	if _, err = staleRuntime.RegisterInbound(dataplane.TunnelInboundCircuit{ID: request.ReceiveTunnelID, Endpoint: dataplane.TunnelNewEndpoint(1, 1)}); err != nil {
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
	creatorSender := new(buildCaptureSender)
	creatorRuntime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: creatorSender, Now: func() uint64 { return now }})
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
	obepSender := new(buildCaptureSender)
	obep, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: obepSender, Now: func() uint64 { return now }}), Sender: obepSender,
		ReplyKeys: newBuildReplyRegistry(), ReplySender: replies, LocalRouter: hop.Router, StaticPrivate: privateBytes,
		LocalDelivery: func(foundation.I2NPMessage) error { return nil }, Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = obep.HandleBuildContext(context.Background(), BuildSource{Router: foundation.Hash{7}, Direct: true}, requests[0].message); err != nil {
		t.Fatal(err)
	}
	routeMatches := replies.peer == replyRouter && replies.tunnel == 42
	replyMatches := replies.reply.Header.Type == foundation.I2NPOutboundTunnelBuildReply && replies.reply.Header.ID == replyID
	expirationMatches := replies.reply.Header.Expiration == now+nextHopSendTimeout && replies.key.ExpiresAt == now+nextHopSendTimeout
	if !routeMatches || !replyMatches || !expirationMatches {
		t.Fatalf("OBEP garlic route = %#v", replies)
	}
	registered, ok := replyKeys.entries[replies.key.Tag]
	if !ok || registered.Key != replies.key.Key || registered.ExpiresAt != now+2*buildMessageLifetime {
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
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Now: func() uint64 { return now }}), Sender: buildDiscardSender{},
		ReplyKeys: newBuildReplyRegistry(), ReplySender: new(captureBuildReplySender), LocalRouter: local,
		LocalDelivery: func(foundation.I2NPMessage) error { return nil }, Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := ShortBuildRequest{
		ReceiveTunnelID: 1, NextTunnelID: 2, NextRouter: local, Endpoint: true,
		RequestMinutes: uint32(now / 60_000), LifetimeSeconds: shortBuildLifetime, NextMessageID: 3,
	}
	if !manager.validTransitRequest(request, ShortBuildKeys{HasGarlicKeys: true}, now, BuildSource{Router: foundation.Hash{1}, Direct: true}) {
		t.Fatal("endpoint request to local router rejected")
	}
	request.Endpoint = false
	if manager.validTransitRequest(request, ShortBuildKeys{}, now, BuildSource{Router: foundation.Hash{1}, Direct: true}) {
		t.Fatal("non-endpoint loop request accepted")
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
	sender := new(buildCaptureSender)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
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
	if err = manager.HandleBuildContext(context.Background(), BuildSource{Router: foundation.Hash{7}, Direct: true}, foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPShortTunnelBuild, ID: 201}, Payload: append([]byte{1}, malformed[:]...)}); err == nil {
		t.Fatal("malformed transit accepted")
	}
	if len(manager.transit) != 0 {
		t.Fatalf("malformed transit reserved slots = %#v", manager.transit)
	}
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPShortTunnelBuild, ID: 202}, Payload: append([]byte{1}, record[:]...)}
	if _, err = runtime.RegisterInbound(dataplane.TunnelInboundCircuit{ID: request.ReceiveTunnelID, Endpoint: dataplane.TunnelNewEndpoint(1, 1)}); err != nil {
		t.Fatal(err)
	}
	if err = manager.HandleBuildContext(context.Background(), BuildSource{Router: foundation.Hash{7}, Direct: true}, foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPShortTunnelBuild, ID: 203}, Payload: append([]byte(nil), message.Payload...)}); err != ErrBuildRejected {
		t.Fatalf("colliding transit error = %v, want %v", err, ErrBuildRejected)
	}
	if len(manager.transit) != 0 {
		t.Fatalf("colliding transit reserved slots = %#v", manager.transit)
	}
	installed, _ := runtime.InspectCircuit(request.ReceiveTunnelID)
	runtime.RemoveCircuit(installed.Token)
	results := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Go(func() {
			duplicate := message
			duplicate.Payload = append([]byte(nil), message.Payload...)
			results <- manager.HandleBuildContext(context.Background(), BuildSource{Router: foundation.Hash{7}, Direct: true}, duplicate)
		})
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
			Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Now: func() uint64 { return now }}), Sender: buildDiscardSender{}, ReplyKeys: newBuildReplyRegistry(),
			LocalRouter: sha256.Sum256([]byte("pending-local")), LocalDelivery: func(foundation.I2NPMessage) error { return nil },
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
	sender := new(buildCaptureSender)
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }}),
		Sender:  sender, ReplyKeys: newBuildReplyRegistry(), LocalRouter: local,
		LocalDelivery: func(foundation.I2NPMessage) error { return nil }, Now: func() uint64 { return now }, Random: new(buildCounterReader),
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
	records, err := foundation.I2NPParseBuildRecords(foundation.I2NPShortTunnelBuild, request.Payload)
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
	next := new(buildCaptureSender)
	participant, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: next, Now: func() uint64 { return now }}),
		Sender:  next, ReplyKeys: newBuildReplyRegistry(), LocalRouter: hop.Router, StaticPrivate: private,
		Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = participant.HandleBuildContext(context.Background(), BuildSource{Router: foundation.Hash{9}, Direct: true}, request); err != nil {
		t.Fatal(err)
	}
	reply := next.take()[0].message
	tampered := reply
	tampered.Payload = append([]byte(nil), reply.Payload...)
	tampered.Payload[1+int(pending.fakePosition)*ShortBuildRecordSize+100] ^= 1
	if err = manager.HandleBuildContext(context.Background(), BuildSource{}, tampered); !errors.Is(err, ErrBuildFakeRecord) {
		t.Fatalf("tampered creator fake error = %v", err)
	}
}

func TestInboundBuildThroughCarrierDoesNotPreflightReplyEndpoint(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	local := sha256.Sum256([]byte("carrier-inbound-creator"))
	first, _ := testShortBuildHop(t, "carrier-inbound-first", 301)
	last, _ := testShortBuildHop(t, "carrier-inbound-last", 302)
	carrierEndpoint := sha256.Sum256([]byte("carrier-inbound-endpoint"))
	carrierFirst := sha256.Sum256([]byte("carrier-inbound-first-hop"))
	sender := new(sessionCaptureTunnelSender)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	if _, err := runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 303, FirstHop: carrierFirst, NextTunnelID: 304}); err != nil {
		t.Fatal(err)
	}
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Sender: sender, ReplyKeys: newBuildReplyRegistry(), LocalRouter: local,
		LocalDelivery: func(foundation.I2NPMessage) error { return nil }, Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.StartInbound(context.Background(), InboundBuild{
		CircuitID: 305, OutboundTunnelID: 303, CarrierEndpoint: carrierEndpoint,
		Hops: []ShortBuildHop{first, last}, ExpiresAt: now + 600_000,
	}); err != nil {
		t.Fatal(err)
	}
	if len(sender.sessions) != 1 || sender.sessions[0] != carrierFirst {
		t.Fatalf("carrier build must prepare only its first hop, got %x", sender.sessions)
	}
}

func TestInboundBuildGarlicWrapsAcrossDifferentCarrierEndpoint(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	local := sha256.Sum256([]byte("wrapped-inbound-creator"))
	hop, private := testShortBuildHop(t, "wrapped-ibgw", 201)
	carrierEndpoint := sha256.Sum256([]byte("carrier-obep"))
	firstHop := sha256.Sum256([]byte("carrier-first"))
	sender := new(buildCaptureSender)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	if _, err := runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 202, FirstHop: firstHop, NextTunnelID: 203}); err != nil {
		t.Fatal(err)
	}
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Sender: sender, ReplyKeys: newBuildReplyRegistry(), LocalRouter: local,
		LocalDelivery: func(foundation.I2NPMessage) error { return nil }, Now: func() uint64 { return now }, Random: new(buildCounterReader),
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
	if len(carried) != 1 || carried[0].peer != firstHop || carried[0].message.Header.Type != foundation.I2NPTunnelData {
		t.Fatalf("carrier output = %#v", carried)
	}
	blocks := make([]dataplane.TunnelBlock, 1)
	count, err := dataplane.TunnelNewEndpoint(1, foundation.I2NPI2PDMaxPayload).Parse(carried[0].message.Payload, blocks, 0)
	if err != nil || count != 1 {
		t.Fatalf("carrier parse = %d, %v", count, err)
	}
	outer, used, err := foundation.I2NPParseUnchecked(blocks[0].Data)
	if err != nil || used != len(blocks[0].Data) || outer.Header.Type != foundation.I2NPGarlic {
		t.Fatalf("outer = %#v, %d, %v", outer, used, err)
	}
	garlicMessage, err := foundation.I2NPParseGarlic(outer.Payload)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := dataplane.GarlicECIESOpenRouterMessage(make([]byte, len(garlicMessage.Encrypted)), private, garlicMessage.Encrypted, now)
	if err != nil || inner.Header.Type != foundation.I2NPShortTunnelBuild {
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
	encodedOptions, err := marshalShortBuildOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	if err = MarshalShortBuildRequest(plaintext[:], request, encodedOptions); err != nil {
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
	sender := new(buildCaptureSender)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Sender: sender, ReplyKeys: newBuildReplyRegistry(), LocalRouter: localHop.Router,
		StaticPrivate: private, Bandwidth: func(ShortBuildRequest) uint32 { return 64 },
		Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !manager.validTransitRequest(parsedRequest, keys, now, BuildSource{Router: foundation.Hash{8}, Direct: true}) {
		t.Fatalf("bandwidth transit request rejected before admission: %+v", parsedRequest)
	}
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPShortTunnelBuild, ID: 304}, Payload: append([]byte{1}, record[:]...)}
	originalPayload := append([]byte(nil), message.Payload...)
	if err = manager.HandleBuildContext(context.Background(), BuildSource{Router: foundation.Hash{8}, Direct: true}, message); err != nil {
		t.Fatal(err)
	}
	forwarded := sender.take()[0].message
	var reply [ShortBuildReplyPlainSize]byte
	if _, err = OpenShortBuildReply(reply[:], forwarded.Payload[1:], keys, 0); err != nil {
		t.Fatal(err)
	}
	mapping, _, err := foundation.ParseMapping(reply[:])
	if err != nil {
		t.Fatal(err)
	}
	it := mapping.Iterator()
	key, value, ok, err := it.Next()
	if err != nil || !ok || string(key) != "b" || string(value) != "64" || reply[len(reply)-1] != 0 {
		t.Fatalf("bandwidth reply = %q=%q ok=%t code=%d err=%v", key, value, ok, reply[len(reply)-1], err)
	}
	installed, exists := runtime.InspectCircuit(request.ReceiveTunnelID)
	if !exists || installed.ExpiresAt != now+600_000 {
		t.Fatalf("transit expiration = %d, installed=%t, want %d", installed.ExpiresAt, exists, now+600_000)
	}
	message.Payload = originalPayload
	if err = manager.HandleBuildContext(context.Background(), BuildSource{Router: nextRouter, Direct: true}, message); !errors.Is(err, ErrBuildRejected) {
		t.Fatalf("predecessor/next loop error = %v", err)
	}
}

func TestBuildManagerRejectsInvalidOptionsCoalescingAndStaticKeyMisuse(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	hop, _ := testShortBuildHop(t, "validation-hop", 401)
	identityKey := hop.StaticKey
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Now: func() uint64 { return now }}), Sender: buildDiscardSender{},
		ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now },
		StaticKeyLookup: func(foundation.Hash) ([32]byte, bool) { return identityKey, true },
	})
	if err != nil {
		t.Fatal(err)
	}
	build := OutboundBuild{CircuitID: 402, Hops: []ShortBuildHop{hop}, ReplyRouter: foundation.Hash{4}, ReplyTunnelID: 403, ExpiresAt: now + 600_000}
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
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Now: func() uint64 { return now }}), Sender: buildDiscardSender{},
		ReplyKeys: newBuildReplyRegistry(), LocalRouter: local, Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	source := BuildSource{Router: foundation.Hash{9}, Direct: true}
	request := ShortBuildRequest{ReceiveTunnelID: 1, NextTunnelID: 2, NextRouter: foundation.Hash{8}, LifetimeSeconds: shortBuildLifetime, NextMessageID: 3}
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
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
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
	legacy := bytes.Repeat([]byte{0x5a}, cryptography.ElGamalPrivateKeySize)
	sender := new(buildCaptureSender)
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return 1 }}),
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
	if !manager.released || manager.staticPrivateKey != nil || manager.legacyEnabled || manager.legacyPrivate != (cryptography.ElGamalPrivateKey{}) || manager.random != nil {
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
