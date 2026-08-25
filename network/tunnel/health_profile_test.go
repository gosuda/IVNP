package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	ivnp "gosuda.org/ivnp"
	"gosuda.org/ivnp/protocol/i2np"
)

func TestPeerProfilesBoundHistoryAndScoreDeterministically(t *testing.T) {
	profiles := NewPeerProfiles(PeerProfilesConfig{MaxPeers: 2, Window: 2})
	var peer ivnp.Hash
	peer[0] = 1
	profiles.RecordSuccess(peer, 30)
	profiles.RecordFailure(peer)
	profiles.RecordSuccess(peer, 10)
	profile, ok := profiles.Snapshot(peer)
	if !ok || profile.Samples != 2 || profile.Successes != 1 || profile.Failures != 1 || profile.MeanLatency != 10 {
		t.Fatalf("profile = %#v, %t", profile, ok)
	}
	if !profiles.Eligible(peer) || profiles.Score(peer) != -10_010 {
		t.Fatalf("eligibility=%t score=%d", profiles.Eligible(peer), profiles.Score(peer))
	}
	profiles.RecordFailure(peer)
	profiles.RecordFailure(peer)
	if profiles.Eligible(peer) {
		t.Fatal("failure-majority peer remained eligible")
	}
}

func TestPeerProfilesPreserveAuthenticatedBuildCompatibilityAcrossAmbiguousDeliveryLoss(t *testing.T) {
	profiles := NewPeerProfiles(PeerProfilesConfig{Window: 8})
	peer := ivnp.Hash{1}
	profiles.Record(peer, Observation{Kind: BuildObservation, Success: true})
	for range 4 {
		profiles.Record(peer, Observation{Kind: DeliveryObservation})
	}
	if !profiles.Eligible(peer) {
		t.Fatal("delivery loss over a multi-peer path overrode authenticated build compatibility")
	}
	profiles.Record(peer, Observation{Kind: BuildObservation})
	if !profiles.Eligible(peer) {
		t.Fatal("one build failure excluded a peer with one authenticated build success")
	}
	profiles.Record(peer, Observation{Kind: BuildObservation})
	if profiles.Eligible(peer) {
		t.Fatal("authenticated build failure majority remained eligible")
	}
}

func TestHealthProbeCorrelatesStatusAndExpiresFailures(t *testing.T) {
	now := uint64(1_000)
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	pool := NewPool(2)
	if err := runtime.RegisterOutbound(OutboundCircuit{ID: 1, FirstHop: ivnp.Hash{9}, NextTunnelID: 2, ExpiresAt: now + 1_000}); err != nil {
		t.Fatal(err)
	}
	if err := pool.Add(Entry{ID: 1, Direction: Outbound, Expires: now + 1_000}, now); err != nil {
		t.Fatal(err)
	}
	builder, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: sender, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	source := &rotationSource{err: errRotationSource}
	rotator, err := NewRotator(RotatorConfig{Pool: pool, Runtime: runtime, Builder: builder, Source: source, Now: func() uint64 { return now }, Target: 1})
	if err != nil {
		t.Fatal(err)
	}
	profiles := NewPeerProfiles(PeerProfilesConfig{Window: 4})
	health, err := NewHealth(HealthConfig{Runtime: runtime, Pool: pool, Maintainer: rotator, Profiles: profiles, Now: func() uint64 { return now }, Timeout: 10, MaxPending: 2, FailureThreshold: 1})
	if err != nil {
		t.Fatal(err)
	}
	peer := ivnp.Hash{7}
	pair := CircuitPair{OutboundID: 1, InboundID: 3, ReplyRouter: ivnp.Hash{8}}
	id, err := health.Probe(context.Background(), pair, peer)
	if err != nil || id == 0 || health.Pending() != 1 {
		t.Fatalf("Probe() = %d, %v; pending=%d", id, err, health.Pending())
	}
	if sent := sender.take(); len(sent) != 1 || sent[0].message.Header.Type != i2np.TunnelData {
		t.Fatalf("probe delivery = %#v", sent)
	}
	now += 4
	if !health.HandleDeliveryStatus(i2np.DeliveryStatusMessage{MessageID: id, Timestamp: 1_000}) || health.Pending() != 0 {
		t.Fatalf("matching status rejected; pending=%d", health.Pending())
	}
	if profile, ok := profiles.Snapshot(peer); !ok || profile.Successes != 1 || profile.MeanLatency != 4 {
		t.Fatalf("success profile = %#v, %t", profile, ok)
	}
	if _, err = health.Probe(context.Background(), pair, peer); err != nil {
		t.Fatal(err)
	}
	now += 10
	if expired, expireErr := health.Expire(context.Background()); expired != 1 || !errors.Is(expireErr, errRotationSource) {
		t.Fatalf("Expire() = %d, %v", expired, expireErr)
	}
	if _, ok := pool.Get(1, now); !ok || source.calls != 1 {
		t.Fatalf("failed replacement retained tunnel=%t replacement calls=%d", ok, source.calls)
	}
	if owner, ok := runtime.CircuitOwner(1); !ok || owner != (ivnp.Hash{}) {
		t.Fatalf("failed replacement removed runtime circuit: owner=%x present=%t", owner, ok)
	}
	if profile, ok := profiles.Snapshot(peer); !ok || profile.Failures != 1 {
		t.Fatalf("failure profile = %#v, %t", profile, ok)
	}
	if err = health.Close(); err != nil {
		t.Fatal(err)
	}
	if health.Pending() != 0 {
		t.Fatalf("pending after Close = %d", health.Pending())
	}
	if _, err = health.Probe(context.Background(), pair, peer); !errors.Is(err, ErrHealthClosed) {
		t.Fatalf("Probe after Close = %v", err)
	}
	if health.HandleDeliveryStatus(i2np.DeliveryStatusMessage{MessageID: id, Timestamp: 1_000}) {
		t.Fatal("closed health checker accepted status")
	}
}

func TestHealthExpiryPreservesCircuitWithBidirectionalTraffic(t *testing.T) {
	now := uint64(1_000)
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	owner := ivnp.Hash{1}
	pool := NewOwnedPool(owner, 2)
	if err := runtime.RegisterOutbound(OutboundCircuit{ID: 1, Owner: owner, FirstHop: ivnp.Hash{9}, NextTunnelID: 3, ExpiresAt: now + 1_000}); err != nil {
		t.Fatal(err)
	}
	delivered := 0
	if err := runtime.RegisterInbound(InboundCircuit{
		ID: 3, Owner: owner, Endpoint: NewEndpoint(8, 4096), ExpiresAt: now + 1_000,
		Local: func(i2np.Message) error {
			delivered++
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := pool.Add(Entry{ID: 1, Owner: owner, Direction: Outbound, Expires: now + 1_000}, now); err != nil {
		t.Fatal(err)
	}
	builder, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: sender, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	source := &rotationSource{err: errRotationSource}
	rotator, err := NewRotator(RotatorConfig{Pool: pool, Runtime: runtime, Builder: builder, Source: source, Now: func() uint64 { return now }, Target: 1})
	if err != nil {
		t.Fatal(err)
	}
	health, err := NewHealth(HealthConfig{
		Runtime: runtime, Pool: pool, Maintainer: rotator, Profiles: NewPeerProfiles(PeerProfilesConfig{Window: 4}),
		Now: func() uint64 { return now }, Timeout: 10, MaxPending: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = health.Close() })

	pair := CircuitPair{OutboundID: 1, InboundID: 700, InboundLocalID: 3, ReplyRouter: ivnp.Hash{8}}
	if _, err = health.Probe(context.Background(), pair, ivnp.Hash{7}); !errors.Is(err, ErrProbeNotReady) {
		t.Fatalf("Probe before traffic = %v, want %v", err, ErrProbeNotReady)
	}
	sendTraffic := func(messageID uint32) {
		t.Helper()
		if sendErr := runtime.SendBlock(context.Background(), 1, Block{Delivery: DeliveryLocal, Last: true, Data: deliveryStatusFrame(t, messageID)}); sendErr != nil {
			t.Fatal(sendErr)
		}
		sent := sender.take()
		if len(sent) != 1 {
			t.Fatalf("application messages = %d, want 1", len(sent))
		}
		if handleErr := runtime.Handle(sent[0].message); handleErr != nil {
			t.Fatal(handleErr)
		}
	}
	sendTraffic(98)
	if _, err = health.Probe(context.Background(), pair, ivnp.Hash{7}); err != nil {
		t.Fatal(err)
	}
	if sent := sender.take(); len(sent) != 1 {
		t.Fatalf("health probe messages = %d, want 1", len(sent))
	}
	sendTraffic(99)
	if delivered != 2 {
		t.Fatalf("locally delivered messages = %d, want 2", delivered)
	}

	now += 10
	if expired, expireErr := health.Expire(context.Background()); expired != 1 || expireErr != nil {
		t.Fatalf("Expire() = %d, %v", expired, expireErr)
	}
	if _, ok := pool.Get(1, now); !ok {
		t.Fatal("health timeout removed a circuit carrying bidirectional traffic")
	}
	if _, ok := runtime.CircuitOwner(1); !ok {
		t.Fatal("health timeout removed the active runtime circuit")
	}
	if source.calls != 0 {
		t.Fatalf("replacement builds = %d, want 0", source.calls)
	}
}

func TestHealthCloseCancelsAndJoinsActiveProbe(t *testing.T) {
	const now = uint64(1_000)
	sender := &cancelingBuildSender{entered: make(chan struct{})}
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	pool := NewPool(2)
	if err := runtime.RegisterOutbound(OutboundCircuit{ID: 1, FirstHop: ivnp.Hash{9}, NextTunnelID: 2, ExpiresAt: now + 1_000}); err != nil {
		t.Fatal(err)
	}
	if err := pool.Add(Entry{ID: 1, Direction: Outbound, Expires: now + 1_000}, now); err != nil {
		t.Fatal(err)
	}
	builder, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: sender, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.ReleaseSensitive()
	rotator, err := NewRotator(RotatorConfig{Pool: pool, Runtime: runtime, Builder: builder, Source: &rotationSource{err: errRotationSource}, Now: func() uint64 { return now }, Target: 1})
	if err != nil {
		t.Fatal(err)
	}
	health, err := NewHealth(HealthConfig{
		Runtime: runtime, Pool: pool, Maintainer: rotator, Profiles: NewPeerProfiles(PeerProfilesConfig{}),
		Now: func() uint64 { return now }, Timeout: 100, MaxPending: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	probed := make(chan error, 1)
	go func() {
		_, probeErr := health.Probe(context.Background(), CircuitPair{OutboundID: 1, InboundID: 3, ReplyRouter: ivnp.Hash{8}}, ivnp.Hash{7})
		probed <- probeErr
	}()
	select {
	case <-sender.entered:
	case <-time.After(time.Second):
		t.Fatal("probe sender did not enter")
	}
	if err = health.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-probed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("active probe result = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join active probe")
	}
	if health.Pending() != 0 {
		t.Fatalf("pending probes after Close = %d", health.Pending())
	}
}

func TestDestinationHealthStateAndRotationAreIndependent(t *testing.T) {
	now := uint64(2_000)
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	type healthOwner struct {
		pool     *Pool
		profiles *PeerProfiles
		health   *Health
		source   *rotationSource
	}
	newOwner := func(owner ivnp.Hash, circuitID uint32) healthOwner {
		pool := NewOwnedPool(owner, 2)
		if err := runtime.RegisterOutbound(OutboundCircuit{ID: circuitID, Owner: owner, FirstHop: ivnp.Hash{9}, NextTunnelID: circuitID + 10, ExpiresAt: now + 1_000}); err != nil {
			t.Fatal(err)
		}
		if err := pool.Add(Entry{ID: circuitID, Owner: owner, Direction: Outbound, Expires: now + 1_000}, now); err != nil {
			t.Fatal(err)
		}
		builder, err := NewBuildManager(BuildManagerConfig{
			Runtime: runtime, Pool: pool, Sender: sender, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now }, Random: new(buildCounterReader),
		})
		if err != nil {
			t.Fatal(err)
		}
		source := &rotationSource{err: errRotationSource}
		rotator, err := NewRotator(RotatorConfig{Pool: pool, Runtime: runtime, Builder: builder, Source: source, Now: func() uint64 { return now }, Target: 1})
		if err != nil {
			t.Fatal(err)
		}
		profiles := NewPeerProfiles(PeerProfilesConfig{Window: 4})
		health, err := NewHealth(HealthConfig{Runtime: runtime, Pool: pool, Maintainer: rotator, Profiles: profiles, Now: func() uint64 { return now }, Timeout: 10, MaxPending: 2, FailureThreshold: 1, ProbeBeforeActivity: true})
		if err != nil {
			t.Fatal(err)
		}
		return healthOwner{pool: pool, profiles: profiles, health: health, source: source}
	}
	first := newOwner(ivnp.Hash{1}, 1)
	second := newOwner(ivnp.Hash{2}, 2)
	firstPeer, secondPeer := ivnp.Hash{11}, ivnp.Hash{12}
	firstID, err := first.health.Probe(context.Background(), CircuitPair{OutboundID: 1, InboundID: 21, ReplyRouter: ivnp.Hash{31}}, firstPeer)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := second.health.Probe(context.Background(), CircuitPair{OutboundID: 2, InboundID: 22, ReplyRouter: ivnp.Hash{32}}, secondPeer)
	if err != nil {
		t.Fatal(err)
	}
	if firstID == secondID {
		t.Fatalf("destination probes shared correlation ID %d", firstID)
	}
	now += 4
	status := i2np.DeliveryStatusMessage{MessageID: firstID, Timestamp: 2_000}
	if !first.health.HandleDeliveryStatus(status) || second.health.HandleDeliveryStatus(status) {
		t.Fatal("one destination's delivery result changed its sibling")
	}
	if profile, ok := first.profiles.Snapshot(firstPeer); !ok || profile.Successes != 1 || profile.MeanLatency != 4 {
		t.Fatalf("first profile = %#v, %t", profile, ok)
	}
	if _, ok := second.profiles.Snapshot(firstPeer); ok {
		t.Fatal("first destination peer leaked into sibling profiles")
	}
	now += 6
	if expired, expireErr := second.health.Expire(context.Background()); expired != 1 || !errors.Is(expireErr, errRotationSource) {
		t.Fatalf("second expiration = %d, %v", expired, expireErr)
	}
	if _, ok := first.pool.Get(1, now); !ok || first.source.calls != 0 {
		t.Fatal("second destination rotation touched first destination pool")
	}
	if _, ok := second.pool.Get(2, now); !ok || second.source.calls != 1 {
		t.Fatal("failed destination replacement did not retain its last circuit")
	}
	if owner, ok := runtime.CircuitOwner(2); !ok || owner != (ivnp.Hash{2}) {
		t.Fatal("failed destination replacement removed its runtime circuit")
	}
	if profile, ok := second.profiles.Snapshot(secondPeer); !ok || profile.Failures != 1 {
		t.Fatalf("second failure profile = %#v, %t", profile, ok)
	}
}
