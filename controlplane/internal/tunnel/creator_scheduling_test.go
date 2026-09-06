package tunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

type schedulingSender struct {
	buildCaptureSender
	prepare func(context.Context, foundation.Hash) error
}

func (s *schedulingSender) EnsureSession(ctx context.Context, peer foundation.Hash) error {
	if s.prepare != nil {
		return s.prepare(ctx, peer)
	}
	return nil
}

func schedulingManager(t *testing.T, budget *CreatorBudget, sender dataplane.TunnelSender, pool *Pool, now *uint64, capacity int, wake func()) *BuildManager {
	t.Helper()
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return *now }}),
		Pool:    pool, Sender: sender, ReplyKeys: dataplane.GarlicNewReplyKeyRegistry(128),
		LocalRouter: foundation.Hash{99}, LocalDelivery: func(foundation.I2NPMessage) error { return nil },
		Now: func() uint64 { return *now }, Random: &buildXorShiftReader{state: 123},
		MaxPending: capacity, CreatorBudget: budget, OnBuildEvent: wake,
		Schedule: func(time.Duration, func()) func() { return func() {} },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.ReleaseSensitive)
	return manager
}

func awaitScheduling[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case result := <-channel:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("creator scheduling did not reach barrier")
	}
	var zero T
	return zero
}

func TestBootstrapPreparesOverlapAndJoinCanceledSibling(t *testing.T) {
	now := uint64(1_700_000_000_000)
	first, _ := testShortBuildHop(t, "parallel-first", 101)
	last, _ := testShortBuildHop(t, "parallel-last", 102)
	entered := make(chan foundation.Hash, 2)
	fail := make(chan struct{})
	joined := make(chan struct{})
	finish := make(chan struct{})
	failure := errors.New("first transport failed")
	sender := &schedulingSender{prepare: func(ctx context.Context, peer foundation.Hash) error {
		entered <- peer
		if peer == first.Router {
			select {
			case <-fail:
				return failure
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		<-ctx.Done()
		close(joined)
		<-finish
		return ctx.Err()
	}}
	manager := schedulingManager(t, nil, sender, nil, &now, 2, nil)
	manager.profiles = NewPeerProfiles(PeerProfilesConfig{})
	result := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case <-fail:
		default:
			close(fail)
		}
		select {
		case <-finish:
		default:
			close(finish)
		}
	})
	go func() {
		_, err := manager.StartInbound(t.Context(), InboundBuild{CircuitID: 103, Hops: []ShortBuildHop{first, last}, ExpiresAt: now + 600_000})
		result <- err
	}()
	one, two := awaitScheduling(t, entered), awaitScheduling(t, entered)
	if one == two {
		t.Fatal("bootstrap prepared the same peer twice")
	}
	close(fail)
	awaitScheduling(t, joined)
	select {
	case err := <-result:
		t.Fatalf("returned before sibling joined: %v", err)
	default:
	}
	close(finish)
	if err := awaitScheduling(t, result); !errors.Is(err, failure) {
		t.Fatalf("bootstrap failure = %v", err)
	}
	if !manager.profiles.EligibleAt(last.Router, now) || manager.profiles.EligibleAt(first.Router, now) {
		t.Fatal("sibling cancellation was recorded as transport failure")
	}
	if manager.Pending() != 0 || len(sender.take()) != 0 {
		t.Fatal("failed preflight retained or sent a build")
	}
}

func TestCreatorBudgetAdmitsBeforePreflightAndWakesOwnersFIFO(t *testing.T) {
	now := uint64(1_700_000_000_000)
	budget := NewCreatorBudget(1, 3)
	var prepares atomic.Int32
	sender := &schedulingSender{prepare: func(context.Context, foundation.Hash) error { prepares.Add(1); return nil }}
	wakeB, wakeC := make(chan struct{}, 8), make(chan struct{}, 8)
	a := schedulingManager(t, budget, sender, NewPool(2), &now, 1, nil)
	b := schedulingManager(t, budget, sender, NewPool(2), &now, 1, func() {
		select {
		case wakeB <- struct{}{}:
		default:
		}
	})
	c := schedulingManager(t, budget, sender, NewPool(2), &now, 1, func() {
		select {
		case wakeC <- struct{}{}:
		default:
		}
	})
	build := rotationBuild(t, 10, now+600_000)
	rotators := make(map[*BuildManager]*Rotator)
	for _, manager := range []*BuildManager{a, b, c} {
		rotators[manager] = schedulingRotator(t, manager, &rotationSource{builds: []OutboundBuild{build}}, &now, 2)
	}
	id, err := a.StartOutbound(t.Context(), build)
	if err != nil {
		t.Fatal(err)
	}
	for _, manager := range []*BuildManager{a, b, b, c} {
		if _, err := rotators[manager].Maintain(t.Context()); !errors.Is(err, ErrBuildPending) {
			t.Fatalf("saturated admission = %v", err)
		}
	}
	if prepares.Load() != 1 {
		t.Fatalf("saturated owners performed %d preflights", prepares.Load())
	}
	a.removePending(id)
	awaitScheduling(t, wakeB)
	for _, manager := range []*BuildManager{b, c} {
		if _, err := manager.StartOutbound(t.Context(), build); !errors.Is(err, ErrBuildPending) {
			t.Fatalf("direct request bypassed maintained FIFO: %v", err)
		}
	}
	if started, err := rotators[b].Maintain(t.Context()); started != 1 || !errors.Is(err, ErrBuildPending) {
		t.Fatalf("oldest waiter could not proceed: started=%d err=%v", started, err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	awaitScheduling(t, wakeC)
	if started, err := rotators[c].Maintain(t.Context()); started != 1 || !errors.Is(err, ErrBuildPending) {
		t.Fatalf("permit leaked on Close: started=%d err=%v", started, err)
	}
	if _, err := rotators[a].Maintain(t.Context()); !errors.Is(err, ErrBuildPending) {
		t.Fatal("expected queued owner")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.active != 0 || len(budget.waiters) != 0 || len(budget.owners) != 0 {
		t.Fatalf("shutdown retained active=%d waiters=%d owners=%d", budget.active, len(budget.waiters), len(budget.owners))
	}
}

func TestPairedMaintainerOverlapsTwoBuildsPerDirection(t *testing.T) {
	now := uint64(1_700_000_000_000)
	entered := make(chan foundation.Hash, 4)
	release := make(chan struct{})
	sender := &schedulingSender{prepare: func(ctx context.Context, peer foundation.Hash) error {
		entered <- peer
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	pool := NewPool(8)
	manager := schedulingManager(t, nil, sender, pool, &now, 4, nil)
	carrierPeer := foundation.Hash{88}
	carrier, err := manager.runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 1, FirstHop: carrierPeer, NextTunnelID: 2, ExpiresAt: now + 600_000})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []Entry{
		{ID: 1, Circuit: carrier, Direction: Outbound, Expires: now + 600_000, HopCount: 1, Hops: [foundation.I2NPMaxVariableBuildRecords]foundation.Hash{carrierPeer}},
		{ID: 2, Direction: Inbound, Expires: now + 600_000, Gateway: foundation.Hash{77}, GatewayTunnelID: 3},
	} {
		if err := pool.Add(entry, now); err != nil {
			t.Fatal(err)
		}
	}
	inbound := &pairedInboundSource{builds: []InboundBuild{pairedInboundBuild(t, 10, now+600_000), pairedInboundBuild(t, 11, now+600_000)}}
	outbound := &pairedOutboundSource{builds: []OutboundBuild{rotationBuild(t, 20, now+600_000), rotationBuild(t, 21, now+600_000)}}
	maintainer, err := NewPairedPoolMaintainer(PairedPoolMaintainerConfig{Pool: pool, Runtime: manager.runtime, Builder: manager, InboundSource: inbound, OutboundSource: outbound, Now: func() uint64 { return now }, InboundTarget: 3, OutboundTarget: 3})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = maintainer.Close() })
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	results := make(chan int, 1)
	failures := make(chan error, 1)
	go func() { count, err := maintainer.Maintain(t.Context()); results <- count; failures <- err }()
	for range 4 {
		awaitScheduling(t, entered)
	}
	if manager.PendingDirection(Inbound) != 2 || manager.PendingDirection(Outbound) != 2 {
		t.Fatal("preparing builds were not direction-bounded")
	}
	if count, err := maintainer.Maintain(t.Context()); count != 0 || err != nil {
		t.Fatalf("concurrent maintenance double-claimed work: %d %v", count, err)
	}
	close(release)
	if count, err := awaitScheduling(t, results), awaitScheduling(t, failures); count != 4 || err != nil {
		t.Fatalf("parallel batch = %d %v", count, err)
	}
	if count, err := maintainer.Maintain(t.Context()); count != 0 || err != nil {
		t.Fatalf("pending target was oversubscribed: %d %v", count, err)
	}
}

func TestRenewalClaimsRetryDuringGraceWithoutDoubleInstallation(t *testing.T) {
	for _, lateWins := range []bool{true, false} {
		t.Run(map[bool]string{true: "late_wins", false: "retry_wins"}[lateWins], func(t *testing.T) {
			now := uint64(1_700_000_000_000)
			pool := NewPool(2)
			manager := schedulingManager(t, nil, buildDiscardSender{}, pool, &now, 2, nil)
			old := Entry{ID: 1, Direction: Outbound, Expires: now + 100_000}
			if err := pool.Add(old, now); err != nil {
				t.Fatal(err)
			}
			first, err := manager.reserveCreator(Outbound, 1, 2, now, now+100_000)
			if err != nil || first == nil {
				t.Fatalf("initial reserve = %v", err)
			}
			if duplicate, err := manager.reserveCreator(Outbound, 1, 2, now, now+100_000); duplicate != nil || err != nil {
				t.Fatal("reserved one renewal twice")
			}
			build := rotationBuild(t, 10, now+600_000)
			build.attempt, build.retireID = first, first.retire.ID
			firstID, err := manager.StartOutbound(t.Context(), build)
			if err != nil {
				t.Fatal(err)
			}
			firstReply := schedulingAcceptedReply(t, manager.pending[firstID])
			now += buildRequestTimeout()
			manager.Expire(now)
			if manager.Pending() != 0 {
				t.Fatal("grace held the active permit")
			}
			retry, err := manager.reserveCreator(Outbound, 1, 2, now, now+100_000)
			if err != nil || retry == nil {
				t.Fatalf("grace blocked retry: %v", err)
			}
			build = rotationBuild(t, 11, now+600_000)
			build.attempt, build.retireID = retry, retry.retire.ID
			retryID, err := manager.StartOutbound(t.Context(), build)
			if err != nil {
				t.Fatal(err)
			}
			retryReply := schedulingAcceptedReply(t, manager.pending[retryID])
			winner, loser := firstReply, retryReply
			if !lateWins {
				winner, loser = retryReply, firstReply
			}
			if err := manager.HandleReply(winner); err != nil {
				t.Fatalf("winning reply: %v", err)
			}
			if err := manager.HandleReply(loser); !errors.Is(err, ErrBuildPending) {
				t.Fatalf("losing reply installed a second circuit: %v", err)
			}
			if pool.Count(Outbound, now+100_000) != 1 {
				t.Fatal("late/retry race overfilled target")
			}
			losingCircuit := uint32(11)
			if !lateWins {
				losingCircuit = 10
			}
			if _, exists := manager.runtime.InspectCircuit(losingCircuit); exists {
				t.Fatal("rejected late circuit remained installed")
			}
			now += buildReplyGracePeriod
			manager.Expire(now)
			if manager.Pending() != 0 {
				t.Fatal("grace cleanup retained admission")
			}
		})
	}
}

func TestRenewalClaimDoesNotRetireReusedCircuitID(t *testing.T) {
	now := uint64(100)
	pool := NewPool(1)
	manager := schedulingManager(t, nil, buildDiscardSender{}, pool, &now, 1, nil)
	old := Entry{ID: 1, Direction: Outbound, Expires: 200}
	var err error
	old.Circuit, err = manager.runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 1, NextTunnelID: 9, ExpiresAt: 200})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Add(old, now); err != nil {
		t.Fatal(err)
	}
	attempt, err := manager.reserveCreator(Outbound, 1, 2, now, 200)
	if err != nil || attempt == nil {
		t.Fatalf("reserve = %v", err)
	}
	defer attempt.finish()
	pool.Remove(old)
	manager.runtime.RemoveCircuit(old.Circuit)
	newer := old
	newer.Circuit, err = manager.runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 1, NextTunnelID: 10, ExpiresAt: 200})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Add(newer, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.installCreatorEntry(Entry{ID: 2, Direction: Outbound, Expires: 300}, attempt, old.ID, now); !errors.Is(err, ErrBuildPending) {
		t.Fatalf("stale retirement succeeded: %v", err)
	}
	if current, ok := pool.Get(1, now); !ok || current != newer {
		t.Fatal("stale claim removed newer installation")
	}
}

func schedulingAcceptedReply(t *testing.T, pending *pendingOutboundBuild) foundation.I2NPMessage {
	t.Helper()
	if len(pending.keys) != 1 {
		t.Fatal("reply fixture requires one hop")
	}
	payload := make([]byte, 1+int(pending.recordCount)*ShortBuildRecordSize)
	payload[0] = pending.recordCount
	offset := 1 + int(pending.positions[0])*ShortBuildRecordSize
	if _, err := SealShortBuildReply(payload[offset:offset+ShortBuildRecordSize], make([]byte, ShortBuildReplyPlainSize), pending.keys[0], pending.positions[0]); err != nil {
		t.Fatal(err)
	}
	return foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPOutboundTunnelBuildReply, ID: pending.replyID}, Payload: payload}
}
