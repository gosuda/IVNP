package tunnel

import (
	"errors"
	"testing"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

func TestRenewalRetryUsesCurrentWindowAfterAnotherRenewalWins(t *testing.T) {
	for _, winnerKind := range []string{"retry", "late reply"} {
		t.Run(winnerKind, func(t *testing.T) {
			now := uint64(1_700_000_000_000)
			const renewalWindow = uint64(100_000)
			pool := NewPool(4)
			manager := schedulingManager(t, nil, buildDiscardSender{}, pool, &now, 2, nil)
			t.Cleanup(func() {
				for _, entry := range pool.Snapshot(0) {
					manager.runtime.RemoveCircuit(entry.Circuit)
				}
			})
			firstOld := installCutoffTunnel(t, manager, pool, 1, now+90_000, now)
			secondOld := installCutoffTunnel(t, manager, pool, 2, now+105_000, now)
			first, err := manager.reserveCreator(Outbound, 2, 2, now, now+renewalWindow)
			if err != nil || first == nil || first.retire.Circuit != firstOld.Circuit {
				t.Fatalf("initial renewal reservation = %v, %v", first, err)
			}
			firstReply := startCutoffBuild(t, manager, first, 10, now)
			now += buildRequestTimeout()
			manager.Expire(now)
			now += 1000
			retry, err := manager.reserveCreator(Outbound, 2, 2, now, now+renewalWindow)
			if err != nil || retry == nil || retry.retire.Circuit != firstOld.Circuit {
				t.Fatalf("retry changed the retirement installation: %v, %v", retry, err)
			}
			retryReply := startCutoffBuild(t, manager, retry, 11, now)
			second, err := manager.reserveCreator(Outbound, 2, 2, now, now+renewalWindow)
			if err != nil || second == nil || second.retire.Circuit != secondOld.Circuit {
				t.Fatalf("newly eligible renewal reservation = %v, %v", second, err)
			}
			secondReply := startCutoffBuild(t, manager, second, 12, now)
			if err := manager.HandleReply(secondReply); err != nil {
				t.Fatalf("second renewal: %v", err)
			}
			winner, loser := retryReply, firstReply
			if winnerKind == "late reply" {
				winner, loser = firstReply, retryReply
			}
			if err := manager.HandleReply(winner); err != nil {
				t.Fatalf("valid renewal rejected after window advanced: %v", err)
			}
			if got := pool.Count(Outbound, now+renewalWindow); got != 2 {
				t.Fatalf("usable renewed tunnels = %d, want two", got)
			}
			if err := manager.HandleReply(loser); !errors.Is(err, ErrBuildPending) {
				t.Fatalf("competing reply installed another renewal: %v", err)
			}
			if got := pool.Count(Outbound, now+renewalWindow); got != 2 {
				t.Fatalf("competing reply changed renewed target count to %d", got)
			}
		})
	}
}

func installCutoffTunnel(t *testing.T, manager *BuildManager, pool *Pool, id uint32, expires, now uint64) Entry {
	t.Helper()
	entry := Entry{ID: id, Direction: Outbound, Expires: expires}
	var err error
	entry.Circuit, err = manager.runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: id, NextTunnelID: id + 100, ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Add(entry, now); err != nil {
		t.Fatal(err)
	}
	return entry
}

func startCutoffBuild(t *testing.T, manager *BuildManager, attempt *creatorAttempt, id uint32, now uint64) foundation.I2NPMessage {
	t.Helper()
	build := rotationBuild(t, id, now+600_000)
	build.attempt, build.retireID = attempt, attempt.retire.ID
	replyID, err := manager.StartOutbound(t.Context(), build)
	if err != nil {
		t.Fatal(err)
	}
	return schedulingAcceptedReply(t, manager.pending[replyID])
}
