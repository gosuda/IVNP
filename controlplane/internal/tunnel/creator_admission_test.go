package tunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

func schedulingRotator(t *testing.T, manager *BuildManager, source OutboundBuildSource, now *uint64, target int) *Rotator {
	t.Helper()
	rotator, err := NewRotator(RotatorConfig{Pool: manager.pool, Runtime: manager.runtime, Builder: manager, Source: source, Now: func() uint64 { return *now }, Target: target})
	if err != nil {
		t.Fatal(err)
	}
	return rotator
}

func TestDirectCreatorAdmissionDoesNotRetainAbandonedWaiters(t *testing.T) {
	for _, kind := range []string{"outbound", "inbound", "variable"} {
		t.Run(kind, func(t *testing.T) {
			now := uint64(1_700_000_000_000)
			budget := NewCreatorBudget(1, 3)
			sender := new(schedulingSender)
			holder := schedulingManager(t, budget, sender, nil, &now, 1, nil)
			abandoned := schedulingManager(t, budget, sender, nil, &now, 1, nil)
			other := schedulingManager(t, budget, sender, nil, &now, 1, nil)
			build := rotationBuild(t, 10, now+600_000)
			start := func(ctx context.Context, manager *BuildManager) (uint32, error) {
				switch kind {
				case "inbound":
					return manager.StartInbound(ctx, InboundBuild{CircuitID: build.CircuitID, Hops: build.Hops, ExpiresAt: build.ExpiresAt})
				case "variable":
					hop := build.Hops[0]
					return manager.StartVariableOutbound(ctx, VariableOutboundBuild{CircuitID: build.CircuitID, Hops: []VariableBuildHop{{Router: hop.Router, Kind: VariableBuildLongECIES, StaticKey: hop.StaticKey, ReceiveTunnelID: hop.ReceiveTunnelID}}, ReplyRouter: build.ReplyRouter, ReplyTunnelID: build.ReplyTunnelID, ExpiresAt: build.ExpiresAt})
				default:
					return manager.StartOutbound(ctx, build)
				}
			}
			id, err := holder.StartOutbound(t.Context(), build)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if _, err := start(ctx, abandoned); !errors.Is(err, ErrBuildPending) {
				t.Fatalf("saturated direct request = %v", err)
			}
			cancel()
			if _, err := start(ctx, abandoned); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled direct request = %v", err)
			}
			holder.removePending(id)
			otherID, err := other.StartOutbound(t.Context(), build)
			if err != nil {
				t.Fatalf("abandoned direct request blocked another owner: %v", err)
			}
			other.removePending(otherID)
			if _, err := start(t.Context(), abandoned); err != nil {
				t.Fatalf("failed direct request left manager unusable: %v", err)
			}
		})
	}
}

type schedulingInboundSource func(context.Context, uint64, uint32) (InboundBuild, error)

func (s schedulingInboundSource) NextInbound(ctx context.Context, now uint64, carrier uint32) (InboundBuild, error) {
	return s(ctx, now, carrier)
}

func TestPairedPreparationFailureReleasesObsoleteWaiters(t *testing.T) {
	for _, failure := range []string{"source", "config", "preflight", "source_with_active_sibling"} {
		t.Run(failure, func(t *testing.T) {
			now := uint64(1_700_000_000_000)
			capacity, outboundTarget, wantPending := 2, 1, 0
			if failure == "source_with_active_sibling" {
				capacity, outboundTarget, wantPending = 3, 2, 1
			}
			budget := NewCreatorBudget(capacity, 3)
			var selfWakes, otherWakes atomic.Int32
			sender := new(schedulingSender)
			if failure == "preflight" {
				sender.prepare = func(context.Context, foundation.Hash) error { return ErrNoEligiblePeers }
			}
			manager := schedulingManager(t, budget, sender, NewPool(8), &now, 4, func() { selfWakes.Add(1) })
			holder := schedulingManager(t, budget, new(schedulingSender), nil, &now, 1, nil)
			other := schedulingManager(t, budget, new(schedulingSender), NewPool(2), &now, 1, func() { otherWakes.Add(1) })
			if _, err := holder.StartOutbound(t.Context(), rotationBuild(t, 30, now+600_000)); err != nil {
				t.Fatal(err)
			}
			carrierPeer := foundation.Hash{88}
			carrier, err := manager.runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 1, FirstHop: carrierPeer, NextTunnelID: 2, ExpiresAt: now + 600_000})
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range []Entry{
				{ID: 1, Circuit: carrier, Direction: Outbound, Expires: now + 600_000, HopCount: 1, Hops: [foundation.I2NPMaxVariableBuildRecords]foundation.Hash{carrierPeer}},
				{ID: 2, Direction: Inbound, Expires: now + 600_000, Gateway: foundation.Hash{77}, GatewayTunnelID: 3},
			} {
				if err := manager.pool.Add(entry, now); err != nil {
					t.Fatal(err)
				}
			}
			otherRotator := schedulingRotator(t, other, &rotationSource{builds: []OutboundBuild{rotationBuild(t, 40, now+600_000)}}, &now, 1)
			validBuild := pairedInboundBuild(t, 10, now+600_000)
			calls := 0
			source := schedulingInboundSource(func(ctx context.Context, _ uint64, carrier uint32) (InboundBuild, error) {
				calls++
				if calls == 1 {
					if _, err := otherRotator.Maintain(ctx); !errors.Is(err, ErrBuildPending) {
						t.Errorf("queue other owner = %v", err)
					}
				}
				if failure == "source" || failure == "source_with_active_sibling" && calls == 1 {
					return InboundBuild{}, ErrNoEligiblePeers
				}
				if failure == "config" {
					return InboundBuild{}, nil
				}
				build := validBuild
				build.OutboundTunnelID = carrier
				return build, nil
			})
			maintainer, err := NewPairedPoolMaintainer(PairedPoolMaintainerConfig{Pool: manager.pool, Runtime: manager.runtime, Builder: manager, InboundSource: source, OutboundSource: new(pairedOutboundSource), Now: func() uint64 { return now }, InboundTarget: 3, OutboundTarget: outboundTarget})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = maintainer.Close() })
			started, err := maintainer.Maintain(t.Context())
			wantErr := ErrNoEligiblePeers
			if failure == "config" {
				wantErr = ErrBuildConfig
			}
			if started != wantPending || !errors.Is(err, wantErr) || !errors.Is(err, ErrBuildPending) {
				t.Fatalf("partial batch = started %d err %v", started, err)
			}
			// Transport failure deliberately requests another policy attempt;
			// source/configuration failure must not self-wake through admission.
			if got := selfWakes.Load(); failure != "preflight" && got != 0 {
				t.Fatalf("failed preparation immediately rescheduled itself %d times", got)
			}
			if otherWakes.Load() == 0 {
				t.Fatal("failed preparation did not wake the next owner")
			}
			if got := manager.Pending(); got != wantPending {
				t.Fatalf("failure disturbed sibling work: pending=%d want=%d", got, wantPending)
			}
			if started, err := otherRotator.Maintain(t.Context()); started != 1 || err != nil {
				t.Fatalf("released preparation permit unavailable to next owner: started=%d err=%v", started, err)
			}
		})
	}
}

func TestMaintainedOutboundPreparationCancelsWaitBeforeDeferredRelease(t *testing.T) {
	for _, kind := range []string{"short", "variable"} {
		t.Run(kind, func(t *testing.T) {
			now := uint64(1_700_000_000_000)
			budget := NewCreatorBudget(2, 2)
			var wakes atomic.Int32
			manager := schedulingManager(t, budget, new(schedulingSender), NewPool(4), &now, 2, func() { wakes.Add(1) })
			holder := schedulingManager(t, budget, new(schedulingSender), nil, &now, 1, nil)
			if _, err := holder.StartOutbound(t.Context(), rotationBuild(t, 30, now+600_000)); err != nil {
				t.Fatal(err)
			}
			attempt, err := manager.reserveCreator(Outbound, 2, 2, now, now)
			if err != nil || attempt == nil {
				t.Fatalf("first maintained reservation = %v, %v", attempt, err)
			}
			if _, err := manager.reserveCreator(Outbound, 2, 2, now, now); !errors.Is(err, ErrBuildPending) {
				t.Fatalf("second maintained reservation = %v", err)
			}
			if kind == "variable" {
				_, err = manager.StartVariableOutbound(t.Context(), VariableOutboundBuild{attempt: attempt})
			} else {
				_, err = manager.StartOutbound(t.Context(), OutboundBuild{attempt: attempt})
			}
			if !errors.Is(err, ErrBuildConfig) {
				t.Fatalf("invalid maintained build = %v", err)
			}
			if wakes.Load() != 0 {
				t.Fatal("Start deferred cleanup woke obsolete maintenance work")
			}
			if manager.Pending() != 0 {
				t.Fatal("failed preparation retained its permit")
			}
			if _, err := manager.StartOutbound(t.Context(), rotationBuild(t, 40, now+600_000)); err != nil {
				t.Fatalf("failed maintained preparation blocked subsequent direct build: %v", err)
			}
		})
	}
}

func TestRotatorCanceledWaitDoesNotBlockNextOwner(t *testing.T) {
	now := uint64(1_700_000_000_000)
	budget := NewCreatorBudget(1, 3)
	sender := new(schedulingSender)
	holder := schedulingManager(t, budget, sender, nil, &now, 1, nil)
	canceled := schedulingManager(t, budget, sender, NewPool(2), &now, 1, nil)
	other := schedulingManager(t, budget, sender, NewPool(2), &now, 1, nil)
	build := rotationBuild(t, 10, now+600_000)
	id, err := holder.StartOutbound(t.Context(), build)
	if err != nil {
		t.Fatal(err)
	}
	first := schedulingRotator(t, canceled, &rotationSource{builds: []OutboundBuild{build}}, &now, 1)
	next := schedulingRotator(t, other, &rotationSource{builds: []OutboundBuild{build}}, &now, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if _, err := first.Maintain(ctx); !errors.Is(err, ErrBuildPending) {
		t.Fatalf("first owner waiting = %v", err)
	}
	if _, err := next.Maintain(t.Context()); !errors.Is(err, ErrBuildPending) {
		t.Fatalf("next owner waiting = %v", err)
	}
	cancel()
	if _, err := first.Maintain(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceling first owner's wait = %v", err)
	}
	holder.removePending(id)
	if started, err := next.Maintain(t.Context()); started != 1 || err != nil {
		t.Fatalf("canceled owner stranded its FIFO successor: started=%d err=%v", started, err)
	}
}
