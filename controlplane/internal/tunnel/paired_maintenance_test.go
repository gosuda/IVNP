package tunnel

import (
	"context"
	"testing"
	"time"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

type pairedInboundSource struct {
	builds   []InboundBuild
	carriers []uint32
}

func (s *pairedInboundSource) NextInbound(ctx context.Context, _ uint64, carrier uint32) (InboundBuild, error) {
	if err := ctx.Err(); err != nil {
		return InboundBuild{}, err
	}
	if len(s.builds) == 0 {
		return InboundBuild{}, errRotationSource
	}
	build := s.builds[0]
	s.builds = s.builds[1:]
	build.OutboundTunnelID = carrier
	s.carriers = append(s.carriers, carrier)
	return build, nil
}

type pairedOutboundSource struct {
	builds []OutboundBuild
	routes []ReplyRoute
}

func (s *pairedOutboundSource) NextOutboundForReply(ctx context.Context, _ uint64, route ReplyRoute) (OutboundBuild, error) {
	if err := ctx.Err(); err != nil {
		return OutboundBuild{}, err
	}
	if len(s.builds) == 0 {
		return OutboundBuild{}, errRotationSource
	}
	build := s.builds[0]
	s.builds = s.builds[1:]
	build.ReplyRouter = route.Gateway
	build.ReplyTunnelID = route.TunnelID
	s.routes = append(s.routes, route)
	return build, nil
}

type cancelingPairedInboundSource struct {
	entered chan struct{}
}

func (s *cancelingPairedInboundSource) NextInbound(ctx context.Context, _ uint64, _ uint32) (InboundBuild, error) {
	close(s.entered)
	<-ctx.Done()
	return InboundBuild{}, ctx.Err()
}

func pairedInboundBuild(t *testing.T, id uint32, expires uint64) InboundBuild {
	t.Helper()
	hop := rotationBuild(t, id, expires).Hops[0]
	return InboundBuild{CircuitID: id, Hops: []ShortBuildHop{hop}, ExpiresAt: expires}
}

func discardPairedPending(manager *BuildManager) {
	manager.mu.Lock()
	inbound := make([]uint32, 0, len(manager.pendingInbound))
	for id := range manager.pendingInbound {
		inbound = append(inbound, id)
	}
	outbound := make([]uint32, 0, len(manager.pending))
	for id := range manager.pending {
		outbound = append(outbound, id)
	}
	manager.mu.Unlock()
	for _, id := range inbound {
		manager.removeInboundPending(id)
	}
	for _, id := range outbound {
		manager.removePending(id)
	}
}

func newPairedMaintainer(t *testing.T, now uint64, target int, renewBefore uint64, inbound *pairedInboundSource, outbound *pairedOutboundSource) (*PairedPoolMaintainer, *Pool, *dataplane.TunnelRuntime, *BuildManager, *buildCaptureSender) {
	t.Helper()
	sender := new(buildCaptureSender)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	pool := NewPool(8)
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: sender, ReplyKeys: newBuildReplyRegistry(),
		LocalRouter: foundation.Hash{1}, LocalDelivery: func(foundation.I2NPMessage) error { return nil },
		Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	maintainer, err := NewPairedPoolMaintainer(PairedPoolMaintainerConfig{
		Pool: pool, Runtime: runtime, Builder: manager, InboundSource: inbound, OutboundSource: outbound,
		Now: func() uint64 { return now }, InboundTarget: target, OutboundTarget: target, RenewBefore: renewBefore,
	})
	if err != nil {
		t.Fatal(err)
	}
	return maintainer, pool, runtime, manager, sender
}

func TestPairedMaintainerBootstrapsOnceThenUsesEstablishedCarrier(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	inboundSource := &pairedInboundSource{builds: []InboundBuild{
		pairedInboundBuild(t, 101, now+10_000),
		pairedInboundBuild(t, 102, now+10_000),
	}}
	outboundSource := &pairedOutboundSource{builds: []OutboundBuild{rotationBuild(t, 201, now+10_000), rotationBuild(t, 202, now+10_000)}}
	maintainer, pool, runtime, manager, sender := newPairedMaintainer(t, now, 2, 0, inboundSource, outboundSource)
	bootstrapHop := inboundSource.builds[0].Hops[0].Router

	if started, err := maintainer.Maintain(context.Background()); err != nil || started != 1 {
		t.Fatalf("bootstrap started=%d err=%v", started, err)
	}
	if got := inboundSource.carriers; len(got) != 1 || got[0] != 0 {
		t.Fatalf("bootstrap carriers=%v, want [0]", got)
	}
	bootstrapMessages := sender.take()
	if len(bootstrapMessages) != 1 || bootstrapMessages[0].peer != bootstrapHop || bootstrapMessages[0].message.Header.Type != foundation.I2NPShortTunnelBuild {
		t.Fatalf("bootstrap direct send=%#v", bootstrapMessages)
	}
	if started, err := maintainer.Maintain(context.Background()); err != nil || started != 0 || len(inboundSource.carriers) != 1 {
		t.Fatalf("pending suppression started=%d err=%v carriers=%v", started, err, inboundSource.carriers)
	}
	discardPairedPending(manager)

	gateway := foundation.Hash{9}
	if err := pool.Add(Entry{ID: 101, Direction: Inbound, Expires: now + 10_000, Gateway: gateway, GatewayTunnelID: 701}, now); err != nil {
		t.Fatal(err)
	}
	if started, err := maintainer.Maintain(context.Background()); err != nil || started != 1 {
		t.Fatalf("outbound transition started=%d err=%v", started, err)
	}
	if len(inboundSource.carriers) != 1 || len(outboundSource.routes) != 1 || outboundSource.routes[0] != (ReplyRoute{Gateway: gateway, TunnelID: 701}) {
		t.Fatalf("transition inbound=%v outbound=%v", inboundSource.carriers, outboundSource.routes)
	}
	discardPairedPending(manager)
	sender.take()

	carrierHop := foundation.Hash{2}
	if err := pool.Add(Entry{ID: 201, Direction: Outbound, Expires: now + 10_000, HopCount: 1, Hops: [foundation.I2NPMaxVariableBuildRecords]foundation.Hash{carrierHop}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 201, FirstHop: carrierHop, NextTunnelID: 202, ExpiresAt: now + 10_000}); err != nil {
		t.Fatal(err)
	}
	if started, err := maintainer.Maintain(context.Background()); err != nil || started != 2 {
		t.Fatalf("established parallel transitions started=%d err=%v", started, err)
	}
	if got := inboundSource.carriers; len(got) != 2 || got[1] != 201 {
		t.Fatalf("established carriers=%v, want [0 201]", got)
	}
	carrierMessages := sender.take()
	haveCarrier := false
	for _, message := range carrierMessages {
		if message.peer == carrierHop && message.message.Header.Type == foundation.I2NPTunnelData {
			haveCarrier = true
		}
	}
	if len(carrierMessages) != 2 || !haveCarrier {
		t.Fatalf("parallel carrier sends=%#v", carrierMessages)
	}
	pair, ok := maintainer.Pair(now)
	pairMismatch := !ok
	if !pairMismatch {
		pairMismatch = pair.OutboundID != 201 ||
			pair.OutboundEndpoint != carrierHop ||
			pair.InboundID != 701 ||
			pair.ReplyRouter != gateway ||
			pair.PeerCount != 1 ||
			pair.Peers[0] != carrierHop
	}
	if pairMismatch {
		t.Fatalf("pair=%#v %t", pair, ok)
	}
	if err := maintainer.Close(); err != nil {
		t.Fatal(err)
	}
	if started, err := maintainer.Maintain(context.Background()); started != 0 || err != ErrPairedMaintenanceClosed {
		t.Fatalf("Maintain after Close = %d, %v", started, err)
	}
	if pair, ok := maintainer.Pair(now); ok || pair != (CircuitPair{}) {
		t.Fatalf("Pair after Close = %#v, %t", pair, ok)
	}
}

func TestPairedMaintainerRenewsDirectionsWithOverlap(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	inboundSource := &pairedInboundSource{builds: []InboundBuild{pairedInboundBuild(t, 101, now+10_000)}}
	outboundSource := &pairedOutboundSource{builds: []OutboundBuild{rotationBuild(t, 201, now+10_000)}}
	maintainer, pool, runtime, manager, _ := newPairedMaintainer(t, now, 1, 100, inboundSource, outboundSource)
	gateway := foundation.Hash{3}
	oldInbound := Entry{ID: 100, Direction: Inbound, Expires: now + 50, Gateway: gateway, GatewayTunnelID: 700}
	oldOutbound := Entry{ID: 200, Direction: Outbound, Expires: now + 50, HopCount: 1, Hops: [foundation.I2NPMaxVariableBuildRecords]foundation.Hash{{4}}}
	if err := pool.Add(oldInbound, now); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: oldOutbound.ID, FirstHop: foundation.Hash{4}, NextTunnelID: 201, ExpiresAt: oldOutbound.Expires}); err != nil {
		t.Fatal(err)
	}
	oldOutbound.Circuit = buildCircuitToken(t, runtime, oldOutbound.ID)
	if err := pool.Add(oldOutbound, now); err != nil {
		t.Fatal(err)
	}

	if started, err := maintainer.Maintain(context.Background()); err != nil || started != 2 {
		t.Fatalf("parallel renewals started=%d err=%v", started, err)
	}
	var inboundPending *pendingInboundBuild
	for _, pending := range manager.pendingInbound {
		inboundPending = pending
	}
	if inboundPending == nil || inboundPending.build.retireID != oldInbound.ID {
		t.Fatalf("inbound renewal=%#v", inboundPending)
	}
	var outboundPending *pendingOutboundBuild
	for _, pending := range manager.pending {
		outboundPending = pending
	}
	if outboundPending == nil || outboundPending.build.retireID != oldOutbound.ID {
		t.Fatalf("outbound renewal=%#v", outboundPending)
	}
	if _, ok := pool.Get(oldInbound.ID, now); !ok {
		t.Fatal("old inbound removed before replacement completed")
	}
	if _, ok := pool.Get(oldOutbound.ID, now); !ok {
		t.Fatal("old outbound removed before replacement completed")
	}
}

func TestPairedMaintainerBuildsReservesAfterActiveTargetsAreSatisfied(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	inbound := &pairedInboundSource{builds: []InboundBuild{pairedInboundBuild(t, 101, now+10_000)}}
	outbound := &pairedOutboundSource{builds: []OutboundBuild{rotationBuild(t, 201, now+10_000)}}
	initial, pool, runtime, manager, _ := newPairedMaintainer(t, now, 1, 100, inbound, outbound)
	defer manager.ReleaseSensitive()
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	maintainer, err := NewPairedPoolMaintainer(PairedPoolMaintainerConfig{
		Pool: pool, Runtime: runtime, Builder: manager, InboundSource: inbound, OutboundSource: outbound,
		Now: func() uint64 { return now }, InboundTarget: 1, OutboundTarget: 1,
		InboundBackup: 1, OutboundBackup: 1, RenewBefore: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer maintainer.Close()
	if err := pool.Add(Entry{ID: 100, Direction: Inbound, Expires: now + 10_000, Gateway: foundation.Hash{3}, GatewayTunnelID: 700}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 200, FirstHop: foundation.Hash{4}, NextTunnelID: 201, ExpiresAt: now + 10_000}); err != nil {
		t.Fatal(err)
	}
	if err := pool.Add(Entry{ID: 200, Circuit: buildCircuitToken(t, runtime, 200), Direction: Outbound, Expires: now + 10_000, HopCount: 1, Hops: [foundation.I2NPMaxVariableBuildRecords]foundation.Hash{{4}}}, now); err != nil {
		t.Fatal(err)
	}
	if started, err := maintainer.Maintain(context.Background()); err != nil || started != 2 {
		t.Fatalf("reserve builds started=%d err=%v, want two", started, err)
	}
	if started, err := maintainer.Maintain(context.Background()); err != nil || started != 0 {
		t.Fatalf("pending reserve demand duplicated: started=%d err=%v", started, err)
	}
}
func TestPairedMaintainerCloseCancelsAndJoinsActiveTransition(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	sender := new(buildCaptureSender)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	pool := NewPool(4)
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: sender, ReplyKeys: newBuildReplyRegistry(),
		LocalRouter: foundation.Hash{1}, LocalDelivery: func(foundation.I2NPMessage) error { return nil },
		Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.ReleaseSensitive()
	source := &cancelingPairedInboundSource{entered: make(chan struct{})}
	maintainer, err := NewPairedPoolMaintainer(PairedPoolMaintainerConfig{
		Pool: pool, Runtime: runtime, Builder: manager, InboundSource: source, OutboundSource: new(pairedOutboundSource),
		Now: func() uint64 { return now }, InboundTarget: 1, OutboundTarget: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	maintained := make(chan error, 1)
	go func() {
		_, maintainErr := maintainer.Maintain(context.Background())
		maintained <- maintainErr
	}()
	select {
	case <-source.entered:
	case <-time.After(time.Second):
		t.Fatal("maintenance source did not enter")
	}
	if err = maintainer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-maintained:
		if err != context.Canceled {
			t.Fatalf("active maintenance result = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join active maintenance")
	}
}

func TestPairedMaintainerRejectsBuilderWiringMismatch(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	inbound := new(pairedInboundSource)
	outbound := new(pairedOutboundSource)
	maintainer, pool, runtime, manager, _ := newPairedMaintainer(t, now, 1, 0, inbound, outbound)
	if maintainer == nil {
		t.Fatal("matching builder wiring rejected")
	}
	otherPool := NewPool(8)
	otherRuntime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Now: func() uint64 { return now }})
	for _, config := range []PairedPoolMaintainerConfig{
		{Pool: otherPool, Runtime: runtime, Builder: manager, InboundSource: inbound, OutboundSource: outbound, Now: func() uint64 { return now }, InboundTarget: 1, OutboundTarget: 1},
		{Pool: pool, Runtime: otherRuntime, Builder: manager, InboundSource: inbound, OutboundSource: outbound, Now: func() uint64 { return now }, InboundTarget: 1, OutboundTarget: 1},
	} {
		if got, err := NewPairedPoolMaintainer(config); got != nil || err != ErrPairedMaintenanceConfig {
			t.Fatalf("mismatched wiring manager=%#v err=%v", got, err)
		}
	}
}

func TestPairedMaintainerBootstrapParallelLimit(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	inboundSource := &pairedInboundSource{builds: []InboundBuild{
		pairedInboundBuild(t, 101, now+10_000),
		pairedInboundBuild(t, 102, now+10_000),
		pairedInboundBuild(t, 103, now+10_000),
	}}
	outboundSource := &pairedOutboundSource{builds: []OutboundBuild{
		rotationBuild(t, 201, now+10_000),
		rotationBuild(t, 202, now+10_000),
	}}
	sender := new(buildCaptureSender)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	pool := NewPool(8)
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: sender, ReplyKeys: newBuildReplyRegistry(),
		LocalRouter: foundation.Hash{1}, LocalDelivery: func(foundation.I2NPMessage) error { return nil },
		Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	maintainer, err := NewPairedPoolMaintainer(PairedPoolMaintainerConfig{
		Pool: pool, Runtime: runtime, Builder: manager, InboundSource: inboundSource, OutboundSource: outboundSource,
		Now: func() uint64 { return now }, InboundTarget: 3, OutboundTarget: 3,
		BootstrapParallelLimit: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Bootstrap should attempt min(inboundTarget, BootstrapParallelLimit) = min(3, 2) = 2
	started, err := maintainer.Maintain(context.Background())
	if err != nil || started != 2 {
		t.Fatalf("bootstrap parallel limit started=%d err=%v, want 2", started, err)
	}
	if got := inboundSource.carriers; len(got) != 2 || got[0] != 0 || got[1] != 0 {
		t.Fatalf("bootstrap parallel carriers=%v, want [0 0]", got)
	}
}
