package tunnel

import (
	"context"
	"errors"
	ivnp "gosuda.org/ivnp/foundation"
	"sync"
)

var (
	ErrPairedMaintenanceConfig = errors.New("tunnel: invalid paired maintenance configuration")
	ErrPairedMaintenanceClosed = errors.New("tunnel: paired pool maintainer is closed")
)

// ReplyRoute identifies a live inbound tunnel through which an outbound build
// reply is returned. Gateway is that inbound tunnel's gateway router.
type ReplyRoute struct {
	Gateway  ivnp.Hash
	TunnelID uint32
}

// PairedOutboundBuildSource selects an outbound path for a concrete live
// inbound reply route. Unlike OutboundBuildSource, it cannot accidentally use
// a stale constructor-time reply tunnel.
type PairedOutboundBuildSource interface {
	NextOutboundForReply(context.Context, uint64, ReplyRoute) (OutboundBuild, error)
}

// MaintenanceHook expires external bounded control-plane state. Hooks run in
// the caller's maintenance schedule; this maintainer never starts goroutines.
type MaintenanceHook func(uint64)

// PairedPoolMaintainerConfig supplies the two build sources and bounded state
// owned by a single tunnel pool. Each direction has its own configured target.
type PairedPoolMaintainerConfig struct {
	Pool           *Pool
	Runtime        *Runtime
	Builder        *BuildManager
	InboundSource  InboundBuildSource
	OutboundSource PairedOutboundBuildSource
	Now            func() uint64
	InboundTarget  int
	OutboundTarget int
	RenewBefore    uint64
	Hooks          []MaintenanceHook
}

// PairedPoolMaintainer establishes and renews a bidirectional tunnel pool in
// strict dependency order: bootstrap inbound, outbound through that inbound
// reply route, then later inbound builds through a live outbound path.
type PairedPoolMaintainer struct {
	pool           *Pool
	runtime        *Runtime
	builder        *BuildManager
	inboundSource  InboundBuildSource
	outboundSource PairedOutboundBuildSource
	now            func() uint64
	inboundTarget  int
	outboundTarget int
	renewBefore    uint64
	hooks          []MaintenanceHook
	lifecycleMu    sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	closed         bool
}

func NewPairedPoolMaintainer(config PairedPoolMaintainerConfig) (*PairedPoolMaintainer, error) {
	newPairedPoolMaintainerRejected := config.Pool == nil || config.Runtime == nil || config.Builder == nil || config.Builder.pool != config.Pool || config.Builder.runtime != config.Runtime || config.InboundSource == nil || config.OutboundSource == nil || config.Now == nil || config.InboundTarget < 1 || config.OutboundTarget < 1 || config.RenewBefore >= 10*60*1000
	if !newPairedPoolMaintainerRejected {
		newPairedPoolMaintainerRejected = config.InboundTarget+config.OutboundTarget > config.Pool.max
	}
	if newPairedPoolMaintainerRejected {
		return nil, ErrPairedMaintenanceConfig
	}
	lifecycle, cancel := context.WithCancel(context.Background())
	return &PairedPoolMaintainer{
		pool: config.Pool, runtime: config.Runtime, builder: config.Builder,
		inboundSource: config.InboundSource, outboundSource: config.OutboundSource,
		now: config.Now, inboundTarget: config.InboundTarget, outboundTarget: config.OutboundTarget, renewBefore: config.RenewBefore,
		hooks: append([]MaintenanceHook(nil), config.Hooks...), ctx: lifecycle, cancel: cancel,
	}, nil
}

// Maintain performs one explicitly scheduled transition. Bootstrap preserves
// tunnel dependency order; once both directions are usable, independent
// inbound and outbound renewals may start concurrently.
func (m *PairedPoolMaintainer) Maintain(ctx context.Context) (int, error) {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.closed {
		return 0, ErrPairedMaintenanceClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.ctx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	now := m.now()
	m.pool.Expire(now)
	m.runtime.Expire(now)
	m.builder.Expire(now)
	for _, hook := range m.hooks {
		hook(now)
	}
	pendingInbound := m.builder.PendingDirection(Inbound)
	pendingOutbound := m.builder.PendingDirection(Outbound)
	cutoff := now + m.renewBefore
	if cutoff < now {
		cutoff = ^uint64(0)
	}

	outbound, haveOutbound := m.pool.Select(Outbound, now)
	inbound, haveInbound := m.pool.Select(Inbound, now)

	// A zero-hop carrier is bootstrap-only. Once an inbound reply route exists,
	// establish its outbound peer before expanding either direction.
	if !haveInbound {
		if pendingInbound != 0 {
			return 0, nil
		}
		build, err := m.inboundSource.NextInbound(ctx, now, 0)
		if err != nil {
			return 0, err
		}
		if _, err = m.builder.StartInbound(ctx, build); err != nil {
			return 0, err
		}
		return 1, nil
	}

	// An outbound tunnel needs the IBGW's receive-tunnel ID, not the creator's
	// local inbound circuit ID.
	if !haveOutbound {
		if pendingOutbound != 0 {
			return 0, nil
		}
		if inbound.Gateway == (ivnp.Hash{}) || inbound.GatewayTunnelID == 0 {
			return 0, nil
		}
		build, err := m.outboundSource.NextOutboundForReply(ctx, now, ReplyRoute{Gateway: inbound.Gateway, TunnelID: inbound.GatewayTunnelID})
		if err != nil {
			return 0, err
		}
		if _, err = m.builder.StartOutbound(ctx, build); err != nil {
			return 0, err
		}
		return 1, nil
	}

	type buildResult struct {
		started bool
		err     error
	}
	actions := make([]func() buildResult, 0, 2)
	if pendingInbound == 0 && m.pool.Count(Inbound, cutoff) < m.inboundTarget {
		actions = append(actions, func() buildResult {
			build, err := m.inboundSource.NextInbound(ctx, now, outbound.ID)
			if err != nil {
				return buildResult{err: err}
			}
			if outbound.HopCount == 0 {
				return buildResult{err: ErrPairedMaintenanceConfig}
			}
			build.CarrierEndpoint = outbound.Hops[outbound.HopCount-1]
			if renewal := m.pool.renewalIDs(Inbound, now, cutoff); len(renewal) != 0 {
				build.retireID = renewal[0]
			}
			_, err = m.builder.StartInbound(ctx, build)
			return buildResult{started: err == nil, err: err}
		})
	}
	if pendingOutbound == 0 && m.pool.Count(Outbound, cutoff) < m.outboundTarget {
		actions = append(actions, func() buildResult {
			build, err := m.outboundSource.NextOutboundForReply(ctx, now, ReplyRoute{Gateway: inbound.Gateway, TunnelID: inbound.GatewayTunnelID})
			if err != nil {
				return buildResult{err: err}
			}
			if renewal := m.pool.renewalIDs(Outbound, now, cutoff); len(renewal) != 0 {
				build.retireID = renewal[0]
			}
			_, err = m.builder.StartOutbound(ctx, build)
			return buildResult{started: err == nil, err: err}
		})
	}
	if len(actions) == 0 {
		return 0, nil
	}
	if len(actions) == 1 {
		result := actions[0]()
		if result.started {
			return 1, result.err
		}
		return 0, result.err
	}
	results := make(chan buildResult, len(actions))
	for _, action := range actions {
		go func() { results <- action() }()
	}
	started := 0
	var resultErr error
	for range actions {
		result := <-results
		if result.started {
			started++
		}
		resultErr = errors.Join(resultErr, result.err)
	}
	return started, resultErr
}

// Close cancels an active transition, rejects future maintenance, and waits
// until the current transition has relinquished its build/source references.
func (m *PairedPoolMaintainer) Close() error {
	if m == nil {
		return nil
	}
	m.cancel()
	m.lifecycleMu.Lock()
	m.closed = true
	clear(m.hooks)
	m.hooks = nil
	m.lifecycleMu.Unlock()
	return nil
}

// Pair reports the current usable outbound/inbound route for health probes and
// NetDB reply selection. InboundID is the IBGW receive-tunnel ID; the local
// creator circuit ID is not routable at the remote gateway.
func (m *PairedPoolMaintainer) Pair(now uint64) (CircuitPair, bool) {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.closed {
		return CircuitPair{}, false
	}
	outbound, haveOutbound := m.pool.Select(Outbound, now)
	inbound, haveInbound := m.pool.Select(Inbound, now)
	if !haveOutbound || !haveInbound || inbound.Gateway == (ivnp.Hash{}) || inbound.GatewayTunnelID == 0 {
		return CircuitPair{}, false
	}
	pair := CircuitPair{OutboundID: outbound.ID, InboundID: inbound.GatewayTunnelID, InboundLocalID: inbound.ID, ReplyRouter: inbound.Gateway}
	if outbound.HopCount != 0 {
		pair.OutboundEndpoint = outbound.Hops[outbound.HopCount-1]
	}
	for _, entry := range [...]Entry{outbound, inbound} {
		for index := range int(entry.HopCount) {
			if pair.PeerCount == uint8(len(pair.Peers)) {
				break
			}
			peer := entry.Hops[index]
			if peer == (ivnp.Hash{}) {
				continue
			}
			duplicate := false
			for existing := range int(pair.PeerCount) {
				if pair.Peers[existing] == peer {
					duplicate = true
					break
				}
			}
			if !duplicate {
				pair.Peers[pair.PeerCount] = peer
				pair.PeerCount++
			}
		}
	}
	return pair, true
}
