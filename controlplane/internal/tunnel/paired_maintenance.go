package tunnel

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

var (
	ErrPairedMaintenanceConfig = errors.New("tunnel: invalid paired maintenance configuration")
	ErrPairedMaintenanceClosed = errors.New("tunnel: paired pool maintainer is closed")
)

// ReplyRoute identifies a live inbound tunnel through which an outbound build
// reply is returned. Gateway is that inbound tunnel's gateway router.
type ReplyRoute struct {
	Gateway  foundation.Hash
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
	Pool                   *Pool
	Runtime                dataplane.TunnelCircuitRuntime
	Builder                *BuildManager
	InboundSource          InboundBuildSource
	OutboundSource         PairedOutboundBuildSource
	Now                    func() uint64
	InboundTarget          int
	OutboundTarget         int
	InboundBackup          int
	OutboundBackup         int
	RenewBefore            uint64
	BootstrapParallelLimit int
	Hooks                  []MaintenanceHook
}

// PairedPoolMaintainer establishes and renews a bidirectional tunnel pool in
// strict dependency order: bootstrap inbound, outbound through that inbound
// reply route, then later inbound builds through a live outbound path.
//
// Lock order: lifecycleMu -> maintenanceMu -> {inboundSourceMu, outboundSourceMu}.
type PairedPoolMaintainer struct {
	pool    *Pool
	runtime dataplane.TunnelCircuitRuntime
	builder *BuildManager
	// +checklocks:inboundSourceMu
	inboundSource InboundBuildSource
	// +checklocks:outboundSourceMu
	outboundSource         PairedOutboundBuildSource
	now                    func() uint64
	inboundTarget          int
	outboundTarget         int
	inboundBackup          int
	outboundBackup         int
	renewBefore            uint64
	bootstrapParallelLimit int
	// +checklocks:lifecycleMu
	hooks            []MaintenanceHook
	maintenanceMu    sync.Mutex
	inboundSourceMu  sync.Mutex
	outboundSourceMu sync.Mutex
	lifecycleMu      sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
	pairIndex        atomic.Uint64
	// attempts joins build attempts that outlive the pass that started them.
	attempts sync.WaitGroup
	// +checklocks:lifecycleMu
	closed bool
}

func NewPairedPoolMaintainer(config PairedPoolMaintainerConfig) (*PairedPoolMaintainer, error) {
	newPairedPoolMaintainerRejected := config.Pool == nil || config.Runtime == nil || config.Builder == nil || config.Builder.pool != config.Pool || config.Builder.runtime != config.Runtime || config.InboundSource == nil || config.OutboundSource == nil || config.Now == nil || config.InboundTarget < 1 || config.OutboundTarget < 1 || config.RenewBefore >= 10*60*1000
	newPairedPoolMaintainerRejected = newPairedPoolMaintainerRejected || config.InboundBackup < 0 || config.OutboundBackup < 0
	if !newPairedPoolMaintainerRejected {
		newPairedPoolMaintainerRejected = config.InboundTarget+config.InboundBackup+config.OutboundTarget+config.OutboundBackup > config.Pool.max
	}
	if newPairedPoolMaintainerRejected {
		return nil, ErrPairedMaintenanceConfig
	}
	config.Pool.mu.Lock()
	config.Pool.outboundTarget = config.OutboundTarget
	config.Pool.renewBefore = config.RenewBefore
	config.Pool.activeOutbound = make(map[uint32]struct{}, config.OutboundTarget)
	config.Pool.mu.Unlock()
	lifecycle, cancel := context.WithCancel(context.Background())
	bootstrapLimit := config.BootstrapParallelLimit
	if bootstrapLimit <= 0 {
		bootstrapLimit = 1
	}
	return &PairedPoolMaintainer{
		pool: config.Pool, runtime: config.Runtime, builder: config.Builder,
		inboundSource: config.InboundSource, outboundSource: config.OutboundSource,
		now: config.Now, inboundTarget: config.InboundTarget, outboundTarget: config.OutboundTarget, renewBefore: config.RenewBefore,
		inboundBackup: config.InboundBackup, outboundBackup: config.OutboundBackup,
		bootstrapParallelLimit: bootstrapLimit,
		hooks:                  append([]MaintenanceHook(nil), config.Hooks...), ctx: lifecycle, cancel: cancel,
	}, nil
}

// Maintain performs one explicitly scheduled transition. Bootstrap preserves
// tunnel dependency order; once both directions are usable, independent
// inbound and outbound renewals may start concurrently. A pass does not wait
// for an attempt that must first establish a new transport session: that
// attempt continues under the caller's deadline, and the next pass can start
// other builds meanwhile.
func (m *PairedPoolMaintainer) Maintain(ctx context.Context) (int, error) {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.closed {
		return 0, ErrPairedMaintenanceClosed
	}
	return m.maintainActive(ctx, m.hooks)
}

// +checklocksread:m.lifecycleMu
// +checklocksexclude:m.maintenanceMu
// +checklocksexclude:m.inboundSourceMu
// +checklocksexclude:m.outboundSourceMu
func (m *PairedPoolMaintainer) maintainActive(ctx context.Context, hooks []MaintenanceHook) (int, error) {
	if !m.maintenanceMu.TryLock() {
		return 0, nil
	}
	defer m.maintenanceMu.Unlock() // +checklocksignore
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := ctx.Err(); err != nil {
		m.builder.creatorBudget.cancelWait(m.builder)
		return 0, err
	}
	now := m.now()
	m.pool.Expire(now)
	m.runtime.Expire(now)
	m.builder.Expire(now)
	for _, hook := range hooks {
		hook(now)
	}
	cutoff := saturatingDeadline(now, m.renewBefore)
	outbound, haveOutbound := m.pool.Select(Outbound, now)
	inbound, haveInbound := m.pool.Select(Inbound, now)
	var attempts []*creatorAttempt
	var resultErr error
	waiting := false
	reserve := func(direction Direction, target, limit int, deadline uint64) {
		for range limit {
			attempt, err := m.builder.reserveCreator(direction, target, limit, now, deadline)
			if err != nil {
				waiting = waiting || errors.Is(err, ErrBuildPending)
				resultErr = errors.Join(resultErr, err)
				break
			}
			if attempt == nil {
				break
			}
			attempts = append(attempts, attempt)
		}
	}
	switch {
	case !haveInbound:
		limit := m.bootstrapParallelLimit
		reserve(Inbound, min(m.inboundTarget, limit), limit, now)
	case !haveOutbound:
		if inbound.Gateway != (foundation.Hash{}) && inbound.GatewayTunnelID != 0 {
			limit := m.bootstrapParallelLimit
			reserve(Outbound, min(m.outboundTarget, limit), limit, now)
		}
	default:
		inboundTarget, outboundTarget := m.inboundTarget, m.outboundTarget
		if m.pool.Count(Inbound, cutoff) >= inboundTarget && m.pool.Count(Outbound, cutoff) >= outboundTarget {
			inboundTarget += m.inboundBackup
			outboundTarget += m.outboundBackup
		}
		inNeeded := inboundTarget - m.pool.Count(Inbound, cutoff)
		outNeeded := outboundTarget - m.pool.Count(Outbound, cutoff)
		inLimit := 0
		if inNeeded > 0 {
			inLimit = m.builder.ParallelLimit(Inbound, inNeeded)
		}
		outLimit := 0
		if outNeeded > 0 {
			outLimit = m.builder.ParallelLimit(Outbound, outNeeded)
		}
		if inLimit > 0 {
			reserve(Inbound, inboundTarget, inLimit, cutoff)
		}
		if outLimit > 0 {
			reserve(Outbound, outboundTarget, outLimit, cutoff)
		}
	}
	if !waiting {
		m.builder.creatorBudget.cancelWait(m.builder)
	}
	if len(attempts) == 0 {
		return 0, resultErr
	}
	base := context.WithoutCancel(ctx)
	var runCtx context.Context
	var cancelRun context.CancelFunc
	if deadline, ok := ctx.Deadline(); ok {
		runCtx, cancelRun = context.WithDeadline(base, deadline)
	} else {
		runCtx, cancelRun = context.WithCancel(base)
	}
	stopLifetime := context.AfterFunc(m.ctx, cancelRun)
	stopPass := context.AfterFunc(ctx, cancelRun)
	defer stopPass()
	type buildResult struct {
		started bool
		err     error
	}
	run := func(attempt *creatorAttempt) buildResult {
		var err error
		if attempt.direction == Inbound {
			carrierID := uint32(0)
			if haveInbound && haveOutbound {
				carrierID = outbound.ID
			}
			m.inboundSourceMu.Lock()
			build, sourceErr := m.inboundSource.NextInbound(runCtx, now, carrierID)
			m.inboundSourceMu.Unlock()
			err = sourceErr
			if err == nil && carrierID != 0 && outbound.HopCount == 0 {
				err = ErrPairedMaintenanceConfig
			}
			if err == nil {
				build.attempt, build.retireID = attempt, attempt.retire.ID
				if carrierID != 0 {
					build.CarrierEndpoint = outbound.Hops[outbound.HopCount-1]
				}
				_, err = m.builder.StartInbound(runCtx, build)
			}
		} else {
			m.outboundSourceMu.Lock()
			build, sourceErr := m.outboundSource.NextOutboundForReply(runCtx, now, ReplyRoute{Gateway: inbound.Gateway, TunnelID: inbound.GatewayTunnelID})
			m.outboundSourceMu.Unlock()
			err = sourceErr
			if err == nil {
				build.attempt, build.retireID = attempt, attempt.retire.ID
				_, err = m.builder.StartOutbound(runCtx, build)
			}
		}
		if err != nil {
			attempt.failPreparation()
		}
		return buildResult{started: err == nil, err: err}
	}
	// Each attempt reports once: when it finishes, or earlier when it starts
	// to wait for a new transport session. The pass waits only for reports.
	results := make(chan buildResult, len(attempts))
	var remaining atomic.Int32
	remaining.Store(int32(len(attempts)))
	m.attempts.Add(len(attempts))
	for _, attempt := range attempts {
		var report sync.Once
		attempt.sessionSetup = func() { report.Do(func() { results <- buildResult{started: true} }) }
		go func() {
			defer m.attempts.Done()
			result := run(attempt)
			report.Do(func() { results <- result })
			if remaining.Add(-1) == 0 {
				stopLifetime()
				cancelRun()
			}
		}()
	}
	started := 0
	for range attempts {
		result := <-results
		if result.started {
			started++
		}
		switch {
		case result.err == nil:
		case resultErr == nil:
			resultErr = result.err
		default:
			resultErr = errors.Join(resultErr, result.err)
		}
	}
	return started, resultErr
}

// Close cancels an active transition, rejects future maintenance, and waits
// until the current transition and every attempt it started have relinquished
// their build/source references.
func (m *PairedPoolMaintainer) Close() error {
	if m == nil {
		return nil
	}
	m.cancel()
	m.lifecycleMu.Lock()
	m.closed = true
	clear(m.hooks)
	m.hooks = nil
	m.builder.creatorBudget.cancelWait(m.builder)
	m.lifecycleMu.Unlock()
	m.attempts.Wait()
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
	return m.pairActive(now)
}

func (m *PairedPoolMaintainer) pairActive(now uint64) (CircuitPair, bool) {
	outbounds := m.pool.SelectableOutbound(now)
	inbounds := m.pool.PublishableInbound(now)
	if len(outbounds) == 0 || len(inbounds) == 0 {
		return CircuitPair{}, false
	}
	idx := m.pairIndex.Add(1) - 1
	var outbound, inbound Entry
	haveOutbound, haveInbound := false, false
	for attempt := range outbounds {
		cand := outbounds[(idx+uint64(attempt))%uint64(len(outbounds))]
		if cand.Expires > now {
			outbound, haveOutbound = cand, true
			break
		}
	}
	for attempt := range inbounds {
		cand := inbounds[(idx+uint64(attempt))%uint64(len(inbounds))]
		if cand.Expires > now && cand.Gateway != (foundation.Hash{}) && cand.GatewayTunnelID != 0 {
			inbound, haveInbound = cand, true
			break
		}
	}
	if !haveOutbound || !haveInbound {
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
			if peer == (foundation.Hash{}) {
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
