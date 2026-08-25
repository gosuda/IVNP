package tunnel

import (
	"context"
	"errors"
)

var ErrRotationConfig = errors.New("tunnel: invalid rotation configuration")

// OutboundBuildSource selects a fresh path and IDs for one replacement tunnel.
// Implementations must exclude peers already used in the returned path.
type OutboundBuildSource interface {
	NextOutbound(context.Context, uint64) (OutboundBuild, error)
}

// Rotator maintains a target number of outbound tunnels. Maintain is intended
// for one router maintenance worker; it performs no background work itself.
type Rotator struct {
	pool        *Pool
	runtime     *Runtime
	builder     *BuildManager
	source      OutboundBuildSource
	now         func() uint64
	target      int
	renewBefore uint64
}

type RotatorConfig struct {
	Pool        *Pool
	Runtime     *Runtime
	Builder     *BuildManager
	Source      OutboundBuildSource
	Now         func() uint64
	Target      int
	RenewBefore uint64
}

func NewRotator(config RotatorConfig) (*Rotator, error) {
	newRotatorRejected := config.Pool == nil || config.Runtime == nil || config.Builder == nil || config.Source == nil || config.Now == nil || config.Target < 1 || config.Target > config.Pool.max
	if !newRotatorRejected {
		newRotatorRejected = config.RenewBefore >= 10*60*1000
	}
	if newRotatorRejected {
		return nil, ErrRotationConfig
	}
	return &Rotator{pool: config.Pool, runtime: config.Runtime, builder: config.Builder, source: config.Source, now: config.Now, target: config.Target, renewBefore: config.RenewBefore}, nil
}

// Maintain expires dead state and starts enough replacement builds to cover
// tunnels already inside the renewal window. Pending builds count toward the
// target so a slow or hostile network cannot create an unbounded build storm.
func (r *Rotator) Maintain(ctx context.Context) (started int, err error) {
	if ctx == nil {
		ctx = context.
			Background()
	}

	if err = ctx.Err(); err != nil {
		return 0, err
	}
	now := r.now()
	r.pool.Expire(now)
	r.runtime.Expire(now)
	r.builder.Expire(now)
	cutoff := now + r.renewBefore
	if cutoff < now {
		cutoff = ^uint64(0)
	}
	usable := r.pool.Count(Outbound, cutoff)
	reserved := r.builder.pendingRetirements()
	renewals := r.pool.renewalIDs(Outbound, now, cutoff)
	candidates := renewals[:0]
	for _, id := range renewals {
		if _, pending := reserved[id]; !pending {
			candidates = append(candidates, id)
		}
	}
	needed := r.target - usable - r.builder.Pending()
	for needed > 0 {
		build, nextErr := r.source.NextOutbound(ctx, now)
		if nextErr != nil {
			return started, nextErr
		}
		if started < len(candidates) {
			build.retireID = candidates[started]
		}
		if _, nextErr = r.builder.StartOutbound(ctx, build); nextErr != nil {
			return started, nextErr
		}
		started++
		needed--
	}
	return started, nil
}
