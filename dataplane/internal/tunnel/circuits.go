package tunnel

import (
	"context"
	"sync/atomic"

	"gosuda.org/ivnp/foundation"
)

// CircuitToken identifies one installation, not a reusable wire tunnel ID.
// Tokens are runtime-scoped and cannot be manufactured by control-plane callers.
type CircuitToken struct {
	id         uint32
	generation *circuitLifetime
}

// CircuitInfo is an immutable inspection snapshot without forwarding secrets.
type CircuitInfo struct {
	FirstHop  foundation.Hash
	Token     CircuitToken
	Owner     foundation.Hash
	ExpiresAt uint64
	Forward   *Forward
}

// CircuitRuntime is the control plane's circuit programming and probe boundary.
// Registration rejects occupied IDs; replacement and removal require the exact
// installation token. Packet processing never calls back into build policy.
type CircuitRuntime interface {
	RegisterOutbound(OutboundCircuit) (CircuitToken, error)
	RegisterInbound(InboundCircuit) (CircuitToken, error)
	RemoveCircuit(CircuitToken) bool
	InspectCircuit(uint32) (CircuitInfo, bool)
	Expire(uint64) int
	OutboundActivity(uint32) (uint64, bool)
	InboundActivity(uint32) (uint64, bool)
	SendBlockPrepared(context.Context, CircuitToken, Block) error
}

// The registry owns one reference. Each admitted packet pins its installation
// before releasing the shard lock; retirement drops only the registry reference.
type circuitLifetime struct {
	refs atomic.Int64
}

func (c *inboundCircuit) release() {
	if c.lifetime.refs.Add(-1) != 0 {
		return
	}
	clear(c.transforms)
	c.transforms = nil
	if c.endpoint != nil {
		c.endpoint.Expire(^uint64(0))
		c.endpoint = nil
	}
	c.local = nil
}

func (c *outboundCircuit) release() {
	if c.lifetime.refs.Add(-1) != 0 {
		return
	}
	clear(c.transforms)
	c.transforms = nil
}

// InspectCircuit includes expired installations until maintenance retires them.
func (r *Runtime) InspectCircuit(id uint32) (CircuitInfo, bool) {
	if r == nil || id == 0 {
		return CircuitInfo{}, false
	}
	shard := r.shard(id)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	if circuit, ok := shard.inbound[id]; ok {
		info := CircuitInfo{Token: CircuitToken{id, &circuit.lifetime}, Owner: circuit.owner, ExpiresAt: circuit.expiresAt}
		if circuit.forward != nil {
			forward := *circuit.forward
			info.Forward = &forward
		}
		return info, true
	}
	if circuit, ok := shard.outbound[id]; ok {
		return CircuitInfo{Token: CircuitToken{id, &circuit.lifetime}, Owner: circuit.owner, ExpiresAt: circuit.expiresAt, FirstHop: circuit.firstHop}, true
	}
	return CircuitInfo{}, false
}

// ReplaceOutbound atomically replaces a live installation without changing its
// owner or wire ID. Already admitted packets finish on the retired generation.
func (r *Runtime) ReplaceOutbound(token CircuitToken, circuit OutboundCircuit) (CircuitToken, error) {
	if token.id != circuit.ID || token.generation == nil {
		return CircuitToken{}, ErrCircuitNotFound
	}
	return r.installOutbound(circuit, token)
}

// ReplaceInbound requires a fresh endpoint so fragments cannot cross generations.
func (r *Runtime) ReplaceInbound(token CircuitToken, circuit InboundCircuit) (CircuitToken, error) {
	if token.id != circuit.ID || token.generation == nil {
		return CircuitToken{}, ErrCircuitNotFound
	}
	return r.installInbound(circuit, token)
}
