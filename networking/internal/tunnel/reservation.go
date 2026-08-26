package tunnel

import (
	"sync"
	"time"

	"gosuda.org/ivnp/foundation"
)

// BuildReservations prevents concurrently pending pools from selecting the
// same peer. A reservation lasts only until its build reaches a terminal state.
type BuildReservations struct {
	mu    sync.Mutex
	peers map[foundation.Hash]struct{}
}

func NewBuildReservations() *BuildReservations {
	return &BuildReservations{peers: make(map[foundation.Hash]struct{})}
}

func (r *BuildReservations) Available(peer foundation.Hash) bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	_, reserved := r.peers[peer]
	r.mu.Unlock()
	return !reserved
}

func (r *BuildReservations) Reserve(hops []ShortBuildHop) *BuildReservation {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, hop := range hops {
		if _, reserved := r.peers[hop.Router]; reserved {
			return nil
		}
	}
	peers := make([]foundation.Hash, len(hops))
	for index, hop := range hops {
		peers[index] = hop.Router
		r.peers[hop.Router] = struct{}{}
	}
	return &BuildReservation{owner: r, peers: peers}
}

// BuildReservation is an idempotently releasable pending-build peer claim.
type BuildReservation struct {
	owner *BuildReservations
	peers []foundation.Hash
	once  sync.Once
}

func (r *BuildReservation) Release() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.owner.mu.Lock()
		for _, peer := range r.peers {
			delete(r.owner.peers, peer)
		}
		r.owner.mu.Unlock()
		clear(r.peers)
		r.peers = nil
	})
}

func (r *BuildReservation) ReleaseAfter(delay time.Duration) {
	if r == nil {
		return
	}
	if delay <= 0 {
		r.Release()
		return
	}
	time.AfterFunc(delay, r.Release)
}
