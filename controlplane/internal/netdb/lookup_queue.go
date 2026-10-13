package netdb

import (
	"context"

	"gosuda.org/ivnp/foundation"
)

const lookupResponderSourceQueue = 8

// LookupSource is authenticated ingress provenance. A non-direct delivery
// does not authenticate Peer and therefore shares the anonymous source budget.
type LookupSource struct {
	Peer   foundation.Hash
	Direct bool
}

type lookupJob struct {
	source foundation.Hash
	lookup foundation.I2NPDatabaseLookupMessage
}

type lookupSourceState struct {
	jobs   []lookupJob
	active bool
}

// lookupQueue is protected by LookupResponder.mu. Reservations include both
// queued jobs and the single executing job per source; ready is round-robin.
type lookupQueue struct {
	sources  map[foundation.Hash]*lookupSourceState
	ready    []foundation.Hash
	reserved int
	wake     chan struct{}
}

func newLookupQueue() lookupQueue {
	return lookupQueue{
		sources: make(map[foundation.Hash]*lookupSourceState),
		wake:    make(chan struct{}, 1),
	}
}

func (q *lookupQueue) canAdmit(peer foundation.Hash) error {
	if state := q.sources[peer]; state != nil {
		inFlight := 0
		if state.active {
			inFlight = 1
		}
		if len(state.jobs)+inFlight >= lookupResponderSourceQueue {
			return ErrLookupResponderSourceFull
		}
	}
	if q.reserved >= lookupResponderQueue {
		return ErrLookupResponderFull
	}
	return nil
}

// push requires the caller to have checked canAdmit under the same lock.
func (q *lookupQueue) push(job lookupJob) {
	state := q.sources[job.source]
	if state == nil {
		state = &lookupSourceState{}
		q.sources[job.source] = state
	}
	state.jobs = append(state.jobs, job)
	q.reserved++
	if !state.active && len(state.jobs) == 1 {
		q.ready = append(q.ready, job.source)
		q.signal()
	}
}

func (q *lookupQueue) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// pop selects the next runnable source, never a second job for an active
// source. Waking the next worker while ready is nonempty prevents lost wakes.
func (q *lookupQueue) pop() (lookupJob, bool) {
	if len(q.ready) == 0 {
		return lookupJob{}, false
	}
	peer := q.ready[0]
	q.ready[0] = foundation.Hash{}
	q.ready = q.ready[1:]
	state := q.sources[peer]
	job := state.jobs[0]
	state.jobs[0] = lookupJob{}
	state.jobs = state.jobs[1:]
	state.active = true
	if len(q.ready) != 0 {
		q.signal()
	}
	return job, true
}

func (q *lookupQueue) finish(peer foundation.Hash) {
	state := q.sources[peer]
	state.active = false
	q.reserved--
	if len(state.jobs) == 0 {
		delete(q.sources, peer)
		return
	}
	q.ready = append(q.ready, peer)
	q.signal()
}

func (q *lookupQueue) drain() {
	for _, state := range q.sources {
		for i := range state.jobs {
			clearLookupJob(&state.jobs[i])
		}
	}
	clear(q.sources)
	q.ready = nil
	q.reserved = 0
}

func (r *LookupResponder) nextJob(ctx context.Context) (lookupJob, bool) {
	for {
		if ctx.Err() != nil {
			return lookupJob{}, false
		}
		r.mu.Lock()
		job, ok := r.queue.pop()
		r.mu.Unlock()
		if ok {
			return job, true
		}
		select {
		case <-ctx.Done():
			return lookupJob{}, false
		case <-r.queue.wake:
		}
	}
}
