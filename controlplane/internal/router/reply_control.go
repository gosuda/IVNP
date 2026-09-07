package router

import (
	"context"
	"errors"
	"sync"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

type ratchetReplyGate struct {
	done             chan struct{}
	err              error
	completed        bool
	policyGeneration uint64
	reservation      *ratchetReplyReservation
}

// A reservation pins reply admission before the receiver commits a session.
// Release rolls back an unsent reservation; Send transfers ownership to a worker.
type ratchetReplyReservation struct {
	mu          sync.Mutex
	sender      *StreamingTunnelSender
	target      foundation.Hash
	gate        *ratchetReplyGate
	previous    *ratchetReplyGate
	transferred bool
	activated   bool
	established bool
	released    bool
}

func (s *StreamingTunnelSender) ReserveRatchetReply(target foundation.Hash) (dataplane.RouterRatchetReplyReservation, error) {
	if s == nil || target == (foundation.Hash{}) {
		return nil, dataplane.RouterErrGarlicDestination
	}
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released || s.preparationCtx.Err() != nil {
		return nil, dataplane.RouterErrDataPlaneConfig
	}
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	previous := s.replyGates[target]
	if previous != nil && !previous.completed {
		return nil, dataplane.RouterErrRoutePreparationBusy
	}
	if previous == nil && len(s.replyGates) >= s.replyGateCapacity {
		for peer, failed := range s.replyGates {
			if !failed.completed {
				continue
			}
			s.execution.RetireRatchetPeer(peer)
			delete(s.replyGates, peer)
			break
		}
		if len(s.replyGates) >= s.replyGateCapacity {
			return nil, dataplane.RouterErrRoutePreparationBusy
		}
	}
	select {
	case s.replySlots <- struct{}{}:
	default:
		return nil, dataplane.RouterErrRoutePreparationBusy
	}
	gate := &ratchetReplyGate{done: make(chan struct{}), policyGeneration: s.policyGeneration}
	s.replyGates[target] = gate
	s.replies.Add(1)
	reservation := &ratchetReplyReservation{sender: s, target: target, gate: gate, previous: previous}
	gate.reservation = reservation
	return reservation, nil
}

func (r *ratchetReplyReservation) Activate() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released || r.transferred {
		return dataplane.RouterErrDataPlaneConfig
	}
	if err := r.sender.preparationCtx.Err(); err != nil {
		return err
	}
	r.activated = true
	return nil
}

func (r *ratchetReplyReservation) Release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.releaseLocked()
}

func (r *ratchetReplyReservation) releaseUnactivated() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.activated {
		r.releaseLocked()
	}
}

func (r *ratchetReplyReservation) releaseLocked() {
	if r.released || r.transferred {
		return
	}
	r.released = true
	r.restorePreviousGate()
	<-r.sender.replySlots
	r.sender.replies.Done()
}

func (r *ratchetReplyReservation) restorePreviousGate() {
	s := r.sender
	s.remoteMu.Lock()
	if r.previous != nil {
		s.replyGates[r.target] = r.previous
		r.gate.err = r.previous.err
	} else {
		delete(s.replyGates, r.target)
	}
	r.gate.completed = true
	r.gate.reservation = nil
	close(r.gate.done)
	s.remoteMu.Unlock()
}

func (r *ratchetReplyReservation) Send(ctx context.Context, packet []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released || r.transferred || !r.activated {
		return dataplane.RouterErrDataPlaneConfig
	}
	return r.sendLocked(ctx, packet)
}

func (r *ratchetReplyReservation) SendEstablished(ctx context.Context, packet []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released || r.transferred || r.activated {
		return dataplane.RouterErrDataPlaneConfig
	}
	r.established = true
	r.restorePreviousGate()
	return r.sendLocked(ctx, packet)
}

func (r *ratchetReplyReservation) sendLocked(ctx context.Context, packet []byte) error {
	r.transferred = true
	var err error
	switch {
	case len(packet) == 0:
		err = dataplane.RouterErrGarlicPacket
	case len(packet) > foundation.I2NPI2PDMaxPayload-4:
		err = foundation.I2NPErrPayloadTooLarge
	case ctx.Err() != nil:
		err = ctx.Err()
	case r.sender.preparationCtx.Err() != nil:
		err = r.sender.preparationCtx.Err()
	}
	if err != nil {
		r.complete(err)
		return err
	}
	owned := append([]byte(nil), packet...)
	go r.sendOwned(owned)
	return nil
}

func (r *ratchetReplyReservation) sendOwned(packet []byte) {
	s := r.sender
	ctx, cancel := context.WithTimeout(s.preparationCtx, s.preparationTimeout)
	var err error
	for {
		if err = ctx.Err(); err != nil {
			break
		}
		err = r.sendPrepared(ctx, packet)
		if !errors.Is(err, dataplane.RouterErrPreparedRouteMissing) {
			break
		}
		if s.awaitControl != nil {
			if err = s.awaitControl(ctx); err != nil {
				break
			}
		}
		if err = s.prepare(ctx, r.target); err != nil && !errors.Is(err, dataplane.RouterErrRouteGeneration) {
			break
		}
	}
	err = s.retireFailedRoute(r.target, err)
	if err != nil && s.logger != nil {
		s.logger.Debug("ratchet reply delivery failed", "error", err)
	}
	cancel()
	clear(packet)
	r.complete(err)
}

func (r *ratchetReplyReservation) sendPrepared(ctx context.Context, packet []byte) error {
	s := r.sender
	// Authorization changes wait for admitted replies, but publication renewal
	// remains independent of the handoff and may replace an unsent route.
	s.replyPolicyMu.RLock()
	defer s.replyPolicyMu.RUnlock()
	s.remoteMu.RLock()
	current := s.policyGeneration
	s.remoteMu.RUnlock()
	if current != r.gate.policyGeneration {
		return dataplane.RouterErrRouteGeneration
	}
	return s.execution.SendRatchetReply(ctx, r.target, packet)
}

func (r *ratchetReplyReservation) complete(err error) {
	s := r.sender
	if !r.established {
		s.remoteMu.Lock()
		r.gate.err = err
		r.gate.completed = true
		r.gate.reservation = nil
		if err == nil {
			delete(s.replyGates, r.target)
		}
		close(r.gate.done)
		s.remoteMu.Unlock()
	}
	<-s.replySlots
	s.replies.Done()
}

func (s *StreamingTunnelSender) waitForRatchetReply(ctx context.Context, target foundation.Hash) error {
	for {
		s.remoteMu.Lock()
		gate := s.replyGates[target]
		if gate == nil {
			s.remoteMu.Unlock()
			return nil
		}
		if gate.completed {
			err := gate.err
			s.remoteMu.Unlock()
			return err
		}
		if s.waiters >= s.waiterCapacity {
			s.remoteMu.Unlock()
			return dataplane.RouterErrRoutePreparationBusy
		}
		s.waiters++
		s.remoteMu.Unlock()
		var err error
		select {
		case <-gate.done:
			err = gate.err
		case <-ctx.Done():
			err = ctx.Err()
		case <-s.preparationCtx.Done():
			err = s.preparationCtx.Err()
		}
		s.remoteMu.Lock()
		s.waiters--
		s.remoteMu.Unlock()
		if err != nil {
			return err
		}
	}
}

func (s *StreamingTunnelSender) releaseReplyReservations() {
	s.remoteMu.Lock()
	reservations := make([]*ratchetReplyReservation, 0, len(s.replyGates))
	for _, gate := range s.replyGates {
		if gate.reservation != nil {
			reservations = append(reservations, gate.reservation)
		}
	}
	s.remoteMu.Unlock()
	for _, reservation := range reservations {
		reservation.releaseUnactivated()
	}
}
