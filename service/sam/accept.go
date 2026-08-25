package sam

import (
	"context"
	"net"

	"gosuda.org/ivnp/internal/ingress"
)

type acceptRequest struct {
	ctx    context.Context
	result chan acceptResult
}

type acceptResult struct {
	connection net.Conn
	err        error
}

// acceptAttachment queues the SAM attachment, not the I2P connection. One
// session-owned worker performs Listener.Accept in request order, providing the
// FIFO guarantee required when multiple STREAM ACCEPT sockets are pending.
func (s *samSession) acceptAttachment(ctx context.Context) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	reservation := s.server.config.AcceptReservationBytes
	if !s.reserve(reservation) {
		return nil, errQueueBudget
	}
	defer s.release(reservation)
	listener, err := s.ensureListener()
	if err != nil {
		return nil, err
	}
	s.acceptOnce.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.ctx.Err() != nil {
			return
		}
		s.acceptIncoming = make(chan acceptResult, 1)
		s.wg.Add(2)
		go s.acceptIncomingLoop(listener, s.acceptIncoming)
		go s.acceptLoop(listener, s.acceptIncoming)
	})
	if s.acceptIncoming == nil {
		return nil, net.ErrClosed
	}
	request := acceptRequest{ctx: ctx, result: make(chan acceptResult)}
	select {
	case s.acceptRequests <- request:
		s.acceptAdmissions.Add(1)
	case <-s.ctx.Done():
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case result := <-request.result:
		return result.connection, result.err
	case <-s.ctx.Done():
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *samSession) acceptIncomingLoop(listener net.Listener, incoming chan<- acceptResult) {
	defer s.wg.Done()
	var workerErr error
	defer func() {
		if value := recover(); value != nil {
			workerErr = ingress.Report(value, s.server.config.PanicReporter, ingress.BoundarySAMWorker, listener.Addr())
		}
		_ = listener.Close()
		if workerErr != nil {
			select {
			case incoming <- acceptResult{err: workerErr}:
			case <-s.ctx.Done():
			}
		}
		close(incoming)
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			workerErr = err
			return
		}
		select {
		case incoming <- acceptResult{connection: connection}:
		case <-s.ctx.Done():
			_ = connection.Close()
			return
		}
	}
}

// acceptLoop independently accepts inbound streams and assigns each stream to
// the oldest attachment whose context is still live. Cancellation therefore
// cannot leave a dead attachment at the head or consume the next stream.
func (s *samSession) acceptLoop(listener net.Listener, incoming <-chan acceptResult) {
	defer s.wg.Done()
	pending := make([]acceptRequest, 0, s.server.config.SessionQueue)
	var held acceptResult
	haveHeld := false
	defer func() {
		if value := recover(); value != nil {
			err := ingress.Report(value, s.server.config.PanicReporter, ingress.BoundarySAMWorker, listener.Addr())
			s.failPendingAcceptRequests(pending, err)
			_ = listener.Close()
		}
		if haveHeld && held.connection != nil {
			_ = held.connection.Close()
		}
	}()
	for {
		for len(pending) != 0 && pending[0].ctx.Err() != nil {
			s.acceptCancellations.Add(1)
			pending = pending[1:]
		}
		if haveHeld && held.err != nil {
			s.failPendingAcceptRequests(pending, held.err)
			s.failAcceptRequests(held.err)
			return
		}
		if haveHeld && len(pending) != 0 {
			request := pending[0]
			pending = pending[1:]
			select {
			case request.result <- held:
				haveHeld = false
				held = acceptResult{}
			case <-request.ctx.Done():
				s.acceptCancellations.Add(1)
				continue
			case <-s.ctx.Done():
				return
			}
			continue
		}
		if len(pending) == 0 {
			select {
			case request := <-s.acceptRequests:
				pending = append(pending, request)
			case <-s.ctx.Done():
				s.failPendingAcceptRequests(pending, net.ErrClosed)
				return
			}
			continue
		}
		select {
		case request := <-s.acceptRequests:
			pending = append(pending, request)
		case <-pending[0].ctx.Done():
			s.acceptCancellations.Add(1)
			pending = pending[1:]
		case result, ok := <-incoming:
			if !ok {
				s.failPendingAcceptRequests(pending, net.ErrClosed)
				return
			}
			held, haveHeld = result, true
		case <-s.ctx.Done():
			s.failPendingAcceptRequests(pending, net.ErrClosed)
			return
		}
	}
}

func (s *samSession) failPendingAcceptRequests(requests []acceptRequest, err error) {
	for _, request := range requests {
		select {
		case request.result <- acceptResult{err: err}:
		case <-request.ctx.Done():
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *samSession) failAcceptRequests(err error) {
	for {
		select {
		case request := <-s.acceptRequests:
			select {
			case request.result <- acceptResult{err: err}:
			case <-request.ctx.Done():
			case <-s.ctx.Done():
				return
			}
		default:
			return
		}
	}
}
