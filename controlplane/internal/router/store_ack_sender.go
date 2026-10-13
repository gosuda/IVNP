package router

import (
	"context"
	"errors"
	"sync"
	"time"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

const (
	databaseStoreAckWorkers        = 4
	databaseStoreAckCapacity       = 64
	databaseStoreAckSourceCapacity = 8
	maxDatabaseStoreAckTimeout     = 5 * time.Second
)

type databaseStoreAck struct {
	source   dataplane.RouterI2NPSource
	gateway  foundation.Hash
	tunnelID uint32
	status   foundation.I2NPDeliveryStatusMessage
}

// databaseStoreAckSender keeps outbound I/O off the serialized control worker.
// Queued and running sends share global and authenticated-source budgets.
// Sources without a direct authenticated peer share the anonymous budget.
type databaseStoreAckSender struct {
	send    func(context.Context, foundation.Hash, uint32, foundation.I2NPDeliveryStatusMessage) error
	timeout time.Duration
	jobs    chan databaseStoreAck

	mu       sync.Mutex
	bySource map[dataplane.RouterI2NPSource]int
	pending  int
	idle     chan struct{}
	err      error
	started  bool
	stopped  bool
	ctx      context.Context
	cancel   context.CancelFunc
	workers  sync.WaitGroup
}

func newDatabaseStoreAckSender(send func(context.Context, foundation.Hash, uint32, foundation.I2NPDeliveryStatusMessage) error, timeout time.Duration) *databaseStoreAckSender {
	idle := make(chan struct{})
	close(idle)
	return &databaseStoreAckSender{
		send:     send,
		timeout:  timeout,
		jobs:     make(chan databaseStoreAck, databaseStoreAckCapacity),
		bySource: make(map[dataplane.RouterI2NPSource]int),
		idle:     idle,
	}
}

func (s *databaseStoreAckSender) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return dataplane.RouterErrControlStopped
	}
	if s.started {
		return dataplane.RouterErrControlStarted
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.started = true
	for range databaseStoreAckWorkers {
		s.workers.Add(1)
		go s.run()
	}
	return nil
}

func databaseStoreAckAdmissionSource(source dataplane.RouterI2NPSource) dataplane.RouterI2NPSource {
	if !source.Direct {
		return dataplane.RouterI2NPSource{}
	}
	return source
}

// Enqueue never waits for a send or for available queue capacity.
// Saturated sources lose acknowledgements without delaying control ingress.
func (s *databaseStoreAckSender) Enqueue(job databaseStoreAck) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.stopped || s.ctx.Err() != nil {
		return dataplane.RouterErrControlStopped
	}
	source := databaseStoreAckAdmissionSource(job.source)
	if s.pending >= databaseStoreAckCapacity || s.bySource[source] >= databaseStoreAckSourceCapacity {
		return dataplane.RouterErrControlOverloaded
	}
	if s.pending == 0 {
		s.idle = make(chan struct{})
	}
	s.pending++
	s.bySource[source]++
	// The channel cannot fill: pending also counts jobs already executing.
	s.jobs <- job
	return nil
}

func (s *databaseStoreAckSender) complete(job databaseStoreAck, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil && !errors.Is(err, context.Canceled) && s.err == nil {
		s.err = err
	}
	source := databaseStoreAckAdmissionSource(job.source)
	if s.bySource[source] == 1 {
		delete(s.bySource, source)
	} else {
		s.bySource[source]--
	}
	s.pending--
	if s.pending == 0 {
		close(s.idle)
	}
}

func (s *databaseStoreAckSender) run() {
	defer s.workers.Done()
	for {
		select {
		case <-s.ctx.Done():
			// Discard queued sends, accounting for each, when shutting down.
			for {
				select {
				case job := <-s.jobs:
					s.complete(job, nil)
				default:
					return
				}
			}
		case job := <-s.jobs:
			if s.ctx.Err() != nil {
				s.complete(job, nil)
				continue
			}
			ctx, cancel := context.WithTimeout(s.ctx, s.timeout)
			err := s.send(ctx, job.gateway, job.tunnelID, job.status)
			cancel()
			s.complete(job, err)
		}
	}
}

func (s *databaseStoreAckSender) WaitIdle(ctx context.Context) error {
	for {
		s.mu.Lock()
		idle, pending, err := s.idle, s.pending, s.err
		s.mu.Unlock()
		if pending == 0 {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-idle:
		}
	}
}

// Close rejects new work, cancels running sends, and drains queued accounting.
func (s *databaseStoreAckSender) Close() {
	s.mu.Lock()
	if !s.stopped {
		s.stopped = true
		if s.started {
			s.cancel()
		}
	}
	s.mu.Unlock()
	s.workers.Wait()
}
