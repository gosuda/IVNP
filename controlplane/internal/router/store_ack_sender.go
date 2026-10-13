package router

import (
	"context"
	"errors"
	"sync"
	"time"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

var (
	ErrStoreAckOverloaded = errors.New("router: database store acknowledgement queue overloaded")
	ErrStoreAckStopped    = errors.New("router: database store acknowledgement sender stopped")
)

const (
	storeAckQueueCapacity  = 64
	storeAckSourceCapacity = 8
	storeAckWorkers        = 4
)

type storeAckJob struct {
	source   dataplane.RouterI2NPSource
	gateway  foundation.Hash
	tunnelID uint32
	status   foundation.I2NPDeliveryStatusMessage
}

// storeAckSender isolates untrusted reply routes from the serialized control
// worker. Admission counts queued and executing sends, including anonymous
// sources as one group. Its send callback must honor context cancellation.
type storeAckSender struct {
	send           func(context.Context, foundation.Hash, uint32, foundation.I2NPDeliveryStatusMessage) error
	timeout        time.Duration
	jobs           chan storeAckJob
	sourceCapacity int
	workers        int

	mu      sync.Mutex
	sources map[dataplane.RouterI2NPSource]int
	pending int
	idle    chan struct{}
	err     error
	ctx     context.Context
	cancel  context.CancelFunc
	started bool
	stopped bool
	wg      sync.WaitGroup
}

func newStoreAckSender(
	send func(context.Context, foundation.Hash, uint32, foundation.I2NPDeliveryStatusMessage) error,
	timeout time.Duration,
	limits dataplane.RouterControlQueueLimits,
) *storeAckSender {
	capacity := min(limits.Items, storeAckQueueCapacity)
	idle := make(chan struct{})
	close(idle)
	return &storeAckSender{
		send:           send,
		timeout:        timeout,
		jobs:           make(chan storeAckJob, capacity),
		sourceCapacity: min(limits.SourceItems, storeAckSourceCapacity, capacity),
		workers:        min(capacity, storeAckWorkers),
		sources:        make(map[dataplane.RouterI2NPSource]int),
		idle:           idle,
	}
}

func (s *storeAckSender) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.stopped {
		return ErrStoreAckStopped
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.started = true
	s.wg.Add(s.workers)
	for range s.workers {
		go s.run()
	}
	return nil
}

func storeAckAdmissionSource(source dataplane.RouterI2NPSource) dataplane.RouterI2NPSource {
	if !source.Direct {
		return dataplane.RouterI2NPSource{}
	}
	return source
}

// Enqueue is nonblocking. A rejected acknowledgement never starts network I/O.
func (s *storeAckSender) Enqueue(job storeAckJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.stopped || s.ctx.Err() != nil {
		return ErrStoreAckStopped
	}
	job.source = storeAckAdmissionSource(job.source)
	if s.pending == cap(s.jobs) || s.sources[job.source] >= s.sourceCapacity {
		return ErrStoreAckOverloaded
	}
	if s.pending == 0 {
		s.idle = make(chan struct{})
	}
	s.pending++
	s.sources[job.source]++
	// The channel cannot be full: pending includes jobs executing in workers.
	s.jobs <- job
	return nil
}

func (s *storeAckSender) complete(job storeAckJob, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil && !errors.Is(err, context.Canceled) && s.err == nil {
		s.err = err
	}
	s.pending--
	count := s.sources[job.source] - 1
	if count == 0 {
		delete(s.sources, job.source)
	} else {
		s.sources[job.source] = count
	}
	if s.pending == 0 {
		close(s.idle)
	}
}

func (s *storeAckSender) run() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
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

// WaitIdle joins acknowledgements admitted before control ingress becomes idle.
func (s *storeAckSender) WaitIdle(ctx context.Context) error {
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

// Close cancels active sends, joins workers, and drops queued replies.
// It is safe to call before Start or more than once.
func (s *storeAckSender) Close() error {
	s.mu.Lock()
	if !s.stopped {
		s.stopped = true
		if s.cancel != nil {
			s.cancel()
		}
	}
	s.mu.Unlock()
	s.wg.Wait()
	for {
		select {
		case job := <-s.jobs:
			s.complete(job, nil)
		default:
			return nil
		}
	}
}
