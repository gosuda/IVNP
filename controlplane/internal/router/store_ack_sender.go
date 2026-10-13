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
	storeAckWorkers   = 4
	storeAckCapacity  = 32
	storeAckPerSource = 2
	storeAckTimeout   = 5 * time.Second
)

var errStoreAckOverloaded = errors.New("router: database store acknowledgement sender overloaded")

type storeAck struct {
	source   dataplane.RouterI2NPSource
	gateway  foundation.Hash
	tunnelID uint32
	status   foundation.I2NPDeliveryStatusMessage
}

// storeAckSender keeps slow, peer-selected reply routes off the serialized
// control queue. Admission counts queued and executing work; indirect sources
// share one anonymous budget. The send function must respect cancellation.
type storeAckSender struct {
	send    func(context.Context, foundation.Hash, uint32, foundation.I2NPDeliveryStatusMessage) error
	jobs    chan storeAck
	mu      sync.Mutex
	sources map[dataplane.RouterI2NPSource]int
	pending int
	idle    chan struct{}
	err     error
	ctx     context.Context
	cancel  context.CancelFunc
	started bool
	stopped bool
	workers sync.WaitGroup
}

func newStoreAckSender(send func(context.Context, foundation.Hash, uint32, foundation.I2NPDeliveryStatusMessage) error) *storeAckSender {
	idle := make(chan struct{})
	close(idle)
	return &storeAckSender{
		send: send, jobs: make(chan storeAck, storeAckCapacity),
		sources: make(map[dataplane.RouterI2NPSource]int), idle: idle,
	}
}

func (s *storeAckSender) Start(ctx context.Context) error {
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
	for range storeAckWorkers {
		s.workers.Go(s.run)
	}
	return nil
}

func storeAckSource(source dataplane.RouterI2NPSource) dataplane.RouterI2NPSource {
	if !source.Direct {
		return dataplane.RouterI2NPSource{}
	}
	return source
}

// Enqueue never waits for network I/O or free capacity. Saturated sources lose
// acknowledgements without delaying admission of unrelated control messages.
func (s *storeAckSender) Enqueue(source dataplane.RouterI2NPSource, gateway foundation.Hash, tunnelID uint32, status foundation.I2NPDeliveryStatusMessage) error {
	source = storeAckSource(source)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.stopped || s.ctx.Err() != nil {
		return dataplane.RouterErrControlStopped
	}
	if s.pending >= storeAckCapacity || s.sources[source] >= storeAckPerSource {
		return errStoreAckOverloaded
	}
	if s.pending == 0 {
		s.idle = make(chan struct{})
	}
	s.pending++
	s.sources[source]++
	// The channel has capacity storeAckCapacity, and pending includes active
	// sends, so this send cannot block while holding the admission lock.
	s.jobs <- storeAck{source: source, gateway: gateway, tunnelID: tunnelID, status: status}
	return nil
}

func (s *storeAckSender) run() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case ack := <-s.jobs:
			var err error
			if s.ctx.Err() == nil {
				ctx, cancel := context.WithTimeout(s.ctx, storeAckTimeout)
				err = s.send(ctx, ack.gateway, ack.tunnelID, ack.status)
				cancel()
			}
			s.complete(ack, err)
		}
	}
}

func (s *storeAckSender) complete(ack storeAck, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil && !errors.Is(err, context.Canceled) && s.err == nil {
		s.err = err
	}
	if count := s.sources[ack.source] - 1; count == 0 {
		delete(s.sources, ack.source)
	} else {
		s.sources[ack.source] = count
	}
	s.pending--
	if s.pending == 0 {
		close(s.idle)
	}
}

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
		case <-s.ctx.Done():
			return dataplane.RouterErrControlStopped
		case <-idle:
		}
	}
}

func (s *storeAckSender) Close() {
	s.mu.Lock()
	if !s.stopped {
		s.stopped = true
		if s.started {
			s.cancel()
		}
	}
	s.mu.Unlock()
	s.workers.Wait()
	// Workers leave on cancellation. Discard remaining queued acknowledgements
	// and release their budgets so WaitIdle cannot strand callers on shutdown.
	for {
		select {
		case ack := <-s.jobs:
			s.complete(ack, nil)
		default:
			return
		}
	}
}
