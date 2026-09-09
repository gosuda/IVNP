package router

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"gosuda.org/ivnp/foundation"
)

var (
	ErrControlOverloaded         = errors.New("router: control ingress overloaded")
	ErrControlStopped            = errors.New("router: control ingress stopped")
	ErrControlStarted            = errors.New("router: control ingress already started")
	errMissingControlHandler     = errors.New("router: missing control handler")
	errInvalidControlQueueLimits = errors.New("router: invalid control queue limits")
)

// ControlMessage retains authenticated provenance across the asynchronous handoff.
// Message.Payload belongs to the caller until Enqueue returns; handlers receive a copy.
type ControlMessage struct {
	Source        I2NPSource
	Message       foundation.I2NPMessage
	NowMillis     uint64
	FromFloodfill bool
	// PrivateStore is a control-plane admission decision, never a wire flag.
	PrivateStore bool
}

// ControlIngress never waits for control execution or queue capacity.
type ControlIngress interface {
	Accepts(foundation.I2NPMessage) bool
	Enqueue(ControlMessage) error
}

// ControlHandler must stop blocking work when its lifecycle context is canceled.
type ControlHandler interface {
	Accepts(foundation.I2NPMessage) bool
	HandleControl(context.Context, ControlMessage) error
}

// ControlQueueLimits count both queued and executing messages. Sources without a
// direct authenticated peer share a single anonymous admission budget.
type ControlQueueLimits struct {
	Items       int
	Bytes       int
	SourceItems int
	SourceBytes int
}

func DefaultControlQueueLimits() ControlQueueLimits {
	return ControlQueueLimits{Items: 256, Bytes: 4 << 20, SourceItems: 32, SourceBytes: 512 << 10}
}

type controlUsage struct {
	items int
	bytes int
}

type ControlQueue struct {
	handler   ControlHandler
	limits    ControlQueueLimits
	messages  chan ControlMessage
	mu        sync.Mutex
	usage     controlUsage
	sources   map[I2NPSource]controlUsage
	started   bool
	stopped   bool
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	idle      chan struct{}
	err       error
	submitted uint64
	completed uint64
	progress  chan struct{}
}

func NewControlQueue(handler ControlHandler, limits ControlQueueLimits) (*ControlQueue, error) {
	if handler == nil {
		return nil, errMissingControlHandler
	}
	positiveLimits := limits.Items > 0 && limits.Bytes > 0 && limits.SourceItems > 0 && limits.SourceBytes > 0
	withinGlobalLimits := limits.SourceItems <= limits.Items && limits.SourceBytes <= limits.Bytes
	if !positiveLimits || !withinGlobalLimits {
		return nil, errInvalidControlQueueLimits
	}
	idle := make(chan struct{})
	close(idle)
	return &ControlQueue{handler: handler, limits: limits, messages: make(chan ControlMessage, limits.Items), sources: make(map[I2NPSource]controlUsage), done: make(chan struct{}), idle: idle}, nil
}

func (q *ControlQueue) Accepts(message foundation.I2NPMessage) bool {
	return q.handler.Accepts(message)
}

func (q *ControlQueue) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.stopped {
		return ErrControlStopped
	}
	if q.started {
		return ErrControlStarted
	}
	q.ctx, q.cancel = context.WithCancel(ctx)
	q.started = true
	go q.run()
	return nil
}

func controlAdmissionSource(source I2NPSource) I2NPSource {
	if !source.Direct {
		return I2NPSource{}
	}
	return source
}

func (q *ControlQueue) Enqueue(message ControlMessage) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.started || q.stopped || q.ctx.Err() != nil {
		return ErrControlStopped
	}
	if !q.Accepts(message.Message) {
		return ErrUnhandledI2NP
	}
	source := controlAdmissionSource(message.Source)
	usage := q.sources[source]
	size := len(message.Message.Payload)
	if q.usage.items >= q.limits.Items || size > q.limits.Bytes-q.usage.bytes || usage.items >= q.limits.SourceItems || size > q.limits.SourceBytes-usage.bytes {
		return ErrControlOverloaded
	}
	message.Message.Payload = bytes.Clone(message.Message.Payload)
	if q.usage.items == 0 {
		q.idle = make(chan struct{})
	}
	q.usage.items++
	q.usage.bytes += size
	usage.items++
	usage.bytes += size
	q.sources[source] = usage
	q.submitted++
	q.messages <- message
	return nil
}

func (q *ControlQueue) complete(message ControlMessage, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err != nil && !errors.Is(err, context.Canceled) && q.err == nil {
		q.err = err
	}
	q.completed++
	if q.progress != nil {
		close(q.progress)
		q.progress = nil
	}
	size := len(message.Message.Payload)
	source := controlAdmissionSource(message.Source)
	usage := q.sources[source]
	usage.items--
	usage.bytes -= size
	if usage.items == 0 {
		delete(q.sources, source)
	} else {
		q.sources[source] = usage
	}
	q.usage.items--
	q.usage.bytes -= size
	if q.usage.items == 0 {
		close(q.idle)
	}
}

func (q *ControlQueue) run() {
	defer close(q.done)
	for {
		select {
		case <-q.ctx.Done():
			q.mu.Lock()
			q.stopped = true
			q.mu.Unlock()
			for {
				select {
				case message := <-q.messages:
					clear(message.Message.Payload)
					q.complete(message, nil)
				default:
					return
				}
			}
		case message := <-q.messages:
			if q.ctx.Err() != nil {
				clear(message.Message.Payload)
				q.complete(message, nil)
				continue
			}
			q.complete(message, q.handler.HandleControl(q.ctx, message))
		}
	}
}

// WaitIdle waits for all admitted work, returning the first execution error.
// New admissions may extend the wait. It does not shut down the queue.
func (q *ControlQueue) WaitIdle(ctx context.Context) error {
	for {
		q.mu.Lock()
		idle, pending, err := q.idle, q.usage.items, q.err
		q.mu.Unlock()
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

// Barrier waits only for work admitted before this call. Handler rejection is
// still completion: callers inspect the resulting state, not unrelated handler
// errors. Cancellation or stopped ingress prevents a successful barrier.
func (q *ControlQueue) Barrier(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	q.mu.Lock()
	watermark := q.submitted
	for {
		if err := ctx.Err(); err != nil {
			q.mu.Unlock()
			return err
		}
		if !q.started || q.stopped || q.ctx.Err() != nil {
			q.mu.Unlock()
			return ErrControlStopped
		}
		if q.completed >= watermark {
			q.mu.Unlock()
			return nil
		}
		if q.progress == nil {
			q.progress = make(chan struct{})
		}
		progress, stopped := q.progress, q.ctx.Done()
		q.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stopped:
			if err := ctx.Err(); err != nil {
				return err
			}
			return ErrControlStopped
		case <-progress:
		}
		q.mu.Lock()
	}
}

// Close cancels the active handler, discards queued messages, and joins the worker.
func (q *ControlQueue) Close() error {
	q.mu.Lock()
	if !q.stopped {
		q.stopped = true
		if q.started {
			q.cancel()
		} else {
			close(q.done)
		}
	}
	q.mu.Unlock()
	<-q.done
	return nil
}
