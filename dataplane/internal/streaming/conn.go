package streaming

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const DefaultWriteQueue = 16

// ByteStream represents the underlying transport for a streaming connection.
type ByteStream interface {
	io.Reader
	io.Writer
	io.Closer
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// Conn wraps a ByteStream as a net.Conn with bounded write queuing and state tracking.
type Conn struct {
	stream ByteStream

	writes chan *writeRequest
	done   chan struct{}
	once   sync.Once

	readMu sync.Mutex

	deadlineMu          sync.Mutex
	readDeadline        time.Time
	writeDeadline       time.Time
	activeWriteDeadline time.Time
	activeRequest       *writeRequest
	writeActive         bool

	stateMu sync.Mutex
	state   State

	closeErr error
}

type writeRequest struct {
	data            []byte
	deadline        time.Time
	result          chan writeResult
	canceled        atomic.Bool
	active          atomic.Bool
	deadlineApplied atomic.Bool
}

type writeResult struct {
	n   int
	err error
}

// NewConn constructs a Conn wrapping the given ByteStream and initial State.
func NewConn(stream ByteStream, state State, queueSize ...int) *Conn {
	size := DefaultWriteQueue
	if len(queueSize) > 0 && queueSize[0] > 0 {
		size = queueSize[0]
	}
	conn := &Conn{
		stream: stream,
		writes: make(chan *writeRequest, size),
		done:   make(chan struct{}),
		state:  state,
	}
	go conn.writeLoop()
	return conn
}

// State returns a snapshot of the current streaming connection state.
func (c *Conn) State() State {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.state
}

// OnPacket processes an incoming streaming packet and transitions the connection state.
func (c *Conn) OnPacket(packet Packet) Action {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.state.OnPacket(packet)
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.isClosed() {
		return 0, net.ErrClosed
	}
	if err := c.applyReadDeadline(); err != nil {
		return 0, err
	}
	n, err := c.stream.Read(p)
	if err != nil && c.isClosed() {
		return n, net.ErrClosed
	}
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		if c.isClosed() {
			return 0, net.ErrClosed
		}
		return 0, nil
	}
	if c.isClosed() {
		return 0, net.ErrClosed
	}

	request := writeRequest{
		data:     p,
		deadline: c.currentWriteDeadline(),
		result:   make(chan writeResult, 1),
	}
	if err := c.enqueue(&request); err != nil {
		return 0, err
	}
	return c.awaitWrite(&request)
}

func (c *Conn) enqueue(request *writeRequest) error {
	timer, timeout := deadlineTimer(request.deadline)
	if timer != nil {
		defer timer.Stop()
	}
	select {
	case c.writes <- request:
		return nil
	case <-c.done:
		return net.ErrClosed
	case <-timeout:
		return timeoutError{}
	}
}

func (c *Conn) awaitWrite(request *writeRequest) (int, error) {
	timer, timeout := deadlineTimer(request.deadline)
	if timer != nil {
		defer timer.Stop()
	}
	select {
	case result := <-request.result:
		return c.normalizeWriteResult(request, result)
	case <-c.done:
		request.canceled.Store(true)
		if request.active.Load() {
			result := <-request.result
			return c.normalizeWriteResult(request, result)
		}
		return 0, net.ErrClosed
	case <-timeout:
		request.canceled.Store(true)
		if request.active.Load() {
			result := <-request.result
			return c.normalizeWriteResult(request, result)
		}
		return 0, timeoutError{}
	}
}

func (c *Conn) writeLoop() {
	for {
		select {
		case <-c.done:
			c.failQueuedWrites()
			return
		case request := <-c.writes:
			// Once a request leaves the queue its caller must wait for this
			// worker's result, even if Close or its deadline races dequeue.
			request.active.Store(true)
			if request.canceled.Load() || c.isClosed() {
				request.result <- writeResult{err: net.ErrClosed}
				continue
			}
			if err := c.beginWrite(request); err != nil {
				request.result <- writeResult{err: err}
				continue
			}
			n, err := c.stream.Write(request.data)
			activeDeadline := c.endWrite()
			deadlineFailure := err != nil && !activeDeadline.IsZero()
			if deadlineFailure && (deadlineExpired(activeDeadline) || c.isClosed()) { // A deadline installed on an already-active request remains
				// its outcome if Close races the underlying stream's wake-up.
				err = timeoutError{}
			} else if err != nil && c.isClosed() && !isTimeoutError(err) {
				err = net.ErrClosed
			}
			request.result <- writeResult{n: n, err: err}
		}
	}
}

func (c *Conn) failQueuedWrites() {
	for {
		select {
		case request := <-c.writes:
			request.result <- writeResult{err: net.ErrClosed}
		default:
			return
		}
	}
}

func (c *Conn) Close() error {
	called := false
	c.once.Do(func() {
		called = true
		close(c.done)
		c.stateMu.Lock()
		if c.state.Status != Reset {
			c.state.Status = Closed
		}
		c.stateMu.Unlock()
		c.closeErr = c.stream.Close()
	})
	if !called {
		return net.ErrClosed
	}
	return c.closeErr
}

func (c *Conn) LocalAddr() net.Addr {
	if stream, ok := c.stream.(interface{ LocalAddr() net.Addr }); ok {
		return stream.LocalAddr()
	}
	return streamAddr("stream")
}

func (c *Conn) RemoteAddr() net.Addr {
	if stream, ok := c.stream.(interface{ RemoteAddr() net.Addr }); ok {
		return stream.RemoteAddr()
	}
	return streamAddr("stream")
}

func (c *Conn) SetDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline, c.writeDeadline = deadline, deadline
	readErr := c.stream.SetReadDeadline(deadline)
	var writeErr error
	if c.writeActive {
		c.activeWriteDeadline = deadline
		c.activeRequest.deadlineApplied.Store(true)
		writeErr = c.stream.SetWriteDeadline(deadline)
	}
	c.deadlineMu.Unlock()
	return errors.Join(readErr, writeErr)
}

func (c *Conn) SetReadDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = deadline
	err := c.stream.SetReadDeadline(deadline)
	c.deadlineMu.Unlock()
	return err
}

func (c *Conn) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = deadline
	var err error
	if c.writeActive {
		c.activeWriteDeadline = deadline
		c.activeRequest.deadlineApplied.Store(true)
		err = c.stream.SetWriteDeadline(deadline)
	}
	c.deadlineMu.Unlock()
	return err
}

func (c *Conn) currentReadDeadline() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.readDeadline
}

func (c *Conn) currentWriteDeadline() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.writeDeadline
}

func (c *Conn) applyReadDeadline() error {
	c.deadlineMu.Lock()
	err := c.stream.SetReadDeadline(c.readDeadline)
	c.deadlineMu.Unlock()
	return err
}

func (c *Conn) beginWrite(request *writeRequest) error {
	c.deadlineMu.Lock()
	c.writeActive, c.activeWriteDeadline, c.activeRequest = true, request.deadline, request
	err := c.stream.SetWriteDeadline(request.deadline)
	if err != nil {
		c.writeActive = false
		c.activeWriteDeadline = time.Time{}
		c.activeRequest = nil
	}
	c.deadlineMu.Unlock()
	return err
}

func (c *Conn) endWrite() time.Time {
	c.deadlineMu.Lock()
	deadline := c.activeWriteDeadline
	if deadline.IsZero() {
		deadline = c.writeDeadline
	}
	c.writeActive = false
	c.activeWriteDeadline = time.Time{}
	c.activeRequest = nil
	c.deadlineMu.Unlock()
	return deadline
}

func (c *Conn) normalizeWriteResult(request *writeRequest, result writeResult) (int, error) {
	if c.isClosed() && isTimeoutError(result.err) && request.deadline.IsZero() && !request.deadlineApplied.Load() {
		return result.n, net.ErrClosed
	}
	return result.n, result.err
}

func isTimeoutError(err error) bool {
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

func deadlineExpired(deadline time.Time) bool {
	// Timers can wake the writer that observes closure a scheduling quantum
	// after the caller whose matching deadline has already expired. Preserve
	// the deadline result at that boundary instead of changing it to closed.
	return !deadline.IsZero() && time.Until(deadline) <= time.Millisecond
}

func (c *Conn) isClosed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func deadlineTimer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	timer := time.NewTimer(time.Until(deadline))
	return timer, timer.C
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type streamAddr string

func (a streamAddr) Network() string { return "stream" }
func (a streamAddr) String() string  { return string(a) }
