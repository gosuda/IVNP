// Package frontend provides local client-facing I2P proxy listeners and an authenticated control server.
package frontend

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
)

var (
	ErrInvalidConfig = errors.New("clientapi: invalid configuration")
	ErrI2PTarget     = errors.New("clientapi: invalid I2P target")
)

type server struct {
	mu         sync.Mutex
	listener   *trackedListener
	context    context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	activities sync.WaitGroup
	started    bool
	closed     bool
}

func (s *server) start(ctx context.Context, address string, allowRemote bool, maxConnections int, listen func(context.Context, string, string) (net.Listener, error), serve func(net.Listener)) error {
	startRejected := ctx == nil || maxConnections < 1
	if !startRejected {
		startRejected = (!allowRemote && !isLocalAddress(address))
	}
	if startRejected {
		return ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.closed {
		return net.ErrClosed
	}
	if listen ==
		nil {
		listen =
			func(ctx context.Context, network,
				address string) (net.
				Listener, error) {
				return (&net.ListenConfig{}).Listen(ctx, network, address)
			}
	}

	listener, err := listen(ctx, "tcp", address)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		_ = listener.Close()
		return err
	}
	lifecycle, cancel := context.WithCancel(ctx)
	s.listener = newTrackedListener(listener, maxConnections)
	s.context = lifecycle
	s.cancel = cancel
	s.done = make(chan struct{})
	s.activities.Add(1)
	s.started = true
	go func() {
		serve(s.listener)
		_ = s.close()
		s.activities.Done()
		s.activities.Wait()
		close(s.done)
	}()
	go func() {
		select {
		case <-lifecycle.Done():
			_ = s.close()
		case <-s.done:
		}
	}()
	return nil
}

func (s *server) close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	cancel := s.cancel
	listener := s.listener
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if listener != nil {
		return listener.Close()
	}
	return nil
}

func (s *server) wait() error {
	s.mu.Lock()
	done := s.done
	started := s.started
	s.mu.Unlock()
	if !started {
		return net.ErrClosed
	}
	<-done
	return nil
}

func (s *server) addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *server) runningContext() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.context == nil {
		return context.Background()
	}
	return s.context
}

func (s *server) serveActivity(serve func()) {
	s.activities.Add(1)
	defer s.activities.Done()
	serve()
}

func (s *server) goServeActivity(serve func()) {
	s.activities.Go(func() {
		serve()
	})
}

func (s *server) connState(_ net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		s.activities.Add(1)
	case http.StateClosed, http.StateHijacked:
		s.activities.Done()
	}
}

type trackedListener struct {
	net.Listener
	sem chan struct{}

	mu     sync.Mutex
	conns  map[*trackedConn]struct{}
	closed bool
}

func newTrackedListener(listener net.Listener, maxConnections int) *trackedListener {
	return &trackedListener{Listener: listener, sem: make(chan struct{}, maxConnections), conns: make(map[*trackedConn]struct{})}
}

// NewConnectionLimitedListener limits the number of simultaneous active connections on listener.
func NewConnectionLimitedListener(listener net.Listener, maxConnections int) net.Listener {
	if maxConnections < 1 {
		maxConnections = 1
	}
	return newTrackedListener(listener, maxConnections)
}

func (l *trackedListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	wrapped := &trackedConn{Conn: conn, listener: l}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = conn.Close()
		<-l.sem
		return nil, net.ErrClosed
	}
	l.conns[wrapped] = struct{}{}
	l.mu.Unlock()
	return wrapped, nil
}

func (l *trackedListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	conns := make([]*trackedConn, 0, len(l.conns))
	for conn := range l.conns {
		conns = append(conns, conn)
	}
	l.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	return l.Listener.Close()
}

type trackedConn struct {
	net.Conn
	listener *trackedListener
	once     sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.listener.mu.Lock()
		delete(c.listener.conns, c)
		c.listener.mu.Unlock()
		<-c.listener.sem
	})
	return err
}

func isLocalAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
