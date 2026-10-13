package main

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	reseedMaxConnections = 256
	reseedMaxHeaderBytes = 16 << 10
)

// newReseedHTTPServer bounds the time and memory spent on each public request.
func newReseedHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    reseedMaxHeaderBytes,
	}
}

// reseedLimitedListener shares slots across public HTTP listeners. A slot is
// held from admission until the accepted connection is closed.
type reseedLimitedListener struct {
	net.Listener
	slots    chan struct{}
	stopped  chan struct{}
	stopOnce sync.Once
}

func newReseedLimitedListener(listener net.Listener, slots chan struct{}) net.Listener {
	return &reseedLimitedListener{
		Listener: listener,
		slots:    slots,
		stopped:  make(chan struct{}),
	}
}

func (l *reseedLimitedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	select {
	case l.slots <- struct{}{}:
		return &reseedLimitedConn{Conn: conn, slots: l.slots}, nil
	case <-l.stopped:
		_ = conn.Close()
		return nil, net.ErrClosed
	}
}

func (l *reseedLimitedListener) Close() error {
	l.stopOnce.Do(func() { close(l.stopped) })
	return l.Listener.Close()
}

type reseedLimitedConn struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (c *reseedLimitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return err
}
