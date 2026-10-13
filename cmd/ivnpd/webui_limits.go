package main

import (
	"net"
	"sync"
)

const (
	maxWebUIConnections = 128
	maxWebUISubscribers = 32
)

// webUILimitedListener rejects excess sockets before net/http starts a
// connection goroutine. Each accepted socket retains its slot until Close.
type webUILimitedListener struct {
	net.Listener
	slots chan struct{}
}

func newWebUILimitedListener(listener net.Listener, limit int) *webUILimitedListener {
	if limit <= 0 {
		panic("webui: connection limit must be positive")
	}
	return &webUILimitedListener{Listener: listener, slots: make(chan struct{}, limit)}
}

func (l *webUILimitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &webUILimitedConn{Conn: conn, slots: l.slots}, nil
		default:
			_ = conn.Close()
		}
	}
}

type webUILimitedConn struct {
	net.Conn
	slots     chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func (c *webUILimitedConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		<-c.slots
	})
	return c.closeErr
}
