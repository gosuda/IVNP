package main

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const maxReseedHTTPConnections = 256

func newReseedHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

func serveReseedHTTP(server *http.Server, permits chan struct{}) error {
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}
	return server.Serve(&limitedListener{Listener: listener, permits: permits})
}

// limitedListener rejects connections above the shared cap before net/http
// allocates a serving goroutine. Accept remains responsive to listener closure.
type limitedListener struct {
	net.Listener
	permits chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.permits <- struct{}{}:
			return &limitedConn{Conn: conn, permits: l.permits}, nil
		default:
			_ = conn.Close()
		}
	}
}

type limitedConn struct {
	net.Conn
	permits chan struct{}
	once    sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.permits })
	return err
}
