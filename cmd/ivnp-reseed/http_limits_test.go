package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func newTestListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func TestReseedHTTPServerLimits(t *testing.T) {
	server := newReseedHTTPServer("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 10*time.Second || server.WriteTimeout != 30*time.Second || server.IdleTimeout != 30*time.Second || server.MaxHeaderBytes != reseedMaxHeaderBytes {
		t.Fatalf("unexpected HTTP bounds: %+v", server)
	}
}

func TestReseedHTTPRejectsOversizedHeaders(t *testing.T) {
	listener := newTestListener(t)
	server := newReseedHTTPServer(listener.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(listener) }()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nX-Pad: %s\r\n\r\n", strings.Repeat("a", reseedMaxHeaderBytes+8<<10)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusRequestHeaderFieldsTooLarge)
	}
}

func TestReseedHTTPRejectsSlowHeaders(t *testing.T) {
	listener := newTestListener(t)
	server := newReseedHTTPServer(listener.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.ReadHeaderTimeout = 50 * time.Millisecond
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(listener) }()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nX-Unfinished: "); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return // Go closes incomplete requests without a response.
		}
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusRequestTimeout)
	}
}

// notifyingListener tells the test when Accept is waiting for an incoming
// connection, so an idle listener cannot consume a shared connection slot.
type notifyingListener struct {
	net.Listener
	accepting chan struct{}
}

func (l *notifyingListener) Accept() (net.Conn, error) {
	close(l.accepting)
	return l.Listener.Accept()
}

func TestReseedConnectionLimitDoesNotReserveIdleSlots(t *testing.T) {
	slots := make(chan struct{}, 1)
	idleBase := &notifyingListener{Listener: newTestListener(t), accepting: make(chan struct{})}
	idle := newReseedLimitedListener(idleBase, slots)
	t.Cleanup(func() { _ = idle.Close() })
	idleDone := make(chan error, 1)
	go func() {
		conn, err := idle.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		idleDone <- err
	}()
	<-idleBase.accepting

	active := newReseedLimitedListener(newTestListener(t), slots)
	t.Cleanup(func() { _ = active.Close() })
	client, err := net.Dial("tcp", active.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, err := active.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		accepted <- err
	}()
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle listener reserved the only connection slot")
	}
	if err := idle.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-idleDone; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("idle listener shutdown = %v, want net.ErrClosed", err)
	}
}

func TestReseedConnectionLimitSharedAndReleased(t *testing.T) {
	slots := make(chan struct{}, 1)
	listenerA := newReseedLimitedListener(newTestListener(t), slots)
	listenerB := newReseedLimitedListener(newTestListener(t), slots)
	t.Cleanup(func() { _ = listenerA.Close(); _ = listenerB.Close() })

	clientA, err := net.Dial("tcp", listenerA.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()
	serverA, err := listenerA.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()
	if got := len(slots); got != 1 {
		t.Fatalf("connections at limit: got %d, want 1", got)
	}

	clientB, err := net.Dial("tcp", listenerB.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := listenerB.Accept()
		accepted <- acceptResult{conn: conn, err: err}
	}()
	select {
	case result := <-accepted:
		if result.conn != nil {
			_ = result.conn.Close()
		}
		t.Fatal("accepted above the shared connection limit")
	case <-time.After(50 * time.Millisecond):
	}

	if err := serverA.Close(); err != nil {
		t.Fatal(err)
	}
	var serverB net.Conn
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatal(result.err)
		}
		serverB = result.conn
	case <-time.After(2 * time.Second):
		t.Fatal("accept did not resume after a connection was closed")
	}
	if got := len(slots); got != 1 {
		t.Fatalf("connections after release: got %d, want 1", got)
	}
	if err := serverB.Close(); err != nil {
		t.Fatal(err)
	}
	_ = serverB.Close()
	if got := len(slots); got != 0 {
		t.Fatalf("connections after double close: got %d, want 0", got)
	}
}

func TestReseedConnectionLimitCloseUnblocksAccept(t *testing.T) {
	slots := make(chan struct{}, 1)
	listenerA := newReseedLimitedListener(newTestListener(t), slots)
	listenerB := newReseedLimitedListener(newTestListener(t), slots)
	t.Cleanup(func() { _ = listenerA.Close(); _ = listenerB.Close() })

	client, err := net.Dial("tcp", listenerA.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	serverConn, err := listenerA.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, err := listenerB.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		accepted <- err
	}()
	if err := listenerB.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-accepted:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("accept after shutdown = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("closing listener did not release blocked Accept")
	}
	if got := len(slots); got != 1 {
		t.Fatalf("closing another listener changed active connection count to %d", got)
	}
	_ = serverConn.Close()
	if got := len(slots); got != 0 {
		t.Fatalf("connection slot leaked after shutdown: %d", got)
	}
}
