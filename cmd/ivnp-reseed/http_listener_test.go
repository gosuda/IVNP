package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestReseedHTTPServerLimits(t *testing.T) {
	server := newReseedHTTPServer(":8080", http.NotFoundHandler())
	if server.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 5s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != 10*time.Second {
		t.Errorf("ReadTimeout = %v, want 10s", server.ReadTimeout)
	}
	if server.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout = %v, want 30s", server.WriteTimeout)
	}
	if server.IdleTimeout != 30*time.Second {
		t.Errorf("IdleTimeout = %v, want 30s", server.IdleTimeout)
	}
	if server.MaxHeaderBytes != 16<<10 {
		t.Errorf("MaxHeaderBytes = %d, want 16384", server.MaxHeaderBytes)
	}
}

func TestReseedHTTPServerClosesSlowHeaders(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := newReseedHTTPServer(listener.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.ReadHeaderTimeout = 100 * time.Millisecond
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-stopped:
			if err != http.ErrServerClosed {
				t.Errorf("Serve() error = %v, want ErrServerClosed", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve did not stop")
		}
	})

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /health HTTP/1.1\r\nHost: localhost\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("incomplete headers kept the connection open: %v", err)
	}
	if bytes.Contains(response, []byte("200 OK")) {
		t.Fatalf("incomplete headers reached handler: %q", response)
	}
}

func TestReseedHTTPConnectionCapSharedBetweenListeners(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	permits := make(chan struct{}, 1)
	firstLimited := &limitedListener{Listener: first, permits: permits}
	secondLimited := &limitedListener{Listener: second, permits: permits}
	type accepted struct {
		conn net.Conn
		err  error
	}
	accept := func(listener net.Listener) <-chan accepted {
		result := make(chan accepted, 1)
		go func() {
			conn, err := listener.Accept()
			result <- accepted{conn: conn, err: err}
		}()
		return result
	}
	firstAccepted := accept(firstLimited)
	firstClient, err := net.Dial("tcp", first.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()

	var held net.Conn
	select {
	case result := <-firstAccepted:
		if result.err != nil {
			t.Fatal(result.err)
		}
		held = result.conn
	case <-time.After(2 * time.Second):
		t.Fatal("first connection was not accepted")
	}
	defer held.Close()

	secondAccepted := accept(secondLimited)
	overflow, err := net.Dial("tcp", second.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer overflow.Close()
	if err := overflow.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := overflow.Read(b[:]); err != io.EOF {
		t.Fatalf("over-limit connection read error = %v, want EOF", err)
	}
	if got := len(permits); got != 1 {
		t.Fatalf("connections charged to limiter = %d, want 1", got)
	}

	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	_ = held.Close() // Repeated Close must not release another connection's permit.
	if got := len(permits); got != 0 {
		t.Fatalf("permits retained after Close = %d, want 0", got)
	}

	replacement, err := net.Dial("tcp", second.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	select {
	case result := <-secondAccepted:
		if result.err != nil {
			t.Fatal(result.err)
		}
		defer result.conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("slot was not reusable after connection closed")
	}
}
