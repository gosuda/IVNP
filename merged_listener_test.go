package ivnp

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// mockNetListener returns connections from a channel and errors on demand.
var (
	errMockListenerFailed = errors.New("listener failed")
	errMockConnClosed     = errors.New("closed")
)

type mockNetListener struct {
	conns chan net.Conn
	fail  chan struct{}
	once  sync.Once
}

func (m *mockNetListener) Accept() (net.Conn, error) {
	select {
	case conn := <-m.conns:
		return conn, nil
	case <-m.fail:
		return nil, errMockListenerFailed
	}
}

func (m *mockNetListener) Close() error {
	m.once.Do(func() { close(m.fail) })
	return nil
}

func (m *mockNetListener) Addr() net.Addr { return mockAddr{} }

type mockAddr struct{}

func (mockAddr) Network() string { return "ivnp" }
func (mockAddr) String() string  { return "test:0" }

// TestMergedListenerSurvivesSubListenerFailure verifies that one failed
// sub-listener does not terminate the merged listener while healthy
// sub-listeners still serve, and that the terminal error surfaces only after
// the last sub-listener retires.
func TestMergedListenerSurvivesSubListenerFailure(t *testing.T) {
	failListener := &mockNetListener{conns: make(chan net.Conn), fail: make(chan struct{})}
	healthyListener := &mockNetListener{conns: make(chan net.Conn), fail: make(chan struct{})}

	owner := &Destination{}
	subs := []*streamListener{
		{Listener: failListener, owner: owner, addr: Addr{}},
		{Listener: healthyListener, owner: owner, addr: Addr{}},
	}
	merged := newMergedListener(owner, subs)
	defer merged.Close()

	// Fail the first sub-listener; the healthy one must keep the merged
	// listener serving.
	failListener.Close()

	// The merged listener must NOT surface the failed sub's error while a
	// healthy sub is still active: Accept blocks instead of failing.
	select {
	case r, ok := <-merged.ch:
		if ok && r.err != nil {
			t.Fatalf("merged Accept returned error %v while healthy sub remains", r.err)
		}
		if ok && r.conn != nil {
			t.Fatalf("unexpected connection: %v", r.conn)
		}
	case <-time.After(50 * time.Millisecond):
		// Good: still blocked waiting for the healthy sub.
	}

	// Now retire the healthy sub too; the terminal error must surface.
	healthyListener.Close()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case r, ok := <-merged.ch:
			if !ok {
				t.Fatal("channel closed without terminal error")
			}
			if r.err == nil {
				continue
			}
			// Terminal error surfaced — the fix is complete.
			return
		case <-deadline:
			t.Fatal("terminal error never surfaced after all subs retired")
		}
	}
}

// TestMergedListenerCloseDrainsBufferedConnections verifies Close does not
// leak accepted connections that were buffered in the channel.
func TestMergedListenerCloseDrainsBufferedConnections(t *testing.T) {
	fail := make(chan struct{})
	l := &mockNetListener{conns: make(chan net.Conn, 1), fail: fail}
	// Leave the listener open so its feed stays active.
	owner := &Destination{}
	sub := &streamListener{Listener: l, owner: owner, addr: Addr{}}
	merged := newMergedListener(owner, []*streamListener{sub})

	// Simulate one accepted connection sitting in the channel when Close runs.
	conn := &mockNetConn{closed: make(chan struct{})}
	l.conns <- conn
	// Wait until feed forwards the connection into merged.ch before closing.
	for len(merged.ch) == 0 {
		runtime.Gosched()
	}

	if err := merged.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-conn.closed:
		// Good: the buffered connection was closed.
	case <-time.After(time.Second):
		t.Fatal("Close did not drain the buffered accepted connection")
	}

	// Idempotent: a second Close returns nil.
	if err := merged.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// mockNetConn is a minimal net.Conn whose Close is observable.
type mockNetConn struct {
	closed chan struct{}
	once   sync.Once
}

func (m *mockNetConn) Read(b []byte) (int, error)  { return 0, errMockConnClosed }
func (m *mockNetConn) Write(b []byte) (int, error) { return 0, errMockConnClosed }
func (m *mockNetConn) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}
func (m *mockNetConn) LocalAddr() net.Addr                { return mockAddr{} }
func (m *mockNetConn) RemoteAddr() net.Addr               { return mockAddr{} }
func (m *mockNetConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockNetConn) SetWriteDeadline(t time.Time) error { return nil }
