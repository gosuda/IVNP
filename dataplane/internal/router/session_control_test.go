package router

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/dataplane/internal/transport/ntcp2"
	"gosuda.org/ivnp/foundation"
)

type controlWriteConn struct {
	blocked   bool
	entered   chan struct{}
	closed    chan struct{}
	enterOnce sync.Once
	closeOnce sync.Once
}

func newControlWriteConn(blocked bool) *controlWriteConn {
	return &controlWriteConn{blocked: blocked, entered: make(chan struct{}), closed: make(chan struct{})}
}
func (c *controlWriteConn) Write(data []byte) (int, error) {
	c.enterOnce.Do(func() { close(c.entered) })
	if c.blocked {
		<-c.closed
		return 0, net.ErrClosed
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(data), nil
	}
}
func (c *controlWriteConn) Read([]byte) (int, error)       { <-c.closed; return 0, net.ErrClosed }
func (c *controlWriteConn) Close() error                   { c.closeOnce.Do(func() { close(c.closed) }); return nil }
func (*controlWriteConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*controlWriteConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*controlWriteConn) SetDeadline(time.Time) error      { return nil }
func (*controlWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (*controlWriteConn) SetWriteDeadline(time.Time) error { return nil }

type registeredControlContext struct {
	context.Context
	registered chan struct{}
}

// Hide the backing cancelCtx so context.AfterFunc uses this context's hook.
func (*registeredControlContext) Value(any) any { return nil }

func (c *registeredControlContext) AfterFunc(f func()) func() bool {
	stop := context.AfterFunc(c.Context, f)
	close(c.registered)
	return stop
}

func controlTestSession(t *testing.T, conn net.Conn) *ntcp2.Session {
	t.Helper()
	direction, err := ntcp2.NewDirection(make([]byte, 32), make([]byte, 16), make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	return ntcp2.NewSession(conn, direction, nil)
}

func TestNTCP2ControlCancellationRetiresBlockedSocket(t *testing.T) {
	testNTCP2ControlCancellation(t, "blocked socket")
}

func TestNTCP2ControlCancellationUnblocksQueuedWriter(t *testing.T) {
	testNTCP2ControlCancellation(t, "queued writer")
}

func testNTCP2ControlCancellation(t *testing.T, name string) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		conn := newControlWriteConn(true)
		session := controlTestSession(t, conn)
		replacementConn := newControlWriteConn(false)
		replacement := controlTestSession(t, replacementConn)
		peer := foundation.Hash{7}
		manager := &NTCP2Manager{started: true, ctx: t.Context(), sessions: map[foundation.Hash]*ntcp2.Session{peer: session}}
		sender, err := manager.PreparedSession(peer)
		if err != nil {
			t.Fatal(err)
		}
		base, cancel := context.WithCancel(t.Context())
		ctx := &registeredControlContext{Context: base, registered: make(chan struct{})}
		controlDone := make(chan error, 1)
		var bulkDone chan error
		finished := false
		defer func() {
			cancel()
			_ = session.Close()
			_ = replacement.Close()
			if !finished {
				<-controlDone
			}
			if bulkDone != nil {
				<-bulkDone
			}
		}()
		if name == "queued writer" {
			bulkDone = make(chan error, 1)
			go func() { bulkDone <- manager.Send(t.Context(), peer, managerHotPathMessage()) }()
			<-conn.entered
		}
		go func() { controlDone <- sender.Send(ctx, managerHotPathMessage()) }()
		<-ctx.registered
		if name == "blocked socket" {
			<-conn.entered
			manager.mu.Lock()
			manager.sessions[peer] = replacement
			manager.mu.Unlock()
		}
		cancel()
		err = <-controlDone
		finished = true
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("control send = %v, want cancellation", err)
		}
		select {
		case <-replacementConn.closed:
			t.Fatal("cancellation retired the replacement session")
		default:
		}
		if name == "queued writer" {
			manager.mu.Lock()
			manager.sessions[peer] = replacement
			manager.mu.Unlock()
		}
		if err := manager.Send(t.Context(), peer, managerHotPathMessage()); err != nil {
			t.Fatalf("replacement session cannot deliver: %v", err)
		}
	})
}

func TestSSU2ControlCancellationDoesNotWaitForBulkSerialization(t *testing.T) {
	for _, name := range []string{"framing", "packet cipher"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				manager, session := newSSU2SendTestHarness(t)
				sender, err := manager.PreparedSession(session.peer)
				if err != nil {
					t.Fatal(err)
				}
				lock := &session.frameMu
				if name == "packet cipher" {
					lock = &session.packetMu
				}
				lock.Lock()
				locked := true
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 1)
				finished := false
				defer func() {
					cancel()
					if locked {
						lock.Unlock()
					}
					if !finished {
						<-done
					}
				}()
				go func() { done <- sender.Send(ctx, managerHotPathMessage()) }()
				synctest.Wait()
				cancel()
				synctest.Wait()
				select {
				case err := <-done:
					finished = true
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("control send = %v, want cancellation", err)
					}
				default:
					t.Fatal("control send ignored cancellation while waiting for bulk serialization")
				}
				lock.Unlock()
				locked = false
				if queued := len(manager.egressQueue); queued != 0 {
					t.Fatalf("canceled control send queued %d packets", queued)
				}
				resumed := make(chan error, 1)
				go func() { resumed <- sender.Send(t.Context(), managerHotPathMessage()) }()
				synctest.Wait()
				slot := <-manager.egressQueue
				slot.done <- nil
				if err := <-resumed; err != nil {
					t.Fatalf("send after canceled writer: %v", err)
				}
			})
		})
	}
}
