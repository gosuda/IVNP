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

func newConfiguredNTCP2Manager(t *testing.T, peers TransportPeerSource) *NTCP2Manager {
	t.Helper()
	privateKey := make([]byte, 32)
	privateKey[0] = 1
	manager, err := NewNTCP2Manager(NTCP2ManagerConfig{
		NetworkID:     2,
		Peers:         peers,
		StaticPrivate: privateKey,
		StaticIV:      make([]byte, 16),
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
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
		manager := newConfiguredNTCP2Manager(t, nil)
		manager.mu.Lock()
		manager.started = true
		manager.ctx = t.Context()
		manager.sessions[peer] = session
		manager.mu.Unlock()
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

func TestSSU2ControlCancellationDoesNotWaitForPacketCipher(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		rawAliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		aliceConn := &blockingWriteSSU2Conn{
			UDPConn: rawAliceConn,
			entered: make(chan struct{}),
			release: make(chan struct{}),
		}
		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		aliceDB := newTransportTestPeers()
		bobDB := newTransportTestPeers()
		now := uint64(time.Now().UnixMilli())
		if err := aliceDB.AdmitRouterInfo(bob.Snapshot(), now); err != nil {
			t.Fatal(err)
		}
		if err := bobDB.AdmitRouterInfo(alice.Snapshot(), now); err != nil {
			t.Fatal(err)
		}
		aliceManager := newSSU2LiveManager(t, aliceDB, aliceStatic, aliceIntro, time.Minute, time.Minute)
		bobManager := newSSU2LiveManager(t, bobDB, bobStatic, bobIntro, time.Minute, time.Minute)
		received := make(chan foundation.I2NPMessage, ssu2EgressSlots+4)
		startSSU2SimManager(t, t.Context(), aliceManager, aliceConn, alice, nil)
		startSSU2SimManager(t, t.Context(), bobManager, bobConn, bob, func(msg foundation.I2NPMessage, _ uint64, _ bool) error {
			received <- msg
			return nil
		})
		t.Cleanup(func() {
			aliceConn.block.Store(false)
			select {
			case <-aliceConn.release:
			default:
				close(aliceConn.release)
			}
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		if err := aliceManager.EnsureSession(t.Context(), bob.Hash()); err != nil {
			t.Fatal(err)
		}
		net_.Advance(20 * time.Millisecond)
		sender, err := aliceManager.PreparedSession(bob.Hash())
		if err != nil {
			t.Fatal(err)
		}

		// Saturate egress slots while the socket write is blocked so a new send
		// waits before packet submission.
		aliceConn.block.Store(true)
		bulkResults := make([]chan error, ssu2EgressSlots)
		for i := range bulkResults {
			bulkResults[i] = make(chan error, 1)
			go func(ch chan error) {
				ch <- aliceManager.writeTo([]byte{1}, bobConn.LocalAddr())
			}(bulkResults[i])
		}
		<-aliceConn.entered
		synctest.Wait()

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- sender.Send(ctx, managerHotPathMessage()) }()
		synctest.Wait()

		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("control send = %v, want cancellation", err)
			}
		default:
			t.Fatal("control send ignored cancellation while waiting for egress slot")
		}

		aliceConn.block.Store(false)
		close(aliceConn.release)
		for _, ch := range bulkResults {
			if err := <-ch; err != nil {
				t.Fatalf("bulk write: %v", err)
			}
		}
		if err := sender.Send(t.Context(), managerHotPathMessage()); err != nil {
			t.Fatalf("send after canceled writer: %v", err)
		}
		if got := <-received; got.Header.ID != managerHotPathMessage().Header.ID {
			t.Fatalf("delivered message ID = %d, want %d", got.Header.ID, managerHotPathMessage().Header.ID)
		}
	})
}

func TestSSU2ControlCancellationReturnsFromEgressWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		rawAliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		aliceConn := &blockingWriteSSU2Conn{
			UDPConn: rawAliceConn,
			entered: make(chan struct{}),
			release: make(chan struct{}),
		}
		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		aliceDB := newTransportTestPeers()
		bobDB := newTransportTestPeers()
		now := uint64(time.Now().UnixMilli())
		if err := aliceDB.AdmitRouterInfo(bob.Snapshot(), now); err != nil {
			t.Fatal(err)
		}
		if err := bobDB.AdmitRouterInfo(alice.Snapshot(), now); err != nil {
			t.Fatal(err)
		}
		aliceManager := newSSU2LiveManager(t, aliceDB, aliceStatic, aliceIntro, time.Minute, time.Minute)
		bobManager := newSSU2LiveManager(t, bobDB, bobStatic, bobIntro, time.Minute, time.Minute)
		received := make(chan foundation.I2NPMessage, 4)
		startSSU2SimManager(t, t.Context(), aliceManager, aliceConn, alice, nil)
		startSSU2SimManager(t, t.Context(), bobManager, bobConn, bob, func(msg foundation.I2NPMessage, _ uint64, _ bool) error {
			received <- msg
			return nil
		})
		t.Cleanup(func() {
			aliceConn.block.Store(false)
			select {
			case <-aliceConn.release:
			default:
				close(aliceConn.release)
			}
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		if err := aliceManager.EnsureSession(t.Context(), bob.Hash()); err != nil {
			t.Fatal(err)
		}
		net_.Advance(20 * time.Millisecond)
		sender, err := aliceManager.PreparedSession(bob.Hash())
		if err != nil {
			t.Fatal(err)
		}

		aliceConn.block.Store(true)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- sender.Send(ctx, managerHotPathMessage()) }()
		<-aliceConn.entered
		synctest.Wait()

		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("control send = %v, want cancellation", err)
			}
		default:
			t.Fatal("control send ignored cancellation while waiting for egress completion")
		}

		aliceConn.block.Store(false)
		close(aliceConn.release)
		synctest.Wait()

		if err := sender.Send(t.Context(), ssu2LiveMessage(77)); err != nil {
			t.Fatalf("send after canceled writer: %v", err)
		}
	})
}
