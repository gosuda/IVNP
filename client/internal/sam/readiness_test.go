package sam

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
)

type readinessController struct {
	loop    *loopController
	ready   <-chan struct{}
	entered chan<- struct{}
}

func (c readinessController) CreateDestination(ctx context.Context, spec destination.DestinationSpec) (destination.DestinationEndpoint, error) {
	endpoint, err := c.loop.CreateDestination(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &readinessEndpoint{DestinationEndpoint: endpoint, ready: c.ready, entered: c.entered}, nil
}
func (c readinessController) DestroyDestination(ctx context.Context, endpoint destination.DestinationEndpoint) error {
	return endpoint.Close()
}

type readinessEndpoint struct {
	destination.DestinationEndpoint
	ready   <-chan struct{}
	entered chan<- struct{}
}

type readinessMonitorConn struct {
	wake chan struct{}
	once sync.Once
}

func (c *readinessMonitorConn) Read([]byte) (int, error) {
	<-c.wake
	return 0, readinessTimeoutError{}
}
func (c *readinessMonitorConn) Write(payload []byte) (int, error) { return len(payload), nil }
func (c *readinessMonitorConn) Close() error {
	c.once.Do(func() { close(c.wake) })
	return nil
}
func (c *readinessMonitorConn) LocalAddr() net.Addr  { return nil }
func (c *readinessMonitorConn) RemoteAddr() net.Addr { return nil }
func (c *readinessMonitorConn) SetDeadline(deadline time.Time) error {
	return c.SetReadDeadline(deadline)
}
func (c *readinessMonitorConn) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		c.once.Do(func() { close(c.wake) })
	}
	return nil
}
func (c *readinessMonitorConn) SetWriteDeadline(time.Time) error { return nil }

type readinessTimeoutError struct{}

func (readinessTimeoutError) Error() string   { return "readiness monitor timeout" }
func (readinessTimeoutError) Timeout() bool   { return true }
func (readinessTimeoutError) Temporary() bool { return false }

func (e *readinessEndpoint) WaitReady(ctx context.Context) error {
	if e.entered != nil {
		close(e.entered)
	}
	select {
	case <-e.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestWaitReadyConnectionBlocksUntilReady(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		monitor := &readinessMonitorConn{wake: make(chan struct{})}
		defer monitor.Close()
		connection := &serverConnection{Conn: monitor, reader: bufio.NewReader(monitor)}
		ready := make(chan struct{})
		entered := make(chan struct{})
		endpoint := &readinessEndpoint{ready: ready, entered: entered}
		result := make(chan error, 1)
		go func() {
			result <- waitReadyConnection(context.Background(), connection, endpoint)
		}()

		<-entered
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("waitReadyConnection returned before readiness: %v", err)
		default:
		}
		close(ready)
		if err := <-result; err != nil {
			t.Fatalf("waitReadyConnection after readiness: %v", err)
		}
	})
}

func TestSessionStatusWaitsForReadinessAndTimesOut(t *testing.T) {
	t.Run("waits", func(t *testing.T) {
		ready := make(chan struct{})
		entered := make(chan struct{})
		loop := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
		server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: readinessController{loop: loop, ready: ready, entered: entered}, ReadinessTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if err = server.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = server.Close(); _ = server.Wait() }()
		connection, reader := samDial(t, server.Addr().String())
		defer connection.Close()
		if _, err = connection.Write([]byte("SESSION CREATE STYLE=STREAM ID=ready DESTINATION=TRANSIENT\n")); err != nil {
			t.Fatal(err)
		}
		<-entered
		close(ready)
		line := readSAMLine(t, reader)
		if !strings.Contains(line, "RESULT=OK DESTINATION=") {
			t.Fatal(line)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		ready := make(chan struct{})
		loop := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
		server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: readinessController{loop: loop, ready: ready}, ReadinessTimeout: 30 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		if err = server.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = server.Close(); _ = server.Wait() }()
		connection, reader := samDial(t, server.Addr().String())
		defer connection.Close()
		_, _ = connection.Write([]byte("SESSION CREATE STYLE=STREAM ID=timeout DESTINATION=TRANSIENT\n"))
		line := readSAMLine(t, reader)
		if line != "SESSION STATUS RESULT=I2P_ERROR MESSAGE=SESSION_NOT_READY" {
			t.Fatal(line)
		}
		loop.mu.Lock()
		defer loop.mu.Unlock()
		for _, endpoint := range loop.endpoints {
			endpoint.mu.Lock()
			closed := endpoint.closed
			endpoint.mu.Unlock()
			if !closed {
				t.Fatal("timed-out destination remained active")
			}
		}
	})

	t.Run("disconnect", func(t *testing.T) {
		ready := make(chan struct{})
		loop := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
		server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: readinessController{loop: loop, ready: ready}, ReadinessTimeout: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		if err = server.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = server.Close(); _ = server.Wait() }()
		connection, _ := samDial(t, server.Addr().String())
		if _, err = connection.Write([]byte("SESSION CREATE STYLE=STREAM ID=disconnect DESTINATION=TRANSIENT\n")); err != nil {
			t.Fatal(err)
		}
		_ = connection.Close()
		waitForSAMCondition(t, time.Second, func() bool {
			loop.mu.Lock()
			count, allClosed := len(loop.endpoints), true
			for _, endpoint := range loop.endpoints {
				endpoint.mu.Lock()
				allClosed = allClosed && endpoint.closed
				endpoint.mu.Unlock()
			}
			loop.mu.Unlock()
			return count != 0 && allClosed
		}, "disconnected readiness destination cleanup")
	})
}
