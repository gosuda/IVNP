package sam

import (
	"context"
	"strings"
	"testing"
	"time"

	ivnp "gosuda.org/ivnp"
	"gosuda.org/ivnp/service/clientapi"
)

type readinessController struct {
	loop  *loopController
	ready <-chan struct{}
}

func (c readinessController) CreateDestination(ctx context.Context, spec clientapi.DestinationSpec) (clientapi.DestinationEndpoint, error) {
	endpoint, err := c.loop.CreateDestination(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &readinessEndpoint{DestinationEndpoint: endpoint, ready: c.ready}, nil
}
func (c readinessController) DestroyDestination(ctx context.Context, endpoint clientapi.DestinationEndpoint) error {
	return endpoint.Close()
}

type readinessEndpoint struct {
	clientapi.DestinationEndpoint
	ready <-chan struct{}
}

func (e *readinessEndpoint) WaitReady(ctx context.Context) error {
	select {
	case <-e.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestSessionStatusWaitsForReadinessAndTimesOut(t *testing.T) {
	t.Run("waits", func(t *testing.T) {
		ready := make(chan struct{})
		loop := &loopController{endpoints: make(map[ivnp.Hash]*loopEndpoint)}
		server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: readinessController{loop: loop, ready: ready}, ReadinessTimeout: time.Second})
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
		result := make(chan string, 1)
		go func() {
			line, _ := reader.ReadString('\n')
			result <- strings.TrimSuffix(line, "\n")
		}()
		select {
		case line := <-result:
			t.Fatalf("status returned before readiness: %q", line)
		case <-time.After(40 * time.Millisecond):
		}
		close(ready)
		select {
		case line := <-result:
			if !strings.Contains(line, "RESULT=OK DESTINATION=") {
				t.Fatal(line)
			}
		case <-time.After(time.Second):
			t.Fatal("status did not follow readiness")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		ready := make(chan struct{})
		loop := &loopController{endpoints: make(map[ivnp.Hash]*loopEndpoint)}
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
		loop := &loopController{endpoints: make(map[ivnp.Hash]*loopEndpoint)}
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
		deadline := time.Now().Add(time.Second)
		for {
			loop.mu.Lock()
			count, allClosed := len(loop.endpoints), true
			for _, endpoint := range loop.endpoints {
				endpoint.mu.Lock()
				allClosed = allClosed && endpoint.closed
				endpoint.mu.Unlock()
			}
			loop.mu.Unlock()
			if count != 0 && allClosed {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("disconnected readiness wait retained its destination")
			}
			time.Sleep(time.Millisecond)
		}
	})
}
