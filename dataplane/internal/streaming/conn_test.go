package streaming

import (
	"errors"
	"net"
	"testing"
	"time"
)

var _ net.Conn = (*Conn)(nil)

func TestConnPipeRoundTripAndStateOwnership(t *testing.T) {
	left, right := net.Pipe()
	clientState := NewState(1, 2)
	client := NewConn(left, clientState)
	server := NewConn(right, NewState(2, 1))
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	serverDone := make(chan error, 1)
	go func() {
		request := make([]byte, len("request"))
		if _, err := server.Read(request); err != nil {
			serverDone <- err
			return
		}
		if string(request) != "request" {
			serverDone <- errors.New("unexpected request")
			return
		}
		_, err := server.Write([]byte("response"))
		serverDone <- err
	}()

	if n, err := client.Write([]byte("request")); err != nil || n != len("request") {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	response := make([]byte, len("response"))
	if n, err := client.Read(response); err != nil || n != len(response) || string(response) != "response" {
		t.Fatalf("Read() = %d, %q, %v", n, response, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}

	client.OnPacket(Packet{Flags: FlagSynchronize})
	if got := client.State(); got.Status != Open {
		t.Fatalf("owned State status = %v, want Open", got.Status)
	}
	if clientState.Status != New {
		t.Fatalf("caller State was mutated to %v", clientState.Status)
	}
}

func TestConnWriteQueueRespectsDeadline(t *testing.T) {
	left, right := net.Pipe()
	stream := &writeSignalStream{Conn: left, writing: make(chan struct{}, 1)}
	conn := NewConn(stream, NewState(1, 2), 1)
	t.Cleanup(func() {
		_ = conn.Close()
		_ = right.Close()
	})

	firstDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("first"))
		firstDone <- err
	}()
	select {
	case <-stream.writing:
	case <-time.After(time.Second):
		t.Fatal("first write did not reach the stream")
	}

	secondDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("second"))
		secondDone <- err
	}()

	deadline := time.NewTimer(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for len(conn.writes) != 1 {
		select {
		case <-deadline.C:
			t.Fatal("second write did not enter the bounded queue")
		case <-ticker.C:
		}
	}

	if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := conn.Write([]byte("third"))
	if !isTimeout(err) {
		t.Fatalf("queued Write() error = %v, want timeout", err)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-firstDone:
		if !isTimeout(err) {
			t.Fatalf("active Write() error = %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("active Write did not return after its deadline")
	}
	select {
	case err := <-secondDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("queued Write() error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued Write did not return after Close")
	}
}

func TestConnReadDeadlineAndClose(t *testing.T) {
	left, right := net.Pipe()
	conn := NewConn(left, NewState(1, 2))
	t.Cleanup(func() { _ = right.Close() })

	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := conn.Read(make([]byte, 1))
	if !isTimeout(err) {
		t.Fatalf("Read() error = %v, want timeout", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read() after Close error = %v, want net.ErrClosed", err)
	}
	if got := conn.State(); got.Status != Closed {
		t.Fatalf("State after Close = %v, want Closed", got.Status)
	}
}

func isTimeout(err error) bool {
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

type writeSignalStream struct {
	net.Conn
	writing chan struct{}
}

func (s *writeSignalStream) Write(p []byte) (int, error) {
	select {
	case s.writing <- struct{}{}:
	default:
	}
	return s.Conn.Write(p)
}
