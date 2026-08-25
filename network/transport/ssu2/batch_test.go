package ssu2

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestUDPBatchRoundTrip(t *testing.T) {
	senderConn := listenUDP(t)
	defer senderConn.Close()
	receiverConn := listenUDP(t)
	defer receiverConn.Close()

	sender, err := NewUDPBatchConn(senderConn)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewUDPBatchConn(receiverConn)
	if err != nil {
		t.Fatal(err)
	}

	out, err := NewBatch(3, 32)
	if err != nil {
		t.Fatal(err)
	}
	toReceiver := addrPort(t, receiverConn.LocalAddr())
	for i, payload := range []string{"first", "second", "third"} {
		packet := &out.Packets()[i]
		packet.Len = copy(packet.Data, payload)
		packet.Addr = toReceiver
	}
	if n, err := sender.WriteBatch(out); err != nil || n != 3 {
		t.Fatalf("WriteBatch = (%d, %v), want (3, nil)", n, err)
	}

	in, err := NewBatch(3, 32)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := receiver.ReadBatch(in); err != nil || n != 3 {
		t.Fatalf("ReadBatch = (%d, %v), want (3, nil)", n, err)
	}
	for i, want := range []string{"first", "second", "third"} {
		packet := in.Packets()[i]
		if got := string(packet.Data[:packet.Len]); got != want {
			t.Errorf("packet %d = %q, want %q", i, got, want)
		}
		if packet.Addr != addrPort(t, senderConn.LocalAddr()) {
			t.Errorf("packet %d address = %v, want sender address", i, packet.Addr)
		}
		packet.Len = copy(packet.Data, "reply-"+want)
		in.Packets()[i] = packet
	}
	if n, err := receiver.WriteBatch(in); err != nil || n != 3 {
		t.Fatalf("reply WriteBatch = (%d, %v), want (3, nil)", n, err)
	}

	replies, err := NewBatch(3, 32)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := sender.ReadBatch(replies); err != nil || n != 3 {
		t.Fatalf("reply ReadBatch = (%d, %v), want (3, nil)", n, err)
	}
	for i, want := range []string{"reply-first", "reply-second", "reply-third"} {
		if got := string(replies.Packets()[i].Data[:replies.Packets()[i].Len]); got != want {
			t.Errorf("reply %d = %q, want %q", i, got, want)
		}
	}
}

func TestUDPBatchWritePrefixLeavesTrailingSlotsUnsent(t *testing.T) {
	senderConn := listenUDP(t)
	defer senderConn.Close()
	receiverConn := listenUDP(t)
	defer receiverConn.Close()
	sender, err := NewUDPBatchConn(senderConn)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := NewBatch(2, 32)
	if err != nil {
		t.Fatal(err)
	}
	toReceiver := addrPort(t, receiverConn.LocalAddr())
	for index, payload := range []string{"first", "trailing"} {
		packet := &batch.Packets()[index]
		packet.Len = copy(packet.Data, payload)
		packet.Addr = toReceiver
	}
	if n, err := sender.WriteBatchPrefix(batch, 1); err != nil || n != 1 {
		t.Fatalf("WriteBatchPrefix = (%d, %v), want (1, nil)", n, err)
	}
	receiverConn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 32)
	if n, _, err := receiverConn.ReadFromUDP(buffer); err != nil || string(buffer[:n]) != "first" {
		t.Fatalf("prefix datagram = %q, %v", buffer[:n], err)
	}
	receiverConn.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	if _, _, err := receiverConn.ReadFromUDP(buffer); !isTimeout(err) {
		t.Fatalf("trailing slot was sent: %v", err)
	}
}

func TestUDPBatchRejectsInvalidPacketBeforeSend(t *testing.T) {
	senderConn := listenUDP(t)
	defer senderConn.Close()
	receiverConn := listenUDP(t)
	defer receiverConn.Close()

	sender, err := NewUDPBatchConn(senderConn)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := NewBatch(2, 16)
	if err != nil {
		t.Fatal(err)
	}
	first := &batch.Packets()[0]
	first.Len = copy(first.Data, "must-not-send")
	first.Addr = addrPort(t, receiverConn.LocalAddr())
	batch.Packets()[1].Len = 1

	if n, err := sender.WriteBatch(batch); !errors.Is(err, ErrInvalidDatagram) || n != 0 {
		t.Fatalf("WriteBatch = (%d, %v), want (0, ErrInvalidDatagram)", n, err)
	}
	receiverConn.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	buf := make([]byte, 16)
	if _, _, err := receiverConn.ReadFromUDP(buf); !errors.Is(err, net.ErrClosed) && !isTimeout(err) {
		t.Fatalf("unexpected packet after rejected batch: %v", err)
	}
}

func TestUDPBatchCloseUnblocksRead(t *testing.T) {
	conn := listenUDP(t)
	batchConn, err := NewUDPBatchConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := NewBatch(1, 32)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := batchConn.ReadBatch(batch)
		result <- err
	}()
	if err := batchConn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadBatch error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadBatch did not unblock after Close")
	}
}

func TestDispatcherBackpressureCopiesPacketsAndCloses(t *testing.T) {
	started := make(chan string, 1)
	release := make(chan struct{})
	var first sync.Once
	dispatcher, err := NewDispatcher(1, 1, 16, func(packet Datagram) {
		started <- string(packet.Data[:packet.Len])
		first.Do(func() { <-release })
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("original")
	packet := Datagram{Data: payload, Len: len(payload)}
	if err := dispatcher.Dispatch(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	copy(payload, "changed!")
	if got := <-started; got != "original" {
		t.Fatalf("handler packet = %q, want copied original", got)
	}
	if err := dispatcher.Dispatch(context.Background(), Datagram{Data: []byte("queued"), Len: 6}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := dispatcher.Dispatch(ctx, Datagram{Data: []byte("blocked"), Len: 7}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked Dispatch error = %v, want context deadline", err)
	}

	closed := make(chan struct{})
	go func() {
		dispatcher.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned while a handler was still active")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after handler returned")
	}
	if err := dispatcher.Dispatch(context.Background(), packet); !errors.Is(err, ErrDispatcherClosed) {
		t.Fatalf("Dispatch after Close error = %v, want ErrDispatcherClosed", err)
	}
}

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func addrPort(t *testing.T, addr net.Addr) netip.AddrPort {
	t.Helper()
	parsed, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func isTimeout(err error) bool {
	timeout, ok := err.(net.Error)
	return ok && timeout.Timeout()
}
