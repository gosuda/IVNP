package ntcp2

import (
	"bytes"
	"net"
	"testing"
)

type partialFrameWriter struct {
	bytes.Buffer
	limit int
}

func (w *partialFrameWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		p = p[:w.limit]
	}
	return w.Buffer.Write(p)
}

func TestDirectionReadWriteToNetConn(t *testing.T) {
	key, sipKey, sipIV := make([]byte, 32), make([]byte, 16), make([]byte, 8)
	for i := range key {
		key[i] = byte(i)
	}
	sender, err := NewDirection(key, sipKey, sipIV)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewDirection(key, sipKey, sipIV)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	payload := []byte("ntcp2 framed transport")
	done := make(chan error, 1)
	go func() { done <- sender.WriteFrame(left, payload) }()
	got, err := receiver.ReadFrame(right, make([]byte, len(payload)))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("ReadFrame=%q err=%v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDirectionWriteFrameHandlesPartialWrites(t *testing.T) {
	key, sipKey, sipIV := make([]byte, 32), make([]byte, 16), make([]byte, 8)
	sender, err := NewDirection(key, sipKey, sipIV)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewDirection(key, sipKey, sipIV)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("partial writes must preserve the complete encrypted frame")
	writer := &partialFrameWriter{limit: 3}
	if err := sender.WriteFrame(writer, payload); err != nil {
		t.Fatal(err)
	}
	got, err := receiver.ReadFrame(bytes.NewReader(writer.Bytes()), make([]byte, len(payload)))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("ReadFrame=%q err=%v", got, err)
	}
}
