package ntcp2

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"gosuda.org/ivnp/crypto/cryptx"
)

func TestSessionBidirectionalFrames(t *testing.T) {
	key, sipKey, sipIV := make([]byte, 32), make([]byte, 16), make([]byte, 8)
	leftSend, _ := NewDirection(key, sipKey, sipIV)
	leftReceive, _ := NewDirection(key, sipKey, sipIV)
	rightSend, _ := NewDirection(key, sipKey, sipIV)
	rightReceive, _ := NewDirection(key, sipKey, sipIV)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	client := NewSession(left, leftSend, leftReceive)
	server := NewSession(right, rightSend, rightReceive)
	done := make(chan error, 1)
	go func() { done <- client.Write([]byte("hello")) }()
	got, err := server.Read(make([]byte, 5))
	if err != nil || !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("server read=%q err=%v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSessionCloseReleasesDirections(t *testing.T) {
	key, sipKey, sipIV := make([]byte, 32), make([]byte, 16), make([]byte, 8)
	send, err := NewDirection(key, sipKey, sipIV)
	if err != nil {
		t.Fatal(err)
	}
	receive, err := NewDirection(key, sipKey, sipIV)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	session := NewSession(left, send, receive)
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	sessionCloseReleasesDirectionsRejected := !send.released || !receive.released || send.sip != (SipState{}) || receive.sip != (SipState{}) || send.nonceBuf != [cryptx.ChaChaNonceSize]byte{}
	if !sessionCloseReleasesDirectionsRejected {
		sessionCloseReleasesDirectionsRejected = receive.nonceBuf != [cryptx.ChaChaNonceSize]byte{}
	}
	if sessionCloseReleasesDirectionsRejected {
		t.Fatal("session close retained directional state")
	}
	if err := session.Write(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close = %v", err)
	}
}
