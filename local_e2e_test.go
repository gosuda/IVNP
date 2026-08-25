package ivnp

import (
	"bytes"
	"context"
	"testing"

	"gosuda.org/ivnp/networking"
)

func TestLocalZeroHopDialerListenerE2E(t *testing.T) {
	network := NewLocalStreamNetwork()
	listener, err := ListenerConfig{Network: network}.Listen(context.Background(), "echo.i2p")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		server := networking.StreamingProtocolNewConn(raw, networking.StreamingProtocolNewState(2, 1))
		defer server.Close()
		buf := make([]byte, 4)
		if _, err = server.Read(buf); err == nil && !bytes.Equal(buf, []byte("ping")) {
			err = ErrAddressInvalid
		}
		if err == nil {
			_, err = server.Write([]byte("pong"))
		}
		serverDone <- err
	}()
	raw, err := Dialer{Network: network}.Dial("i2p", "echo.i2p")
	if err != nil {
		t.Fatal(err)
	}
	client := networking.StreamingProtocolNewConn(raw, networking.StreamingProtocolNewState(1, 2))
	defer client.Close()
	if _, err = client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err = client.Read(reply); err != nil || !bytes.Equal(reply, []byte("pong")) {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
