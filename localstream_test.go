package ivnp

import (
	"bytes"
	"context"
	"testing"
)

func TestLocalStreamNetworkDialListen(t *testing.T) {
	network := NewLocalStreamNetwork()
	listener, err := ListenerConfig{Network: network}.Listen(context.Background(), "service.i2p")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		_, err = conn.Read(buf)
		if err == nil && !bytes.Equal(buf, []byte("hello")) {
			err = ErrAddressInvalid
		}
		accepted <- err
	}()
	conn, err := Dialer{Network: network}.Dial("i2p", "service.i2p")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}
