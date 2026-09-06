package router

import (
	"context"
	"net"
	"testing"
)

func TestNativeSocketRuntimeUsesStandardSockets(t *testing.T) {
	runtime := &NativeSocketRuntime{}
	listener, err := runtime.ListenStream(context.Background(), Endpoint{Network: "tcp", Address: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	conn, err := runtime.DialStream(context.Background(), Endpoint{Network: "tcp", Address: listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case server := <-accepted:
		server.Close()
	case err := <-acceptErr:
		t.Fatal(err)
	}

	packet, err := runtime.ListenUDP(context.Background(), Endpoint{Network: "udp4", Address: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	if packet.LocalAddr() == nil {
		t.Fatal("packet listener has no local address")
	}
}
