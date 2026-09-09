package dataplane_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"gosuda.org/ivnp/dataplane"
)

func TestStreamingProtocolRoundTrip(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		server := dataplane.StreamingProtocolNewConn(serverRaw, dataplane.StreamingProtocolNewState(2, 1))
		defer server.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(server, buf); err != nil {
			serverDone <- err
			return
		}
		var err error
		if !bytes.Equal(buf, []byte("ping")) {
			err = errors.New("unexpected request payload")
		}
		if err == nil {
			_, err = server.Write([]byte("pong"))
		}
		serverDone <- err
	}()
	client := dataplane.StreamingProtocolNewConn(clientRaw, dataplane.StreamingProtocolNewState(1, 2))
	defer client.Close()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(client, reply); err != nil || !bytes.Equal(reply, []byte("pong")) {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
