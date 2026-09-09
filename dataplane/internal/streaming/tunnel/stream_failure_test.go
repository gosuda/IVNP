package streamingtunnel

import (
	"context"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

func TestFailedStreamDialReleasesExplicitPort(t *testing.T) {
	fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
	client, server := newTunnelNetworkPair(t, fabric, DefaultRetransmitAfter)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := client.DialStream(ctx, server.B32()+":81", 4242)
	if err == nil {
		_ = connection.Close()
		t.Fatal("dial to unbound port succeeded")
	}
	listener, err := client.ListenStream(context.Background(), ":4242")
	if err != nil {
		t.Fatalf("bind after failed dial: %v", err)
	}
	_ = listener.Close()
}
