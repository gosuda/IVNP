package streamingtunnel

import (
	"bytes"
	"context"
	"errors"
	"testing"

	dataplanestreaming "gosuda.org/ivnp/dataplane/internal/streaming"
	"gosuda.org/ivnp/foundation"
)

type acknowledgingWritePeer struct {
	network    *TunnelNetwork
	connection *tunnelConn
	payload    []byte
	ack        [HeaderLen]byte
}

func (p *acknowledgingWritePeer) SendTunnel(ctx context.Context, delivery Delivery) error {
	packet, err := dataplanestreaming.Parse(delivery.Payload)
	if err != nil {
		return err
	}
	if !bytes.Equal(packet.Payload, p.payload) {
		return errors.New("write peer received an unexpected payload")
	}
	ack := Packet{SendStreamID: p.connection.localID, ReceiveStreamID: p.connection.remoteID, AckThrough: packet.Sequence}
	n, err := ack.MarshalTo(p.ack[:])
	if err != nil {
		return err
	}
	if err := p.network.HandleDelivery(ctx, Delivery{
		From: p.connection.peer, To: p.network.localHash, Protocol: ProtocolStreaming,
		FromPort: p.connection.remotePort, ToPort: p.connection.localPort, Payload: p.ack[:n],
	}); err != nil {
		return err
	}
	return nil
}

func newAcknowledgedWrite(tb testing.TB) (*tunnelConn, *acknowledgingWritePeer) {
	tb.Helper()
	local, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(local.ReleaseSensitive)
	peer := &acknowledgingWritePeer{payload: bytes.Repeat([]byte{0x42}, 1024)}
	network, err := NewTunnelNetwork(TunnelNetworkConfig{Destination: local, Sender: peer})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		if err := network.Close(); err != nil {
			tb.Error(err)
		}
	})
	connection := network.newConn(1, 2, foundation.Hash{3}, foundation.Identity{}, 100, 200, true)
	if err := network.register(connection); err != nil {
		tb.Fatal(err)
	}
	peer.network, peer.connection = network, connection
	return connection, peer
}

func BenchmarkEstablishedWriteWithAcknowledgment(b *testing.B) {
	connection, peer := newAcknowledgedWrite(b)
	for range 64 {
		if _, err := connection.Write(peer.payload); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := connection.Write(peer.payload); err != nil {
			b.Fatal(err)
		}
	}
}
