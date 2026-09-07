package streamingtunnel

import (
	"context"
	"encoding/binary"
	"io"
	"testing"
	"testing/synctest"
	"time"

	dataplanestreaming "gosuda.org/ivnp/dataplane/internal/streaming"
	"gosuda.org/ivnp/foundation"
)

func TestTunnelNetworkSelectiveACKsCoverReportedHoles(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		sequence    uint32
		wantThrough uint32
		wantNACKs   int
	}{
		{name: "reordered packet", sequence: 3, wantThrough: 3, wantNACKs: 2},
		{name: "full NACK list", sequence: MaxWindow + 1, wantThrough: MaxWindow + 1, wantNACKs: MaxWindow},
		{name: "unrepresentable gap", sequence: MaxWindow + 2, wantThrough: 0, wantNACKs: 0},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
				client, server := newTunnelNetworkPair(t, fabric, time.Second)
				connection := client.newConn(1, 2, server.localHash, foundation.Identity{}, 1234, 80, true)
				if err := client.register(connection); err != nil {
					t.Fatal(err)
				}
				sent := make(chan []byte, 1)
				client.sender = handshakeSendFunc(func(_ context.Context, delivery Delivery) error {
					sent <- append([]byte(nil), delivery.Payload...)
					return nil
				})
				deliverReliabilityPacket(t, connection, Packet{Sequence: scenario.sequence, Payload: []byte("late")})
				ack, err := dataplanestreaming.Parse(<-sent)
				if err != nil {
					t.Fatal(err)
				}
				if ack.AckThrough != scenario.wantThrough || len(ack.NACKs)/4 != scenario.wantNACKs {
					t.Fatalf("ACK through %d with %d NACKs, want through %d with %d NACKs", ack.AckThrough, len(ack.NACKs)/4, scenario.wantThrough, scenario.wantNACKs)
				}
				for index := range scenario.wantNACKs {
					if got := binary.BigEndian.Uint32(ack.NACKs[index*4:]); got != uint32(index+1) || got >= ack.AckThrough {
						t.Fatalf("NACK %d = %d, want %d below ACK through %d", index, got, index+1, ack.AckThrough)
					}
				}
			})
		})
	}
}

func TestTunnelNetworkPiggybackACKsDoNotSignalLoss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
		client, server := newTunnelNetworkPair(t, fabric, time.Second)
		connection := client.newConn(1, 2, server.localHash, foundation.Identity{}, 1234, 80, true)
		if err := client.register(connection); err != nil {
			t.Fatal(err)
		}
		dataSends, ackSends := 0, 0
		replied := make(chan struct{})
		client.sender = handshakeSendFunc(func(_ context.Context, delivery Delivery) error {
			packet, err := dataplanestreaming.Parse(delivery.Payload)
			if err != nil {
				return err
			}
			if packet.Sequence != 0 {
				dataSends++
			} else {
				ackSends++
				if ackSends == 12 {
					close(replied)
				}
			}
			return nil
		})
		if _, err := connection.Write([]byte("request in flight")); err != nil {
			t.Fatal(err)
		}
		for sequence := uint32(1); sequence <= 12; sequence++ {
			deliverReliabilityPacket(t, connection, Packet{Sequence: sequence, AckThrough: 0, Payload: []byte("reply")})
		}
		<-replied
		synctest.Wait()
		if dataSends != 1 {
			t.Fatalf("unchanged piggyback ACKs caused %d data sends, want the original only", dataSends)
		}
		deliverReliabilityPacket(t, connection, Packet{AckThrough: 1})
		if _, err := connection.Write([]byte("next request")); err != nil {
			t.Fatal(err)
		}
	})
}

func TestTunnelFastRetransmitCountsNACKsAcrossACKProgress(t *testing.T) {
	network := &TunnelNetwork{retransmit: time.Second, maxRetries: 4, readCapacity: 1}
	connection := network.newConn(1, 2, foundation.Hash{1}, foundation.Identity{}, 1, 2, true)
	now := time.Now()
	for sequence := uint32(1); sequence <= 4; sequence++ {
		connection.pending[sequence] = pendingPacket{wire: []byte{byte(sequence)}, sent: now}
	}
	nack := []byte{0, 0, 0, 1}
	for through := uint32(2); through <= 4; through++ {
		resend := connection.acknowledgeLocked(through, nack, now)
		if through < 4 && len(resend) != 0 {
			t.Fatalf("fast retransmit after only %d NACKs", through-1)
		}
		if through == 4 && (len(resend) != 1 || resend[0].wire[0] != 1) {
			t.Fatalf("third NACK alongside advancing ACK = %v, want retransmit of packet 1", resend)
		}
	}
}

func TestTunnelNetworkRetransmitsLostSynchronizeReply(t *testing.T) {
	testRetransmitsSynchronizeReply(t, true)
}

func TestTunnelNetworkRetransmitsAfterLostHandshakeACK(t *testing.T) {
	testRetransmitsSynchronizeReply(t, false)
}

func testRetransmitsSynchronizeReply(t *testing.T, dropReply bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
		client, server := newTunnelNetworkPair(t, fabric, time.Second)
		listener, err := server.ListenI2P(t.Context(), ":80")
		if err != nil {
			t.Fatal(err)
		}
		syns, replies, acks := 0, 0, 0
		retried := make(chan struct{}, 1)
		client.sender = handshakeSendFunc(func(ctx context.Context, delivery Delivery) error {
			packet, err := dataplanestreaming.Parse(delivery.Payload)
			if err != nil {
				return err
			}
			if packet.Flags&FlagSynchronize != 0 {
				syns++
				if syns > 1 {
					return nil
				}
			} else if packet.Sequence == 0 {
				acks++
				if !dropReply && acks == 1 {
					return nil
				}
			}
			return fabric.SendTunnel(ctx, delivery)
		})
		server.sender = handshakeSendFunc(func(ctx context.Context, delivery Delivery) error {
			packet, err := dataplanestreaming.Parse(delivery.Payload)
			if err != nil {
				return err
			}
			if packet.Flags&FlagSynchronize != 0 {
				replies++
				if dropReply && replies == 1 {
					return nil
				}
				if replies == 2 {
					retried <- struct{}{}
				}
			}
			return fabric.SendTunnel(ctx, delivery)
		})
		outbound, err := client.DialI2P(t.Context(), server.B32()+":80")
		if err != nil {
			t.Fatal(err)
		}
		inbound, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-retried:
		case <-time.After(3 * time.Second):
			t.Fatal("unacknowledged SYN reply was not retransmitted")
		}
		synctest.Wait()
		if _, err := outbound.Write([]byte("connected")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len("connected"))
		if _, err := io.ReadFull(inbound, got); err != nil || string(got) != "connected" {
			t.Fatalf("stream after handshake loss = %q, %v", got, err)
		}
	})
}

func deliverReliabilityPacket(t testing.TB, connection *tunnelConn, packet Packet) {
	t.Helper()
	packet.SendStreamID, packet.ReceiveStreamID = connection.localID, connection.remoteID
	wire, err := marshalPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.network.HandleDelivery(t.Context(), Delivery{
		From: connection.peer, To: connection.network.localHash,
		FromPort: connection.remotePort, ToPort: connection.localPort,
		Protocol: ProtocolStreaming, Payload: wire,
	}); err != nil {
		t.Fatal(err)
	}
}
