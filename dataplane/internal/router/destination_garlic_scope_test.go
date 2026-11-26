package router

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"testing"

	dataplanegarlic "gosuda.org/ivnp/dataplane/internal/garlic"
	"gosuda.org/ivnp/foundation"
)

// destinationScopeCapture records every router-authority sink so a test can
// prove that garlic decrypted with a Destination's keys never reaches one.
type destinationScopeCapture struct {
	routed     []foundation.Hash
	tunneled   []foundation.Hash
	delivered  []foundation.Hash
	control    []ControlMessage
	garlic     int
	tunnelData int
	gateway    int
}

type destinationScopeControl struct{ capture *destinationScopeCapture }

func (destinationScopeControl) Accepts(foundation.I2NPMessage) bool { return true }

func (c destinationScopeControl) Enqueue(message ControlMessage) error {
	message.Message.Payload = append([]byte(nil), message.Message.Payload...)
	c.capture.control = append(c.capture.control, message)
	return nil
}

func newDestinationScopeService(capture *destinationScopeCapture) *Service {
	return NewService(Sinks{
		Router: func(to foundation.Hash, _ foundation.I2NPMessage) error {
			capture.routed = append(capture.routed, to)
			return nil
		},
		Destination: func(_, to foundation.Hash, _ foundation.I2NPMessage) error {
			capture.delivered = append(capture.delivered, to)
			return nil
		},
		Tunnel: func(to foundation.Hash, _ uint32, _ foundation.I2NPMessage) error {
			capture.tunneled = append(capture.tunneled, to)
			return nil
		},
		Garlic: func(I2NPSource, foundation.I2NPMessage) error {
			capture.garlic++
			return nil
		},
		TunnelData: func(foundation.I2NPMessage) error {
			capture.tunnelData++
			return nil
		},
		TunnelGateway: func(uint32, foundation.I2NPMessage) error {
			capture.gateway++
			return nil
		},
		Control: destinationScopeControl{capture: capture},
	})
}

// destinationScopeCloves returns a bundled LeaseSet store followed by every
// clove a remote peer could use to act with the hosting router's authority,
// and two legitimate Data cloves for the receiving Destination.
func destinationScopeCloves(t *testing.T, local foundation.Hash, bundled foundation.Hash, leaseSet []byte, now uint64) []dataplanegarlic.Clove {
	t.Helper()
	attacker := foundation.Sum([]byte("attacker router"))
	otherLocal := foundation.Hash{0x0d, 0x02}
	expires := now + 30_000
	store, err := foundation.NetworkDatabaseMarshalDatabaseStore(bundled, foundation.I2NPStoreLeaseSet2, leaseSet, 0, foundation.Hash{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	replyingStore, err := foundation.NetworkDatabaseMarshalDatabaseStore(bundled, foundation.I2NPStoreLeaseSet2, leaseSet, 0xdeadbeef, attacker, 0)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err = writer.Write([]byte("router info")); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	routerStore, err := foundation.NetworkDatabaseMarshalDatabaseStore(attacker, foundation.I2NPStoreRouterInfo, compressed.Bytes(), 0, foundation.Hash{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	status := make([]byte, 12)
	binary.BigEndian.PutUint32(status, 0x1337)
	tunnelData := make([]byte, foundation.I2NPTunnelDataMessageLen)
	binary.BigEndian.PutUint32(tunnelData, 7)
	embedded := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: 0x5150, Expiration: expires}, Payload: status}
	gateway := make([]byte, foundation.I2NPTunnelGatewayHeaderLen+foundation.I2NPStandardHeaderLen+len(status))
	binary.BigEndian.PutUint32(gateway, 9)
	binary.BigEndian.PutUint16(gateway[4:], uint16(len(gateway)-foundation.I2NPTunnelGatewayHeaderLen))
	if _, err = embedded.MarshalTo(gateway[foundation.I2NPTunnelGatewayHeaderLen:]); err != nil {
		t.Fatal(err)
	}
	data := []byte{0, 0, 0, 1, 'x'}
	local0 := dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryLocal}
	entries := []struct {
		delivery dataplanegarlic.Delivery
		kind     foundation.I2NPMessageType
		payload  []byte
	}{
		{local0, foundation.I2NPDatabaseStore, store},
		{dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryRouter, To: attacker}, foundation.I2NPDeliveryStatus, status},
		{dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryTunnel, To: attacker, TunnelID: 99}, foundation.I2NPDeliveryStatus, status},
		{dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryDestination, To: otherLocal}, foundation.I2NPData, data},
		{local0, foundation.I2NPDatabaseStore, replyingStore},
		{local0, foundation.I2NPDatabaseStore, routerStore},
		{local0, foundation.I2NPDeliveryStatus, status},
		{local0, foundation.I2NPGarlic, []byte{0, 0, 0, 4, 1, 2, 3, 4}},
		{local0, foundation.I2NPTunnelData, tunnelData},
		{local0, foundation.I2NPTunnelGateway, gateway},
		{dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryDestination, To: local}, foundation.I2NPData, data},
		{local0, foundation.I2NPData, data},
	}
	cloves := make([]dataplanegarlic.Clove, len(entries))
	for index, entry := range entries {
		cloves[index] = dataplanegarlic.Clove{
			Delivery:   entry.delivery,
			Message:    foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: entry.kind, ID: 0x4000 + uint32(index), Expiration: expires}, Payload: entry.payload},
			ID:         0x8000 + uint32(index),
			Expiration: expires,
		}
	}
	return cloves
}

func destinationScopeRatchetPayload(t *testing.T, cloves []dataplanegarlic.Clove) []byte {
	t.Helper()
	var payload []byte
	for _, clove := range cloves {
		var delivery [64]byte
		n, err := clove.Delivery.MarshalTo(delivery[:])
		if err != nil {
			t.Fatal(err)
		}
		body := append([]byte(nil), delivery[:n]...)
		body = append(body, byte(clove.Message.Header.Type))
		body = binary.BigEndian.AppendUint32(body, clove.Message.Header.ID)
		body = binary.BigEndian.AppendUint32(body, uint32(clove.Message.Header.Expiration/1000))
		body = append(body, clove.Message.Payload...)
		payload = append(payload, 11, byte(len(body)>>8), byte(len(body)))
		payload = append(payload, body...)
	}
	return payload
}

func wrapDestinationScopeGarlic(packet []byte, now uint64) foundation.I2NPMessage {
	payload := make([]byte, 4+len(packet))
	binary.BigEndian.PutUint32(payload, uint32(len(packet)))
	copy(payload[4:], packet)
	return foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPGarlic, ID: 1, Expiration: now + 30_000}, Payload: payload}
}

func assertDestinationScoped(t *testing.T, capture *destinationScopeCapture, local, bundled foundation.Hash) {
	t.Helper()
	if len(capture.routed) != 0 || len(capture.tunneled) != 0 {
		t.Fatalf("destination garlic forwarded with router authority: router=%x tunnel=%x", capture.routed, capture.tunneled)
	}
	if capture.garlic != 0 || capture.tunnelData != 0 || capture.gateway != 0 {
		t.Fatalf("destination garlic reached router sinks: garlic=%d tunnelData=%d gateway=%d", capture.garlic, capture.tunnelData, capture.gateway)
	}
	if len(capture.delivered) != 2 || capture.delivered[0] != local || capture.delivered[1] != local {
		t.Fatalf("destination deliveries = %x, want two to %x", capture.delivered, local)
	}
	if len(capture.control) != 1 {
		t.Fatalf("control handoffs = %d, want only the bundled LeaseSet", len(capture.control))
	}
	handoff := capture.control[0]
	store, err := foundation.I2NPParseDatabaseStore(handoff.Message.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if handoff.Message.Header.Type != foundation.I2NPDatabaseStore || store.Key != bundled || store.ReplyToken != 0 || !handoff.PrivateStore || handoff.Source != (I2NPSource{}) {
		t.Fatalf("bundled LeaseSet handoff = %+v (key %x token %d), want a private reply-free store of %x", handoff, store.Key, store.ReplyToken, bundled)
	}
}

type destinationScopePeers struct {
	local, remote               *foundation.LocalDestination
	localRatchet, remoteRatchet *dataplanegarlic.RatchetManager
	leaseSet                    []byte
}

func newDestinationScopePeers(t *testing.T, now uint64) *destinationScopePeers {
	t.Helper()
	local, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.ReleaseSensitive)
	remote, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remote.ReleaseSensitive)
	localRatchet, err := dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(localRatchet.ReleaseSensitive)
	remoteRatchet, err := dataplanegarlic.NewRatchetManager(remote, dataplanegarlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remoteRatchet.ReleaseSensitive)
	return &destinationScopePeers{local: local, remote: remote, localRatchet: localRatchet, remoteRatchet: remoteRatchet, leaseSet: signedDataPlaneLeaseSet2(t, remote, now)}
}

func TestDestinationGarlicConfinedToReceivingDestination(t *testing.T) {
	const now = uint64(1_000_000)
	t.Run("ratchet-unbound", func(t *testing.T) {
		peers := newDestinationScopePeers(t, now)
		capture := new(destinationScopeCapture)
		receiver, err := NewGarlicReceiver(GarlicReceiverConfig{
			Service: newDestinationScopeService(capture), ReplyKeys: dataplanegarlic.NewReplyKeyRegistry(1), Now: func() uint64 { return now },
			Destinations: map[foundation.Hash]GarlicDestination{peers.local.Hash(): {Ratchet: peers.localRatchet}},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(receiver.ReleaseSensitive)
		payload := destinationScopeRatchetPayload(t, destinationScopeCloves(t, peers.local.Hash(), peers.remote.Hash(), peers.leaseSet, now))
		public := peers.local.X25519Public()
		packet, err := peers.remoteRatchet.EncryptUnbound(make([]byte, foundation.I2NPI2PDMaxPayload-4), public[:], uint16(foundation.CryptoX25519), payload, now)
		if err != nil {
			t.Fatal(err)
		}
		_ = receiver.HandleGarlic(wrapDestinationScopeGarlic(packet, now))
		assertDestinationScoped(t, capture, peers.local.Hash(), peers.remote.Hash())
	})
	t.Run("ratchet-bound", func(t *testing.T) {
		peers := newDestinationScopePeers(t, now)
		capture := new(destinationScopeCapture)
		var replies []foundation.Hash
		receiver, err := NewGarlicReceiver(GarlicReceiverConfig{
			Service: newDestinationScopeService(capture), ReplyKeys: dataplanegarlic.NewReplyKeyRegistry(1), Now: func() uint64 { return now },
			Destinations: map[foundation.Hash]GarlicDestination{peers.local.Hash(): {
				Ratchet: peers.localRatchet,
				ReserveRatchetReply: func(target foundation.Hash) (RatchetReplyReservation, error) {
					return dataPlaneReplyReservation(func(context.Context, []byte) error {
						replies = append(replies, target)
						return nil
					}), nil
				},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(receiver.ReleaseSensitive)
		payload := destinationScopeRatchetPayload(t, destinationScopeCloves(t, peers.local.Hash(), peers.remote.Hash(), peers.leaseSet, now))
		public := peers.local.X25519Public()
		packet, err := peers.remoteRatchet.Encrypt(make([]byte, foundation.I2NPI2PDMaxPayload-4), peers.local.Hash(), public[:], uint16(foundation.CryptoX25519), payload, now)
		if err != nil {
			t.Fatal(err)
		}
		_ = receiver.HandleGarlic(wrapDestinationScopeGarlic(packet, now))
		assertDestinationScoped(t, capture, peers.local.Hash(), peers.remote.Hash())
		if len(replies) != 1 || replies[0] != peers.remote.Hash() {
			t.Fatalf("New Session replies = %x, want one to %x", replies, peers.remote.Hash())
		}
	})
	t.Run("clove-set", func(t *testing.T) {
		peers := newDestinationScopePeers(t, now)
		capture := new(destinationScopeCapture)
		service := newDestinationScopeService(capture)
		set := testCloveSet(t, destinationScopeCloves(t, peers.local.Hash(), peers.remote.Hash(), peers.leaseSet, now), 77, now+30_000)
		_ = service.handleDestinationGarlicCloveSet(peers.local.Hash(), set, now, false)
		assertDestinationScoped(t, capture, peers.local.Hash(), peers.remote.Hash())
	})
}

// Router-key garlic keeps router authority: the same clove set decrypted with
// the router's own keys is still dispatched to the router-wide sinks.
func TestRouterGarlicCloveSetKeepsRouterDispatch(t *testing.T) {
	const now = uint64(1_000_000)
	peers := newDestinationScopePeers(t, now)
	capture := new(destinationScopeCapture)
	service := newDestinationScopeService(capture)
	set := testCloveSet(t, destinationScopeCloves(t, peers.local.Hash(), peers.remote.Hash(), peers.leaseSet, now), 78, now+30_000)
	_ = service.HandleGarlicCloveSet(set, now, false)
	if len(capture.routed) != 1 || len(capture.tunneled) != 1 || capture.garlic != 1 || capture.tunnelData != 1 || capture.gateway != 1 {
		t.Fatalf("router garlic dispatch changed: router=%d tunnel=%d garlic=%d tunnelData=%d gateway=%d", len(capture.routed), len(capture.tunneled), capture.garlic, capture.tunnelData, capture.gateway)
	}
	if len(capture.control) != 4 {
		t.Fatalf("router garlic control handoffs = %d, want 4", len(capture.control))
	}
	for _, handoff := range capture.control {
		if handoff.PrivateStore {
			t.Fatalf("router garlic store marked private: %+v", handoff)
		}
	}
}
