package router

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	dataplanentcp2 "gosuda.org/ivnp/dataplane/internal/transport/ntcp2"
	dataplanessu2 "gosuda.org/ivnp/dataplane/internal/transport/ssu2"
	"gosuda.org/ivnp/foundation"
)

func TestNTCP2ReplayAdmissionUsesBoundedRing(t *testing.T) {
	manager := &NTCP2Manager{networkID: 2, replaySeen: make(map[[32]byte]struct{}, ntcp2ReplayEntries)}
	var ephemeral [32]byte
	for index := range ntcp2ReplayEntries {
		ephemeral[0] = byte(index)
		ephemeral[1] = byte(index >> 8)
		if manager.replayedRequest(ephemeral[:]) {
			t.Fatalf("replay entry %d rejected on first admission", index)
		}
	}
	ephemeral = [32]byte{}
	if !manager.replayedRequest(ephemeral[:]) {
		t.Fatal("replay admission accepted the retained oldest entry")
	}
	ephemeral[1] = 16
	if manager.replayedRequest(ephemeral[:]) {
		t.Fatal("replay admission rejected a new entry after the ring filled")
	}
	ephemeral = [32]byte{}
	if manager.replayedRequest(ephemeral[:]) {
		t.Fatal("replay admission retained an evicted entry")
	}
}

func TestSSU2ManagerDataFramingUsesReceiveAndSessionBuffers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		aliceDB := newTransportTestPeers()
		bobDB := newTransportTestPeers()
		now := uint64(time.Now().UnixMilli())
		if err := aliceDB.AdmitRouterInfo(bob.Snapshot(), now); err != nil {
			t.Fatal(err)
		}
		if err := bobDB.AdmitRouterInfo(alice.Snapshot(), now); err != nil {
			t.Fatal(err)
		}
		aliceManager := newSSU2LiveManager(t, aliceDB, aliceStatic, aliceIntro, time.Minute, time.Minute)
		bobManager := newSSU2LiveManager(t, bobDB, bobStatic, bobIntro, time.Minute, time.Minute)
		ctx, cancel := context.WithCancel(t.Context())
		message := managerHotPathMessage()
		var delivered foundation.I2NPMessage
		haveDelivered := make(chan struct{}, 1)
		startSSU2SimManager(t, ctx, aliceManager, aliceConn, alice, nil)
		startSSU2SimManager(t, ctx, bobManager, bobConn, bob, func(incoming foundation.I2NPMessage, _ uint64, _ bool) error {
			delivered = incoming
			select {
			case haveDelivered <- struct{}{}:
			default:
			}
			return nil
		})
		t.Cleanup(func() {
			cancel()
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})
		if err := aliceManager.EnsureSession(ctx, bob.Hash()); err != nil {
			t.Fatal(err)
		}
		if err := aliceManager.Send(ctx, bob.Hash(), message); err != nil {
			t.Fatal(err)
		}
		<-haveDelivered
		wantHeader := message.Header
		expiration, ok := foundation.I2NPEncodeTransportExpiration(message.Header.Expiration)
		if !ok {
			t.Fatal("test expiration is not encodable")
		}
		wantHeader.Expiration = foundation.I2NPDecodeTransportExpiration(expiration)
		if delivered.Header != wantHeader || string(delivered.Payload) != string(message.Payload) {
			t.Fatalf("SSU2 data framing delivered %#v, want header %#v payload %x", delivered, wantHeader, message.Payload)
		}
	})
}

func TestNTCP2ManagerWriteFramesI2NP(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	key := make([]byte, 32)
	sipKey := make([]byte, 16)
	sipIV := make([]byte, 8)
	send, err := dataplanentcp2.NewDirection(key, sipKey, sipIV)
	if err != nil {
		t.Fatal(err)
	}
	receive, err := dataplanentcp2.NewDirection(key, sipKey, sipIV)
	if err != nil {
		t.Fatal(err)
	}
	writer := dataplanentcp2.NewSession(left, send, receive)
	readerSend, _ := dataplanentcp2.NewDirection(key, sipKey, sipIV)
	readerReceive, _ := dataplanentcp2.NewDirection(key, sipKey, sipIV)
	reader := dataplanentcp2.NewSession(right, readerSend, readerReceive)
	frame := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		plain, err := reader.Read(make([]byte, 512))
		if err != nil {
			readErr <- err
			return
		}
		frame <- append([]byte(nil), plain...)
	}()
	message := managerHotPathMessage()
	if err = writeNTCP2I2NP(writer, message); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-readErr:
		t.Fatal(err)
	case plain := <-frame:
		if plain[0] != dataplanentcp2.BlockI2NP || string(plain[dataplanentcp2.BlockHeaderLen+foundation.I2NPTransportHeaderLen:]) != string(message.Payload) {
			t.Fatalf("NTCP2 framed payload = %x", plain)
		}
	case <-time.After(time.Second):
		t.Fatal("NTCP2 framed write did not arrive")
	}
}

func BenchmarkSSU2ManagerDataSendFraming(b *testing.B) {
	message := managerHotPathMessage()
	var payloadStorage [dataplanessu2.MaxIPv4PacketLen]byte
	payload, _ := marshalSSU2I2NPTo(payloadStorage[:], message)
	var key [32]byte
	key[0] = 1
	send, _ := dataplanessu2.NewDataCipher(key[:], key[:], key[:])
	session := &ssu2TransportSession{
		sendID: 9, receiveID: 7, send: send, nextPacket: 1,
		sent:   make(map[uint32]*ssu2SentPacket),
		remote: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:1")),
	}
	free := make(chan *ssu2EgressSlot, 1)
	queue := make(chan *ssu2EgressSlot, 1)
	free <- &ssu2EgressSlot{done: make(chan error, 1)}
	manager := &SSU2Manager{networkID: 2,
		started:        true,
		ctx:            context.Background(),
		sessionsByID:   map[uint64]*ssu2TransportSession{7: session},
		sessionsByPeer: map[foundation.Hash]*ssu2TransportSession{foundation.Hash{}: session},
		bindings:       TransportBindings{Clock: transportTestClock{now: time.Unix(1, 0)}},
		egressFree:     free,
		egressQueue:    queue,
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case slot := <-queue:
				slot.done <- nil
			case <-stop:
				return
			}
		}
	}()
	b.Cleanup(func() { close(stop) })
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := manager.sendSessionData(session, payload, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSSU2FragmentSendFraming(b *testing.B) {
	message := managerHotPathMessage()
	message.Payload = make([]byte, dataplanessu2.MaxIPv4PacketLen-dataplanessu2.ShortHeaderLen-dataplanessu2.PacketTagLen-3-foundation.I2NPTransportHeaderLen+1)
	var frame [dataplanessu2.MaxIPv4PacketLen]byte
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		fragments := 0
		if err := forEachSSU2I2NPFragment(frame[:], message, dataplanessu2.MaxIPv4PacketLen, func([]byte, bool) error {
			fragments++
			return nil
		}); err != nil {
			b.Fatal(err)
		}
		if fragments != 2 {
			b.Fatalf("fragment count = %d, want 2", fragments)
		}
	}
}

func BenchmarkSSU2ManagerDataReceiveFraming(b *testing.B) {
	message := managerHotPathMessage()
	var payloadStorage [dataplanessu2.MaxIPv4PacketLen]byte
	payload, _ := marshalSSU2I2NPTo(payloadStorage[:], message)
	var key [32]byte
	key[0] = 1
	send, _ := dataplanessu2.NewDataCipher(key[:], key[:], key[:])
	receive, _ := dataplanessu2.NewDataCipher(key[:], key[:], key[:])
	manager := &SSU2Manager{networkID: 2, ctx: context.Background(), bindings: TransportBindings{Clock: transportTestClock{now: time.Unix(1, 0)}, HandleI2NPContext: func(context.Context, foundation.Hash, foundation.I2NPMessage, uint64, bool) error { return nil }}}
	session := &ssu2TransportSession{receiveID: 7, receive: receive}
	packetBuffer := make([]byte, dataplanessu2.MaxIPv4PacketLen)
	b.ReportAllocs()
	b.ResetTimer()
	for packetNumber := range b.N {
		packet, err := send.SealDataTo(packetBuffer, dataplanessu2.ShortHeader{DestinationID: 7, PacketNumber: uint32(packetNumber + 1), Type: dataplanessu2.Data}, payload)
		if err != nil {
			b.Fatal(err)
		}
		manager.handleData(session, packet)
	}
}

func BenchmarkNTCP2ManagerMarshalFrame(b *testing.B) {
	message := managerHotPathMessage()
	frame := make([]byte, foundation.I2NPTransportHeaderLen+len(message.Payload))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := marshalNTCP2I2NPTo(frame, message); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkNTCP2ManagerWriteFrame(b *testing.B) {
	message := managerHotPathMessage()
	message.Payload = make([]byte, 1024)
	direction, err := dataplanentcp2.NewDirection(make([]byte, 32), make([]byte, 16), make([]byte, 8))
	if err != nil {
		b.Fatal(err)
	}
	connection := &managerHotPathStreamConn{}
	session := dataplanentcp2.NewSession(connection, direction, nil)
	b.Cleanup(func() { _ = session.Close() })
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := writeNTCP2I2NP(session, message); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNTCP2ReplayAdmission(b *testing.B) {
	manager := &NTCP2Manager{networkID: 2, replaySeen: make(map[[32]byte]struct{}, ntcp2ReplayEntries)}
	for index := range ntcp2ReplayEntries {
		input := managerHotReplayInput(index)
		if manager.replayedRequest(input[:]) {
			b.Fatal("failed to prime replay admission ring")
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := range b.N {
		input := managerHotReplayInput(ntcp2ReplayEntries + index)
		if manager.replayedRequest(input[:]) {
			b.Fatal("fresh replay admission rejected")
		}
	}
}

func managerHotReplayInput(index int) [32]byte {
	return [32]byte{byte(index), byte(index >> 8), byte(index >> 16), byte(index >> 24)}
}

func managerHotPathMessage() foundation.I2NPMessage {
	return foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: 7, Expiration: 60_000}, Payload: make([]byte, 64)}
}

type managerHotPathStreamConn struct{}

func (*managerHotPathStreamConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*managerHotPathStreamConn) Write(frame []byte) (int, error)  { return len(frame), nil }
func (*managerHotPathStreamConn) Close() error                     { return nil }
func (*managerHotPathStreamConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*managerHotPathStreamConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*managerHotPathStreamConn) SetDeadline(time.Time) error      { return nil }
func (*managerHotPathStreamConn) SetReadDeadline(time.Time) error  { return nil }
func (*managerHotPathStreamConn) SetWriteDeadline(time.Time) error { return nil }

type managerHotPathPacketConn struct {
	writes int
	length int
}

func (c *managerHotPathPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}
func (c *managerHotPathPacketConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	c.writes++
	c.length = len(packet)
	return len(packet), nil
}
func (*managerHotPathPacketConn) Close() error                     { return nil }
func (*managerHotPathPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*managerHotPathPacketConn) SetDeadline(time.Time) error      { return nil }
func (*managerHotPathPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*managerHotPathPacketConn) SetWriteDeadline(time.Time) error { return nil }
