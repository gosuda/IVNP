package router

import (
	"context"
	ivnp "gosuda.org/ivnp/i2p"
	"gosuda.org/ivnp/network/transport/ntcp2"
	"gosuda.org/ivnp/network/transport/ssu2"
	"gosuda.org/ivnp/protocol/i2np"
	"gosuda.org/ivnp/protocol/netdb"
	"gosuda.org/ivnp/support/observability"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// The allocation ceilings document the deliberate ownership boundary: framing
// writes into supplied buffers, while an authenticated I2NP delivery owns one
// payload copy after the receive datagram is reused.
func TestManagerHotPathAllocationBudgets(t *testing.T) {
	message := managerHotPathMessage()
	ntcpFrame := make([]byte, i2np.TransportHeaderLen+len(message.Payload))
	if got := testing.AllocsPerRun(100, func() {
		if err := marshalNTCP2I2NPTo(ntcpFrame, message); err != nil {
			t.Fatal(err)
		}
	}); got != 0 {
		t.Fatalf("NTCP2 caller-buffer marshal allocations = %v, want 0", got)
	}

	var ssuFrame [ssu2.MaxIPv4PacketLen]byte
	if got := testing.AllocsPerRun(100, func() {
		frame, err := marshalSSU2I2NPTo(ssuFrame[:], message)
		if err != nil {
			t.Fatal(err)
		}
		managerHotPathFrame = frame
	}); got != 0 {
		t.Fatalf("SSU2 caller-buffer frame allocations = %v, want 0", got)
	}

	fragmented := message
	fragmented.Payload = make([]byte, ssu2.MaxIPv4PacketLen-ssu2.ShortHeaderLen-ssu2.PacketTagLen-3-i2np.TransportHeaderLen+1)
	var fragmentFrame [ssu2.MaxIPv4PacketLen]byte
	if got := testing.AllocsPerRun(100, func() {
		fragments := 0
		if err := forEachSSU2I2NPFragment(fragmentFrame[:], fragmented, func([]byte) error {
			fragments++
			return nil
		}); err != nil {
			t.Fatal(err)
		} else if fragments != 2 {
			t.Fatalf("SSU2 fragment count = %d, want 2", fragments)
		}
	}); got != 0 {
		t.Fatalf("SSU2 caller-buffer fragment allocations = %v, want 0", got)
	}

	manager := &NTCP2Manager{replaySeen: make(map[[32]byte]struct{}, ntcp2ReplayEntries)}
	var ephemeral [32]byte
	if got := testing.AllocsPerRun(100, func() {
		ephemeral[0]++
		if manager.replayedRequest(ephemeral[:]) {
			t.Fatal("fresh replay admission rejected")
		}
	}); got != 0 {
		t.Fatalf("NTCP2 replay admission allocations = %v, want 0 after manager initialization", got)
	}
}

func TestNTCP2ReplayAdmissionUsesBoundedRing(t *testing.T) {
	manager := &NTCP2Manager{replaySeen: make(map[[32]byte]struct{}, ntcp2ReplayEntries)}
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
	message := managerHotPathMessage()
	var payloadStorage [ssu2.MaxIPv4PacketLen]byte
	payload, err := marshalSSU2I2NPTo(payloadStorage[:], message)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	key[0] = 1
	send, err := ssu2.NewDataCipher(key[:], key[:], key[:])
	if err != nil {
		t.Fatal(err)
	}
	receive, err := ssu2.NewDataCipher(key[:], key[:], key[:])
	if err != nil {
		t.Fatal(err)
	}
	var delivered i2np.Message
	manager := &SSU2Manager{bindings: TransportBindings{
		Clock: fixedClock{now: time.Unix(1, 0)},
		HandleI2NPContext: func(_ context.Context, _ ivnp.Hash, message i2np.Message, _ uint64, _ bool) error {
			delivered = message
			return nil
		},
	}}
	session := &ssu2TransportSession{receiveID: 7, receive: receive}
	packetBuffer := make([]byte, ssu2.MaxIPv4PacketLen)
	seal := func() []byte {
		packet, err := send.SealDataTo(packetBuffer, ssu2.ShortHeader{DestinationID: 7, PacketNumber: 1, Type: ssu2.Data}, payload)
		if err != nil {
			t.Fatal(err)
		}
		return packet
	}
	manager.handleData(session, seal())
	if delivered.Header != message.Header || string(delivered.Payload) != string(message.Payload) {
		t.Fatalf("SSU2 data framing delivered %#v, want %#v", delivered, message)
	}
	if got := testing.AllocsPerRun(100, func() { manager.handleData(session, seal()) }); got > 3 {
		t.Fatalf("SSU2 data receive allocations = %v, want at most AEAD seal/open and ACK ownership", got)
	}

	output, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	manager.started = true
	manager.ctx = context.Background()
	manager.conn = output
	manager.sessionsByID = map[uint64]*ssu2TransportSession{7: session}
	manager.sessionsByPeer = map[ivnp.Hash]*ssu2TransportSession{ivnp.Hash{}: session}
	session.peer = ivnp.Hash{}
	session.remote = output.LocalAddr()
	session.sendID = 9
	session.send = send
	session.nextPacket = 1
	session.sent = make(map[uint32]*ssu2SentPacket)
	if err := manager.sendSessionData(session, payload, false); err != nil {
		t.Fatal(err)
	}
	output.SetReadDeadline(time.Now().Add(time.Second))
	wire := make([]byte, ssu2.MaxIPv4PacketLen)
	n, _, err := output.ReadFromUDP(wire)
	if err != nil {
		t.Fatal(err)
	}
	opened := make([]byte, len(payload))
	if _, plain, err := receive.OpenDataTo(opened, wire[:n]); err != nil || string(plain) != string(payload) {
		t.Fatalf("SSU2 data send frame = %x, %v", plain, err)
	}
}

func TestSSU2LiveVectorReadAuthDispatchWriteAllocations(t *testing.T) {
	aliceConn := newSSU2LoopbackConn(t)
	bobConn := newSSU2LoopbackConn(t)
	alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
	bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
	aliceDB := netdb.NewDatabase(alice.Hash(), 16)
	bobDB := netdb.NewDatabase(bob.Hash(), 16)
	now := uint64(time.Now().UnixMilli())
	if err := aliceDB.AdmitRouterInfo(bob.Snapshot(), false, now); err != nil {
		t.Fatal(err)
	}
	if err := bobDB.AdmitRouterInfo(alice.Snapshot(), false, now); err != nil {
		t.Fatal(err)
	}
	aliceMetrics, bobMetrics := observability.NewRegistry(), observability.NewRegistry()
	aliceManager, err := NewSSU2Manager(SSU2ManagerConfig{
		Database: aliceDB, StaticPrivate: aliceStatic, IntroKey: aliceIntro,
		IdleTimeout: time.Minute, HandshakeTimeout: 500 * time.Millisecond, Metrics: aliceMetrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	bobManager, err := NewSSU2Manager(SSU2ManagerConfig{
		Database: bobDB, StaticPrivate: bobStatic, IntroKey: bobIntro,
		IdleTimeout: time.Minute, HandshakeTimeout: 500 * time.Millisecond, Metrics: bobMetrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var delivered atomic.Uint64
	startSSU2LiveManager(t, ctx, aliceManager, aliceConn, alice, nil)
	startSSU2LiveManager(t, ctx, bobManager, bobConn, bob, func(i2np.Message, uint64, bool) error {
		delivered.Add(1)
		return nil
	})
	t.Cleanup(func() {
		cancel()
		closeSSU2LiveManager(t, aliceManager)
		closeSSU2LiveManager(t, bobManager)
	})

	message := ssu2LiveMessage(900)
	for range 16 {
		message.Header.ID++
		if err = aliceManager.Send(ctx, bob.Hash(), message); err != nil {
			t.Fatal(err)
		}
	}
	waitForSSU2Live(t, 5*time.Second, func() bool {
		aliceManager.mu.RLock()
		session := aliceManager.sessionsByPeer[bob.Hash()]
		peerTests := len(aliceManager.peerTests)
		aliceManager.mu.RUnlock()
		if session == nil || peerTests != 0 || delivered.Load() < 16 {
			return false
		}
		session.sendMu.Lock()
		pending := len(session.sent)
		session.sendMu.Unlock()
		return pending == 0
	}, "warm live vector/auth/dispatch/write path")

	var sendErr error
	before := delivered.Load()
	allocations := testing.AllocsPerRun(64, func() {
		message.Header.ID++
		sendErr = aliceManager.Send(ctx, bob.Hash(), message)
	})
	if sendErr != nil {
		t.Fatal(sendErr)
	}
	waitForSSU2Live(t, 5*time.Second, func() bool {
		return delivered.Load() >= before+65
	}, "measured live vector/auth/dispatch/write delivery")
	if allocations != 0 {
		t.Fatalf("live SSU2 vector read/auth/dispatch/write allocations = %v, want 0 after warmup", allocations)
	}
	for name, snapshot := range map[string]observability.SSU2Snapshot{
		"alice": aliceMetrics.Snapshot().SSU2,
		"bob":   bobMetrics.Snapshot().SSU2,
	} {
		if snapshot.ReceivedDatagrams != snapshot.EnqueuedDatagrams+snapshot.ReceiveQueueDrops ||
			snapshot.EnqueuedDatagrams != snapshot.ProcessedDatagrams+snapshot.IngressQueueDepth ||
			snapshot.SendEnqueuedDatagrams != snapshot.SentDatagrams+snapshot.SendFailedDatagrams+snapshot.SendQueueDrops+snapshot.EgressQueueDepth {
			t.Fatalf("%s SSU2 conservation failed after live allocation run: %+v", name, snapshot)
		}
	}
}

func TestNTCP2ManagerWriteFramesI2NP(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	key := make([]byte, 32)
	sipKey := make([]byte, 16)
	sipIV := make([]byte, 8)
	send, err := ntcp2.NewDirection(key, sipKey, sipIV)
	if err != nil {
		t.Fatal(err)
	}
	receive, err := ntcp2.NewDirection(key, sipKey, sipIV)
	if err != nil {
		t.Fatal(err)
	}
	writer := ntcp2.NewSession(left, send, receive)
	readerSend, _ := ntcp2.NewDirection(key, sipKey, sipIV)
	readerReceive, _ := ntcp2.NewDirection(key, sipKey, sipIV)
	reader := ntcp2.NewSession(right, readerSend, readerReceive)
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
		if plain[0] != ntcp2.BlockI2NP || string(plain[ntcp2.BlockHeaderLen+i2np.TransportHeaderLen:]) != string(message.Payload) {
			t.Fatalf("NTCP2 framed payload = %x", plain)
		}
	case <-time.After(time.Second):
		t.Fatal("NTCP2 framed write did not arrive")
	}
}

func BenchmarkSSU2ManagerDataSendFraming(b *testing.B) {
	message := managerHotPathMessage()
	var payloadStorage [ssu2.MaxIPv4PacketLen]byte
	payload, _ := marshalSSU2I2NPTo(payloadStorage[:], message)
	var key [32]byte
	key[0] = 1
	send, _ := ssu2.NewDataCipher(key[:], key[:], key[:])
	session := &ssu2TransportSession{
		sendID: 9, receiveID: 7, send: send, nextPacket: 1,
		sent:   make(map[uint32]*ssu2SentPacket),
		remote: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:1")),
	}
	free := make(chan *ssu2EgressSlot, 1)
	queue := make(chan *ssu2EgressSlot, 1)
	free <- &ssu2EgressSlot{done: make(chan error, 1)}
	manager := &SSU2Manager{
		started:        true,
		ctx:            context.Background(),
		sessionsByID:   map[uint64]*ssu2TransportSession{7: session},
		sessionsByPeer: map[ivnp.Hash]*ssu2TransportSession{ivnp.Hash{}: session},
		bindings:       TransportBindings{Clock: fixedClock{now: time.Unix(1, 0)}},
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
	message.Payload = make([]byte, ssu2.MaxIPv4PacketLen-ssu2.ShortHeaderLen-ssu2.PacketTagLen-3-i2np.TransportHeaderLen+1)
	var frame [ssu2.MaxIPv4PacketLen]byte
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		fragments := 0
		if err := forEachSSU2I2NPFragment(frame[:], message, func([]byte) error {
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
	var payloadStorage [ssu2.MaxIPv4PacketLen]byte
	payload, _ := marshalSSU2I2NPTo(payloadStorage[:], message)
	var key [32]byte
	key[0] = 1
	send, _ := ssu2.NewDataCipher(key[:], key[:], key[:])
	receive, _ := ssu2.NewDataCipher(key[:], key[:], key[:])
	manager := &SSU2Manager{ctx: context.Background(), bindings: TransportBindings{Clock: fixedClock{now: time.Unix(1, 0)}, HandleI2NPContext: func(context.Context, ivnp.Hash, i2np.Message, uint64, bool) error { return nil }}}
	session := &ssu2TransportSession{receiveID: 7, receive: receive}
	packetBuffer := make([]byte, ssu2.MaxIPv4PacketLen)
	b.ReportAllocs()
	b.ResetTimer()
	for packetNumber := range b.N {
		packet, err := send.SealDataTo(packetBuffer, ssu2.ShortHeader{DestinationID: 7, PacketNumber: uint32(packetNumber + 1), Type: ssu2.Data}, payload)
		if err != nil {
			b.Fatal(err)
		}
		manager.handleData(session, packet)
	}
}

func BenchmarkNTCP2ManagerMarshalFrame(b *testing.B) {
	message := managerHotPathMessage()
	frame := make([]byte, i2np.TransportHeaderLen+len(message.Payload))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := marshalNTCP2I2NPTo(frame, message); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkNTCP2ReplayAdmission(b *testing.B) {
	manager := &NTCP2Manager{replaySeen: make(map[[32]byte]struct{}, ntcp2ReplayEntries)}
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

var managerHotPathFrame []byte

func managerHotPathMessage() i2np.Message {
	return i2np.Message{Header: i2np.Header{Type: i2np.DeliveryStatus, ID: 7, Expiration: 60_000}, Payload: make([]byte, 64)}
}

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
