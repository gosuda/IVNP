package router

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	dataplanegarlic "gosuda.org/ivnp/dataplane/internal/garlic"
	dataplanestreaming "gosuda.org/ivnp/dataplane/internal/streaming"
	dataplanestreamingtunnel "gosuda.org/ivnp/dataplane/internal/streaming/tunnel"
	dataplanetunnel "gosuda.org/ivnp/dataplane/internal/tunnel"
	"gosuda.org/ivnp/foundation"
)

type dataPlaneTunnelSender struct {
	mu       sync.Mutex
	handle   func(context.Context, foundation.I2NPMessage) error
	messages []foundation.I2NPMessage
}

func (s *dataPlaneTunnelSender) Send(ctx context.Context, _ foundation.Hash, message foundation.I2NPMessage) error {
	copyMessage := foundation.I2NPMessage{Header: message.Header, Payload: append([]byte(nil), message.Payload...)}
	s.mu.Lock()
	s.messages = append(s.messages, copyMessage)
	handle := s.handle
	s.mu.Unlock()
	if handle == nil {
		return nil
	}
	return handle(ctx, copyMessage)
}

type dataPlaneControlCapture struct{ messages []ControlMessage }

func (*dataPlaneControlCapture) Accepts(message foundation.I2NPMessage) bool {
	return message.Header.Type == foundation.I2NPDatabaseStore
}
func (c *dataPlaneControlCapture) Enqueue(message ControlMessage) error {
	message.Message.Payload = append([]byte(nil), message.Message.Payload...)
	c.messages = append(c.messages, message)
	return nil
}

type dataPlaneReplyReservation func(context.Context, []byte) error

func (dataPlaneReplyReservation) Activate() error { return nil }
func (f dataPlaneReplyReservation) Send(ctx context.Context, packet []byte) error {
	return f(ctx, packet)
}
func (f dataPlaneReplyReservation) SendEstablished(ctx context.Context, packet []byte) error {
	return f(ctx, packet)
}
func (dataPlaneReplyReservation) Release() {}

type ratchetReceiverFixture struct {
	receiver              *GarlicReceiver
	local, remote         *dataplanegarlic.RatchetManager
	localHash, remoteHash foundation.Hash
	now                   uint64
	newSessionReply       []byte
	replies               [][]byte
	reserveErr            error
}

func newRatchetReceiverFixture(t *testing.T) *ratchetReceiverFixture {
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
	f := &ratchetReceiverFixture{localHash: local.Hash(), remoteHash: remote.Hash(), now: 1_000_000}
	f.local, err = dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.local.ReleaseSensitive)
	f.remote, err = dataplanegarlic.NewRatchetManager(remote, dataplanegarlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.remote.ReleaseSensitive)
	public := remote.X25519Public()
	packet, err := f.local.Encrypt(make([]byte, 2048), f.remoteHash, public[:], uint16(foundation.CryptoX25519), nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.remote.Receive(make([]byte, 2048), make([]byte, 2048), packet, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Candidate.Discard()
	if _, err := f.remote.CommitNew(result.Candidate, f.localHash, f.now); err != nil {
		t.Fatal(err)
	}
	f.newSessionReply = result.Reply
	f.receiver, err = NewGarlicReceiver(GarlicReceiverConfig{
		Service: NewService(Sinks{}), ReplyKeys: dataplanegarlic.NewReplyKeyRegistry(1), Now: func() uint64 { return f.now },
		Destinations: map[foundation.Hash]GarlicDestination{f.localHash: {
			Ratchet: f.local,
			ReserveRatchetReply: func(target foundation.Hash) (RatchetReplyReservation, error) {
				if target != f.remoteHash {
					t.Fatalf("reply target = %x, want %x", target, f.remoteHash)
				}
				if f.reserveErr != nil {
					return nil, f.reserveErr
				}
				return dataPlaneReplyReservation(func(_ context.Context, packet []byte) error {
					f.replies = append(f.replies, append([]byte(nil), packet...))
					return nil
				}), nil
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.receiver.ReleaseSensitive)
	return f
}

func (f *ratchetReceiverFixture) receive(packet []byte) error {
	payload := make([]byte, 4+len(packet))
	binary.BigEndian.PutUint32(payload, uint32(len(packet)))
	copy(payload[4:], packet)
	return f.receiver.HandleGarlic(foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPGarlic}, Payload: payload})
}

func (f *ratchetReceiverFixture) establish(t *testing.T) {
	t.Helper()
	if err := f.receive(f.newSessionReply); err != nil {
		t.Fatal(err)
	}
	if len(f.replies) != 1 {
		t.Fatalf("NSR confirmations = %d, want 1", len(f.replies))
	}
	got, err := f.remote.Receive(make([]byte, 2048), nil, f.replies[0], f.now)
	if err != nil || got.NewSession || len(got.Payload) != 0 || got.Peer != f.localHash {
		t.Fatalf("NSR confirmation = %#v, %v", got, err)
	}
	f.replies = nil
}

func TestGarlicReceiverConfirmsNewSessionReplyWithoutApplicationTraffic(t *testing.T) {
	f := newRatchetReceiverFixture(t)
	f.establish(t)
}

func TestGarlicReceiverAcknowledgesRequestedMessages(t *testing.T) {
	for _, withClove := range []bool{false, true} {
		name := "ack-only"
		if withClove {
			name = "application-clove"
		}
		t.Run(name, func(t *testing.T) {
			f := newRatchetReceiverFixture(t)
			f.establish(t)
			var payload []byte
			delivered := false
			f.receiver.service.SetDestinationSink(func(from, to foundation.Hash, message foundation.I2NPMessage) error {
				data, err := foundation.I2NPParseData(message.Payload)
				if err != nil {
					return err
				}
				if from != f.remoteHash || to != f.localHash || !bytes.Equal(data.Data, []byte("message")) {
					t.Fatalf("delivered message = %x to %x: %x", from, to, message.Payload)
				}
				delivered = true
				return nil
			})
			if withClove {
				content := []byte("message")
				data := make([]byte, 4+len(content))
				binary.BigEndian.PutUint32(data, uint32(len(content)))
				copy(data[4:], content)
				var err error
				payload, err = appendRatchetGarlicClove(make([]byte, 256), dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryDestination, To: f.localHash}, foundation.I2NPMessage{
					Header: foundation.I2NPHeader{Type: foundation.I2NPData, ID: 1, Expiration: f.now + 1000}, Payload: data,
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			packet, err := f.remote.EncryptExisting(make([]byte, 512), f.localHash, payload, dataplanegarlic.RatchetOptions{ACKRequest: true}, f.now)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.receive(packet); err != nil {
				t.Fatal(err)
			}
			if delivered != withClove || len(f.replies) != 1 {
				t.Fatalf("delivered=%t replies=%d, want delivered=%t replies=1", delivered, len(f.replies), withClove)
			}
			got, err := f.remote.Receive(make([]byte, 512), nil, f.replies[0], f.now)
			if err != nil || len(got.ACKs) != 1 || got.ACKs[0] != (dataplanegarlic.RatchetACK{TagSet: 0, Message: 0}) || got.ReplyRequested {
				t.Fatalf("ratchet ACK = %#v, %v", got, err)
			}
			ackOnly, err := f.remote.EncryptExisting(make([]byte, 512), f.localHash, nil, dataplanegarlic.RatchetOptions{ACKs: got.ACKs}, f.now)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.receive(ackOnly); err != nil || len(f.replies) != 1 {
				t.Fatalf("ACK-only packet triggered a response: replies=%d error=%v", len(f.replies), err)
			}
		})
	}
}

func TestGarlicReceiverCompletesRekeyWithoutApplicationReply(t *testing.T) {
	f := newRatchetReceiverFixture(t)
	f.establish(t)
	packet, err := f.remote.EncryptExisting(make([]byte, 512), f.localHash, nil, dataplanegarlic.RatchetOptions{RequestDH: true}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.receive(packet); err != nil || len(f.replies) != 1 {
		t.Fatalf("rekey-only packet: replies=%d error=%v", len(f.replies), err)
	}
	if _, err := f.remote.Receive(make([]byte, 512), nil, f.replies[0], f.now); err != nil {
		t.Fatal(err)
	}
	packet, err = f.remote.EncryptExisting(make([]byte, 512), f.localHash, nil, dataplanegarlic.RatchetOptions{ACKRequest: true}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.receive(packet); err != nil || len(f.replies) != 2 {
		t.Fatalf("new tagset packet: replies=%d error=%v", len(f.replies), err)
	}
	got, err := f.remote.Receive(make([]byte, 512), nil, f.replies[1], f.now)
	if err != nil || len(got.ACKs) != 1 || got.ACKs[0] != (dataplanegarlic.RatchetACK{TagSet: 1, Message: 0}) {
		t.Fatalf("new tagset ACK = %#v, %v", got, err)
	}
}

func TestGarlicReceiverDeliversPayloadWhenACKAdmissionFails(t *testing.T) {
	f := newRatchetReceiverFixture(t)
	f.establish(t)
	delivered := false
	f.receiver.service.SetDestinationSink(func(_, _ foundation.Hash, message foundation.I2NPMessage) error {
		data, err := foundation.I2NPParseData(message.Payload)
		delivered = err == nil && bytes.Equal(data.Data, []byte("deliver despite overload"))
		return err
	})
	content := []byte("deliver despite overload")
	data := make([]byte, 4+len(content))
	binary.BigEndian.PutUint32(data, uint32(len(content)))
	copy(data[4:], content)
	payload, err := appendRatchetGarlicClove(make([]byte, 256), dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryDestination, To: f.localHash}, foundation.I2NPMessage{
		Header: foundation.I2NPHeader{Type: foundation.I2NPData, ID: 1, Expiration: f.now + 1000}, Payload: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := f.remote.EncryptExisting(make([]byte, 512), f.localHash, payload, dataplanegarlic.RatchetOptions{ACKRequest: true}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.reserveErr = ErrRoutePreparationBusy
	if err := f.receive(packet); !errors.Is(err, ErrRoutePreparationBusy) || !delivered || len(f.replies) != 0 {
		t.Fatalf("overloaded ACK admission: delivered=%t replies=%d error=%v", delivered, len(f.replies), err)
	}
}

type dataPlaneDirectSender func(context.Context, dataplanestreamingtunnel.Delivery) error

func (f dataPlaneDirectSender) SendTunnel(ctx context.Context, delivery dataplanestreamingtunnel.Delivery) error {
	return f(ctx, delivery)
}

func TestRatchetGarlicClovesMatchI2PDCompactBlocks(t *testing.T) {
	const fixtureHex = "0b000d0001010203040000000aaabbcc" +
		"0b002c20" +
		"1111111111111111111111111111111111111111111111111111111111111111" +
		"14050607080000000bddee"
	fixture, err := hex.DecodeString(fixtureHex)
	if err != nil {
		t.Fatal(err)
	}
	cloves, err := parseRatchetGarlicCloves(fixture)
	if err != nil {
		t.Fatal(err)
	}
	ratchetGarlicClovesMatchI2PDCompactBlocksRejected := len(cloves) != 2 || cloves[0].Delivery.Type != dataplanegarlic.DeliveryLocal ||
		cloves[0].Message.Header.Type != foundation.I2NPDatabaseStore || cloves[0].Message.Header.ID != 0x01020304 ||
		cloves[0].Message.Header.Expiration != 10_000
	if !ratchetGarlicClovesMatchI2PDCompactBlocksRejected {
		ratchetGarlicClovesMatchI2PDCompactBlocksRejected = !bytes.Equal(cloves[0].Message.Payload, []byte{0xaa, 0xbb, 0xcc})
	}
	if ratchetGarlicClovesMatchI2PDCompactBlocksRejected {
		t.Fatalf("LeaseSet clove = %#v", cloves[0])
	}
	var destination foundation.Hash
	for index := range destination {
		destination[index] = 0x11
	}
	ratchetGarlicClovesMatchI2PDCompactBlocksRejected = cloves[1].Delivery.Type != dataplanegarlic.DeliveryDestination || cloves[1].Delivery.To != destination ||
		cloves[1].Message.Header.Type != foundation.I2NPData || cloves[1].Message.Header.ID != 0x05060708 ||
		cloves[1].Message.Header.Expiration != 11_000
	if !ratchetGarlicClovesMatchI2PDCompactBlocksRejected {
		ratchetGarlicClovesMatchI2PDCompactBlocksRejected = !bytes.Equal(cloves[1].Message.Payload, []byte{0xdd, 0xee})
	}
	if ratchetGarlicClovesMatchI2PDCompactBlocksRejected {
		t.Fatalf("Data clove = %#v", cloves[1])
	}

	encoded := make([]byte, len(fixture))
	first, err := appendRatchetGarlicClove(encoded, dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryLocal}, cloves[0].Message)
	if err != nil {
		t.Fatal(err)
	}
	second, err := appendRatchetGarlicClove(encoded[len(first):], dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryDestination, To: destination}, cloves[1].Message)
	if err != nil {
		t.Fatal(err)
	}
	if got := encoded[:len(first)+len(second)]; !bytes.Equal(got, fixture) {
		t.Fatalf("compact blocks = %x, want %x", got, fixture)
	}
}

func TestDestinationDataUsesI2CPGzipHeader(t *testing.T) {
	payload := []byte("native-streaming-payload")
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	gzipPayload := compressed.Bytes()
	binary.BigEndian.PutUint16(gzipPayload[4:6], 1234)
	binary.BigEndian.PutUint16(gzipPayload[6:8], 5678)
	gzipPayload[9] = dataplanestreamingtunnel.ProtocolStreaming
	data := make([]byte, 4+len(gzipPayload))
	binary.BigEndian.PutUint32(data[:4], uint32(len(gzipPayload)))
	copy(data[4:], gzipPayload)
	protocol, fromPort, toPort, decoded, err := parseDestinationData(data)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != dataplanestreamingtunnel.ProtocolStreaming || fromPort != 1234 || toPort != 5678 || !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded Data = protocol %d ports %d/%d payload %q", protocol, fromPort, toPort, decoded)
	}

	encoded, err := marshalDestinationDataTo(make([]byte, 256), dataplanestreamingtunnel.Delivery{
		Protocol: dataplanestreamingtunnel.ProtocolStreaming, FromPort: 1234, ToPort: 5678, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded[4:8], []byte{0x1f, 0x8b, 0x08, 0x00}) || encoded[13] != dataplanestreamingtunnel.ProtocolStreaming {
		t.Fatalf("I2CP gzip header = %x", encoded[4:14])
	}
	_, _, _, roundTrip, err := parseDestinationData(encoded)
	if err != nil || !bytes.Equal(roundTrip, payload) {
		t.Fatalf("stored-block round trip = %q, %v", roundTrip, err)
	}
}

func TestHandleDestinationDataAcceptsDelayedStreamingSYN(t *testing.T) {
	clientDestination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	serverDestination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clientDestination.ReleaseSensitive()
		serverDestination.ReleaseSensitive()
	})

	serverDestinations := NewDestinationManager()
	t.Cleanup(func() { _ = serverDestinations.Close() })
	serverSession, err := serverDestinations.Create(DestinationSessionConfig{
		Default: true,
		Streaming: dataplanestreamingtunnel.TunnelNetworkConfig{
			Destination: serverDestination,
			Sender: dataPlaneDirectSender(func(context.Context, dataplanestreamingtunnel.Delivery) error {
				return nil
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverSession.ListenI2P(context.Background(), ":80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serverHash := serverDestination.Hash()
	serverGarlic := dataplanegarlic.NewSessionManager(dataplanegarlic.SessionManagerConfig{})
	t.Cleanup(func() { _ = serverGarlic.Close() })
	receiver, err := NewGarlicReceiver(GarlicReceiverConfig{
		Service: NewService(Sinks{}),
		Destinations: map[foundation.Hash]GarlicDestination{
			serverHash: {Sessions: serverGarlic},
		},
		ReplyKeys: dataplanegarlic.NewReplyKeyRegistry(1),
		Now:       func() uint64 { return 1_000 },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(receiver.ReleaseSensitive)

	clientIdentity, err := clientDestination.Identity()
	if err != nil {
		t.Fatal(err)
	}
	clientRaw := append([]byte(nil), clientIdentity.Bytes()...)
	signatureLen, ok := clientDestination.SigningKeyType().SignatureLen()
	if !ok {
		t.Fatal("client signing type has no signature length")
	}
	options := make([]byte, 0, 2+len(clientRaw)+2+signatureLen)
	options = append(options, 0, 0)
	options = append(options, clientRaw...)
	options = append(options, 0x06, 0xc2)
	options = append(options, make([]byte, signatureLen)...)
	packet := dataplanestreaming.Packet{
		ReceiveStreamID: 1,
		Sequence:        0,
		NACKCount:       8,
		NACKs:           append([]byte(nil), serverHash[:]...),
		Flags: dataplanestreamingtunnel.FlagSynchronize | dataplanestreamingtunnel.FlagNoACK |
			dataplanestreamingtunnel.FlagDelayRequested | dataplanestreamingtunnel.FlagFromIncluded |
			dataplanestreamingtunnel.FlagMaxPacketSize | dataplanestreamingtunnel.FlagSignatureIncluded,
		Options: options,
	}
	wire := make([]byte, packet.EncodedLen())
	if _, err = packet.MarshalTo(wire); err != nil {
		t.Fatal(err)
	}
	signature, err := clientDestination.Sign(wire)
	if err != nil {
		t.Fatal(err)
	}
	signatureOffset := dataplanestreaming.HeaderLen + len(packet.NACKs) + 2 + len(clientRaw) + 2
	copy(wire[signatureOffset:signatureOffset+len(signature)], signature)

	data, err := marshalDestinationDataTo(make([]byte, foundation.I2NPI2PDMaxPayload), dataplanestreamingtunnel.Delivery{
		Protocol: dataplanestreamingtunnel.ProtocolStreaming,
		FromPort: 1234,
		ToPort:   80,
		Payload:  wire,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = receiver.HandleDestinationData(clientDestination.Hash(), serverHash, foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPData},
		Payload: data,
	}, serverDestinations); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if connection == nil {
		t.Fatal("delayed SYN did not create a stream")
	}
}

func TestStreamingTunnelSenderReleasesScratchBeforeTunnelIO(t *testing.T) {
	const now = uint64(1_000)
	started := make(chan struct{})
	release := make(chan struct{})
	bridge := &dataPlaneTunnelSender{handle: func(context.Context, foundation.I2NPMessage) error {
		close(started)
		<-release
		return nil
	}}
	runtime := dataplanetunnel.NewRuntime(dataplanetunnel.RuntimeConfig{Sender: bridge, Now: func() uint64 { return now }})
	const outboundID = uint32(91)
	circuit, err := runtime.RegisterOutbound(dataplanetunnel.OutboundCircuit{ID: outboundID, FirstHop: foundation.Hash{1}, NextTunnelID: 2})
	if err != nil {
		t.Fatal(err)
	}
	sender := &PreparedRouteSender{
		tunnels: runtime,
		now:     func() uint64 { return now },
		nextID:  func() (uint32, error) { return 1, nil },
		scratch: make(chan *streamingSenderScratch, 1),
	}
	scratch := new(streamingSenderScratch)
	encrypted := scratch.encrypted.bytes(1)
	encrypted[0] = 0xaa
	done := make(chan error, 1)
	go func() {
		done <- sender.finishEncryptedSend(context.Background(), &PreparedRoute{Circuit: circuit, Gateway: foundation.Hash{1}, TunnelID: 3, Expires: now + 1_000}, encrypted, now+1_000, scratch)
	}()
	<-started
	select {
	case returned := <-sender.scratch:
		if returned != scratch || encrypted[0] != 0 {
			t.Fatal("scratch was not cleared before tunnel I/O")
		}
	default:
		t.Fatal("scratch remained held during tunnel I/O")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGarlicReceiverDeliversConcurrentNewSessionPayloads(t *testing.T) {
	const now = uint64(1_000_000)
	initiator, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	responder, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	initiatorHash, responderHash := initiator.Hash(), responder.Hash()
	responderKey := responder.X25519Public()
	left, err := dataplanegarlic.NewRatchetManager(initiator, dataplanegarlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	right, err := dataplanegarlic.NewRatchetManager(responder, dataplanegarlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		left.ReleaseSensitive()
		right.ReleaseSensitive()
		initiator.ReleaseSensitive()
		responder.ReleaseSensitive()
	})
	data, err := marshalDestinationDataTo(make([]byte, 256), dataplanestreamingtunnel.Delivery{
		From: initiatorHash, To: responderHash, Protocol: dataplanestreamingtunnel.ProtocolStreaming,
	})
	if err != nil {
		t.Fatal(err)
	}
	set := signedDataPlaneLeaseSet2(t, initiator, now)
	storePayload, err := foundation.NetworkDatabaseMarshalDatabaseStore(initiatorHash, foundation.I2NPStoreLeaseSet2, set, 0, foundation.Hash{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: 2, Expiration: now + 1_000}, Payload: storePayload}
	static := initiator.X25519Public()
	observed := foundation.Sum(static[:])
	if target, targetErr := ratchetReplyTarget([]dataplanegarlic.Clove{{Delivery: dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryLocal}, Message: store}}, observed); targetErr != nil || target != initiatorHash {
		t.Fatalf("valid LS2 binding target = %x, %v", target, targetErr)
	}
	forgedPayload := append([]byte(nil), store.Payload...)
	forgedPayload[len(forgedPayload)-1] ^= 1
	forged := store
	forged.Payload = forgedPayload
	if _, targetErr := ratchetReplyTarget([]dataplanegarlic.Clove{{Delivery: dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryLocal}, Message: forged}}, observed); !errors.Is(targetErr, ErrGarlicPacket) {
		t.Fatalf("forged LS2 binding error = %v, want %v", targetErr, ErrGarlicPacket)
	}
	newPacket := func(storeID, dataID uint32) []byte {
		t.Helper()
		packetStore := store
		packetStore.Header.ID = storeID
		message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPData, ID: dataID, Expiration: now + 1_000}, Payload: data}
		payload := make([]byte, 2*foundation.NetworkDatabaseMaxLeaseSetBytes)
		first, appendErr := appendRatchetGarlicClove(payload, dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryLocal}, packetStore)
		if appendErr != nil {
			t.Fatal(appendErr)
		}
		second, appendErr := appendRatchetGarlicClove(payload[len(first):], dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryDestination, To: responderHash}, message)
		if appendErr != nil {
			t.Fatal(appendErr)
		}
		payload = payload[:len(first)+len(second)]
		packet, encryptErr := left.Encrypt(make([]byte, foundation.I2NPI2PDMaxPayload-4), responderHash, responderKey[:], uint16(foundation.CryptoX25519), payload, now)
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		return packet
	}
	wrap := func(packet []byte) foundation.I2NPMessage {
		payload := make([]byte, 4+len(packet))
		binary.BigEndian.PutUint32(payload[:4], uint32(len(packet)))
		copy(payload[4:], packet)
		return foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPGarlic}, Payload: payload}
	}
	control := new(dataPlaneControlCapture)
	service := NewService(Sinks{Control: control})
	delivered := make([]uint32, 0, 2)
	service.SetDestinationSink(func(_ foundation.Hash, _ foundation.Hash, message foundation.I2NPMessage) error {
		delivered = append(delivered, message.Header.ID)
		return nil
	})
	var replyTarget foundation.Hash
	var reply []byte
	replies := 0
	admitReply := false
	receiver, err := NewGarlicReceiver(GarlicReceiverConfig{
		Service: service, ReplyKeys: dataplanegarlic.NewReplyKeyRegistry(1), Now: func() uint64 { return now },
		Destinations: map[foundation.Hash]GarlicDestination{responderHash: {
			Ratchet: right,
			ReserveRatchetReply: func(target foundation.Hash) (RatchetReplyReservation, error) {
				if !admitReply {
					return nil, ErrRoutePreparationBusy
				}
				return dataPlaneReplyReservation(func(_ context.Context, packet []byte) error {
					replies++
					replyTarget, reply = target, append([]byte(nil), packet...)
					return nil
				}), nil
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	firstPacket := wrap(newPacket(2, 1))
	if err := receiver.HandleGarlic(firstPacket); !errors.Is(err, ErrRoutePreparationBusy) {
		t.Fatalf("reply admission failure = %v", err)
	}
	if right.Stats().Sessions != 0 || len(delivered) != 0 {
		t.Fatal("failed reservation committed or delivered a new session")
	}
	admitReply = true
	for _, message := range []foundation.I2NPMessage{wrap(newPacket(2, 1)), wrap(newPacket(4, 3))} {
		if err = receiver.HandleGarlic(message); err != nil {
			t.Fatal(err)
		}
	}
	if len(delivered) != 2 || delivered[0] != 1 || delivered[1] != 3 {
		t.Fatalf("delivered Data IDs = %v, want [1 3]", delivered)
	}
	if len(control.messages) != 2 {
		t.Fatalf("bundled LeaseSet handoffs = %d, want 2", len(control.messages))
	}
	if replies != 1 || replyTarget != initiatorHash || len(reply) == 0 {
		t.Fatalf("New Session replies = %d to %x with %d bytes, want one reply to %x", replies, replyTarget, len(reply), initiatorHash)
	}
	if stats := right.Stats(); stats.Sessions != 1 {
		t.Fatalf("responder sessions = %d, want 1", stats.Sessions)
	}
	if _, err = left.Receive(make([]byte, len(reply)), make([]byte, len(reply)), reply, now); err != nil {
		t.Fatalf("initiator did not transition to Existing Session: %v", err)
	}
	existing, err := left.EncryptExisting(make([]byte, foundation.I2NPI2PDMaxPayload-4), responderHash, []byte{11, 0, 0}, dataplanegarlic.RatchetOptions{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = right.Receive(make([]byte, len(existing)), make([]byte, len(existing)), existing, now); err != nil {
		t.Fatalf("responder rejected Existing Session: %v", err)
	}
}
func signedDataPlaneLegacyLeaseSet(t *testing.T, address foundation.LocalAddress, lease foundation.NetworkDatabaseLease) []byte {
	t.Helper()
	raw, err := foundation.DecodeI2PBase64(address.Destination)
	if err != nil {
		t.Fatal(err)
	}
	identity, _, err := foundation.ParseIdentity(raw)
	if err != nil {
		t.Fatal(err)
	}
	signing, rest := identity.SigningKeyParts()
	if len(rest) != 0 {
		t.Fatal("split fixture signing key")
	}
	unsigned := append(raw, address.EncryptionPublic[:]...)
	unsigned = append(unsigned, signing...)
	unsigned = append(unsigned, 1)
	unsigned = append(unsigned, lease.Gateway[:]...)
	unsigned = binary.BigEndian.AppendUint32(unsigned, lease.TunnelID)
	unsigned = binary.BigEndian.AppendUint64(unsigned, lease.EndDate)
	return append(unsigned, ed25519.Sign(address.SigningPrivate, unsigned)...)
}

func signedDataPlaneLeaseSet2(t *testing.T, destination *foundation.LocalDestination, now uint64) []byte {
	t.Helper()
	identity, err := destination.Identity()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := append([]byte(nil), identity.Bytes()...)
	unsigned = binary.BigEndian.AppendUint32(unsigned, uint32(now/1000))
	unsigned = binary.BigEndian.AppendUint16(unsigned, 60)
	unsigned = append(unsigned, 0, 0, 0, 0, 1)
	unsigned = binary.BigEndian.AppendUint16(unsigned, uint16(foundation.CryptoX25519))
	unsigned = binary.BigEndian.AppendUint16(unsigned, 32)
	key := destination.X25519Public()
	unsigned = append(unsigned, key[:]...)
	unsigned = append(unsigned, 1)
	gateway := foundation.Hash{1}
	unsigned = append(unsigned, gateway[:]...)
	unsigned = binary.BigEndian.AppendUint32(unsigned, 1)
	unsigned = binary.BigEndian.AppendUint32(unsigned, uint32(now/1000)+60)
	signature, err := destination.Sign(append([]byte{byte(foundation.I2NPStoreLeaseSet2)}, unsigned...))
	if err != nil {
		t.Fatal(err)
	}
	return append(unsigned, signature...)
}

func TestLegacyGarlicSYNTeachesReceiverSenderLeaseSet(t *testing.T) {
	const now = uint64(1_000)
	senderAddress, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	stored := signedDataPlaneLegacyLeaseSet(t, senderAddress, foundation.NetworkDatabaseLease{
		Gateway: foundation.Hash{1}, TunnelID: 7, EndDate: now + 120_000,
	})
	var nextID uint32
	sender := &PreparedRouteSender{
		nextID: func() (uint32, error) {
			nextID++
			return nextID, nil
		},
	}
	bundle, err := foundation.NetworkDatabaseMarshalDatabaseStore(senderAddress.Hash, foundation.I2NPStoreLeaseSet, stored, 0, foundation.Hash{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	syn := make([]byte, dataplanestreaming.HeaderLen)
	binary.BigEndian.PutUint16(syn[18:20], dataplanestreamingtunnel.FlagSynchronize)
	wire, err := sender.destinationCloveSetTo(make([]byte, foundation.I2NPI2PDMaxPayload), make([]byte, foundation.I2NPI2PDMaxPayload), dataplanestreamingtunnel.Delivery{
		From: senderAddress.Hash, To: foundation.Hash{2}, Protocol: dataplanestreamingtunnel.ProtocolStreaming, Payload: syn,
	}, now+60_000, &PreparedRoute{LocalLeaseSet: bundle})
	if err != nil {
		t.Fatal(err)
	}
	set, err := dataplanegarlic.ParseCloveSet(wire)
	if err != nil {
		t.Fatal(err)
	}
	cloves := set.Cloves()
	first, ok, err := cloves.Next()
	if err != nil || !ok || first.Delivery.Type != dataplanegarlic.DeliveryLocal || first.Message.Header.Type != foundation.I2NPDatabaseStore {
		t.Fatalf("first legacy SYN clove = %#v, %t, %v", first, ok, err)
	}

	control := new(dataPlaneControlCapture)
	service := NewService(Sinks{Control: control})
	service.SetDestinationSink(func(foundation.Hash, foundation.Hash, foundation.I2NPMessage) error { return nil })
	if err = service.HandleGarlicCloveSet(set, now, false); err != nil {
		t.Fatal(err)
	}
	if len(control.messages) != 1 {
		t.Fatalf("local LeaseSet handoffs = %d, want 1", len(control.messages))
	}
	store, err := foundation.I2NPParseDatabaseStore(control.messages[0].Message.Payload)
	if err != nil {
		t.Fatal(err)
	}
	received, err := foundation.NetworkDatabaseParseLeaseSet(store.Data)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := received.Verify()
	if err != nil || !valid || received.Destination.Hash() != senderAddress.Hash {
		t.Fatalf("receiver did not learn an authenticated sender LeaseSet: %v", err)
	}
}

func TestGarlicReceiverConstructorFailureDoesNotReturnSensitiveOwner(t *testing.T) {
	hash := foundation.Sum([]byte("invalid-garlic-destination"))
	receiver, err := NewGarlicReceiver(GarlicReceiverConfig{
		Service: NewService(Sinks{}), ReplyKeys: dataplanegarlic.NewReplyKeyRegistry(1),
		Now: func() uint64 { return 1 }, StaticPrivate: bytes.Repeat([]byte{0x42}, 32),
		Destinations: map[foundation.Hash]GarlicDestination{hash: {}},
	})
	if !errors.Is(err, ErrDataPlaneConfig) || receiver != nil {
		t.Fatalf("NewGarlicReceiver partial failure = %#v, %v", receiver, err)
	}
}
func TestGarlicReceiverUnregisterWaitsForInflightAndReleasesStaticKey(t *testing.T) {
	local, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer local.ReleaseSensitive()
	ratchet, err := dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer ratchet.ReleaseSensitive()
	static := bytes.Repeat([]byte{0x42}, 32)
	receiver, err := NewGarlicReceiver(GarlicReceiverConfig{
		Service: NewService(Sinks{}), ReplyKeys: dataplanegarlic.NewReplyKeyRegistry(1),
		Now: func() uint64 { return 1_800_000_000_000 }, StaticPrivate: static,
	})
	if err != nil {
		t.Fatal(err)
	}
	remove, err := receiver.RegisterDestination(local.Hash(), GarlicDestination{Ratchet: ratchet})
	if err != nil {
		t.Fatal(err)
	}
	receiver.destinationsMu.RLock()
	state := receiver.destinations[local.Hash()]
	receiver.destinationsMu.RUnlock()
	heldScratch := make([]*garlicReceiveScratch, 0, cap(state.scratch))
	for range cap(state.scratch) {
		heldScratch = append(heldScratch, <-state.scratch)
	}
	payload := make([]byte, 4+64)
	binary.BigEndian.PutUint32(payload[:4], 64)
	handleDone := make(chan struct{})
	go func() {
		_ = receiver.HandleGarlic(foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPGarlic}, Payload: payload})
		close(handleDone)
	}()
	deadline := time.NewTimer(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		state.inFlightMu.Lock()
		inFlight := state.inFlight
		state.inFlightMu.Unlock()
		if inFlight == 1 {
			break
		}
		select {
		case <-deadline.C:
			for _, scratch := range heldScratch {
				state.scratch <- scratch
			}
			t.Fatal("garlic handler never acquired its destination snapshot")
		case <-ticker.C:
		}
	}
	removeDone := make(chan struct{})
	go func() {
		remove()
		close(removeDone)
	}()
	select {
	case <-removeDone:
		for _, scratch := range heldScratch {
			state.scratch <- scratch
		}
		t.Fatal("destination unregister returned during in-flight receive")
	case <-time.After(20 * time.Millisecond):
	}
	for _, scratch := range heldScratch {
		state.scratch <- scratch
	}
	select {
	case <-handleDone:
	case <-time.After(time.Second):
		t.Fatal("garlic receive did not finish")
	}
	select {
	case <-removeDone:
	case <-time.After(time.Second):
		t.Fatal("destination unregister did not pass its in-flight barrier")
	}
	receiver.ReleaseSensitive()
	receiver.ReleaseSensitive()
	if !receiver.released || receiver.hasStatic || receiver.staticPrivate != ([32]byte{}) || len(receiver.destinations) != 0 {
		t.Fatal("garlic receiver retained sensitive static or destination state")
	}
}
