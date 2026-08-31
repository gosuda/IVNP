package tunnel

import (
	"bytes"
	"testing"

	"gosuda.org/ivnp/internal/packet"
	"gosuda.org/ivnp/networking/internal/i2np"
)

func TestGatewayRoundTripsDeliveryInstructions(t *testing.T) {
	var router, gateway [32]byte
	for i := range router {
		router[i] = byte(i + 1)
		gateway[i] = byte(255 - i)
	}
	blocks := []Block{
		{Delivery: DeliveryLocal, Last: true, Data: []byte("local")},
		{Delivery: DeliveryTunnel, Gateway: gateway, TunnelID: 7, Last: true, Data: []byte("tunnel")},
		{Delivery: DeliveryRouter, Gateway: router, Last: true, Data: []byte("router")},
	}
	buf := testPacketBuffer(t)
	defer buf.Release()
	g := NewGateway(bytes.NewReader(bytes.Repeat([]byte{0x7f}, i2np.TunnelDataMessageLen)))
	if err := g.Encode(9, blocks, buf); err != nil {
		t.Fatal(err)
	}

	endpoint := NewEndpoint(4, 4096)
	got := make([]Block, len(blocks))
	payload, ok := buf.Payload()
	if !ok {
		t.Fatal("payload unavailable")
	}
	n, err := endpoint.Parse(payload, got, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(blocks) {
		t.Fatalf("deliveries = %d, want %d", n, len(blocks))
	}
	for i := range blocks {
		if got[i].Delivery != blocks[i].Delivery || got[i].TunnelID != blocks[i].TunnelID || got[i].Gateway != blocks[i].Gateway || !got[i].Last || !bytes.Equal(got[i].Data, blocks[i].Data) {
			t.Fatalf("delivery %d = %#v, want %#v", i, got[i], blocks[i])
		}
	}
	// The direct delivery remains a borrowed view into caller packet storage.
	// Its exact offset is not material to the public API, so mutate it to prove aliasing.
	got[0].Data[0] = 'L'
	payload, ok = buf.Payload()
	if !ok || !bytes.Contains(payload, []byte("Local")) {
		t.Fatal("unfragmented delivery did not alias packet storage")
	}
}

func TestGatewayFragmentsAndReassembles(t *testing.T) {
	message := bytes.Repeat([]byte("fragmented message "), 160)
	block := Block{Delivery: DeliveryTunnel, TunnelID: 11, Last: true, Data: message}
	buffers := make([]*packet.Buffer, 4)
	for index := range buffers {
		buffers[index] = testPacketBuffer(t)
	}
	for _, buf := range buffers {
		defer buf.Release()
	}
	g := NewGateway(bytes.NewReader(bytes.Repeat([]byte{0x7f}, 4*i2np.TunnelDataMessageLen)))
	n, err := g.Fragment(13, block, buffers)
	if err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Fatalf("fragment count = %d, want at least 2", n)
	}

	endpoint := NewEndpoint(4, len(message))
	out := make([]Block, 1)
	for i := range n - 1 {
		payload, ok := buffers[i].Payload()
		if !ok {
			t.Fatalf("fragment %d payload unavailable", i)
		}
		if count, err := endpoint.Parse(payload, out, uint64(i)); err != nil || count != 0 {
			t.Fatalf("fragment %d = %d, %v", i, count, err)
		}
	}
	payload, ok := buffers[n-1].Payload()
	if !ok {
		t.Fatal("final fragment payload unavailable")
	}
	count, err := endpoint.Parse(payload, out, uint64(n))
	if err != nil || count != 1 {
		t.Fatalf("final fragment = %d, %v", count, err)
	}
	if got := out[0]; got.Delivery != block.Delivery || got.TunnelID != block.TunnelID || got.MessageID == 0 || !got.Last || !bytes.Equal(got.Data, message) {
		t.Fatalf("reassembled block = %#v, want generated nonzero message ID", got)
	}
}

func TestGatewayRejectsTruncatedAndOversizedBlocks(t *testing.T) {
	g := NewGateway(bytes.NewReader(bytes.Repeat([]byte{1}, i2np.TunnelDataMessageLen)))
	buf := testPacketBuffer(t)
	defer buf.Release()
	if err := g.Encode(1, []Block{{Delivery: DeliveryLocal, Last: true, Data: bytes.Repeat([]byte{1}, maxBlockBytes)}}, buf); err == nil {
		t.Fatal("oversized block accepted")
	}
	endpoint := NewEndpoint(1, 1)
	if _, err := endpoint.Parse(make([]byte, i2np.TunnelDataMessageLen-1), nil, 0); err == nil {
		t.Fatal("truncated TunnelData accepted")
	}
}

func TestGatewayRejectsChecksumMismatch(t *testing.T) {
	buf := testPacketBuffer(t)
	defer buf.Release()
	if err := NewGateway(bytes.NewReader(bytes.Repeat([]byte{0x7f}, i2np.TunnelDataMessageLen))).Encode(
		1, []Block{{Delivery: DeliveryLocal, Last: true, Data: []byte("authenticated")}}, buf,
	); err != nil {
		t.Fatal(err)
	}
	payload, ok := buf.Payload()
	if !ok {
		t.Fatal("payload unavailable")
	}
	payload[len(payload)-1] ^= 1
	if _, err := NewEndpoint(1, 64).Parse(payload, make([]Block, 1), 0); err != ErrGatewayPayload {
		t.Fatalf("tampered payload error = %v, want %v", err, ErrGatewayPayload)
	}
}

func testPacketBuffer(t *testing.T) *packet.Buffer {
	t.Helper()
	buffer, ok := packet.Acquire(0, i2np.TunnelDataMessageLen)
	if !ok {
		t.Fatal("packet buffer acquisition failed")
	}
	return buffer
}

func TestBlockIteratorRejectsUnsupportedInstructionFlags(t *testing.T) {
	for _, payload := range [][]byte{
		{0x10, 0, 0},             // delay requested
		{0x04, 0, 0},             // extended options
		{0x01, 0, 0},             // reserved bit
		{0x80, 0, 0, 0, 1, 0, 0}, // follow-on fragment zero
	} {
		it := NewBlockIterator(payload)
		if _, _, err := it.Next(); err == nil {
			t.Fatalf("accepted unsupported instruction %x", payload[0])
		}
	}
}
