package tunnel

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"testing"

	"gosuda.org/ivnp/networking/internal/i2np"
)

func TestBuildManagerGatewayTransitRelaysJavaUnknownI2NPCorpus(t *testing.T) {
	// TunnelGatewayMessage and UnknownI2NPMessage records were sampled every 30
	// seconds during a 10-minute run of Java I2P router commit
	// fda1ced99c3b1e8513b88c543bca3aeb668330a8.
	const path = "testdata/java-fda1ced/tunnel-gateway-unknown-222.corpus"
	corpus, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Java TunnelGateway corpus: %v", err)
	}
	records := splitJavaTunnelCorpus(t, corpus)
	if len(records) != 21 {
		t.Fatalf("Java TunnelGateway corpus has %d records, want 21 samples spanning both run endpoints", len(records))
	}
	for index, fixture := range records {
		testJavaUnknownI2NPRelay(t, index, fixture)
	}
}

func splitJavaTunnelCorpus(t testing.TB, corpus []byte) [][]byte {
	t.Helper()
	var records [][]byte
	for offset := 0; offset < len(corpus); {
		if len(corpus)-offset < 4 {
			t.Fatalf("Java TunnelGateway corpus has truncated record length at byte %d", offset)
		}
		length := int(binary.BigEndian.Uint32(corpus[offset : offset+4]))
		offset += 4
		if length > len(corpus)-offset {
			t.Fatalf("Java TunnelGateway record %d declares %d bytes with %d remaining", len(records), length, len(corpus)-offset)
		}
		records = append(records, corpus[offset:offset+length])
		offset += length
	}
	return records
}

func testJavaUnknownI2NPRelay(t testing.TB, record int, fixture []byte) {
	t.Helper()
	envelope, used, err := i2np.Parse(fixture)
	if err != nil || used != len(fixture) || envelope.Header.Type != i2np.TunnelGateway {
		t.Fatalf("record %d: parse Java TunnelGateway = type %d, %d/%d bytes, %v", record, envelope.Header.Type, used, len(fixture), err)
	}
	gateway, err := i2np.ParseTunnelGateway(envelope.Payload)
	if err != nil {
		t.Fatalf("record %d: %v", record, err)
	}
	const (
		now        = uint64(1_700_000_000_000)
		futureType = i2np.MessageType(222)
	)
	if gateway.Embedded.Header.Type != futureType {
		t.Fatalf("record %d: Java TunnelGateway embedded type = %d, want %d", record, gateway.Embedded.Header.Type, futureType)
	}
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Sender: sender, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatalf("record %d: %v", record, err)
	}
	next := sha256.Sum256([]byte("gateway-next"))
	request := ShortBuildRequest{
		ReceiveTunnelID: gateway.TunnelID, NextTunnelID: 12, NextRouter: next, Gateway: true,
		RequestMinutes: uint32(now / 60_000), LifetimeSeconds: shortBuildLifetime, NextMessageID: 13,
	}
	var keys ShortBuildKeys
	for index := range keys.LayerKey {
		keys.LayerKey[index] = byte(index + 1)
		keys.IVKey[index] = byte(255 - index)
	}
	if err = manager.installTransitCircuit(request, keys, now); err != nil {
		t.Fatalf("record %d: %v", record, err)
	}
	if err = runtime.HandleGateway(gateway.TunnelID, gateway.Embedded); err != nil {
		t.Fatalf("record %d: %v", record, err)
	}
	sent := sender.take()
	if len(sent) != 1 || sent[0].peer != next || sent[0].message.Header.Type != i2np.TunnelData {
		t.Fatalf("record %d: gateway injection = %#v", record, sent)
	}
	payload := append([]byte(nil), sent[0].message.Payload...)
	decryptor, err := NewLayerDecryptor(keys.LayerKey[:], keys.IVKey[:])
	if err != nil {
		t.Fatalf("record %d: %v", record, err)
	}
	if err = decryptor.Transform(payload[4:], payload[4:]); err != nil {
		t.Fatalf("record %d: %v", record, err)
	}
	blocks := make([]Block, 1)
	count, err := NewEndpoint(1, i2np.I2PDMaxPayload).Parse(payload, blocks)
	if err != nil || count != 1 || blocks[0].Delivery != DeliveryLocal {
		t.Fatalf("record %d: gateway payload blocks = %d, %#v, %v", record, count, blocks[0], err)
	}
	delivered, used, err := i2np.ParseUnchecked(blocks[0].Data)
	if err != nil || used != len(blocks[0].Data) || delivered.Header != gateway.Embedded.Header || !bytes.Equal(delivered.Payload, gateway.Embedded.Payload) {
		t.Fatalf("record %d: unknown gateway payload delivery = %#v, %d, %v", record, delivered, used, err)
	}
}
