package i2np

import (
	"encoding/binary"
	"errors"
	"testing"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/internal/wire"
)

func TestStandardFrameRoundTripAndChecksum(t *testing.T) {
	message := Message{
		Header:  Header{Type: DeliveryStatus, ID: 0x01020304, Expiration: 0x0102030405060708},
		Payload: []byte{0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 9},
	}
	wire := make([]byte, message.EncodedLen())
	if n, err := message.MarshalTo(wire); err != nil || n != len(wire) {
		t.Fatalf("MarshalTo() = %d, %v", n, err)
	}
	parsed, n, err := Parse(wire)
	if err != nil || n != len(wire) {
		t.Fatalf("Parse() = %#v, %d, %v", parsed, n, err)
	}
	if parsed.Header != message.Header || string(parsed.Payload) != string(message.Payload) {
		t.Fatalf("parsed message = %#v", parsed)
	}
	wire[len(wire)-1] ^= 1
	if _, _, err := Parse(wire); !errors.Is(err, ErrChecksum) {
		t.Fatalf("checksum error = %v, want ErrChecksum", err)
	}
}

func TestI2PDAndWireMaximumBounds(t *testing.T) {
	payload := make([]byte, I2PDMaxPayload+1)
	message := Message{Payload: payload}
	if _, err := message.MarshalTo(make([]byte, StandardHeaderLen+len(payload))); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("i2pd limit error = %v, want ErrPayloadTooLarge", err)
	}
	wire := make([]byte, StandardHeaderLen+len(payload))
	if _, err := message.MarshalWireTo(wire); err != nil {
		t.Fatalf("MarshalWireTo() = %v", err)
	}
	if _, _, err := Parse(wire); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("Parse(i2pd oversized) = %v, want ErrPayloadTooLarge", err)
	}
	parsed, n, err := ParseWire(wire)
	if err != nil || n != len(wire) || len(parsed.Payload) != len(payload) {
		t.Fatalf("ParseWire() = %d payload bytes, %d, %v", len(parsed.Payload), n, err)
	}
}

func TestParseRejectsDeclaredTruncation(t *testing.T) {
	frame := make([]byte, StandardHeaderLen)
	binary.BigEndian.PutUint16(frame[13:15], 1)
	if _, _, err := Parse(frame); !errors.Is(err, wire.ErrShortBuffer) {
		t.Fatalf("Parse() error = %v, want short buffer", err)
	}
}

func TestDatabaseStoreConditionalLengths(t *testing.T) {
	payload := make([]byte, 37+2+3)
	payload[32] = byte(StoreRouterInfo)
	binary.BigEndian.PutUint16(payload[37:39], 3)
	copy(payload[39:], []byte{1, 2, 3})
	store, err := ParseDatabaseStore(payload)
	if err != nil || store.Type != StoreRouterInfo || string(store.Data) != "\x01\x02\x03" {
		t.Fatalf("ParseDatabaseStore() = %#v, %v", store, err)
	}
	binary.BigEndian.PutUint16(payload[37:39], 4)
	if _, err := ParseDatabaseStore(payload); !errors.Is(err, ErrMalformed) {
		t.Fatalf("compressed RI size error = %v, want ErrMalformed", err)
	}
}

func TestDatabaseLookupMaximumAndConditionalTagBounds(t *testing.T) {
	payload := make([]byte, MaxDatabaseLookupPayload)
	payload[64] = lookupDelivery | lookupEncrypted
	binary.BigEndian.PutUint32(payload[65:69], 1)
	binary.BigEndian.PutUint16(payload[69:71], MaxDatabaseLookupExcluded)
	off := 71 + MaxDatabaseLookupExcluded*ivnp.HashLength
	off += 32
	payload[off] = MaxDatabaseReplyTags
	lookup, err := ParseDatabaseLookup(payload)
	if err != nil {
		t.Fatal(err)
	}
	if lookup.ExcludedCount() != MaxDatabaseLookupExcluded || lookup.ReplyTagCount() != MaxDatabaseReplyTags || lookup.ReplyTagLen != 32 {
		t.Fatalf("lookup bounds = %d exclusions, %d tags x %d", lookup.ExcludedCount(), lookup.ReplyTagCount(), lookup.ReplyTagLen)
	}
	payload[69], payload[70] = 2, 1 // 513 exceeds the specification bound.
	if _, err := ParseDatabaseLookup(payload); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversized exclude count error = %v, want ErrPayloadTooLarge", err)
	}
}

type databaseLookupLayoutCase struct {
	name       string
	flags      uint8
	exclusions int
	tags       int
	tagLen     int
}

func TestDatabaseLookupReplyLayouts(t *testing.T) {
	tests := []databaseLookupLayoutCase{
		{name: "unencrypted tunnel", flags: lookupDelivery | lookupTypeMask, exclusions: 1},
		{name: "legacy AES", flags: lookupEncrypted | 0x04, exclusions: 2, tags: 2, tagLen: 32},
		{name: "ECIES AEAD", flags: lookupDelivery | lookupECIES | 0x08, exclusions: 1, tags: 1, tagLen: 8},
		{name: "ECIES with legacy bit", flags: lookupEncrypted | lookupECIES, tags: 1, tagLen: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDatabaseLookupReplyLayout(t, tt)
		})
	}
}

func testDatabaseLookupReplyLayout(t *testing.T, test databaseLookupLayoutCase) {
	t.Helper()
	size := 65 + 2 + test.exclusions*ivnp.HashLength
	if test.flags&lookupDelivery != 0 {
		size += 4
	}
	if test.tagLen != 0 {
		size += 32 + 1 + test.tags*test.tagLen
	}
	payload := make([]byte, size)
	payload[64] = test.flags
	off := 65
	if test.flags&lookupDelivery != 0 {
		binary.BigEndian.PutUint32(payload[off:off+4], 1)
		off += 4
	}
	binary.BigEndian.PutUint16(payload[off:off+2], uint16(test.exclusions))
	off += 2
	for i := range test.exclusions {
		payload[off+i*ivnp.HashLength] = byte(i + 1)
	}
	off += test.exclusions * ivnp.HashLength
	if test.tagLen != 0 {
		payload[off] = 0xa5
		off += 32
		payload[off] = byte(test.tags)
		off++
		payload[off] = 0x5a
	}
	lookup, err := ParseDatabaseLookup(payload)
	if err != nil {
		t.Fatal(err)
	}
	if lookup.ExcludedCount() != test.exclusions || lookup.ReplyTagCount() != test.tags || int(lookup.ReplyTagLen) != test.tagLen {
		t.Fatalf("lookup = %d exclusions, %d tags x %d", lookup.ExcludedCount(), lookup.ReplyTagCount(), lookup.ReplyTagLen)
	}
	if test.flags&lookupDelivery != 0 && lookup.ReplyTunnelID != 1 {
		t.Fatalf("reply tunnel = %d, want 1", lookup.ReplyTunnelID)
	}
	if test.tagLen != 0 && (lookup.ReplyKey[0] != 0xa5 || lookup.ReplyTags[0] != 0x5a) {
		t.Fatalf("reply fields = %x %x", lookup.ReplyKey, lookup.ReplyTags)
	}
}

func TestDatabaseLookupRejectsMalformedReplyLayouts(t *testing.T) {
	makeLookup := func(flags uint8, tags, tagLen int) []byte {
		size := 67
		if tagLen != 0 {
			size += 32 + 1 + tags*tagLen
		}
		payload := make([]byte, size)
		payload[64] = flags
		if tagLen != 0 {
			payload[67+32] = byte(tags)
		}
		return payload
	}
	tests := []struct {
		name    string
		payload []byte
		want    error
	}{
		{name: "trailing unencrypted", payload: append(makeLookup(0, 0, 0), 1), want: ErrMalformed},
		{name: "trailing legacy", payload: append(makeLookup(lookupEncrypted, 1, 32), 1), want: ErrMalformed},
		{name: "trailing ECIES", payload: append(makeLookup(lookupECIES, 1, 8), 1), want: ErrMalformed},
		{name: "truncated ECIES", payload: makeLookup(lookupECIES, 1, 8)[:107], want: wire.ErrShortBuffer},
		{name: "multiple ECIES tags", payload: makeLookup(lookupECIES, 2, 16), want: ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseDatabaseLookup(tt.payload); !errors.Is(err, tt.want) {
				t.Fatalf("ParseDatabaseLookup() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDatabaseSearchReplyExactFormula(t *testing.T) {
	payload := make([]byte, MaxDatabaseSearchReplyPayload)
	payload[32] = MaxDatabaseSearchPeers
	message, err := ParseDatabaseSearchReply(payload)
	if err != nil || message.PeerCount() != MaxDatabaseSearchPeers {
		t.Fatalf("ParseDatabaseSearchReply() = %d peers, %v", message.PeerCount(), err)
	}
	if _, err := ParseDatabaseSearchReply(payload[:len(payload)-1]); !errors.Is(err, ErrMalformed) {
		t.Fatalf("truncated reply error = %v, want ErrMalformed", err)
	}
}

func TestFixedAndVariablePayloadBounds(t *testing.T) {
	tunnel := make([]byte, TunnelDataMessageLen)
	binary.BigEndian.PutUint32(tunnel[:4], 1)
	if message, err := ParseTunnelData(tunnel); err != nil || len(message.Data) != TunnelDataPayloadLen {
		t.Fatalf("ParseTunnelData() = %#v, %v", message, err)
	}
	tunnel[0], tunnel[1], tunnel[2], tunnel[3] = 0, 0, 0, 0
	if _, err := ParseTunnelData(tunnel); !errors.Is(err, ErrInvalidTunnelID) {
		t.Fatalf("zero tunnel ID error = %v", err)
	}

	variable := make([]byte, 1+MaxVariableBuildRecords*BuildRecordLen)
	variable[0] = MaxVariableBuildRecords
	build, err := ParseBuildRecords(VariableTunnelBuild, variable)
	if err != nil || build.Count != MaxVariableBuildRecords {
		t.Fatalf("ParseBuildRecords() = %#v, %v", build, err)
	}
	variable[0] = MaxVariableBuildRecords + 1
	if _, err := ParseBuildRecords(VariableTunnelBuild, variable); !errors.Is(err, ErrMalformed) {
		t.Fatalf("invalid build count error = %v", err)
	}
}

func TestTunnelGatewayRequiresCompleteEmbeddedFrame(t *testing.T) {
	embedded := make([]byte, StandardHeaderLen+12)
	embedded[0] = byte(DeliveryStatus)
	binary.BigEndian.PutUint16(embedded[13:15], 12)
	gateway := make([]byte, TunnelGatewayHeaderLen+len(embedded))
	binary.BigEndian.PutUint32(gateway[:4], 7)
	binary.BigEndian.PutUint16(gateway[4:6], uint16(len(embedded)))
	copy(gateway[6:], embedded)
	parsed, err := ParseTunnelGateway(gateway)
	if err != nil || parsed.Embedded.Header.Type != DeliveryStatus {
		t.Fatalf("ParseTunnelGateway() = %#v, %v", parsed, err)
	}
	binary.BigEndian.PutUint16(gateway[4:6], uint16(len(embedded)-1))
	if _, err := ParseTunnelGateway(gateway); !errors.Is(err, ErrMalformed) {
		t.Fatalf("mismatched gateway length error = %v", err)
	}
}

func TestDataAndGarlicRejectOversizedUint32Claims(t *testing.T) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(I2PDMaxPayload))
	if _, err := ParseData(payload); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("data oversized claim = %v", err)
	}
	if _, err := ParseGarlic(payload); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("garlic oversized claim = %v", err)
	}
}

func BenchmarkParseStandard(b *testing.B) {
	message := Message{Header: Header{Type: DeliveryStatus}, Payload: make([]byte, 12)}
	wire := make([]byte, message.EncodedLen())
	if _, err := message.MarshalTo(wire); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = Parse(wire)
	}
}

var messageSink Message
var messageErrorSink error

func TestParseStandardHasNoHeapAllocation(t *testing.T) {
	message := Message{Header: Header{Type: DeliveryStatus}, Payload: make([]byte, 12)}
	frame := make([]byte, message.EncodedLen())
	if _, err := message.MarshalTo(frame); err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(1_000, func() {
		messageSink, _, messageErrorSink = Parse(frame)
	})
	if messageErrorSink != nil {
		t.Fatal(messageErrorSink)
	}
	if allocs != 0 {
		t.Fatalf("Parse() allocations/run = %f, want 0", allocs)
	}
}

func TestDatabaseStoreDefersJavaRouterInfoInflationCap(t *testing.T) {
	compressed := make([]byte, 37+2+MaxRouterInfoBytes+1)
	compressed[32] = byte(StoreRouterInfo)
	binary.BigEndian.PutUint16(compressed[37:39], MaxRouterInfoBytes+1)
	store, err := ParseDatabaseStore(compressed)
	if err != nil || len(store.Data) != MaxRouterInfoBytes+1 {
		t.Fatalf("compressed RouterInfo field = %d bytes, %v", len(store.Data), err)
	}
}

func TestDatabaseStoreEnforcesLeaseSetObjectCap(t *testing.T) {
	leaseSet := make([]byte, 37+I2PDMaxLeaseSetBytes+1)
	leaseSet[32] = byte(StoreLeaseSet)
	if _, err := ParseDatabaseStore(leaseSet); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("LeaseSet cap = %v", err)
	}
}
