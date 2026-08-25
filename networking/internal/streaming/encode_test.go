package streaming

import (
	"errors"
	"testing"

	"gosuda.org/ivnp/internal/wire"
)

func TestPacketMarshalToRoundTrip(t *testing.T) {
	want := Packet{
		SendStreamID:    1,
		ReceiveStreamID: 2,
		Sequence:        3,
		AckThrough:      4,
		ResendDelay:     5,
		Flags:           FlagSynchronize | FlagClose | FlagReset | FlagNoACK,
		NACKs:           []byte{0, 0, 0, 9, 0, 0, 0, 11},
		Options:         []byte{1, 2},
		Payload:         []byte{3, 4, 5},
	}
	frame := make([]byte, want.EncodedLen())
	n, err := want.MarshalTo(frame)
	if err != nil || n != len(frame) {
		t.Fatalf("MarshalTo() = %d, %v; want %d, nil", n, err, len(frame))
	}

	got, err := Parse(frame)
	if err != nil {
		t.Fatal(err)
	}
	packetMarshalToRoundTripRejected := got.SendStreamID != want.SendStreamID || got.ReceiveStreamID != want.ReceiveStreamID ||
		got.Sequence != want.Sequence || got.AckThrough != want.AckThrough ||
		got.NACKCount != 2 || got.ResendDelay != want.ResendDelay || got.Flags != want.Flags ||
		string(got.NACKs) != string(want.NACKs) || string(got.Options) != string(want.Options)
	if !packetMarshalToRoundTripRejected {
		packetMarshalToRoundTripRejected = string(got.Payload) != string(want.Payload)
	}
	if packetMarshalToRoundTripRejected {
		t.Fatalf("Parse(MarshalTo()) = %#v; want %#v", got, want)
	}
}

func TestPacketMarshalToRejectsInvalidInputs(t *testing.T) {
	invalidNACKs := Packet{NACKs: []byte{1, 2, 3}}
	if invalidNACKs.EncodedLen() != -1 {
		t.Fatalf("EncodedLen() = %d, want -1", invalidNACKs.EncodedLen())
	}
	if _, err := invalidNACKs.MarshalTo(make([]byte, HeaderLen)); !errors.Is(err, ErrPacket) {
		t.Fatalf("MarshalTo() error = %v, want %v", err, ErrPacket)
	}

	oversized := Packet{Payload: make([]byte, MaxPacketSize-HeaderLen+1)}
	if oversized.EncodedLen() != -1 {
		t.Fatalf("EncodedLen() = %d, want -1", oversized.EncodedLen())
	}
	if _, err := oversized.MarshalTo(nil); !errors.Is(err, ErrPacket) {
		t.Fatalf("MarshalTo() error = %v, want %v", err, ErrPacket)
	}

	packet := Packet{Payload: []byte{1}}
	if _, err := packet.MarshalTo(make([]byte, packet.EncodedLen()-1)); !errors.Is(err, wire.ErrShortBuffer) {
		t.Fatalf("MarshalTo() error = %v, want %v", err, wire.ErrShortBuffer)
	}
}

func TestPacketMarshalToAllocs(t *testing.T) {
	packet := Packet{Payload: []byte{1, 2, 3}}
	frame := make([]byte, packet.EncodedLen())
	allocs := testing.AllocsPerRun(1_000, func() {
		if _, err := packet.MarshalTo(frame); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("MarshalTo() allocations = %v, want 0", allocs)
	}
}

func BenchmarkStreamingPacketMarshalTo(b *testing.B) {
	packet := Packet{Payload: []byte{1, 2, 3}}
	frame := make([]byte, packet.EncodedLen())
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := packet.MarshalTo(frame); err != nil {
			b.Fatal(err)
		}
	}
}
