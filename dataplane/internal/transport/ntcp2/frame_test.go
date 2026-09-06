package ntcp2

import (
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"gosuda.org/ivnp/internal/wire"
)

func TestSipHashReferenceVector(t *testing.T) {
	if got, want := sipHash24(0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x0706050403020100), uint64(0x93f5f5799a932462); got != want {
		t.Fatalf("sipHash24() = %#x, want %#x", got, want)
	}
}

func TestDirectionRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	sipKey := make([]byte, 16)
	sipIV := make([]byte, 8)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range sipKey {
		sipKey[i] = byte(i + 32)
	}
	for i := range sipIV {
		sipIV[i] = byte(i + 48)
	}
	sender, err := NewDirection(key, sipKey, sipIV)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewDirection(key, sipKey, sipIV)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte{BlockDateTime, 0, 4, 0, 0, 0, 7, BlockPadding, 0, 2, 1, 2}
	if err := ValidateBlocks(plain); err != nil {
		t.Fatal(err)
	}
	frameStorage := make([]byte, FrameLengthLen+len(plain)+FrameTagLen)
	frame, err := sender.SealTo(frameStorage, plain)
	if err != nil {
		t.Fatal(err)
	}
	outStorage := make([]byte, len(plain))
	opened, err := receiver.OpenTo(outStorage, frame)
	if err != nil || string(opened) != string(plain) {
		t.Fatalf("OpenTo() = %x, %v", opened, err)
	}
}

func TestDirectionRejectsLengthAndNonceViolations(t *testing.T) {
	key, sipKey, sipIV := make([]byte, 32), make([]byte, 16), make([]byte, 8)
	direction, err := NewDirection(key, sipKey, sipIV)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := direction.SealTo(make([]byte, 1), nil); !errors.Is(err, wire.ErrShortBuffer) {
		t.Fatalf("short frame destination = %v", err)
	}
	direction.nonce = math.MaxUint64 - 1
	if _, err := direction.SealTo(make([]byte, FrameLengthLen+FrameTagLen), nil); !errors.Is(err, ErrNonceExhausted) {
		t.Fatalf("nonce exhaustion = %v", err)
	}
	other, err := NewDirection(key, sipKey, sipIV)
	if err != nil {
		t.Fatal(err)
	}
	probe := *other
	bad := make([]byte, FrameLengthLen+FrameTagLen)
	binary.BigEndian.PutUint16(bad[:2], probe.sip.nextMask())
	if _, err := other.OpenTo(make([]byte, 0), bad); !errors.Is(err, ErrFrameLength) {
		t.Fatalf("invalid obfuscated length = %v", err)
	}
}

func TestBlockOrderingAndLengths(t *testing.T) {
	paddingThenData := []byte{BlockPadding, 0, 0, BlockI2NP, 0, 0}
	if err := ValidateBlocks(paddingThenData); !errors.Is(err, ErrBlockOrder) {
		t.Fatalf("padding order = %v", err)
	}
	terminationThenPadding := []byte{BlockTermination, 0, 0, BlockPadding, 0, 0}
	if err := ValidateBlocks(terminationThenPadding); err != nil {
		t.Fatalf("termination + padding = %v", err)
	}
	badDate := []byte{BlockDateTime, 0, 3, 0, 0, 0}
	if err := ValidateBlocks(badDate); !errors.Is(err, ErrBlockLength) {
		t.Fatalf("datetime length = %v", err)
	}
}

func BenchmarkDirectionSealTo(b *testing.B) {
	key, sipKey, sipIV := make([]byte, 32), make([]byte, 16), make([]byte, 8)
	direction, err := NewDirection(key, sipKey, sipIV)
	if err != nil {
		b.Fatal(err)
	}
	plain := make([]byte, 1024)
	dst := make([]byte, FrameLengthLen+len(plain)+FrameTagLen)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := direction.SealTo(dst, plain); err != nil {
			b.Fatal(err)
		}
	}
}
