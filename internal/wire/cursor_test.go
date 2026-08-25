package wire

import (
	"errors"
	"testing"
)

func TestCursorReadsBigEndianWithoutCopy(t *testing.T) {
	input := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	c := NewCursor(input)

	if got, err := c.ReadU8(); err != nil || got != 1 {
		t.Fatalf("ReadU8() = %d, %v", got, err)
	}
	if got, err := c.ReadU16(); err != nil || got != 0x0203 {
		t.Fatalf("ReadU16() = %#x, %v", got, err)
	}
	if got, err := c.ReadU32(); err != nil || got != 0x04050607 {
		t.Fatalf("ReadU32() = %#x, %v", got, err)
	}
	if got, err := c.ReadU64(); err != nil || got != 0x08090a0b0c0d0e0f {
		t.Fatalf("ReadU64() = %#x, %v", got, err)
	}
	if !c.Done() {
		t.Fatalf("cursor has %d trailing bytes", c.Remaining())
	}
}

func TestCursorRejectsTruncationWithoutAdvancing(t *testing.T) {
	c := NewCursor([]byte{1})
	if _, err := c.ReadU16(); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("ReadU16() error = %v, want ErrShortBuffer", err)
	}
	if got := c.Offset(); got != 0 {
		t.Fatalf("offset after rejected read = %d, want 0", got)
	}
	if _, err := c.ReadBytes(-1); !errors.Is(err, ErrLargeField) {
		t.Fatalf("ReadBytes(-1) error = %v, want ErrLargeField", err)
	}
}

func TestWriterSerializesBigEndian(t *testing.T) {
	var dst [15]byte
	w := NewWriter(dst[:])
	for _, put := range []func() error{
		func() error { return w.PutU8(1) },
		func() error { return w.PutU16(0x0203) },
		func() error { return w.PutU32(0x04050607) },
		func() error { return w.PutU64(0x08090a0b0c0d0e0f) },
	} {
		if err := put(); err != nil {
			t.Fatal(err)
		}
	}
	want := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if got := w.Bytes(); string(got) != string(want) {
		t.Fatalf("serialized %x, want %x", got, want)
	}
	if err := w.PutU8(0); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("overflow error = %v, want ErrShortBuffer", err)
	}
}

func BenchmarkCursorU32(b *testing.B) {
	input := []byte{0, 0, 0, 1}
	b.ReportAllocs()
	for b.Loop() {
		c := NewCursor(input)
		_, _ = c.ReadU32()
	}
}
