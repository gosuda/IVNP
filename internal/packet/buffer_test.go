package packet

import (
	"bytes"
	"testing"
)

func TestBufferPushAppendWireLayout(t *testing.T) {
	buf, ok := Acquire(4, 5)
	if !ok {
		t.Fatal("Acquire failed")
	}
	defer buf.Release()

	header, ok := buf.Push(2)
	if !ok {
		t.Fatal("Push failed")
	}
	copy(header, "HI")
	payload, ok := buf.Append(3)
	if !ok {
		t.Fatal("Append failed")
	}
	copy(payload, "xyz")

	if got, ok := buf.Header(); !ok || !bytes.Equal(got, []byte("HI")) {
		t.Fatalf("Header() = %q, %t", got, ok)
	}
	if got, ok := buf.Payload(); !ok || !bytes.Equal(got, []byte("xyz")) {
		t.Fatalf("Payload() = %q, %t", got, ok)
	}
	if got, ok := buf.Bytes(); !ok || !bytes.Equal(got, []byte("HIxyz")) {
		t.Fatalf("Bytes() = %q, %t", got, ok)
	}
	if got, ok := buf.AvailableHeader(); !ok || got != 2 {
		t.Fatalf("AvailableHeader() = %d, %t", got, ok)
	}
	if got, ok := buf.AvailablePayload(); !ok || got != 2 {
		t.Fatalf("AvailablePayload() = %d, %t", got, ok)
	}
}

func TestBufferRejectsInvalidOperationsWithoutMutation(t *testing.T) {
	buf, ok := Acquire(1, 1)
	if !ok {
		t.Fatal("Acquire failed")
	}
	defer buf.Release()
	if bytes, ok := buf.Push(2); ok || bytes != nil {
		t.Fatalf("Push beyond header = %v, %t", bytes, ok)
	}
	if bytes, ok := buf.Append(-1); ok || bytes != nil {
		t.Fatalf("negative Append = %v, %t", bytes, ok)
	}
	if bytes, ok := buf.Consume(-1); ok || bytes != nil {
		t.Fatalf("negative Consume = %v, %t", bytes, ok)
	}
	if got, ok := buf.AvailableHeader(); !ok || got != 1 {
		t.Fatalf("AvailableHeader() = %d, %t", got, ok)
	}
	if got, ok := buf.AvailablePayload(); !ok || got != 1 {
		t.Fatalf("AvailablePayload() = %d, %t", got, ok)
	}
}

func TestBufferReleaseInvalidatesHandle(t *testing.T) {
	buf, ok := Acquire(1, 1)
	if !ok {
		t.Fatal("Acquire failed")
	}
	buf.Release()
	buf.Release()
	if bytes, ok := buf.Append(0); ok || bytes != nil {
		t.Fatalf("released Append = %v, %t", bytes, ok)
	}
	if _, ok := buf.AvailablePayload(); ok {
		t.Fatal("released buffer reported available payload")
	}
}

func BenchmarkBufferOperationsAfterWarmup(b *testing.B) {
	buf, ok := Acquire(8, 128)
	if !ok {
		b.Fatal("Acquire failed")
	}
	defer buf.Release()

	b.ReportAllocs()
	for b.Loop() {
		buf.start = buf.reserved
		buf.end = buf.reserved
		header, ok := buf.Push(1)
		if !ok {
			b.Fatal("Push failed")
		}
		header[0] = 1
		payload, ok := buf.Append(1)
		if !ok {
			b.Fatal("Append failed")
		}
		payload[0] = 2
		if _, ok := buf.Consume(2); !ok {
			b.Fatal("Consume(2) failed")
		}
	}
}
