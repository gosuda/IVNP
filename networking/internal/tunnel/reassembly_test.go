package tunnel

import (
	"bytes"
	"errors"
	"testing"
)

func TestReassemblerHandlesOutOfOrderFragments(t *testing.T) {
	r := NewReassembler(2, 16)
	if _, done, err := r.Add(Fragment{MessageID: 1, Number: 1, Last: true, Data: []byte("world")}, 1); err != nil || done {
		t.Fatalf("last fragment = %t, %v", done, err)
	}
	message, done, err := r.Add(Fragment{MessageID: 1, Number: 0, Data: []byte("hello ")}, 2)
	if err != nil || !done || !bytes.Equal(message, []byte("hello world")) {
		t.Fatalf("message = %q, %t, %v", message, done, err)
	}
}

func TestReassemblerRejectsMessageOverConfiguredLimit(t *testing.T) {
	r := NewReassembler(1, 5)
	if _, _, err := r.Add(Fragment{MessageID: 1, Data: []byte("1234")}, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(Fragment{MessageID: 1, Number: 1, Last: true, Data: []byte("56")}, 2); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized reassembly error = %v, want %v", err, ErrTooLarge)
	}
	if len(r.entries) != 0 {
		t.Fatal("oversized reassembly retained partial data")
	}
}
