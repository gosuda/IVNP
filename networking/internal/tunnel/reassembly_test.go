package tunnel

import (
	"bytes"
	"testing"
)

func TestReassemblerHandlesOutOfOrderFragments(t *testing.T) {
	r := NewReassembler(2, 16)
	if _, done, err := r.Add(Fragment{MessageID: 1, Number: 1, Last: true, Data: []byte("world")}); err != nil || done {
		t.Fatalf("last fragment = %t, %v", done, err)
	}
	message, done, err := r.Add(Fragment{MessageID: 1, Number: 0, Data: []byte("hello ")})
	if err != nil || !done || !bytes.Equal(message, []byte("hello world")) {
		t.Fatalf("message = %q, %t, %v", message, done, err)
	}
}
