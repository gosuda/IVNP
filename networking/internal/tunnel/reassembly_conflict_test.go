package tunnel

import (
	"errors"
	"testing"
)

func TestReassemblerRejectsAmbiguousLastAndDuplicates(t *testing.T) {
	r := NewReassembler(2, 64)
	if _, _, err := r.Add(Fragment{MessageID: 1, Number: 5, Data: []byte("late")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(Fragment{MessageID: 1, Number: 0, Last: true, Data: []byte("first")}); !errors.Is(err, ErrFragment) {
		t.Fatalf("late fragment conflict = %v", err)
	}
	if _, _, err := r.Add(Fragment{MessageID: 2, Number: 0, Data: []byte("a")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(Fragment{MessageID: 2, Number: 0, Data: []byte("b")}); !errors.Is(err, ErrFragment) {
		t.Fatalf("duplicate conflict = %v", err)
	}
	r = NewReassembler(2, 64)
	if _, _, err := r.Add(Fragment{MessageID: 3, Number: 0, Data: []byte("same")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(Fragment{MessageID: 3, Number: 0, Last: true, Data: []byte("same")}); !errors.Is(err, ErrFragment) {
		t.Fatalf("duplicate terminal conflict = %v", err)
	}
}

func TestReassemblerEvictsAndExpiresIncompleteEntries(t *testing.T) {
	r := NewReassembler(1, 64)
	_, _, _ = r.Add(Fragment{MessageID: 1, Number: 0, Data: []byte("a")})
	_, _, _ = r.Add(Fragment{MessageID: 2, Number: 0, Data: []byte("b")})
	if len(r.entries) != 1 || r.entries[2] == nil {
		t.Fatalf("LRU entries = %#v", r.entries)
	}
	if removed := r.Expire(r.clock + 1); removed != 1 || len(r.entries) != 0 {
		t.Fatalf("Expire = %d, entries=%d", removed, len(r.entries))
	}
}
