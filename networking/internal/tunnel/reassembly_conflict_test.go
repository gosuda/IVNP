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

func TestReassemblerPooledEntryDoesNotRetainEvictedFragments(t *testing.T) {
	reassembler := NewReassembler(1, 64)
	if _, _, err := reassembler.Add(Fragment{MessageID: 1, Number: 0, Data: []byte("old")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reassembler.Add(Fragment{MessageID: 2, Number: 0, Data: []byte("new")}); err != nil {
		t.Fatal(err)
	}
	message, done, err := reassembler.Add(Fragment{MessageID: 2, Number: 1, Last: true, Data: []byte(" tail")})
	if err != nil || !done || string(message) != "new tail" {
		t.Fatalf("reused entry message = %q, %t, %v", message, done, err)
	}
	if message, done, err = reassembler.Add(Fragment{MessageID: 1, Number: 1, Last: true, Data: []byte(" tail")}); err != nil || done || message != nil {
		t.Fatalf("evicted message resumed with pooled data = %q, %t, %v", message, done, err)
	}
}

func BenchmarkReassemblerPooledFragments(b *testing.B) {
	reassembler := NewReassembler(1, 64)
	first := Fragment{Number: 0, Data: []byte("first")}
	last := Fragment{Number: 1, Last: true, Data: []byte("last")}
	b.ReportAllocs()
	for b.Loop() {
		first.MessageID++
		last.MessageID = first.MessageID
		if _, _, err := reassembler.Add(first); err != nil {
			b.Fatal(err)
		}
		if _, done, err := reassembler.Add(last); err != nil || !done {
			b.Fatalf("complete = %t, %v", done, err)
		}
	}
}
