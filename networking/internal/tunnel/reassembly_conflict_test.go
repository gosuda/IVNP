package tunnel

import (
	"errors"
	"testing"
)

func TestReassemblerRejectsAmbiguousLastAndDuplicates(t *testing.T) {
	r := NewReassembler(2, 64)
	if _, _, err := r.Add(Fragment{MessageID: 1, Number: 5, Data: []byte("late")}, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(Fragment{MessageID: 1, Number: 0, Last: true, Data: []byte("first")}, 1); !errors.Is(err, ErrFragment) {
		t.Fatalf("late fragment conflict = %v", err)
	}
	if _, _, err := r.Add(Fragment{MessageID: 2, Number: 0, Data: []byte("a")}, 2); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(Fragment{MessageID: 2, Number: 0, Data: []byte("b")}, 2); !errors.Is(err, ErrFragment) {
		t.Fatalf("duplicate conflict = %v", err)
	}
	r = NewReassembler(2, 64)
	if _, _, err := r.Add(Fragment{MessageID: 3, Number: 0, Data: []byte("same")}, 3); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(Fragment{MessageID: 3, Number: 0, Last: true, Data: []byte("same")}, 3); !errors.Is(err, ErrFragment) {
		t.Fatalf("duplicate terminal conflict = %v", err)
	}
}

func TestReassemblerEvictsAndExpiresIncompleteEntries(t *testing.T) {
	r := NewReassembler(1, 64)
	_, _, _ = r.Add(Fragment{MessageID: 1, Number: 0, Data: []byte("a")}, 1)
	_, _, _ = r.Add(Fragment{MessageID: 2, Number: 0, Data: []byte("b")}, 2)
	if len(r.entries) != 1 || r.entries[2] == nil {
		t.Fatalf("LRU entries = %#v", r.entries)
	}
	if removed := r.Expire(2); removed != 1 || len(r.entries) != 0 {
		t.Fatalf("Expire = %d, entries=%d", removed, len(r.entries))
	}
}

func TestReassemblerPooledEntryDoesNotRetainEvictedFragments(t *testing.T) {
	reassembler := NewReassembler(1, 64)
	if _, _, err := reassembler.Add(Fragment{MessageID: 1, Number: 0, Data: []byte("old")}, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reassembler.Add(Fragment{MessageID: 2, Number: 0, Data: []byte("new")}, 2); err != nil {
		t.Fatal(err)
	}
	message, done, err := reassembler.Add(Fragment{MessageID: 2, Number: 1, Last: true, Data: []byte(" tail")}, 3)
	if err != nil || !done || string(message) != "new tail" {
		t.Fatalf("reused entry message = %q, %t, %v", message, done, err)
	}
	if message, done, err = reassembler.Add(Fragment{MessageID: 1, Number: 1, Last: true, Data: []byte(" tail")}, 4); err != nil || done || message != nil {
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
		if _, _, err := reassembler.Add(first, uint64(first.MessageID)); err != nil {
			b.Fatal(err)
		}
		if _, done, err := reassembler.Add(last, uint64(last.MessageID)); err != nil || !done {
			b.Fatalf("complete = %t, %v", done, err)
		}
	}
}
