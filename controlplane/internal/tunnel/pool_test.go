package tunnel

import (
	"testing"
)

func TestPoolSelectAndExpire(t *testing.T) {
	p := NewPool(2)
	if err := p.Add(Entry{ID: 1, Direction: Inbound, Expires: 10}, 0); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(Entry{ID: 2, Direction: Outbound, Expires: 20}, 0); err != nil {
		t.Fatal(err)
	}
	e, ok := p.Select(Outbound, 5)
	if !ok || e.ID != 2 {
		t.Fatalf("select=%#v %t", e, ok)
	}
	if n := p.Expire(11); n != 1 {
		t.Fatalf("expire=%d", n)
	}
	if _, ok := p.Get(1, 5); ok {
		t.Fatal("expired tunnel retained")
	}
}

func TestPoolRejectsCapacityWithoutEviction(t *testing.T) {
	p := NewPool(1)
	if err := p.Add(Entry{ID: 1, Direction: Outbound, Expires: 20}, 0); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(Entry{ID: 2, Direction: Outbound, Expires: 10}, 0); err != ErrPoolFull {
		t.Fatalf("capacity error = %v, want %v", err, ErrPoolFull)
	}
	if entry, ok := p.Get(1, 0); !ok || entry.ID != 1 {
		t.Fatalf("existing entry = %#v, %t", entry, ok)
	}
	if _, ok := p.Get(2, 0); ok {
		t.Fatal("rejected entry was retained")
	}
}

func TestPoolPurgesExpiredEntriesBeforeCapacityCheck(t *testing.T) {
	p := NewPool(1)
	if err := p.Add(Entry{ID: 1, Direction: Outbound, Expires: 10}, 0); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(Entry{ID: 2, Direction: Outbound, Expires: 20}, 10); err != nil {
		t.Fatalf("add after expiry = %v", err)
	}
	if _, ok := p.Get(1, 0); ok {
		t.Fatal("expired entry retained")
	}
	if entry, ok := p.Get(2, 10); !ok || entry.ID != 2 {
		t.Fatalf("replacement entry = %#v, %t", entry, ok)
	}
}

func TestPoolReplaceRetiresOnlyNamedEntryAndCanRollback(t *testing.T) {
	p := NewPool(2)
	old := Entry{ID: 1, Direction: Outbound, Expires: 10}
	healthy := Entry{ID: 2, Direction: Outbound, Expires: 20}
	if err := p.Add(old, 0); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(healthy, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Replace(Entry{ID: 3, Direction: Outbound, Expires: 30}, 99, 0); err != ErrPoolFull {
		t.Fatalf("unnamed replacement error = %v, want %v", err, ErrPoolFull)
	}
	replacement := Entry{ID: 3, Direction: Outbound, Expires: 30}
	retired, replaced, err := p.Replace(replacement, old.ID, 0)
	if err != nil || !replaced || retired != old {
		t.Fatalf("replace retired=%#v replaced=%t err=%v", retired, replaced, err)
	}
	if _, ok := p.Get(healthy.ID, 0); !ok {
		t.Fatal("replacement evicted unrelated healthy entry")
	}
	p.RollbackReplace(replacement, retired, replaced, 0)
	if entry, ok := p.Get(old.ID, 0); !ok || entry != old {
		t.Fatalf("rollback entry = %#v, %t", entry, ok)
	}
	if _, ok := p.Get(replacement.ID, 0); ok {
		t.Fatal("rollback retained replacement")
	}
}
