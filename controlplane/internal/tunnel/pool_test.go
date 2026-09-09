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

func TestOutboundReservePromotesAtRenewalWithoutRetiringAdmittedEntry(t *testing.T) {
	maintainer, pool, _, manager, _ := newPairedMaintainer(t, 0, 1, 10, new(pairedInboundSource), new(pairedOutboundSource))
	defer maintainer.Close()
	defer manager.ReleaseSensitive()
	active := Entry{ID: 1, Direction: Outbound, Expires: 100}
	if err := pool.Add(active, 0); err != nil {
		t.Fatal(err)
	}
	if selected, ok := pool.Select(Outbound, 0); !ok || selected.ID != active.ID {
		t.Fatalf("initial selection = %v, %v", selected.ID, ok)
	}
	backup := Entry{ID: 2, Direction: Outbound, Expires: 200}
	if err := pool.Add(backup, 0); err != nil {
		t.Fatal(err)
	}
	if entries := pool.SelectableOutbound(89); len(entries) != 1 || entries[0].ID != active.ID {
		t.Fatalf("reserve entered normal selection: %v", entries)
	}
	if entries := pool.SelectableOutbound(90); len(entries) != 1 || entries[0].ID != backup.ID {
		t.Fatalf("reserve not promoted at renewal: %v", entries)
	}
	if retained, ok := pool.Get(active.ID, 90); !ok || retained.Expires != 100 {
		t.Fatal("promotion invalidated admitted entry before its expiration")
	}
	if !pool.Remove(backup) {
		t.Fatal("failed active removal")
	}
	if selected, ok := pool.Select(Outbound, 90); !ok || selected.ID != active.ID {
		t.Fatalf("live draining fallback = %v, %v", selected.ID, ok)
	}
}

func TestInboundPublicationBoundsOverlapWithoutDroppingLiveEntries(t *testing.T) {
	pool := NewPool(32)
	for id := uint32(1); id <= 32; id++ {
		if err := pool.Add(Entry{ID: id, Direction: Inbound, Expires: uint64(100 + id)}, 0); err != nil {
			t.Fatal(err)
		}
	}
	published := pool.PublishableInbound(0)
	if len(published) != 16 {
		t.Fatalf("published %d leases, want 16", len(published))
	}
	for _, entry := range published {
		if entry.ID <= 16 {
			t.Fatalf("draining entry %d displaced a newer lease", entry.ID)
		}
	}
	if pool.Count(Inbound, 0) != 32 {
		t.Fatal("publication cap removed live entries")
	}
}
