package netdb

import (
	"testing"

	"gosuda.org/ivnp"
)

func routerWithSeed(seed byte) RouterInfo {
	encoded := legacyIdentity()
	encoded[0] = seed
	identity, _, err := ivnp.ParseIdentity(encoded)
	if err != nil {
		panic(err)
	}
	return RouterInfo{Identity: identity}
}

func TestStoreVerifiedNeverDowngradesRouterInfo(t *testing.T) {
	var local ivnp.Hash
	table := NewTable(local, 4)
	newer := routerWithSeed(1)
	newer.Published = 20
	table.StoreVerified(newer, true, 20)
	older := newer
	older.Published = 10
	table.StoreVerified(older, false, 30)
	stored, ok := table.Get(newer.Hash())
	if !ok || stored.Info.Published != newer.Published || !stored.Floodfill || stored.LastSeen != 20 {
		t.Fatalf("stale RouterInfo replaced newer entry: %#v, %t", stored, ok)
	}
}
func TestDistanceMetricAndClosestSelection(t *testing.T) {
	var local ivnp.Hash
	var near, middle, far ivnp.Hash
	near[31] = 1
	middle[0] = 1
	far[0] = 0x80
	if got := distanceBucket(local, near); got != 255 {
		t.Fatalf("near bucket = %d", got)
	}
	if got := distanceBucket(local, far); got != 0 {
		t.Fatalf("far bucket = %d", got)
	}
	if !distanceLess(local, near, middle) || !distanceLess(local, middle, far) {
		t.Fatal("XOR ordering is wrong")
	}

	table := NewTable(local, 4)
	nearInfo, middleInfo, farInfo := routerWithSeed(1), routerWithSeed(2), routerWithSeed(3)
	table.StoreVerified(nearInfo, true, 10)
	table.StoreVerified(middleInfo, false, 10)
	table.StoreVerified(farInfo, true, 10)
	out := make([]RouterRef, 0, 3)
	closest := table.ClosestInto(out, nearInfo.Hash())
	if len(closest) != 3 || closest[0].Hash != nearInfo.Hash() {
		t.Fatalf("closest results = %#v", closest)
	}
	floodfills := table.ClosestFloodfillsInto(out, nearInfo.Hash())
	if len(floodfills) != 2 || !floodfills[0].Floodfill || !floodfills[1].Floodfill {
		t.Fatalf("floodfill results = %#v", floodfills)
	}
}

func TestJavaKademliaRangeVectors(t *testing.T) {
	local := ivnp.Hash{}
	vectors := []struct {
		peer ivnp.Hash
		want int
	}{
		{peer: ivnp.Hash{}, want: -1},
		{peer: ivnp.Hash{31: 0x01}, want: 0},
		{peer: ivnp.Hash{31: 0x02}, want: 8},
		{peer: ivnp.Hash{31: 0x0f}, want: 31},
		{peer: ivnp.Hash{0: 0x80}, want: 2040},
		{peer: ivnp.Hash{0: 0xf0}, want: 2047},
	}
	for _, vector := range vectors {
		if got := kademliaRange(local, vector.peer); got != vector.want {
			t.Fatalf("kademliaRange(%x) = %d, want %d", vector.peer, got, vector.want)
		}
	}
}

func TestJavaKBucketRejectTrimmerAndIndependentRouterStore(t *testing.T) {
	candidate := routerWithSeed(10)
	candidateRange := kademliaRange(ivnp.Hash{}, candidate.Hash())
	table := NewTable(ivnp.Hash{}, 5)
	table.mu.Lock()
	table.routing.buckets = []kBucket{{begin: uint16(candidateRange), end: uint16(candidateRange), members: make([]ivnp.Hash, 5)}}
	table.mu.Unlock()
	table.StoreVerified(candidate, false, 1)
	if _, ok := table.Get(candidate.Hash()); !ok {
		t.Fatal("RouterInfo rejected with full terminal KBucket")
	}
	if got := table.ClosestRoutingInto(make([]RouterRef, 0, 1), candidate.Hash()); len(got) != 0 {
		t.Fatalf("RejectTrimmer admitted candidate: %#v", got)
	}
	if removed := table.Expire(2); removed != 1 || table.Len() != 0 {
		t.Fatalf("Expire() = %d, len %d", removed, table.Len())
	}
}

func TestJavaKBucketSplitShape(t *testing.T) {
	set := newKBucketSet(5)
	for marker := byte(0x80); marker <= 0x85; marker++ {
		var peer ivnp.Hash
		peer[0], peer[31] = marker, marker
		set.add(ivnp.Hash{}, peer, 1)
	}
	if len(set.buckets) != 2 {
		t.Fatalf("bucket count = %d, want 2", len(set.buckets))
	}
	if first, second := set.buckets[0], set.buckets[1]; first.begin != 0 || first.end != 2039 || second.begin != 2040 || second.end != 2047 {
		t.Fatalf("split = (%d,%d) (%d,%d)", first.begin, first.end, second.begin, second.end)
	}
}

func TestJavaKBucketSplitReinsertionRejectsTerminalOverflow(t *testing.T) {
	set := newKBucketSet(5)
	for marker := byte(1); marker <= 7; marker++ {
		var peer ivnp.Hash
		peer[0], peer[31] = 0x80, marker
		if got := kademliaRange(ivnp.Hash{}, peer); got != 2040 {
			t.Fatalf("range = %d, want 2040", got)
		}
		set.add(ivnp.Hash{}, peer, 1)
	}
	index := set.bucketIndex(2040)
	terminal := set.buckets[index]
	if terminal.begin != 2040 || terminal.end != 2040 {
		t.Fatalf("terminal range = (%d,%d)", terminal.begin, terminal.end)
	}
	if len(terminal.members) != 5 {
		t.Fatalf("terminal members = %d, want RejectTrimmer cap 5", len(terminal.members))
	}
}

func TestClosestIntoHasNoHeapAllocation(t *testing.T) {
	var local ivnp.Hash
	table := NewTable(local, 4)
	for seed := byte(1); seed <= 3; seed++ {
		table.StoreVerified(routerWithSeed(seed), seed&1 == 1, 1)
	}
	out := make([]RouterRef, 0, 3)
	var target ivnp.Hash
	allocs := testing.AllocsPerRun(1_000, func() { out = table.ClosestInto(out[:0], target) })
	if allocs != 0 {
		t.Fatalf("ClosestInto allocations/run = %f, want 0", allocs)
	}
}
