package netdb

import (
	"testing"

	"gosuda.org/ivnp/foundation"
)

func legacyIdentity() []byte {
	identity := make([]byte, foundation.IdentityBaseLength+foundation.CertificateHeader)
	identity[384] = byte(foundation.CertificateNull)
	return identity
}
func routerWithSeed(seed byte) foundation.NetworkDatabaseRouterInfo {
	encoded := legacyIdentity()
	encoded[0] = seed
	identity, _, err := foundation.ParseIdentity(encoded)
	if err != nil {
		panic(err)
	}
	return foundation.NetworkDatabaseRouterInfo{Identity: identity}
}

func TestStoreVerifiedNeverDowngradesRouterInfo(t *testing.T) {
	var local foundation.Hash
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
	var local foundation.Hash
	var near, middle, far foundation.Hash
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
	local := foundation.Hash{}
	vectors := []struct {
		peer foundation.Hash
		want int
	}{
		{peer: foundation.Hash{}, want: -1},
		{peer: foundation.Hash{31: 0x01}, want: 0},
		{peer: foundation.Hash{31: 0x02}, want: 8},
		{peer: foundation.Hash{31: 0x0f}, want: 31},
		{peer: foundation.Hash{0: 0x80}, want: 2040},
		{peer: foundation.Hash{0: 0xf0}, want: 2047},
	}
	for _, vector := range vectors {
		if got := kademliaRange(local, vector.peer); got != vector.want {
			t.Fatalf("kademliaRange(%x) = %d, want %d", vector.peer, got, vector.want)
		}
	}
}

func TestJavaKBucketRejectTrimmerAndIndependentRouterStore(t *testing.T) {
	candidate := routerWithSeed(10)
	candidateRange := kademliaRange(foundation.Hash{}, candidate.Hash())
	table := NewTable(foundation.Hash{}, 5)
	table.mu.Lock()
	table.routing.buckets = []kBucket{{begin: uint16(candidateRange), end: uint16(candidateRange), members: make([]foundation.Hash, 5)}}
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
		var peer foundation.Hash
		peer[0], peer[31] = marker, marker
		set.add(foundation.Hash{}, peer, 1)
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
		var peer foundation.Hash
		peer[0], peer[31] = 0x80, marker
		if got := kademliaRange(foundation.Hash{}, peer); got != 2040 {
			t.Fatalf("range = %d, want 2040", got)
		}
		set.add(foundation.Hash{}, peer, 1)
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

func bucketZeroSeed(t *testing.T, ordinal int) byte {
	t.Helper()
	var local foundation.Hash
	found := 0
	for candidate := 0; candidate < 256; candidate++ {
		info := routerWithSeed(byte(candidate))
		if distanceBucket(local, info.Hash()) == 0 {
			if found == ordinal {
				return byte(candidate)
			}
			found++
		}
	}
	t.Fatalf("insufficient bucket-0 seeds for ordinal %d", ordinal)
	return 0
}

func routerWithSeedAndHost(t *testing.T, seed byte, host string, published uint64) foundation.NetworkDatabaseRouterInfo {
	t.Helper()
	info := routerWithSeed(seed)
	entries := []foundation.MappingEntry{
		{Key: []byte("host"), Value: []byte(host)},
		{Key: []byte("port"), Value: []byte("12345")},
	}
	optionsLen, err := foundation.MappingEncodedLen(entries)
	if err != nil {
		t.Fatal(err)
	}
	optionsRaw := make([]byte, optionsLen)
	if _, err := foundation.MarshalMappingTo(optionsRaw, entries); err != nil {
		t.Fatal(err)
	}
	emptyRaw := []byte{0, 0}
	wire := make([]byte, 0, 512)
	wire = append(wire, info.Identity.Bytes()...)
	var header [9]byte
	header[8] = 1
	wire = append(wire, header[:]...)
	var addrHeader [9]byte
	addrHeader[0] = 5
	wire = append(wire, addrHeader[:]...)
	wire = append(wire, byte(len("NTCP2")))
	wire = append(wire, "NTCP2"...)
	wire = append(wire, optionsRaw...)
	wire = append(wire, 0)
	wire = append(wire, emptyRaw...)
	wire = append(wire, make([]byte, 40)...)
	parsed, err := foundation.NetworkDatabaseParseRouterInfo(wire)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Published = published
	return parsed
}

func TestRoutingBucketSubnetDiversityQuota(t *testing.T) {
	var local foundation.Hash
	table := NewTable(local, 8)

	s1 := bucketZeroSeed(t, 0)
	s2 := bucketZeroSeed(t, 1)
	s3 := bucketZeroSeed(t, 2)
	s4 := bucketZeroSeed(t, 3)
	first := routerWithSeedAndHost(t, s1, "198.51.100.1", 10)
	second := routerWithSeedAndHost(t, s2, "198.51.100.2", 10)
	thirdSameV4Subnet := routerWithSeedAndHost(t, s3, "198.51.100.3", 10)
	distinctV4Subnet := routerWithSeedAndHost(t, s4, "203.0.113.1", 10)
	for _, candidate := range []foundation.NetworkDatabaseRouterInfo{first, second, thirdSameV4Subnet, distinctV4Subnet} {
		if band := distanceBucket(local, candidate.Hash()); band != 0 {
			t.Fatalf("candidate distanceBucket = %d, want 0", band)
		}
		table.StoreVerified(candidate, false, 10)
	}

	// All 4 verified RouterInfos remain in the independent data store.
	if got := table.Len(); got != 4 {
		t.Fatalf("table.Len() = %d, want 4", got)
	}
	// Only 2 from 198.51.0.0/16 plus 1 from 203.0.0.0/16 may enter the routing index.
	routing := table.ClosestRoutingInto(make([]RouterRef, 0, 8), local)
	if len(routing) != 3 {
		t.Fatalf("routing count = %d, want 3 (2 from /16 + 1 distinct)", len(routing))
	}
	for _, ref := range routing {
		if ref.Hash == thirdSameV4Subnet.Hash() {
			t.Fatal("third router in same IPv4 /16 subnet admitted to routing bucket")
		}
	}

	// Updating distinctV4Subnet to rebind into the saturated 198.51.0.0/16 subnet
	// must evict it from the routing index while keeping its newer RouterInfo in the store.
	rebound := routerWithSeedAndHost(t, s4, "198.51.100.99", 20)
	table.StoreVerified(rebound, false, 20)
	routing = table.ClosestRoutingInto(make([]RouterRef, 0, 8), local)
	if len(routing) != 2 {
		t.Fatalf("routing count after subnet-rebinding update = %d, want 2", len(routing))
	}

	// Verify IPv6 /48 per-bucket quota as well.
	v6first := routerWithSeedAndHost(t, bucketZeroSeed(t, 4), "2001:db8:abcd:1::1", 10)
	v6second := routerWithSeedAndHost(t, bucketZeroSeed(t, 5), "2001:db8:abcd:2::1", 10)
	v6thirdSame48 := routerWithSeedAndHost(t, bucketZeroSeed(t, 6), "2001:db8:abcd:3::1", 10)
	for _, candidate := range []foundation.NetworkDatabaseRouterInfo{v6first, v6second, v6thirdSame48} {
		table.StoreVerified(candidate, false, 10)
	}
	routing = table.ClosestRoutingInto(make([]RouterRef, 0, 8), local)
	if len(routing) != 4 {
		t.Fatalf("routing count after IPv6 /48 admission = %d, want 4", len(routing))
	}
	for _, ref := range routing {
		if ref.Hash == v6thirdSame48.Hash() {
			t.Fatal("third router in same IPv6 /48 subnet admitted to routing bucket")
		}
	}
}
