package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

// testAddress is one RouterAddress: transport style, host, and port.
type testAddress struct {
	style, host, port string
}

func createTestRouterInfoAddrs(t *testing.T, seed byte, caps, family string, published uint64, addrs ...testAddress) (foundation.NetworkDatabaseRouterInfo, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{seed}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	identity := make([]byte, foundation.IdentityBaseLength+7)
	copy(identity[352:384], public)
	identity[384] = byte(foundation.CertificateKey)
	identity[385], identity[386] = 0, 4
	identity[387], identity[388] = 0, byte(foundation.SigningEdDSASHA512Ed25519)
	identity[389], identity[390] = 0, byte(foundation.CryptoElGamal)

	var address []byte
	for _, a := range addrs {
		addrOptions := make([]byte, 128)
		addrLen, err := foundation.MarshalMappingTo(addrOptions, []foundation.MappingEntry{
			{Key: []byte("host"), Value: []byte(a.host)},
			{Key: []byte("port"), Value: []byte(a.port)},
		})
		if err != nil {
			t.Fatal(err)
		}
		address = append(address, 4)
		address = append(address, make([]byte, 8)...)
		address = append(address, byte(len(a.style)))
		address = append(address, a.style...)
		address = append(address, addrOptions[:addrLen]...)
	}

	entries := []foundation.MappingEntry{{Key: []byte("caps"), Value: []byte(caps)}}
	if family != "" {
		entries = append(entries, foundation.MappingEntry{Key: []byte("family"), Value: []byte(family)})
	}
	entries = append(entries, foundation.MappingEntry{Key: []byte("netId"), Value: []byte("2")})
	options := make([]byte, 256)
	optionLen, err := foundation.MarshalMappingTo(options, entries)
	if err != nil {
		t.Fatal(err)
	}

	unsigned := append(identity, make([]byte, 8)...)
	binary.BigEndian.PutUint64(unsigned[len(identity):], published)
	unsigned = append(unsigned, byte(len(addrs)))
	unsigned = append(unsigned, address...)
	unsigned = append(unsigned, 0)
	unsigned = append(unsigned, options[:optionLen]...)
	wire := append(unsigned, ed25519.Sign(private, unsigned)...)
	info, err := foundation.NetworkDatabaseParseRouterInfo(wire)
	if err != nil {
		t.Fatal(err)
	}
	return info, wire
}

type countingDialer struct {
	mu      sync.Mutex
	targets []string
	rtt     time.Duration
}

func (d *countingDialer) dial(_ context.Context, network, address string) (time.Duration, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.targets = append(d.targets, network+"://"+address)
	return d.rtt, nil
}

func (d *countingDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.targets)
}

func findPeer(t *testing.T, store *PeerStore, hash foundation.Hash) (PeerRecord, bool) {
	t.Helper()
	for _, p := range store.Snapshot() {
		if p.Hash == hash {
			return p, true
		}
	}
	return PeerRecord{}, false
}

func TestAdmissionLeavesPeerUnchecked(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	store := NewPeerStore()
	info, raw := createTestRouterInfoAddrs(t, 1, "fR", "", now, testAddress{"NTCP2", "203.0.113.7", "1234"})
	if _, ok := store.AddOrUpdateWithSeen(info, raw, now); !ok {
		t.Fatal("peer should be admitted")
	}
	rec, _ := findPeer(t, store, info.Hash())
	if rec.Stats.IsReachable {
		t.Fatal("a freshly seen RouterInfo must not count as reachable before a successful probe")
	}
	if got := store.ReachableCount(); got != 0 {
		t.Fatalf("ReachableCount = %d, want 0 before any probe", got)
	}

	// Seeing the RouterInfo again must not mark it reachable either.
	store.AddOrUpdateWithSeen(info, raw, now+1000)
	if rec, _ := findPeer(t, store, info.Hash()); rec.Stats.IsReachable {
		t.Fatal("a repeated sighting must not count as reachable")
	}

	store.RecordProbeResult(info.Hash(), true, 40*time.Millisecond)
	if rec, _ := findPeer(t, store, info.Hash()); !rec.Stats.IsReachable {
		t.Fatal("a successful probe should mark the peer reachable")
	}
}

func TestProberNeverCountsUDPOnlyPeerReachable(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	store := NewPeerStore()
	info, raw := createTestRouterInfoAddrs(t, 2, "fR", "", now,
		testAddress{"SSU2", "198.51.77.77", "9999"},
		testAddress{"SSU2", "2001:db8:dead::1", "9999"},
	)
	if _, ok := store.AddOrUpdateWithSeen(info, raw, now); !ok {
		t.Fatal("SSU2-only peer should be admitted into an empty store")
	}

	d := &countingDialer{rtt: 100 * time.Millisecond}
	prober := NewProber(store, 4)
	prober.SetDialer(d.dial)
	if success := prober.ProbeAll(context.Background()); success != 0 {
		t.Fatalf("ProbeAll successes = %d, want 0 for an unprobeable peer", success)
	}
	if ok, _ := prober.ProbeSingle(context.Background(), info.Hash()); ok {
		t.Fatal("ProbeSingle must not report success without contacting the peer")
	}
	if n := d.count(); n != 0 {
		t.Fatalf("dialer called %d times for an SSU2-only peer, want 0", n)
	}

	rec, _ := findPeer(t, store, info.Hash())
	if rec.Stats.IsReachable {
		t.Fatal("SSU2-only peer must stay unchecked")
	}
	if rec.Stats.SuccessProbes != 0 || rec.Stats.WinSuccess != 0 {
		t.Fatalf("SSU2-only peer recorded %d/%d probe successes without network contact",
			rec.Stats.SuccessProbes, rec.Stats.WinSuccess)
	}
}

// The H5 scenario: a spoofed SSU2-only floodfill claiming an honest peer's
// /16 and a unique family must neither evict the probed honest peer nor reach
// the signed bundle.
func TestUncheckedUDPOnlyPeerCannotDisplaceCheckedPeer(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	store := NewPeerStore()

	honest, honestRaw := createTestRouterInfoAddrs(t, 1, "fR", "", now, testAddress{"NTCP2", "198.51.100.1", "1234"})
	if _, ok := store.AddOrUpdateWithSeen(honest, honestRaw, now); !ok {
		t.Fatal("honest peer should be admitted")
	}
	for range 10 {
		store.RecordProbeResult(honest.Hash(), true, 80*time.Millisecond)
	}

	evil, evilRaw := createTestRouterInfoAddrs(t, 2, "fR", "evil-unique-1", now,
		testAddress{"SSU2", "198.51.77.77", "9999"},
		testAddress{"SSU2", "2001:db8:dead::1", "9999"},
	)
	store.AddOrUpdateWithSeen(evil, evilRaw, now)

	d := &countingDialer{rtt: 100 * time.Millisecond}
	prober := NewProber(store, 4)
	prober.SetDialer(d.dial)
	for range 20 {
		for _, p := range store.Snapshot() {
			prober.ProbeSingle(context.Background(), p.Hash)
		}
	}
	store.PruneRedundant()

	if _, ok := findPeer(t, store, honest.Hash()); !ok {
		t.Fatal("checked honest peer was evicted by an unchecked peer")
	}
	if rec, ok := findPeer(t, store, evil.Hash()); ok && rec.Stats.IsReachable {
		t.Fatal("unprobed SSU2-only peer counted as reachable")
	}

	cfg := DefaultSelectorConfig()
	cfg.TargetCount = 10
	cfg.MinBundlePeers = 1
	selected := SelectDiversePeers(store.Snapshot(), cfg)
	if len(selected) != 1 || selected[0].Hash != honest.Hash() {
		var got []foundation.Hash
		for _, p := range selected {
			got = append(got, p.Hash)
		}
		t.Fatalf("bundle = %x, want only the honest peer %x", got, honest.Hash())
	}
}

// A UDP-only peer can never be checked, so it must not hold a /16 against a
// peer the prober can verify.
func TestUDPOnlyPeerCannotSquatSubnet(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	store := NewPeerStore()

	squatter, squatterRaw := createTestRouterInfoAddrs(t, 2, "fR", "", now, testAddress{"SSU2", "198.51.77.77", "9999"})
	if _, ok := store.AddOrUpdateWithSeen(squatter, squatterRaw, now); !ok {
		t.Fatal("SSU2-only peer should be admitted into an empty /16")
	}

	honest, honestRaw := createTestRouterInfoAddrs(t, 1, "LR", "", now, testAddress{"NTCP2", "198.51.100.1", "1234"})
	if _, ok := store.AddOrUpdateWithSeen(honest, honestRaw, now); !ok {
		t.Fatal("probeable peer must be admitted into a /16 held only by an unprobeable peer")
	}

	prober := NewProber(store, 4)
	prober.SetDialer((&countingDialer{rtt: 60 * time.Millisecond}).dial)
	prober.ProbeAll(context.Background())
	store.PruneRedundant()

	if rec, ok := findPeer(t, store, honest.Hash()); !ok || !rec.Stats.IsReachable {
		t.Fatal("probeable peer should be retained and verified")
	}
	if _, ok := findPeer(t, store, squatter.Hash()); ok {
		t.Fatal("unprobeable peer should lose the /16 to a verified peer")
	}
}

// +checklocksignore
func TestCapacityEvictionSparesCheckedPeers(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	store := NewPeerStore()
	store.maxPeers = 4

	var checked []foundation.Hash
	for i := range 4 {
		info, raw := createTestRouterInfoAddrs(t, byte(10+i), "fR", "", now,
			testAddress{"NTCP2", netip.AddrFrom4([4]byte{byte(20 + i), 1, 1, 1}).String(), "1234"})
		if _, ok := store.AddOrUpdateWithSeen(info, raw, now); !ok {
			t.Fatalf("peer %d should be admitted", i)
		}
		store.RecordProbeResult(info.Hash(), true, time.Duration(50+i)*time.Millisecond)
		checked = append(checked, info.Hash())
	}

	newcomer, newcomerRaw := createTestRouterInfoAddrs(t, 50, "fR", "", now,
		testAddress{"SSU2", "60.1.1.1", "9999"},
		testAddress{"SSU2", "2001:db8:beef::1", "9999"},
	)
	if rec, ok := store.AddOrUpdateWithSeen(newcomer, newcomerRaw, now); ok || rec != nil {
		t.Fatal("unchecked newcomer must be refused when only checked peers could make room")
	}
	for _, h := range checked {
		if _, ok := findPeer(t, store, h); !ok {
			t.Fatalf("checked peer %x was evicted to admit an unchecked newcomer", h[:4])
		}
	}

	// Once a checked peer fails out, an unchecked newcomer may take its slot.
	store.RecordProbeResult(checked[0], false, 0)
	store.RecordProbeResult(checked[0], false, 0)
	if _, ok := store.AddOrUpdateWithSeen(newcomer, newcomerRaw, now); !ok {
		t.Fatal("newcomer should displace the failed peer")
	}
	for _, h := range checked[1:] {
		if _, ok := findPeer(t, store, h); !ok {
			t.Fatalf("checked peer %x was evicted to admit an unchecked newcomer", h[:4])
		}
	}
}

// Router families are self-declared and unverified, so they must not give a
// peer an extra contention group nor exclude peers from the bundle.
func TestUnverifiedFamilyIgnoredForContentionAndSelection(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	store := NewPeerStore()

	a, aRaw := createTestRouterInfoAddrs(t, 1, "fR", "acme", now, testAddress{"NTCP2", "198.51.100.1", "1234"})
	b, bRaw := createTestRouterInfoAddrs(t, 2, "LR", "acme", now, testAddress{"NTCP2", "203.0.113.9", "1234"})
	for _, p := range []struct {
		info foundation.NetworkDatabaseRouterInfo
		raw  []byte
	}{{a, aRaw}, {b, bRaw}} {
		if _, ok := store.AddOrUpdateWithSeen(p.info, p.raw, now); !ok {
			t.Fatal("peer should be admitted")
		}
		store.RecordProbeResult(p.info.Hash(), true, 50*time.Millisecond)
	}

	// A peer that loses its only /16 cannot stay in the store by declaring a
	// unique family.
	loser, loserRaw := createTestRouterInfoAddrs(t, 3, "LR", "unique-family", now, testAddress{"NTCP2", "198.51.100.2", "1234"})
	if rec, ok := store.AddOrUpdateWithSeen(loser, loserRaw, now); ok || rec != nil {
		t.Fatal("peer losing its /16 must not be retained through a self-declared family")
	}

	if pruned := store.PruneRedundant(); pruned != 0 {
		t.Fatalf("PruneRedundant evicted %d peers sharing a declared family, want 0", pruned)
	}

	cfg := DefaultSelectorConfig()
	cfg.TargetCount = 10
	cfg.MinBundlePeers = 1
	selected := SelectDiversePeers(store.Snapshot(), cfg)
	if len(selected) != 2 {
		t.Fatalf("selected = %d, want 2: a shared self-declared family must not exclude peers", len(selected))
	}
}

func TestRouterInfoAddressChangeRequiresReprobe(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	store := NewPeerStore()

	info, raw := createTestRouterInfoAddrs(t, 1, "fR", "", now, testAddress{"NTCP2", "203.0.113.7", "1234"})
	if _, ok := store.AddOrUpdateWithSeen(info, raw, now); !ok {
		t.Fatal("peer should be admitted")
	}
	store.RecordProbeResult(info.Hash(), true, 40*time.Millisecond)

	moved, movedRaw := createTestRouterInfoAddrs(t, 1, "fR", "", now+1000, testAddress{"SSU2", "198.51.77.77", "9999"})
	store.AddOrUpdateWithSeen(moved, movedRaw, now+1000)

	rec, ok := findPeer(t, store, info.Hash())
	if !ok {
		t.Fatal("re-published peer should remain in the store")
	}
	if rec.Stats.IsReachable {
		t.Fatal("reachability verified at an old address must not carry over to new advertised addresses")
	}
}

func TestLoadFromFileDropsUnverifiedReachability(t *testing.T) {
	recent := time.Now().Add(-time.Minute)
	legacy := []PeerRecord{
		{
			Hash:     foundation.Hash{1},
			Raw:      []byte("raw"),
			IPv4:     []netip.Addr{netip.MustParseAddr("198.51.77.77")},
			Ports:    []uint16{9999},
			UDPPorts: []uint16{9999},
			HasSSU2:  true,
			Stats: PeerStats{
				TotalProbes:   20,
				SuccessProbes: 20,
				WinProbes:     20,
				WinSuccess:    20,
				IsReachable:   true,
				LastSeen:      recent,
				LastProbed:    recent,
				EWMARTT:       50 * time.Millisecond,
			},
		},
		{
			Hash:     foundation.Hash{2},
			Raw:      []byte("raw"),
			IPv4:     []netip.Addr{netip.MustParseAddr("203.0.113.7")},
			Ports:    []uint16{1234},
			TCPPorts: []uint16{1234},
			HasNTCP2: true,
			Stats:    PeerStats{IsReachable: true, LastSeen: recent},
		},
		{
			Hash:     foundation.Hash{3},
			Raw:      []byte("raw"),
			IPv4:     []netip.Addr{netip.MustParseAddr("192.0.2.7")},
			Ports:    []uint16{1234},
			TCPPorts: []uint16{1234},
			HasNTCP2: true,
			Stats:    PeerStats{IsReachable: true, TotalProbes: 3, SuccessProbes: 3, LastSeen: recent},
		},
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "peers.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	store := NewPeerStore()
	if err := store.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}
	udp, _ := findPeer(t, store, foundation.Hash{1})
	if udp.Stats.IsReachable || udp.Stats.SuccessProbes != 0 || udp.Stats.WinSuccess != 0 {
		t.Fatalf("legacy SSU2-only record kept passive probe credit: %+v", udp.Stats)
	}
	if never, _ := findPeer(t, store, foundation.Hash{2}); never.Stats.IsReachable {
		t.Fatal("legacy record never probed successfully must load as unchecked")
	}
	if probed, _ := findPeer(t, store, foundation.Hash{3}); !probed.Stats.IsReachable {
		t.Fatal("legacy record with real probe successes should stay reachable")
	}
}
