package overlay

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

func testDescriptor() FabricDescriptor {
	return FabricDescriptor{
		ID:        PublicFastFabricID,
		NetworkID: 77,
		MaxPeers:  128,
		Reviewed:  true,
		Public:    true,
	}
}

// privateDescriptor is a non-public fabric descriptor for confined realms.
func privateDescriptor() FabricDescriptor {
	return FabricDescriptor{
		ID:        FabricID(sha256Sum("test-private-fabric/v1")),
		NetworkID: 88,
		MaxPeers:  64,
		Reviewed:  true,
	}
}

func testPresence() *DualPresence {
	return &DualPresence{
		FabricID:     PublicFastFabricID,
		NetworkID:    77,
		RealmID:      PublicFastRealmID,
		ContactKey:   [32]byte{7, 7, 7},
		Incarnation:  0,
		Sequence:     3,
		NotAfter:     time.Now().Add(time.Hour).Unix(),
		Port:         47001,
		Capabilities: []string{CapDirect, CapStreamV1},
		Endpoints: []Endpoint{
			{Transport: "tls13", Address: netip.MustParseAddrPort("9.9.9.9:9443")},
		},
	}
}

func TestPresenceRoundTrip(t *testing.T) {
	p := testPresence()
	entries, err := p.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	m := marshalMapping(t, entries)
	got, err := ParseDualPresence(m, testDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	if got.FabricID != p.FabricID || got.NetworkID != p.NetworkID || got.RealmID != p.RealmID {
		t.Fatalf("scope fields mismatch: %+v", got)
	}
	if got.ContactKey != p.ContactKey || got.Sequence != p.Sequence || got.Port != p.Port {
		t.Fatalf("service fields mismatch: %+v", got)
	}
	if len(got.Endpoints) != 1 || !got.HasCapability(CapDirect) {
		t.Fatalf("capability fields mismatch: %+v", got)
	}
	if got.Digest() == ([32]byte{}) {
		t.Fatalf("parsed presence lacks verified digest")
	}
}

func TestPresenceDescriptorMismatch(t *testing.T) {
	p := testPresence()
	entries, err := p.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	m := marshalMapping(t, entries)
	other := testDescriptor()
	other.NetworkID = 78
	if _, err := ParseDualPresence(m, other); !errors.Is(err, CodeFabricMismatch) {
		t.Fatalf("netid mismatch: %v", err)
	}
	var foreign FabricID
	foreign[0] = 0xff
	other = testDescriptor()
	other.ID = foreign
	if _, err := ParseDualPresence(m, other); !errors.Is(err, CodeFabricMismatch) {
		t.Fatalf("fabric mismatch: %v", err)
	}
}

func TestPresenceDirectRequiresContact(t *testing.T) {
	p := testPresence()
	p.Endpoints = nil
	if _, err := p.MarshalEntries(); !errors.Is(err, CodeEndpointBindingInvalid) {
		t.Fatalf("direct without contact: %v", err)
	}
	p.Capabilities = []string{CapRouted}
	if _, err := p.MarshalEntries(); err != nil {
		t.Fatalf("routed without direct contact: %v", err)
	}
}

func TestPresenceUnknownCapability(t *testing.T) {
	p := testPresence()
	p.Capabilities = []string{"made-up"}
	if _, err := p.MarshalEntries(); !errors.Is(err, CodeUnsupportedCapability) {
		t.Fatalf("unknown capability: %v", err)
	}
}

func TestPresenceDigestTamper(t *testing.T) {
	p := testPresence()
	entries, err := p.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	for i := range entries {
		if string(entries[i].Key) == "x-ivnp.s" {
			entries[i].Value = []byte("4")
		}
	}
	m := marshalMapping(t, entries)
	if _, err := ParseDualPresence(m, testDescriptor()); !errors.Is(err, CodeEndpointBindingInvalid) {
		t.Fatalf("tampered sequence: %v", err)
	}
}

func TestPresenceCombinedBudget(t *testing.T) {
	p := testPresence()
	entries, err := p.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	// Add x-ov entries plus a large unknown x-ivnp key until the combined
	// extension size crosses the budget.
	extra := ContactEnvelope{
		RealmID: PublicFastRealmID, MemberID: MemberID{1}, ChannelKey: [32]byte{2},
		NotAfter: time.Now().Unix(), Admission: AdmissionOpen,
	}
	ov, err := extra.MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	all := append(append([]foundation.MappingEntry(nil), entries...), ov...)
	filler := make([]byte, 255)
	for i := range filler {
		filler[i] = 'a'
	}
	all = append(all,
		foundation.MappingEntry{Key: []byte("x-ivnp.z1"), Value: filler},
		foundation.MappingEntry{Key: []byte("x-ivnp.z2"), Value: filler})
	all = sortEntries(all)
	m := marshalMapping(t, all)
	if _, err := ParseDualPresence(m, testDescriptor()); !errors.Is(err, CodeRecordTooLarge) {
		t.Fatalf("over-budget extension: %v", err)
	}
}

// resignPresence rebuilds a tampered entry set with a fresh digest so only
// the targeted field is malformed, not the signature.
func resignPresence(t *testing.T, entries []foundation.MappingEntry, key, value string) []foundation.MappingEntry {
	t.Helper()
	var hashed []foundation.MappingEntry
	for _, e := range entries {
		if string(e.Key) == "x-ivnp.h" {
			continue
		}
		if string(e.Key) == key {
			e.Value = []byte(value)
		}
		hashed = append(hashed, e)
	}
	digest, err := presenceDigest(hashed)
	if err != nil {
		t.Fatal(err)
	}
	return sortEntries(append(hashed,
		foundation.MappingEntry{Key: []byte("x-ivnp.h"), Value: []byte(encode32(digest))}))
}

// TestPresenceZeroKeyRejected: a zero contact key is not a usable endpoint
// key; it must not silently disable channel-key binding, in either direction.
func TestPresenceZeroKeyRejected(t *testing.T) {
	p := testPresence()
	entries, err := p.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	m := marshalMapping(t, resignPresence(t, entries, "x-ivnp.k", encode32([32]byte{})))
	if _, err := ParseDualPresence(m, testDescriptor()); !errors.Is(err, CodeEndpointBindingInvalid) {
		t.Fatalf("zero contact key parsed: %v", err)
	}
	p.ContactKey = [32]byte{}
	if _, err := p.MarshalEntries(); !errors.Is(err, CodeEndpointBindingInvalid) {
		t.Fatalf("zero contact key marshaled: %v", err)
	}
}

func TestPresenceAbsent(t *testing.T) {
	plain := []foundation.MappingEntry{{Key: []byte("unrelated"), Value: []byte("x")}}
	m := marshalMapping(t, plain)
	got, err := ParseDualPresence(m, testDescriptor())
	if err != nil || got != nil {
		t.Fatalf("absent extension: %v %v", got, err)
	}
}
