package overlay

import (
	"crypto/ed25519"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

func marshalMapping(t *testing.T, entries []foundation.MappingEntry) foundation.Mapping {
	t.Helper()
	n, err := foundation.MappingEncodedLen(entries)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, n)
	if _, err := foundation.MarshalMappingTo(buf, entries); err != nil {
		t.Fatal(err)
	}
	m, used, err := foundation.ParseMapping(buf)
	if err != nil || used != n {
		t.Fatalf("mapping reparse: used=%d n=%d err=%v", used, n, err)
	}
	return m
}

func testEnvelope() *ContactEnvelope {
	return &ContactEnvelope{
		RealmID:      PublicFastRealmID,
		MemberID:     MemberID{1, 2, 3},
		ChannelKey:   [32]byte{9, 9, 9},
		Incarnation:  0,
		Sequence:     7,
		NotAfter:     time.Now().Add(time.Hour).Unix(),
		Admission:    AdmissionOpen,
		Capabilities: []string{"stream", "datagram"},
		Port:         47001,
		Endpoints: []Endpoint{
			{Transport: "tls13", Address: netip.MustParseAddrPort("8.8.8.7:4433")},
		},
	}
}

func TestContactRoundTrip(t *testing.T) {
	env := testEnvelope()
	entries, err := env.MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	m := marshalMapping(t, entries)
	got, err := ParseContactEnvelope(m, RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("no extension found")
	}
	if got.RealmID != env.RealmID || got.MemberID != env.MemberID || got.ChannelKey != env.ChannelKey {
		t.Fatalf("identity fields mismatch: %+v", got)
	}
	if got.Sequence != env.Sequence || got.NotAfter != env.NotAfter || got.Admission != env.Admission {
		t.Fatalf("generation fields mismatch: %+v", got)
	}
	if got.Port != env.Port || len(got.Endpoints) != 1 {
		t.Fatalf("service fields mismatch: %+v", got)
	}
}

func TestContactDigestTamper(t *testing.T) {
	env := testEnvelope()
	entries, err := env.MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	for i := range entries {
		if string(entries[i].Key) == "x-ov.s" {
			entries[i].Value = []byte("8")
		}
	}
	m := marshalMapping(t, entries)
	if _, err := ParseContactEnvelope(m, RecordLS2); !errors.Is(err, CodeEndpointBindingInvalid) {
		t.Fatalf("tampered sequence: %v", err)
	}
}

func TestContactRIPortForbidden(t *testing.T) {
	env := testEnvelope()
	if _, err := env.MarshalEntries(RecordRI); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("port in ri record: %v", err)
	}
	env.Port = 0
	if _, err := env.MarshalEntries(RecordRI); err != nil {
		t.Fatalf("ri without port: %v", err)
	}
}

func TestContactBudget(t *testing.T) {
	env := testEnvelope()
	env.Port = 0
	env.Capabilities = nil
	env.Endpoints = nil
	big := Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("8.8.8.7:4433")}
	env.Endpoints = []Endpoint{big, big}
	entries, err := env.MarshalEntries(RecordRI)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, e := range entries {
		total += len(e.Key) + len(e.Value) + 4
	}
	if total > contactBudgetRI {
		t.Fatalf("marshaled set exceeded ri budget without rejection")
	}
}

func TestContactVersionReject(t *testing.T) {
	env := testEnvelope()
	entries, err := env.MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	var tampered []foundation.MappingEntry
	for _, e := range entries {
		if string(e.Key) == "x-ov.v" {
			tampered = append(tampered, foundation.MappingEntry{Key: e.Key, Value: []byte("3")})
			continue
		}
		if string(e.Key) != "x-ov.h" {
			tampered = append(tampered, e)
		}
	}
	digest, err := contactDigest(tampered)
	if err != nil {
		t.Fatal(err)
	}
	tampered = append(tampered, foundation.MappingEntry{Key: []byte("x-ov.h"), Value: []byte(encode32(digest))})
	tampered = sortEntries(tampered)
	m := marshalMapping(t, tampered)
	if _, err := ParseContactEnvelope(m, RecordLS2); !errors.Is(err, CodeUnsupportedCapability) {
		t.Fatalf("unknown version: %v", err)
	}
}

// resignEnvelope rebuilds a tampered entry set with a fresh digest so only
// the targeted field is malformed, not the signature.
func resignEnvelope(t *testing.T, entries []foundation.MappingEntry, key, value string) []foundation.MappingEntry {
	t.Helper()
	var hashed []foundation.MappingEntry
	for _, e := range entries {
		if string(e.Key) == "x-ov.h" {
			continue
		}
		if string(e.Key) == key {
			e.Value = []byte(value)
		}
		hashed = append(hashed, e)
	}
	digest, err := contactDigest(hashed)
	if err != nil {
		t.Fatal(err)
	}
	return sortEntries(append(hashed,
		foundation.MappingEntry{Key: []byte("x-ov.h"), Value: []byte(encode32(digest))}))
}

// TestContactZeroKeyRejected: a zero channel key is not a usable contact key;
// it must not silently disable endpoint-key binding.
func TestContactZeroKeyRejected(t *testing.T) {
	env := testEnvelope()
	entries, err := env.MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	m := marshalMapping(t, resignEnvelope(t, entries, "x-ov.k", encode32([32]byte{})))
	if _, err := ParseContactEnvelope(m, RecordLS2); !errors.Is(err, CodeEndpointBindingInvalid) {
		t.Fatalf("zero channel key: %v", err)
	}
	if _, err := (&ContactEnvelope{
		RealmID: PublicFastRealmID, MemberID: MemberID{1}, ChannelKey: [32]byte{},
		NotAfter: time.Now().Unix(), Admission: AdmissionOpen,
	}).MarshalEntries(RecordLS2); !errors.Is(err, CodeEndpointBindingInvalid) {
		t.Fatalf("zero channel key marshaled: %v", err)
	}
}

// TestContactCapabilityStrict: parsed capability lists must be sorted unique
// tokens drawn from the defined set — the wire form is canonical.
func TestContactCapabilityStrict(t *testing.T) {
	entries, err := testEnvelope().MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		value string
		want  error
	}{
		// Unknown tokens parse: the digest covers them and they carry no
		// defined meaning. Only malformed lists fail.
		{"unknown token", "bogus,stream", nil},
		{"duplicate token", "stream,stream", CodeInvalidConfig},
		{"unsorted tokens", "stream,datagram", CodeInvalidConfig},
		{"empty segment", "stream,,fast", CodeInvalidConfig},
	} {
		m := marshalMapping(t, resignEnvelope(t, entries, "x-ov.c", tc.value))
		if _, err := ParseContactEnvelope(m, RecordLS2); !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
}

// TestContactParseBudgets: the record-kind extension budget applies while
// parsing, not only while marshaling; LS2 counts x-ivnp.* toward the shared
// 1024-byte budget.
func TestContactParseBudgets(t *testing.T) {
	env := testEnvelope()
	env.Port = 0
	entries, err := env.MarshalEntries(RecordRI)
	if err != nil {
		t.Fatal(err)
	}
	filler := make([]byte, 200)
	for i := range filler {
		filler[i] = 'a'
	}
	// The digest covers unknown x-ov.* keys, so re-sign after adding filler.
	fat := append([]foundation.MappingEntry(nil), entries...)
	for i := 0; i < 3; i++ {
		fat = append(fat, foundation.MappingEntry{
			Key: []byte("x-ov.zz" + string(rune('a'+i))), Value: filler})
	}
	m := marshalMapping(t, resignEnvelope(t, fat, "", ""))
	if _, err := ParseContactEnvelope(m, RecordRI); !errors.Is(err, CodeRecordTooLarge) {
		t.Fatalf("over-budget ri extension: %v", err)
	}
	if _, err := ParseContactEnvelope(m, RecordLS2); err != nil {
		t.Fatalf("same set inside ls2 budget: %v", err)
	}
	// Now push the LS2 over its combined budget with x-ivnp.* keys.
	ls2Entries, err := testEnvelope().MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	big := append([]foundation.MappingEntry(nil), ls2Entries...)
	for i := 0; i < 3; i++ {
		big = append(big, foundation.MappingEntry{
			Key: []byte("x-ivnp.zz" + string(rune('a'+i))), Value: make([]byte, 255)})
	}
	m = marshalMapping(t, sortEntries(big))
	if _, err := ParseContactEnvelope(m, RecordLS2); !errors.Is(err, CodeRecordTooLarge) {
		t.Fatalf("combined ls2 budget not enforced: %v", err)
	}
}

func sortEntries(entries []foundation.MappingEntry) []foundation.MappingEntry {
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if string(entries[i].Key) > string(entries[j].Key) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	return entries
}

func TestLocalContactRecord(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := testEnvelope()
	entries, err := env.MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	record, err := MarshalLocalContact(priv, entries)
	if err != nil {
		t.Fatal(err)
	}
	m, err := VerifyLocalContact(record, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseContactEnvelope(m, RecordLS2); err != nil || got == nil {
		t.Fatalf("local contact extension: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := VerifyLocalContact(record, other); !errors.Is(err, CodeEndpointBindingInvalid) {
		t.Fatalf("wrong signer: %v", err)
	}
	tampered := append([]byte(nil), record...)
	tampered[10] ^= 1
	if _, err := VerifyLocalContact(tampered, pub); err == nil {
		t.Fatalf("tampered record verified")
	}
}

func TestEndpointGrammar(t *testing.T) {
	cases := []struct {
		text  string
		valid bool
	}{
		{"tls13@203.0.113.7:4433", true},
		{"fast1@[2001:db8::1]:443", true},
		{"tls13@8.8.8.8:443", true},
		{"tls13@[::1]:443", true},
		{"TLS13@1.2.3.4:5", false},
		{"tls13@example.com:443", false},
		{"tls13@1.2.3.4:0", false},
		{"tls13@1.2.3.4:65536", false},
		{"tls13@1.2.3.4", false},
		{"tls13@fe80::1%eth0:443", false},
		{"toolongtransporttoken17@1.2.3.4:5", false},
		{"tls13@1.2.3.4:0443", false},
	}
	for _, c := range cases {
		ep, err := ParseEndpoint(c.text)
		if c.valid && err != nil {
			t.Fatalf("%s rejected: %v", c.text, err)
		}
		if !c.valid && err == nil {
			t.Fatalf("%s accepted", c.text)
		}
		if c.valid && ep.String() != c.text {
			t.Fatalf("%s re-encodes as %s", c.text, ep.String())
		}
	}
}

func TestEndpointPublic(t *testing.T) {
	for _, text := range []string{
		"tls13@8.8.8.8:443",
		"tls13@9.9.9.9:443",
		"tls13@[2606:4700:4700::1111]:443",
	} {
		ep, _ := ParseEndpoint(text)
		if !ep.Public() {
			t.Fatalf("%s not classified public", text)
		}
	}
	for _, text := range []string{
		"tls13@127.0.0.1:443", "tls13@10.0.0.1:443", "tls13@192.168.1.1:443",
		"tls13@169.254.1.1:443", "tls13@0.0.0.0:443", "tls13@255.255.255.255:443",
		"tls13@224.0.0.1:443", "tls13@[::1]:443", "tls13@[fe80::1]:443",
		"tls13@[fd00::1]:443",
		// IANA special-purpose space that netip still reports as global
		// unicast: documentation, benchmarking, protocol assignments,
		// reserved, and the broadcast tail.
		"tls13@192.0.2.1:443", "tls13@198.51.100.1:443", "tls13@203.0.113.1:443",
		"tls13@198.18.0.1:443", "tls13@198.19.255.254:443",
		"tls13@192.0.0.9:443", "tls13@240.1.2.3:443", "tls13@255.255.255.254:443",
		"tls13@100.64.0.1:443", "tls13@0.1.2.3:443",
		"tls13@[2001:db8::1]:443", "tls13@[fec0::1]:443", "tls13@[2002::1]:443",
		"tls13@[100::1]:443", "tls13@[2001:2::1]:443",
		"tls13@[64:ff9b::808:808]:443", "tls13@[64:ff9b:1::1]:443",
	} {
		ep, _ := ParseEndpoint(text)
		if ep.Public() {
			t.Fatalf("%s classified public", text)
		}
	}
}

func TestCanonicalDecimal(t *testing.T) {
	if _, err := parseCanonicalUint("0", 64); err != nil {
		t.Fatalf("zero rejected")
	}
	for _, bad := range []string{"", "00", "01", "-1", "+1", " 1", "1 ", "1.0", "abc"} {
		if _, err := parseCanonicalUint(bad, 64); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestAdmissionTokenRoundTrip(t *testing.T) {
	for _, a := range []AdmissionMode{AdmissionOpen, AdmissionCredential, AdmissionPSK, AdmissionCredentialPSK} {
		got, ok := admissionFromToken(a.token())
		if !ok || got != a {
			t.Fatalf("token %q did not round trip", a.token())
		}
	}
	if _, ok := admissionFromToken("bogus"); ok {
		t.Fatalf("unknown admission token accepted")
	}
	if strings.Contains(AdmissionOpen.token(), " ") {
		t.Fatalf("admission token contains whitespace")
	}
}
