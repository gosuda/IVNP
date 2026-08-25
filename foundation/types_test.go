package foundation

import (
	"bytes"
	"errors"
	"testing"
)

func TestParseIdentityEd25519X25519(t *testing.T) {
	wire := make([]byte, IdentityBaseLength+7)
	for i := range wire[:32] {
		wire[i] = byte(i + 1)
	}
	for i := range wire[352:384] {
		wire[i] = byte(i)
	}
	wire[384] = byte(CertificateKey)
	wire[385], wire[386] = 0, 4
	wire[387], wire[388] = 0, byte(SigningEdDSASHA512Ed25519)
	wire[389], wire[390] = 0, byte(CryptoX25519)

	identity, n, err := ParseIdentity(wire)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(wire) || identity.EncodedLen() != len(wire) {
		t.Fatalf("parsed length = %d/%d, want %d", n, identity.EncodedLen(), len(wire))
	}
	if identity.SigningKeyType() != SigningEdDSASHA512Ed25519 || identity.CryptoKeyType() != CryptoX25519 {
		t.Fatalf("key types = %d/%d", identity.SigningKeyType(), identity.CryptoKeyType())
	}
	crypto, cryptoExtra := identity.CryptoKeyParts()
	if len(crypto) != 32 || len(cryptoExtra) != 0 || !bytes.Equal(crypto, wire[:32]) {
		t.Fatalf("crypto key parts = %x / %x", crypto, cryptoExtra)
	}
	signing, signingExtra := identity.SigningKeyParts()
	if len(signing) != 32 || len(signingExtra) != 0 || !bytes.Equal(signing, wire[352:384]) {
		t.Fatalf("signing key parts = %x / %x", signing, signingExtra)
	}
	if got, want := identity.Hash(), Sum(wire); got != want {
		t.Fatalf("identity hash = %x, want %x", got, want)
	}
}

func TestParseIdentityP521ReadsCertificateOverflow(t *testing.T) {
	wire := make([]byte, IdentityBaseLength+11)
	for i := range wire[256:384] {
		wire[i] = byte(i)
	}
	wire[384] = byte(CertificateKey)
	wire[385], wire[386] = 0, 8
	wire[387], wire[388] = 0, byte(SigningECDSASHA512P521)
	wire[389], wire[390] = 0, byte(CryptoElGamal)
	copy(wire[391:], []byte{0xaa, 0xbb, 0xcc, 0xdd})

	identity, _, err := ParseIdentity(wire)
	if err != nil {
		t.Fatal(err)
	}
	first, rest := identity.SigningKeyParts()
	if !bytes.Equal(first, wire[256:384]) || !bytes.Equal(rest, wire[391:]) {
		t.Fatalf("P521 key parts do not preserve key order")
	}
}

func TestParseIdentityRejectsBadKeyCertificateLength(t *testing.T) {
	wire := make([]byte, IdentityBaseLength+7)
	wire[384] = byte(CertificateKey)
	wire[385], wire[386] = 0, 4
	wire[387], wire[388] = 0, byte(SigningECDSASHA512P521)
	wire[389], wire[390] = 0, byte(CryptoElGamal)
	if _, _, err := ParseIdentity(wire); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("ParseIdentity() error = %v, want ErrInvalidIdentity", err)
	}
}

func TestParseIdentityRejectsRemovedCryptoType5(t *testing.T) {
	if _, ok := CryptoKeyType(5).PublicKeyLen(); ok {
		t.Fatal("removed crypto type 5 has a public-key length")
	}
	wire := make([]byte, IdentityBaseLength+7)
	wire[384] = byte(CertificateKey)
	wire[385], wire[386] = 0, 4
	wire[387], wire[388] = 0, byte(SigningEdDSASHA512Ed25519)
	wire[389], wire[390] = 0, 5
	if _, _, err := ParseIdentity(wire); !errors.Is(err, ErrUnknownKeyType) {
		t.Fatalf("ParseIdentity(type 5) error = %v, want ErrUnknownKeyType", err)
	}
}

func TestMappingRoundTripAndCanonicalValidation(t *testing.T) {
	entries := []MappingEntry{
		{Key: []byte("caps"), Value: []byte("f")},
		{Key: []byte("netId"), Value: []byte("2")},
	}
	n, err := MappingEncodedLen(entries)
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, n)
	if got, err := MarshalMappingTo(wire, entries); err != nil || got != n {
		t.Fatalf("MarshalMappingTo() = %d, %v; want %d, nil", got, err, n)
	}
	mapping, consumed, err := ParseMapping(wire)
	if err != nil || consumed != n {
		t.Fatalf("ParseMapping() = %d, %v", consumed, err)
	}
	if err := mapping.ValidateCanonical(); err != nil {
		t.Fatal(err)
	}
	it := mapping.Iterator()
	key, value, ok, err := it.Next()
	if err != nil || !ok || string(key) != "caps" || string(value) != "f" {
		t.Fatalf("first mapping entry = %q=%q, %t, %v", key, value, ok, err)
	}
}

func TestMappingRejectsNonCanonicalEntries(t *testing.T) {
	entries := []MappingEntry{
		{Key: []byte("z"), Value: []byte("1")},
		{Key: []byte("a"), Value: []byte("2")},
	}
	if _, err := MappingEncodedLen(entries); !errors.Is(err, ErrUnsortedMapping) {
		t.Fatalf("MappingEncodedLen() error = %v, want ErrUnsortedMapping", err)
	}
	if _, _, err := ParseMapping([]byte{0, 3, 1, 'a', '='}); !errors.Is(err, ErrInvalidMapping) {
		t.Fatalf("ParseMapping(truncated) error = %v, want ErrInvalidMapping", err)
	}
}

func TestEncodersRejectUnsignedLengthOverflow(t *testing.T) {
	certificate := Certificate{Type: CertificateHashCash, Payload: make([]byte, 1<<16)}
	if _, err := certificate.MarshalTo(make([]byte, certificate.EncodedLen())); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("certificate length overflow error = %v, want ErrInvalidCertificate", err)
	}

	entries := make([]MappingEntry, 128)
	for i := range entries {
		key := make([]byte, 255)
		key[len(key)-1] = byte(i)
		entries[i] = MappingEntry{Key: key, Value: make([]byte, 255)}
	}
	if _, err := MappingEncodedLen(entries); !errors.Is(err, ErrInvalidMapping) {
		t.Fatalf("mapping size overflow error = %v, want ErrInvalidMapping", err)
	}
}

func BenchmarkParseIdentityEd25519X25519(b *testing.B) {
	wire := make([]byte, IdentityBaseLength+7)
	wire[384] = byte(CertificateKey)
	wire[385], wire[386] = 0, 4
	wire[387], wire[388] = 0, byte(SigningEdDSASHA512Ed25519)
	wire[389], wire[390] = 0, byte(CryptoX25519)
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = ParseIdentity(wire)
	}
}

var identitySink Identity
var identityErrorSink error

func TestParseIdentityHasNoHeapAllocation(t *testing.T) {
	encoded := make([]byte, IdentityBaseLength+7)
	encoded[384] = byte(CertificateKey)
	encoded[385], encoded[386] = 0, 4
	encoded[387], encoded[388] = 0, byte(SigningEdDSASHA512Ed25519)
	encoded[389], encoded[390] = 0, byte(CryptoX25519)
	allocs := testing.AllocsPerRun(1_000, func() {
		identitySink, _, identityErrorSink = ParseIdentity(encoded)
	})
	if identityErrorSink != nil {
		t.Fatal(identityErrorSink)
	}
	if allocs != 0 {
		t.Fatalf("ParseIdentity() allocations/run = %f, want 0", allocs)
	}
}
