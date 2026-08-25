package netdb

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/wire"
	"testing"
)

func TestLocalLeaseSetSnapshotExpiresAndReplaces(t *testing.T) {
	identityBytes := legacyIdentity()
	identity, _, err := ivnp.ParseIdentity(identityBytes)
	if err != nil {
		t.Fatal(err)
	}
	local, err := NewLocalLeaseSet(identity)
	if err != nil {
		t.Fatal(err)
	}

	leases := []Lease{
		{TunnelID: 1, EndDate: 10},
		{TunnelID: 2, EndDate: 20},
	}
	if err := local.ReplaceInboundLeases(leases); err != nil {
		t.Fatal(err)
	}
	initial, ok := local.Snapshot(10)
	if !ok {
		t.Fatal("initial Snapshot failed")
	}
	if len(initial.Leases) != 2 || initial.ExpiresAt != 10 || initial.Version != 1 {
		t.Fatalf("initial snapshot = %#v", initial)
	}

	current, ok := local.Snapshot(11)
	if !ok {
		t.Fatal("current Snapshot failed")
	}
	if len(current.Leases) != 1 || current.Leases[0].TunnelID != 2 || current.ExpiresAt != 20 {
		t.Fatalf("expired snapshot = %#v", current)
	}
	if removed := local.Expire(11); removed != 1 {
		t.Fatalf("Expire() removed %d, want 1", removed)
	}
	if err := local.ReplaceInboundLeases([]Lease{{TunnelID: 3, EndDate: 30}}); err != nil {
		t.Fatal(err)
	}
	replaced, ok := local.Snapshot(11)
	if !ok {
		t.Fatal("replacement Snapshot failed")
	}
	if len(replaced.Leases) != 1 || replaced.Leases[0].TunnelID != 3 || replaced.ExpiresAt != 30 || replaced.Version != 3 {
		t.Fatalf("replacement snapshot = %#v", replaced)
	}

	if len(initial.Leases) != 2 || initial.Leases[0].TunnelID != 1 || initial.ExpiresAt != 10 {
		t.Fatalf("previous snapshot changed after replacement: %#v", initial)
	}
}

func TestLocalLeaseSetCopiesIdentityAndBoundsLeases(t *testing.T) {
	identityBytes := legacyIdentity()
	identity, _, err := ivnp.ParseIdentity(identityBytes)
	if err != nil {
		t.Fatal(err)
	}
	local, err := NewLocalLeaseSet(identity)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := identity.Hash()
	identityBytes[0] = 1
	snapshot, ok := local.Snapshot(0)
	if local.Hash() != wantHash || !ok || snapshot.Identity.Hash() != wantHash {
		t.Fatal("local identity aliases caller-owned bytes")
	}

	tooMany := make([]Lease, MaxLeases+1)
	for index := range tooMany {
		tooMany[index].TunnelID = uint32(index + 1)
	}
	if err := local.ReplaceInboundLeases(tooMany); !errors.Is(err, ErrTooManyItems) {
		t.Fatalf("oversized lease replacement error = %v, want ErrTooManyItems", err)
	}
	if got, ok := local.Snapshot(0); !ok || len(got.Leases) != 0 || got.Version != 0 {
		t.Fatalf("oversized replacement changed state: %#v", got)
	}
	if err := local.ReplaceInboundLeases([]Lease{{TunnelID: 0, EndDate: 1}}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("zero tunnel ID error = %v, want ErrMalformed", err)
	}
}

func TestLocalLeaseSetSnapshotMarshalLegacy(t *testing.T) {
	identity, private := ed25519Identity(t)
	local, err := NewLocalLeaseSet(identity)
	if err != nil {
		t.Fatal(err)
	}
	var gateway ivnp.Hash
	gateway[0] = 1
	if err := local.ReplaceInboundLeases([]Lease{{Gateway: gateway, TunnelID: 1, EndDate: 2}}); err != nil {
		t.Fatal(err)
	}
	snapshot, ok := local.Snapshot(0)
	if !ok {
		t.Fatal("Snapshot failed")
	}
	encryptionKey := make([]byte, 256)
	signingKey := make([]byte, ed25519.PublicKeySize)
	if _, err := rand.Read(encryptionKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(signingKey); err != nil {
		t.Fatal(err)
	}
	wireBytes := make([]byte, snapshot.Identity.EncodedLen()+len(encryptionKey)+len(signingKey)+1+44+ed25519.SignatureSize)
	n, err := snapshot.MarshalLegacy(wireBytes, encryptionKey, signingKey, func(unsigned []byte) ([]byte, error) {
		return ed25519.Sign(private, unsigned), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(wireBytes) {
		t.Fatalf("MarshalLegacy() length = %d, want %d", n, len(wireBytes))
	}

	parsed, err := ParseLeaseSet(wireBytes[:n])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.EncryptionKey == nil || string(parsed.EncryptionKey) != string(encryptionKey) ||
		string(parsed.SigningKey) != string(signingKey) || parsed.LeaseCount() != 1 {
		t.Fatalf("ParseLeaseSet(MarshalLegacy()) = %#v", parsed)
	}
	if valid, err := parsed.Verify(); err != nil || !valid {
		t.Fatalf("ParseLeaseSet(MarshalLegacy()).Verify() = %t, %v", valid, err)
	}
}

func TestLocalLeaseSetSnapshotMarshalLegacyRejectsMalformedKeysAndSignature(t *testing.T) {
	identity, private := ed25519Identity(t)
	snapshot := LocalLeaseSetSnapshot{Identity: identity}
	encryptionKey := make([]byte, 256)
	signingKey := make([]byte, ed25519.PublicKeySize)
	wireBytes := make([]byte, identity.EncodedLen()+len(encryptionKey)+len(signingKey)+1+ed25519.SignatureSize)
	for index := range wireBytes {
		wireBytes[index] = 0xaa
	}
	called := false
	signer := func(unsigned []byte) ([]byte, error) {
		called = true
		return ed25519.Sign(private, unsigned), nil
	}

	if _, err := snapshot.MarshalLegacy(wireBytes, encryptionKey[:255], signingKey, signer); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("short encryption key error = %v, want ErrInvalidKeyLength", err)
	}
	if _, err := snapshot.MarshalLegacy(wireBytes, encryptionKey, signingKey[:31], signer); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("short signing key error = %v, want ErrInvalidKeyLength", err)
	}
	if called {
		t.Fatal("signer called for malformed key")
	}
	for index, value := range wireBytes {
		if value != 0xaa {
			t.Fatalf("malformed key changed dst at %d", index)
		}
	}

	if _, err := snapshot.MarshalLegacy(wireBytes, encryptionKey, signingKey, func([]byte) ([]byte, error) {
		return make([]byte, ed25519.SignatureSize-1), nil
	}); !errors.Is(err, ivnp.ErrMalformedSignature) {
		t.Fatalf("short signature error = %v, want ivnp.ErrMalformedSignature", err)
	}
	if _, err := snapshot.MarshalLegacy(wireBytes[:len(wireBytes)-1], encryptionKey, signingKey, signer); !errors.Is(err, wire.ErrShortBuffer) {
		t.Fatalf("short destination error = %v, want wire.ErrShortBuffer", err)
	}
}

func TestLocalLeaseSetSnapshotRejectsCorruptedRetainedIdentity(t *testing.T) {
	identity, _, err := ivnp.ParseIdentity(legacyIdentity())
	if err != nil {
		t.Fatal(err)
	}
	local, err := NewLocalLeaseSet(identity)
	if err != nil {
		t.Fatal(err)
	}
	local.identity = []byte{0xff}
	if snapshot, ok := local.Snapshot(0); ok || snapshot.Identity.Bytes() != nil {
		t.Fatalf("corrupted snapshot = %#v, %t", snapshot, ok)
	}
}

func ed25519Identity(t *testing.T) (ivnp.Identity, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([]byte, ivnp.IdentityBaseLength+7)
	copy(encoded[352:384], public)
	encoded[384] = byte(ivnp.CertificateKey)
	encoded[385], encoded[386] = 0, 4
	encoded[387], encoded[388] = 0, byte(ivnp.SigningEdDSASHA512Ed25519)
	encoded[389], encoded[390] = 0, byte(ivnp.CryptoElGamal)
	identity, n, err := ivnp.ParseIdentity(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(encoded) {
		t.Fatalf("ParseIdentity() consumed %d, want %d", n, len(encoded))
	}
	return identity, private
}
