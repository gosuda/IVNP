package foundation

import (
	"bytes"
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
	"time"
)

// Values were independently derived from the ELS2 specification's RFC-5869
// equations (not through the implementation under test).
func TestEncryptedLeaseSetDerivationVectors(t *testing.T) {
	public := make([]byte, 32)
	for index := range public {
		public[index] = byte(index)
	}
	alpha, err := EncryptedLeaseSetAlpha(SigningEdDSASHA512Ed25519, public, time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	wantAlpha, _ := hex.DecodeString("b9b1603f9d7fcd61620e615f1ca2bb5858af4c83dfd1ef6395f71f7a8d0c790e")
	if !bytes.Equal(alpha[:], wantAlpha) {
		t.Fatalf("alpha = %x", alpha)
	}
	blinded := make([]byte, 32)
	for index := range blinded {
		blinded[index] = byte(index + 32)
	}
	subcredential, err := EncryptedLeaseSetSubcredential(SigningEdDSASHA512Ed25519, public, blinded)
	if err != nil {
		t.Fatal(err)
	}
	wantSubcredential, _ := hex.DecodeString("377f82ab47ba70a9f8bacb8b4230b14ac3641ae29b42e82d6005d07e86283ab5")
	if !bytes.Equal(subcredential[:], wantSubcredential) {
		t.Fatalf("subcredential = %x", subcredential)
	}
}

func TestRed25519BlindingMatchesPublicDerivation(t *testing.T) {
	public, private, err := GenerateRed25519Key()
	if err != nil {
		t.Fatal(err)
	}
	date := time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC)
	blindedPrivate, err := BlindEncryptedLeaseSetPrivate(SigningRedDSASHA512Ed25519, private[:], public[:], date, nil)
	if err != nil {
		t.Fatal(err)
	}
	blindedPublic, err := BlindEncryptedLeaseSetPublic(SigningRedDSASHA512Ed25519, public[:], date, nil)
	if err != nil {
		t.Fatal(err)
	}
	scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(blindedPrivate[:])
	if err != nil {
		t.Fatal(err)
	}
	if derived := new(edwards25519.Point).ScalarBaseMult(scalar).Bytes(); !bytes.Equal(derived, blindedPublic[:]) {
		t.Fatalf("private/public blinding disagree: %x != %x", derived, blindedPublic)
	}
}

func TestEncryptedLocalDestinationPrivateRoundTrip(t *testing.T) {
	destination, err := GenerateEncryptedLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([]byte, destination.PrivateEncodedLen())
	if _, err = destination.MarshalPrivateTo(encoded); err != nil {
		t.Fatal(err)
	}
	imported, err := ImportLocalDestination(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer imported.ReleaseSensitive()
	if imported.SigningKeyType() != SigningRedDSASHA512Ed25519 || imported.Hash() != destination.Hash() {
		t.Fatalf("imported encrypted destination = %v, %x", imported.SigningKeyType(), imported.Hash())
	}
}
