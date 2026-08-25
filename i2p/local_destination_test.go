package i2p

import (
	"bytes"
	"errors"
	"testing"

	"gosuda.org/ivnp/crypto/cryptx"
)

func TestLocalDestinationUsesX25519AndClearsPrivateState(t *testing.T) {
	destination, err := GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := destination.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if identity.CryptoKeyType() != CryptoX25519 || identity.SigningKeyType() != SigningEdDSASHA512Ed25519 {
		t.Fatalf("identity types = %d/%d", identity.CryptoKeyType(), identity.SigningKeyType())
	}
	private := make([]byte, 32)
	if err := destination.CopyX25519Private(private); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(private, make([]byte, len(private))) || destination.Hash() != identity.Hash() {
		t.Fatal("missing local ECIES material")
	}
	clone, err := destination.Clone()
	if err != nil {
		t.Fatal(err)
	}
	destination.ReleaseSensitive()
	if _, err := destination.Sign([]byte("closed")); !errors.Is(err, cryptx.ErrSensitiveReleased) {
		t.Fatalf("Sign after release = %v", err)
	}
	if err := destination.CopyX25519Private(private); !errors.Is(err, cryptx.ErrSensitiveReleased) {
		t.Fatalf("CopyX25519Private after release = %v", err)
	}
	if _, err := clone.Sign([]byte("still live")); err != nil {
		t.Fatal(err)
	}
	clone.ReleaseSensitive()
}

func TestLocalDestinationPrivateStateRoundTrip(t *testing.T) {
	destination, err := GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([]byte, destination.PrivateEncodedLen())
	if _, err := destination.MarshalPrivateTo(encoded); err != nil {
		t.Fatal(err)
	}
	imported, err := ImportLocalDestination(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	defer imported.ReleaseSensitive()
	if imported.Hash() != destination.Hash() || !bytes.Equal(imported.Destination(), destination.Destination()) {
		t.Fatal("private state changed public destination")
	}
	if imported.CryptoTypes() != [3]CryptoKeyType{CryptoMLKEM1024X25519, CryptoMLKEM768X25519, CryptoX25519} {
		t.Fatalf("persisted crypto types = %v", imported.CryptoTypes())
	}
	for _, cryptoType := range imported.CryptoTypes() {
		public, publicErr := imported.CryptoPublic(cryptoType)
		if publicErr != nil || public != imported.X25519Public() {
			t.Fatalf("crypto type %d public binding = %x, %v", cryptoType, public, publicErr)
		}
		private := make([]byte, 32)
		if privateErr := imported.CopyCryptoPrivate(cryptoType, private); privateErr != nil {
			t.Fatalf("crypto type %d private binding = %v", cryptoType, privateErr)
		}
		clear(private)
	}
	if legacy, legacyErr := ImportLocalDestination(encoded[:len(encoded)-1]); legacyErr != nil {
		t.Fatalf("legacy private encoding migration = %v", legacyErr)
	} else {
		legacy.ReleaseSensitive()
	}
	encoded[len(encoded)-1] ^= 1
	if _, err := ImportLocalDestination(encoded); err == nil {
		t.Fatal("accepted invalid crypto capability policy")
	}
}

func TestLegacyLocalDestinationPrivateStateRoundTrip(t *testing.T) {
	destination, err := GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	identity, err := destination.Identity()
	if err != nil || identity.CryptoKeyType() != CryptoElGamal {
		t.Fatalf("legacy identity = %#v, %v", identity, err)
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
	if imported.Hash() != destination.Hash() || !bytes.Equal(imported.Destination(), destination.Destination()) {
		t.Fatal("legacy private state changed public destination")
	}
	originalElGamal := make([]byte, cryptx.ElGamalPrivateKeySize)
	importedElGamal := make([]byte, cryptx.ElGamalPrivateKeySize)
	if err = destination.CopyElGamalPrivate(originalElGamal); err != nil {
		t.Fatal(err)
	}
	if err = imported.CopyElGamalPrivate(importedElGamal); err != nil || !bytes.Equal(importedElGamal, originalElGamal) {
		t.Fatalf("ElGamal private round trip mismatch: %v", err)
	}
	if imported.X25519Public() != destination.X25519Public() {
		t.Fatal("LS2 X25519 key changed across private-state import")
	}
}
