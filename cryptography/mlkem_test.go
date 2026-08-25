package cryptography

import (
	"bytes"
	"crypto/mlkem"
	"errors"
	"testing"
)

func TestMLKEMFIPS203Encapsulation(t *testing.T) {
	for _, cryptoType := range []uint16{MLKEM768X25519, MLKEM1024X25519} {
		t.Run(string(rune(cryptoType)), func(t *testing.T) {
			params, ok := Parameters(cryptoType)
			if !ok {
				t.Fatal("missing parameters")
			}
			public, private, err := GenerateMLKEM(cryptoType)
			if err != nil {
				t.Fatal(err)
			}
			defer private.ReleaseSensitive()
			if public.CryptoType() != cryptoType || len(public.Bytes()) != params.PublicKeySize || private.CryptoType() != cryptoType {
				t.Fatalf("generated key metadata = type %d public %d private %d", public.CryptoType(), len(public.Bytes()), private.CryptoType())
			}
			parsed, err := NewMLKEMPublicKey(cryptoType, public.Bytes())
			if err != nil {
				t.Fatalf("parse generated public key: %v", err)
			}
			shared, ciphertext, err := Encapsulate(parsed)
			if err != nil || len(ciphertext) != params.CiphertextSize {
				t.Fatalf("Encapsulate = %d, %v", len(ciphertext), err)
			}
			opened, err := private.Decapsulate(ciphertext)
			if err != nil || !bytes.Equal(opened[:], shared[:]) {
				t.Fatalf("Decapsulate = %x, %v", opened, err)
			}
			if _, err := private.Decapsulate(ciphertext[:len(ciphertext)-1]); err != ErrMLKEM {
				t.Fatalf("short ciphertext error = %v, want ErrMLKEM", err)
			}
		})
	}
}

func TestMLKEMRejectsInvalidAndUnknownKeys(t *testing.T) {
	if _, err := NewMLKEMPublicKey(MLKEM768X25519, make([]byte, 1)); err != ErrMLKEM {
		t.Fatalf("short public key error = %v, want ErrMLKEM", err)
	}
	if _, _, err := GenerateMLKEM(999); err != ErrMLKEMUnsupported {
		t.Fatalf("GenerateMLKEM(unknown) = %v, want ErrMLKEMUnsupported", err)
	}
}

func TestMLKEMType5IsRemoved(t *testing.T) {
	if _, ok := Parameters(5); ok {
		t.Fatal("Parameters accepted removed ML-KEM-512 crypto type 5")
	}
	if _, err := NewMLKEMPublicKey(5, make([]byte, 800)); !errors.Is(err, ErrMLKEMUnsupported) {
		t.Fatalf("NewMLKEMPublicKey(type 5) = %v", err)
	}
	if _, _, err := GenerateMLKEM(5); !errors.Is(err, ErrMLKEMUnsupported) {
		t.Fatalf("GenerateMLKEM(type 5) = %v", err)
	}
}

func TestMLKEMPrivateReleaseZeroizesSeed(t *testing.T) {
	_, private, err := GenerateMLKEM(MLKEM768X25519)
	if err != nil {
		t.Fatal(err)
	}
	private.ReleaseSensitive()
	private.ReleaseSensitive()
	if private.seed != [mlkem.SeedSize]byte{} || !private.released {
		t.Fatal("released ML-KEM key retained seed")
	}
	if _, err := private.Decapsulate(make([]byte, mlkem.CiphertextSize768)); !errors.Is(err, ErrSensitiveReleased) {
		t.Fatalf("Decapsulate after release = %v", err)
	}
}
