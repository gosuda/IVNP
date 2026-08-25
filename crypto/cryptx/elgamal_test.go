package cryptx

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestElGamalDeterministicKeyEncryptDecrypt(t *testing.T) {
	zeroes := bytes.NewReader(make([]byte, 1024))
	public, private, err := generateElGamalKeyPair(zeroes)
	if err != nil {
		t.Fatal(err)
	}
	if public[ElGamalPublicKeySize-1] != 2 {
		t.Fatalf("public key = %x, want generator 2", public)
	}
	if private[ElGamalPrivateKeySize-1] != 1 {
		t.Fatalf("private key = %x, want exponent 1", private)
	}
	plaintext := bytes.Repeat([]byte{0x5a}, ElGamalPlaintextSize)
	ciphertext, err := encryptElGamal(bytes.NewReader(make([]byte, 1024)), make([]byte, ElGamalCiphertextSize), public, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) != ElGamalCiphertextSize || ciphertext[0] != 0 || ciphertext[257] != 0 {
		t.Fatalf("ciphertext layout = %d bytes, prefixes %d/%d", len(ciphertext), ciphertext[0], ciphertext[257])
	}
	opened, err := DecryptElGamal(make([]byte, ElGamalPlaintextSize), private, ciphertext)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("DecryptElGamal() = %x, %v", opened, err)
	}
}

func TestElGamalPublicFromPrivate(t *testing.T) {
	public, private, err := GenerateElGamalKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	derived, err := ElGamalPublicFromPrivate(private)
	if err != nil || derived != public {
		t.Fatalf("ElGamalPublicFromPrivate() = %x, %v", derived, err)
	}
	if _, err = ElGamalPublicFromPrivate(ElGamalPrivateKey{}); err != ErrElGamal {
		t.Fatalf("zero private exponent error = %v, want %v", err, ErrElGamal)
	}
}

func TestElGamalRejectsMalformedBlocks(t *testing.T) {
	public, private, err := GenerateElGamalKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := bytes.Repeat([]byte{1}, ElGamalPlaintextSize)
	ciphertext, err := EncryptElGamal(make([]byte, ElGamalCiphertextSize), public, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	for name, malformed := range map[string][]byte{
		"short":  ciphertext[:ElGamalCiphertextSize-1],
		"prefix": append([]byte(nil), ciphertext...),
	} {
		if name == "prefix" {
			malformed[0] = 1
		}
		if _, err := DecryptElGamal(make([]byte, ElGamalPlaintextSize), private, malformed); err != ErrElGamal {
			t.Errorf("%s error = %v, want %v", name, err, ErrElGamal)
		}
	}

	// Construct a mathematically valid ciphertext with an invalid embedded hash,
	// so rejection exercises the post-decryption authentication check.
	p, _, err := elGamalParameters()
	if err != nil {
		t.Fatal(err)
	}
	var m [255]byte
	m[0] = 0xff
	copy(m[33:], plaintext)
	hash := sha256.Sum256(plaintext)
	copy(m[1:33], hash[:])
	m[1] ^= 1
	bad := make([]byte, ElGamalCiphertextSize)
	bad[0], bad[257] = 0, 0
	big.NewInt(2).FillBytes(bad[1:257])
	b := new(big.Int).Mul(big.NewInt(2), new(big.Int).SetBytes(m[:]))
	b.Mod(b, p)
	b.FillBytes(bad[258:])
	var privateOne ElGamalPrivateKey
	privateOne[ElGamalPrivateKeySize-1] = 1
	if _, err := DecryptElGamal(make([]byte, ElGamalPlaintextSize), privateOne, bad); err != ErrElGamal {
		t.Fatalf("invalid hash error = %v, want %v", err, ErrElGamal)
	}
}

func TestElGamalRejectsOversizeDecodedRepresentative(t *testing.T) {
	_, private, err := GenerateElGamalKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := elGamalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, ElGamalCiphertextSize)
	ciphertext[0], ciphertext[257] = 0, 0
	ciphertext[256] = 1 // a = 1, so decryption yields b directly.
	new(big.Int).Sub(p, big.NewInt(1)).FillBytes(ciphertext[258:])
	if _, err := DecryptElGamal(make([]byte, ElGamalPlaintextSize), private, ciphertext); err != ErrElGamal {
		t.Fatalf("oversize representative error = %v, want %v", err, ErrElGamal)
	}
}
