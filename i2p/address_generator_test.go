package i2p

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"gosuda.org/ivnp/crypto/cryptx"
)

func TestGenerateAddress(t *testing.T) {
	encoded, wantHash, public, private, err := GenerateAddress()
	if err != nil {
		t.Fatal(err)
	}
	if len(public) != ed25519.PublicKeySize || len(private) != ed25519.PrivateKeySize {
		t.Fatalf("key lengths = %d, %d", len(public), len(private))
	}
	if !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		t.Fatal("private key does not match returned public key")
	}

	encoding := base64.NewEncoding(i2pBase64Alphabet)
	raw := make([]byte, encoding.DecodedLen(len(encoded)))
	n, err := encoding.Decode(raw, encoded)
	if err != nil {
		t.Fatalf("decode destination: %v", err)
	}
	raw = raw[:n]
	if got := encoding.EncodeToString(raw); got != string(encoded) {
		t.Fatalf("base64 round trip = %q, want %q", got, encoded)
	}

	identity, consumed, err := ParseIdentity(raw)
	if err != nil {
		t.Fatalf("parse generated Destination: %v", err)
	}
	if consumed != len(raw) {
		t.Fatalf("parsed length = %d, want %d", consumed, len(raw))
	}
	if certificate := identity.Certificate(); certificate.Type != CertificateKey || !bytes.Equal(certificate.Payload, []byte{0, byte(SigningEdDSASHA512Ed25519), 0, byte(CryptoElGamal)}) {
		t.Fatalf("certificate = type %d payload %x", certificate.Type, certificate.Payload)
	}
	if identity.SigningKeyType() != SigningEdDSASHA512Ed25519 || identity.CryptoKeyType() != CryptoElGamal {
		t.Fatalf("key types = signing %d crypto %d", identity.SigningKeyType(), identity.CryptoKeyType())
	}
	first, rest := identity.SigningKeyParts()
	if len(rest) != 0 || !bytes.Equal(first, public) || !bytes.Equal(raw[352:384], public) {
		t.Fatal("Ed25519 public key is not in the legacy signing-key field")
	}
	if got := identity.Hash(); got != wantHash {
		t.Fatalf("hash = %x, want %x", got, wantHash)
	}
}

func TestLocalAddressB32AndDestinationParser(t *testing.T) {
	address, err := GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ParseDestination(address.Destination)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Hash() != address.Hash {
		t.Fatalf("parsed hash = %x, want %x", identity.Hash(), address.Hash)
	}
	if got, want := address.B32(), B32(address.Hash); got != want {
		t.Fatalf("B32() = %q, want %q", got, want)
	}
}

func TestI2PBase64RoundTripsPaddedAndUnpaddedValues(t *testing.T) {
	raw := []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb}
	encoded := EncodeI2PBase64(raw)
	for _, value := range []string{encoded, strings.TrimRight(encoded, "=")} {
		decoded, err := DecodeI2PBase64([]byte(value))
		if err != nil || !bytes.Equal(decoded, raw) {
			t.Fatalf("DecodeI2PBase64(%q) = %x, %v", value, decoded, err)
		}
	}
}

func TestGenerateLocalAddressIncludesElGamalPublicKey(t *testing.T) {
	address, err := GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	encoding := base64.NewEncoding(i2pBase64Alphabet)
	raw := make([]byte, encoding.DecodedLen(len(address.Destination)))
	n, err := encoding.Decode(raw, address.Destination)
	if err != nil {
		t.Fatal(err)
	}
	identity, consumed, err := ParseIdentity(raw[:n])
	if err != nil || consumed != n {
		t.Fatalf("parse generated local Destination: %v, %d", err, consumed)
	}
	encryptionPublic, rest := identity.CryptoKeyParts()
	if len(rest) != 0 || !bytes.Equal(encryptionPublic, address.EncryptionPublic[:]) {
		t.Fatal("legacy encryption field does not contain returned ElGamal public key")
	}
	var plain [222]byte
	plain[0] = 1
	ciphertext, err := cryptx.EncryptElGamal(make([]byte, cryptx.ElGamalCiphertextSize), address.EncryptionPublic, plain[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cryptx.DecryptElGamal(make([]byte, len(plain)), address.EncryptionPrivate, ciphertext); err != nil {
		t.Fatalf("returned ElGamal private key does not decrypt: %v", err)
	}
}

func TestGenerateAddressProducesDistinctHashes(t *testing.T) {
	_, first, _, _, err := GenerateAddress()
	if err != nil {
		t.Fatal(err)
	}
	_, second, _, _, err := GenerateAddress()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("generated Destinations have the same hash")
	}
}

func TestGenerateLocalRouterAddressCreatesCanonicalX25519Identity(t *testing.T) {
	address, err := GenerateLocalRouterAddress()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := address.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if identity.Hash() != address.Hash || address.IdentityHash() != address.Hash {
		t.Fatalf("identity hash = %x, owner hash = %x", identity.Hash(), address.Hash)
	}
	if identity.SigningKeyType() != SigningEdDSASHA512Ed25519 || identity.CryptoKeyType() != CryptoX25519 {
		t.Fatalf("key types = %d/%d", identity.SigningKeyType(), identity.CryptoKeyType())
	}
	if certificate := identity.Certificate(); certificate.Type != CertificateKey ||
		!bytes.Equal(certificate.Payload, []byte{0, byte(SigningEdDSASHA512Ed25519), 0, byte(CryptoX25519)}) {
		t.Fatalf("certificate = type %d payload %x", certificate.Type, certificate.Payload)
	}
	crypto, cryptoRest := identity.CryptoKeyParts()
	if len(cryptoRest) != 0 || !bytes.Equal(crypto, address.X25519Public[:]) {
		t.Fatal("RouterIdentity crypto key does not contain the X25519 public key")
	}
	derived, err := ecdh.X25519().NewPrivateKey(address.X25519Private[:])
	if err != nil || !bytes.Equal(derived.PublicKey().Bytes(), address.X25519Public[:]) {
		t.Fatal("X25519 private key does not match RouterIdentity public key")
	}
	signing, signingRest := identity.SigningKeyParts()
	if len(signingRest) != 0 || !bytes.Equal(signing, address.SigningPublic) {
		t.Fatal("RouterIdentity signing key does not contain the Ed25519 public key")
	}
	message := []byte("router identity signature")
	if !ed25519.Verify(address.SigningPublic, message, ed25519.Sign(address.SigningPrivate, message)) {
		t.Fatal("RouterIdentity signing private key does not match its public key")
	}
	encoded := address.Base64()
	parsed, err := ParseDestination([]byte(encoded))
	if err != nil || !bytes.Equal(parsed.Bytes(), address.RouterIdentity) {
		t.Fatalf("canonical RouterIdentity base64 parse = %v", err)
	}
}
