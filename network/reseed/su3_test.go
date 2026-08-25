package reseed

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
	"time"

	"gosuda.org/ivnp"
)

func TestVerifySU3JavaNONEwithRSAPKCS1v15(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	version, signerID, content := bytes.Repeat([]byte{'1'}, su3MinimumVersion), []byte("test-signer"), []byte("zip payload")
	header := make([]byte, su3HeaderLen)
	copy(header[:7], []byte{'I', '2', 'P', 's', 'u', '3', 0})
	binary.BigEndian.PutUint16(header[8:10], uint16(ivnp.SigningRSASHA512_4096))
	binary.BigEndian.PutUint16(header[10:12], su3RSASignatureLen)
	header[13], header[15] = byte(len(version)), byte(len(signerID))
	binary.BigEndian.PutUint64(header[16:24], uint64(len(content)))
	header[25], header[27] = su3FileTypeZIP, su3ContentTypeReseed
	signed := append(append(append([]byte{}, header...), version...), signerID...)
	signed = append(signed, content...)
	digest := sha512.Sum512(signed)
	signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.Hash(0), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	container := append(append([]byte(nil), signed...), signature...)
	signers := map[string]SU3Signer{"test-signer": {SigningType: ivnp.SigningRSASHA512_4096, PublicKey: private.N.FillBytes(make([]byte, su3RSASignatureLen))}}
	verified, err := VerifySU3(container, signers, int64(len(content)))
	if err != nil || !bytes.Equal(verified, content) {
		t.Fatalf("VerifySU3() = %q, %v", verified, err)
	}

	rawSign := func(encoded []byte) []byte {
		t.Helper()
		return new(big.Int).Exp(new(big.Int).SetBytes(encoded), private.D, private.N).FillBytes(make([]byte, su3RSASignatureLen))
	}
	validEncoded := make([]byte, su3RSASignatureLen)
	validEncoded[1] = 1
	separator := len(validEncoded) - len(digest) - 1
	for index := 2; index < separator; index++ {
		validEncoded[index] = 0xff
	}
	copy(validEncoded[separator+1:], digest[:])

	allZeroPrefix := make([]byte, su3RSASignatureLen)
	copy(allZeroPrefix[len(allZeroPrefix)-len(digest):], digest[:])
	asn1Signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA512, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	brokenPadding := append([]byte(nil), validEncoded...)
	brokenPadding[20] = 0
	shortPadding := make([]byte, su3RSASignatureLen)
	shortPadding[1] = 1
	for index := 2; index < 9; index++ {
		shortPadding[index] = 0xff
	}
	copy(shortPadding[10:], digest[:])
	tamperedDigest := append([]byte(nil), validEncoded...)
	tamperedDigest[len(tamperedDigest)-1] ^= 1

	for name, invalidSignature := range map[string][]byte{
		"all-zero prefix":  rawSign(allZeroPrefix),
		"ASN.1 DigestInfo": asn1Signature,
		"non-FF padding":   rawSign(brokenPadding),
		"fewer than 8 FF":  rawSign(shortPadding),
		"digest tamper":    rawSign(tamperedDigest),
	} {
		t.Run(name, func(t *testing.T) {
			tampered := append(append([]byte(nil), signed...), invalidSignature...)
			if _, err := VerifySU3(tampered, signers, int64(len(content))); !errors.Is(err, ErrSU3Signature) {
				t.Fatalf("VerifySU3() error = %v, want ErrSU3Signature", err)
			}
		})
	}

	tamperedContent := append([]byte(nil), container...)
	tamperedContent[len(signed)-1] ^= 1
	if _, err := VerifySU3(tamperedContent, signers, int64(len(content))); !errors.Is(err, ErrSU3Signature) {
		t.Fatalf("content digest tamper error = %v, want ErrSU3Signature", err)
	}
}

func TestDefaultSU3SignersLoadExactCertificateNames(t *testing.T) {
	signers, err := DefaultSU3Signers()
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 17 {
		t.Fatalf("default signer count = %d, want 17", len(signers))
	}
	for _, signerID := range []string{
		"admin@likogan.dev",
		"reseedserver@mail.i2p",
		"reseed@diva.exchange",
	} {
		signer, found := signers[signerID]
		if !found || signer.SigningType != ivnp.SigningRSASHA512_4096 || len(signer.PublicKey) != su3RSASignatureLen {
			t.Fatalf("default signer %q = %#v, found=%t", signerID, signer, found)
		}
	}
}

func TestDefaultSU3SignersRejectCertificatesOutsideInjectedTime(t *testing.T) {
	if _, err := DefaultSU3SignersAt(time.Unix(0, 0)); !errors.Is(err, ErrDefaultSigners) {
		t.Fatalf("DefaultSU3SignersAt() error = %v, want ErrDefaultSigners", err)
	}
}
