package ivnp

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

func TestVerifyEd25519AndPrehash(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("router info")
	signature := ed25519.Sign(private, message)
	if valid, err := VerifySignature(SigningEdDSASHA512Ed25519, public, nil, message, signature); err != nil || !valid {
		t.Fatalf("Ed25519 verification = %t, %v", valid, err)
	}
	if valid, err := VerifySignature(SigningRedDSASHA512Ed25519, public, nil, message, signature); err != nil || !valid {
		t.Fatalf("RedDSA verification = %t, %v", valid, err)
	}
	prefixed := append([]byte{3}, message...)
	prefixedSignature := ed25519.Sign(private, prefixed)
	if valid, err := VerifySignaturePrefixed(3, SigningEdDSASHA512Ed25519, public, nil, message, prefixedSignature); err != nil || !valid {
		t.Fatalf("prefixed Ed25519 verification = %t, %v", valid, err)
	}
	digest := sha512.Sum512(message)
	prehashSignature, err := private.Sign(rand.Reader, digest[:], &ed25519.Options{Hash: crypto.SHA512})
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := VerifySignature(SigningEdDSASHA512Ed25519ph, public, nil, message, prehashSignature); err != nil || !valid {
		t.Fatalf("Ed25519ph verification = %t, %v", valid, err)
	}
}

func TestVerifyECDSAWireEncodings(t *testing.T) {
	cases := []struct {
		kind  SigningKeyType
		curve elliptic.Curve
		hash  crypto.Hash
		width int
	}{
		{SigningECDSASHA256P256, elliptic.P256(), crypto.SHA256, 32},
		{SigningECDSASHA384P384, elliptic.P384(), crypto.SHA384, 48},
		{SigningECDSASHA512P521, elliptic.P521(), crypto.SHA512, 66},
	}
	message := []byte("lease set")
	for _, test := range cases {
		t.Run(test.curve.Params().Name, func(t *testing.T) {
			private, err := ecdsa.GenerateKey(test.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			digest := digestForTest(test.hash, message)
			r, s, err := ecdsa.Sign(rand.Reader, private, digest)
			if err != nil {
				t.Fatal(err)
			}
			public := make([]byte, test.width*2)
			private.PublicKey.X.FillBytes(public[:test.width])
			private.PublicKey.Y.FillBytes(public[test.width:])
			signature := make([]byte, test.width*2)
			r.FillBytes(signature[:test.width])
			s.FillBytes(signature[test.width:])
			first, rest := public, []byte(nil)
			if len(public) > 128 {
				first, rest = public[:128], public[128:]
			}
			valid, err := VerifySignature(test.kind, first, rest, message, signature)
			if err != nil || !valid {
				t.Fatalf("verification = %t, %v", valid, err)
			}
		})
	}
}

func TestVerifyRSAAndDSA(t *testing.T) {
	message := []byte("signed router info")
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDigest := sha256.Sum256(message)
	rsaSignature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivate, crypto.SHA256, rsaDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	rsaPublic := rsaPrivate.PublicKey.N.FillBytes(make([]byte, 256))
	if valid, err := VerifySignature(SigningRSASHA256_2048, rsaPublic, nil, message, rsaSignature); err != nil || !valid {
		t.Fatalf("RSA verification = %t, %v", valid, err)
	}

	dsaParameters.once.Do(initDSAParameters)
	dsaPrivate := new(dsa.PrivateKey)
	dsaPrivate.Parameters = dsaParameters.params
	if err := dsa.GenerateKey(dsaPrivate, rand.Reader); err != nil {
		t.Fatal(err)
	}
	dsaDigest := sha1.Sum(message)
	r, s, err := dsa.Sign(rand.Reader, dsaPrivate, dsaDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	dsaPublic := dsaPrivate.Y.FillBytes(make([]byte, 128))
	dsaSignature := make([]byte, 40)
	r.FillBytes(dsaSignature[:20])
	s.FillBytes(dsaSignature[20:])
	if !dsa.Verify(&dsaPrivate.PublicKey, dsaDigest[:], r, s) {
		t.Fatal("standard-library DSA verification failed")
	}
	if valid, err := VerifySignature(SigningDSASHA1, dsaPublic, nil, message, dsaSignature); err != nil || !valid {
		t.Fatalf("DSA verification = %t, %v", valid, err)
	}
}

func TestVerifySignatureRejectsMalformedWireData(t *testing.T) {
	if valid, err := VerifySignature(SigningEdDSASHA512Ed25519, make([]byte, 32), nil, nil, nil); err != ErrMalformedSignature || valid {
		t.Fatalf("signature validation = %t, %v", valid, err)
	}
	if valid, err := VerifySignature(SigningGOSTR3410_256, make([]byte, 64), nil, nil, make([]byte, 64)); err != nil || valid {
		t.Fatalf("invalid GOST signature = %t, %v", valid, err)
	}
}

func digestForTest(hash crypto.Hash, message []byte) []byte {
	switch hash {
	case crypto.SHA256:
		digest := sha256.Sum256(message)
		return digest[:]
	case crypto.SHA384:
		digest := sha512.Sum384(message)
		return digest[:]
	case crypto.SHA512:
		digest := sha512.Sum512(message)
		return digest[:]
	default:
		panic("unsupported hash")
	}
}
