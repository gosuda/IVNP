package ivnp

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
	"sync"

	"gosuda.org/ivnp/crypto/gost"
	"gosuda.org/ivnp/internal/pool"
)

var ErrUnsupportedSignature = errors.New("i2p: signature type is not supported by the configured crypto backend")

// VerifySignature verifies I2P's fixed-width wire signatures. first and rest
// are the public-key slices returned by Identity.SigningKeyParts; rest exists
// for key types whose public key overflows the fixed 128-byte identity field.
func VerifySignature(kind SigningKeyType, first, rest, message, signature []byte) (bool, error) {
	keyLen, ok := kind.PublicKeyLen()
	if !ok || len(first)+len(rest) != keyLen {
		return false, ErrInvalidIdentity
	}
	signatureLen, ok := kind.SignatureLen()
	if !ok || len(signature) != signatureLen {
		return false, ErrMalformedSignature
	}

	switch kind {
	case SigningDSASHA1:
		return verifyDSA(first, message, signature)
	case SigningECDSASHA256P256:
		return verifyECDSA(elliptic.P256(), crypto.SHA256, first, rest, message, signature)
	case SigningECDSASHA384P384:
		return verifyECDSA(elliptic.P384(), crypto.SHA384, first, rest, message, signature)
	case SigningECDSASHA512P521:
		return verifyECDSA(elliptic.P521(), crypto.SHA512, first, rest, message, signature)
	case SigningRSASHA256_2048:
		return verifyRSA(crypto.SHA256, first, rest, message, signature)
	case SigningRSASHA384_3072:
		return verifyRSA(crypto.SHA384, first, rest, message, signature)
	case SigningRSASHA512_4096:
		return verifyRSA(crypto.SHA512, first, rest, message, signature)
	case SigningEdDSASHA512Ed25519:
		return ed25519.Verify(ed25519.PublicKey(first), message, signature), nil
	case SigningEdDSASHA512Ed25519ph:
		digest := sha512.Sum512(message)
		err := ed25519.VerifyWithOptions(ed25519.PublicKey(first), digest[:], signature, &ed25519.Options{Hash: crypto.SHA512})
		return err == nil, nil
	case SigningRedDSASHA512Ed25519:
		// I2P RedDSA changes private-key and nonce generation. Its Java
		// reference implementation inherits EdDSA verification unchanged.
		return ed25519.Verify(ed25519.PublicKey(first), message, signature), nil
	case SigningGOSTR3410_256:
		return gost.Verify256(first, message, signature[:32], signature[32:]), nil
	case SigningGOSTR3410_512:
		return gost.Verify512(first, message, signature[:64], signature[64:]), nil
	default:
		return false, ErrUnsupportedSignature
	}
}

// VerifySignaturePrefixed verifies a signature over prefix || message. It
// uses a bounded slab so LeaseSet2 verification does not create a transient
// heap object proportional to an attacker-controlled netdb payload.
func VerifySignaturePrefixed(prefix byte, kind SigningKeyType, first, rest, message, signature []byte) (bool, error) {
	joined, ok := pool.Acquire(len(message) + 1)
	if !ok {
		return false, ErrMalformedSignature
	}
	joined[0] = prefix
	copy(joined[1:], message)
	valid, err := VerifySignature(kind, first, rest, joined, signature)
	pool.Release(joined)
	return valid, err
}

// Verify verifies a signature using this identity's advertised signing key.
func (i Identity) Verify(message, signature []byte) (bool, error) {
	first, rest := i.SigningKeyParts()
	return VerifySignature(i.SigningKeyType(), first, rest, message, signature)
}

var ErrMalformedSignature = errors.New("i2p: malformed signature")

func verifyECDSA(curve elliptic.Curve, hash crypto.Hash, first, rest, message, signature []byte) (bool, error) {
	keyLen := len(first) + len(rest)
	var encoded [132]byte
	copy(encoded[:], first)
	copy(encoded[len(first):], rest)
	coordinateLen := keyLen / 2
	x := new(big.Int).SetBytes(encoded[:coordinateLen])
	y := new(big.Int).SetBytes(encoded[coordinateLen:keyLen])
	if !curve.IsOnCurve(x, y) {
		return false, nil
	}
	digest, err := hashMessage(hash, message)
	if err != nil {
		return false, err
	}
	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])
	return ecdsa.Verify(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}, digest, r, s), nil
}

func verifyRSA(hash crypto.Hash, first, rest, message, signature []byte) (bool, error) {
	var encoded [512]byte
	copy(encoded[:], first)
	copy(encoded[len(first):], rest)
	publicKey := rsa.PublicKey{N: new(big.Int).SetBytes(encoded[:len(first)+len(rest)]), E: 65537}
	digest, err := hashMessage(hash, message)
	if err != nil {
		return false, err
	}
	return rsa.VerifyPKCS1v15(&publicKey, hash, digest, signature) == nil, nil
}

func hashMessage(hash crypto.Hash, message []byte) ([]byte, error) {
	switch hash {
	case crypto.SHA256:
		digest := sha256.Sum256(message)
		return digest[:], nil
	case crypto.SHA384:
		digest := sha512.Sum384(message)
		return digest[:], nil
	case crypto.SHA512:
		digest := sha512.Sum512(message)
		return digest[:], nil
	default:
		return nil, ErrUnsupportedSignature
	}
}

var dsaParameters struct {
	once   sync.Once
	params dsa.Parameters
	err    error
}

func verifyDSA(publicKey, message, signature []byte) (bool, error) {
	if len(publicKey) != 128 || len(signature) != 40 {
		return false, nil
	}
	dsaParameters.once.Do(initDSAParameters)
	if dsaParameters.err != nil {
		return false, dsaParameters.err
	}
	digest := sha1.Sum(message)
	public := dsa.PublicKey{Parameters: dsaParameters.params, Y: new(big.Int).SetBytes(publicKey)}
	r := new(big.Int).SetBytes(signature[:20])
	s := new(big.Int).SetBytes(signature[20:])
	return dsa.Verify(&public, digest[:], r, s), nil
}

func initDSAParameters() {
	dsaParameters.params.P, dsaParameters.err = hexInt("9c05b2aa960d9b97b8931963c9cc9e8c3026e9b8ed92fad0a69cc886d5bf8015fcadae31a0ad18fab3f01b00a358de237655c4964afaa2b337e96ad316b9fb1cc564b5aec5b69a9ff6c3e4548707fef8503d91dd8602e867e6d35d2235c1869ce2479c3b9d5401de04e0727fb33d6511285d4cf29538d9e3b6051f5b22cc1c93")
	if dsaParameters.err != nil {
		return
	}
	dsaParameters.params.Q, dsaParameters.err = hexInt("a5dfc28fef4ca1e286744cd8eed9d29d684046b7")
	if dsaParameters.err != nil {
		return
	}
	dsaParameters.params.G, dsaParameters.err = hexInt("0c1f4d27d40093b429e962d7223824e0bbc47e7c832a39236fc683af84889581075ff9082ed32353d4374d7301cda1d23c431f4698599dda02451824ff369752593647cc3ddc197de985e43d136cdcfc6bd5409cd2f450821142a5e6f8eb1c3ab5d0484b8129fcf17bce4f7f33321c3cb3dbb14a905e7b2b3e93be4708cbcc82")
}

func hexInt(encoded string) (*big.Int, error) {
	value, ok := new(big.Int).SetString(encoded, 16)
	if !ok {
		return nil, errors.New("i2p: malformed static DSA parameter")
	}
	return value, nil
}
