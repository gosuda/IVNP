package foundation

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/hkdf"
)

var ErrEncryptedSigningKey = errors.New("i2p: invalid encrypted LeaseSet signing key")

// GenerateRed25519Key generates a random Red25519 scalar and its corresponding public point.
func GenerateRed25519Key() (public, private [32]byte, err error) {
	var uniform [64]byte
	if _, err = io.ReadFull(rand.Reader, uniform[:]); err != nil {
		return public, private, err
	}
	scalar, err := new(edwards25519.Scalar).SetUniformBytes(uniform[:])
	clear(uniform[:])
	if err != nil {
		return public, private, err
	}
	copy(private[:], scalar.Bytes())
	copy(public[:], new(edwards25519.Point).ScalarBaseMult(scalar).Bytes())
	return public, private, nil
}

// Red25519Sign computes a RedDSA signature using the randomized nonce scheme specified for encrypted LeaseSets.
func Red25519Sign(private [32]byte, message []byte) ([]byte, error) {
	a, err := new(edwards25519.Scalar).SetCanonicalBytes(private[:])
	if err != nil {
		return nil, ErrEncryptedSigningKey
	}
	public := new(edwards25519.Point).ScalarBaseMult(a).Bytes()
	var random [80]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return nil, err
	}
	rDigest := sha512.New()
	rDigest.Write(random[:])
	rDigest.Write(public)
	rDigest.Write(message)
	var digest [64]byte
	rDigest.Sum(digest[:0])
	clear(random[:])
	r, err := new(edwards25519.Scalar).SetUniformBytes(digest[:])
	clear(digest[:])
	if err != nil {
		return nil, ErrEncryptedSigningKey
	}
	encodedR := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
	kDigest := sha512.New()
	kDigest.Write(encodedR)
	kDigest.Write(public)
	kDigest.Write(message)
	kDigest.Sum(digest[:0])
	k, err := new(edwards25519.Scalar).SetUniformBytes(digest[:])
	clear(digest[:])
	if err != nil {
		return nil, ErrEncryptedSigningKey
	}
	s := new(edwards25519.Scalar).MultiplyAdd(k, a, r)
	signature := make([]byte, 64)
	copy(signature, encodedR)
	copy(signature[32:], s.Bytes())
	return signature, nil
}

func encryptedKeyData(signingType SigningKeyType, public []byte) ([]byte, error) {
	if (signingType != SigningEdDSASHA512Ed25519 && signingType != SigningRedDSASHA512Ed25519) || len(public) != 32 {
		return nil, ErrEncryptedSigningKey
	}
	data := make([]byte, 36)
	copy(data, public)
	binary.BigEndian.PutUint16(data[32:34], uint16(signingType))
	binary.BigEndian.PutUint16(data[34:36], uint16(SigningRedDSASHA512Ed25519))
	return data, nil
}

// EncryptedLeaseSetAlpha computes the blinding scalar (alpha) for the specified date and secret.
func EncryptedLeaseSetAlpha(signingType SigningKeyType, public []byte, date time.Time, secret []byte) ([32]byte, error) {
	var out [32]byte
	keydata, err := encryptedKeyData(signingType, public)
	if err != nil {
		return out, err
	}
	hash := sha256.New()
	hash.Write([]byte("I2PGenerateAlpha"))
	hash.Write(keydata)
	salt := hash.Sum(nil)
	dateString := []byte(date.UTC().Format("20060102"))
	ikm := make([]byte, 0, len(dateString)+len(secret))
	ikm = append(ikm, dateString...)
	ikm = append(ikm, secret...)
	var uniform [64]byte
	if _, err = io.ReadFull(hkdf.New(sha256.New, ikm, salt, []byte("i2pblinding1")), uniform[:]); err != nil {
		return out, err
	}
	clear(keydata)
	clear(salt)
	clear(ikm)
	scalar, err := new(edwards25519.Scalar).SetUniformBytes(uniform[:])
	clear(uniform[:])
	if err != nil {
		return out, ErrEncryptedSigningKey
	}
	copy(out[:], scalar.Bytes())
	return out, nil
}

// BlindEncryptedLeaseSetPublic derives the daily blinded public key from a destination signing public key.
func BlindEncryptedLeaseSetPublic(signingType SigningKeyType, public []byte, date time.Time, secret []byte) ([32]byte, error) {
	var blinded [32]byte
	alphaBytes, err := EncryptedLeaseSetAlpha(signingType, public, date, secret)
	if err != nil {
		return blinded, err
	}
	alpha, err := new(edwards25519.Scalar).SetCanonicalBytes(alphaBytes[:])
	clear(alphaBytes[:])
	if err != nil {
		return blinded, ErrEncryptedSigningKey
	}
	point, err := new(edwards25519.Point).SetBytes(public)
	if err != nil {
		return blinded, ErrEncryptedSigningKey
	}
	point.Add(point, new(edwards25519.Point).ScalarBaseMult(alpha))
	copy(blinded[:], point.Bytes())
	return blinded, nil
}

// BlindEncryptedLeaseSetPrivate derives the daily blinded private scalar for signing encrypted LeaseSets.
func BlindEncryptedLeaseSetPrivate(signingType SigningKeyType, private []byte, public []byte, date time.Time, secret []byte) ([32]byte, error) {
	var blinded [32]byte
	alphaBytes, err := EncryptedLeaseSetAlpha(signingType, public, date, secret)
	if err != nil {
		return blinded, err
	}
	alpha, err := new(edwards25519.Scalar).SetCanonicalBytes(alphaBytes[:])
	clear(alphaBytes[:])
	if err != nil {
		return blinded, ErrEncryptedSigningKey
	}
	var a *edwards25519.Scalar
	switch signingType {
	case SigningEdDSASHA512Ed25519:
		if len(private) != 64 && len(private) != 32 {
			return blinded, ErrEncryptedSigningKey
		}
		seed := private[:32]
		digest := sha512.Sum512(seed)
		digest[0] &= 248
		digest[31] &= 63
		digest[31] |= 64
		a, err = new(edwards25519.Scalar).SetUniformBytes(digest[:])
		clear(digest[:])
	case SigningRedDSASHA512Ed25519:
		if len(private) != 32 {
			return blinded, ErrEncryptedSigningKey
		}
		a, err = new(edwards25519.Scalar).SetCanonicalBytes(private)
	default:
		return blinded, ErrEncryptedSigningKey
	}
	if err != nil {
		return blinded, ErrEncryptedSigningKey
	}
	a.Add(a, alpha)
	copy(blinded[:], a.Bytes())
	return blinded, nil
}

// EncryptedLeaseSetSubcredential derives the subcredential binding the unblinded signing key to the blinded key.
func EncryptedLeaseSetSubcredential(signingType SigningKeyType, public []byte, blinded []byte) ([32]byte, error) {
	var subcredential [32]byte
	keydata, err := encryptedKeyData(signingType, public)
	if err != nil || len(blinded) != 32 {
		return subcredential, ErrEncryptedSigningKey
	}
	credentialHash := sha256.New()
	credentialHash.Write([]byte("credential"))
	credentialHash.Write(keydata)
	credential := credentialHash.Sum(nil)
	subHash := sha256.New()
	subHash.Write([]byte("subcredential"))
	subHash.Write(credential)
	subHash.Write(blinded)
	copy(subcredential[:], subHash.Sum(nil))
	clear(keydata)
	clear(credential)
	return subcredential, nil
}
