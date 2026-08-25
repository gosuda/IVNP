// Package ivnp provides the stable public facade for IVNP's embedded router,
// client services, and I2P protocol primitives.
package ivnp

import (
	"crypto/ed25519"
	"gosuda.org/ivnp/foundation"
	"time"
)

const (
	HashLength         = foundation.HashLength
	IdentityBaseLength = foundation.IdentityBaseLength
	CertificateHeader  = foundation.CertificateHeader

	CertificateNull     = foundation.CertificateNull
	CertificateHashCash = foundation.CertificateHashCash
	CertificateHidden   = foundation.CertificateHidden
	CertificateSigned   = foundation.CertificateSigned
	CertificateMultiple = foundation.CertificateMultiple
	CertificateKey      = foundation.CertificateKey

	SigningDSASHA1              = foundation.SigningDSASHA1
	SigningECDSASHA256P256      = foundation.SigningECDSASHA256P256
	SigningECDSASHA384P384      = foundation.SigningECDSASHA384P384
	SigningECDSASHA512P521      = foundation.SigningECDSASHA512P521
	SigningRSASHA256_2048       = foundation.SigningRSASHA256_2048
	SigningRSASHA384_3072       = foundation.SigningRSASHA384_3072
	SigningRSASHA512_4096       = foundation.SigningRSASHA512_4096
	SigningEdDSASHA512Ed25519   = foundation.SigningEdDSASHA512Ed25519
	SigningEdDSASHA512Ed25519ph = foundation.SigningEdDSASHA512Ed25519ph
	SigningGOSTR3410_256        = foundation.SigningGOSTR3410_256
	SigningGOSTR3410_512        = foundation.SigningGOSTR3410_512
	SigningRedDSASHA512Ed25519  = foundation.SigningRedDSASHA512Ed25519

	CryptoElGamal         = foundation.CryptoElGamal
	CryptoP256            = foundation.CryptoP256
	CryptoP384            = foundation.CryptoP384
	CryptoP521            = foundation.CryptoP521
	CryptoX25519          = foundation.CryptoX25519
	CryptoMLKEM768X25519  = foundation.CryptoMLKEM768X25519
	CryptoMLKEM1024X25519 = foundation.CryptoMLKEM1024X25519
)

var (
	ErrInvalidCertificate   = foundation.ErrInvalidCertificate
	ErrUnknownKeyType       = foundation.ErrUnknownKeyType
	ErrInvalidIdentity      = foundation.ErrInvalidIdentity
	ErrInvalidMapping       = foundation.ErrInvalidMapping
	ErrUnsortedMapping      = foundation.ErrUnsortedMapping
	ErrDestinationSmall     = foundation.ErrDestinationSmall
	ErrUnsupportedSignature = foundation.ErrUnsupportedSignature
	ErrMalformedSignature   = foundation.ErrMalformedSignature
	ErrEncryptedSigningKey  = foundation.ErrEncryptedSigningKey
)

type (
	Hash               = foundation.Hash
	CertificateType    = foundation.CertificateType
	Certificate        = foundation.Certificate
	SigningKeyType     = foundation.SigningKeyType
	CryptoKeyType      = foundation.CryptoKeyType
	Identity           = foundation.Identity
	Mapping            = foundation.Mapping
	MappingIterator    = foundation.MappingIterator
	MappingEntry       = foundation.MappingEntry
	LocalDestination   = foundation.LocalDestination
	LocalAddress       = foundation.LocalAddress
	LocalIdentityOwner = foundation.LocalIdentityOwner
	LocalRouterAddress = foundation.LocalRouterAddress
)

func Sum(src []byte) Hash { return foundation.Sum(src) }

func ParseCertificate(src []byte) (Certificate, int, error) { return foundation.ParseCertificate(src) }

func ParseIdentity(src []byte) (Identity, int, error) { return foundation.ParseIdentity(src) }

func ParseMapping(src []byte) (Mapping, int, error) { return foundation.ParseMapping(src) }

func MappingEncodedLen(entries []MappingEntry) (int, error) {
	return foundation.MappingEncodedLen(entries)
}

func MarshalMappingTo(dst []byte, entries []MappingEntry) (int, error) {
	return foundation.MarshalMappingTo(dst, entries)
}

func VerifySignature(kind SigningKeyType, first, rest, message, signature []byte) (bool, error) {
	return foundation.VerifySignature(kind, first, rest, message, signature)
}

func VerifySignaturePrefixed(prefix byte, kind SigningKeyType, first, rest, message, signature []byte) (bool, error) {
	return foundation.VerifySignaturePrefixed(prefix, kind, first, rest, message, signature)
}

func GenerateRed25519Key() (public, private [32]byte, err error) {
	return foundation.GenerateRed25519Key()
}

func Red25519Sign(private [32]byte, message []byte) ([]byte, error) {
	return foundation.Red25519Sign(private, message)
}

func EncryptedLeaseSetAlpha(signingType SigningKeyType, public []byte, date time.Time, secret []byte) ([32]byte, error) {
	return foundation.EncryptedLeaseSetAlpha(signingType, public, date, secret)
}

func BlindEncryptedLeaseSetPublic(signingType SigningKeyType, public []byte, date time.Time, secret []byte) ([32]byte, error) {
	return foundation.BlindEncryptedLeaseSetPublic(signingType, public, date, secret)
}

func BlindEncryptedLeaseSetPrivate(signingType SigningKeyType, private, public []byte, date time.Time, secret []byte) ([32]byte, error) {
	return foundation.BlindEncryptedLeaseSetPrivate(signingType, private, public, date, secret)
}

func EncryptedLeaseSetSubcredential(signingType SigningKeyType, public, blinded []byte) ([32]byte, error) {
	return foundation.EncryptedLeaseSetSubcredential(signingType, public, blinded)
}

func GenerateLocalDestination() (*LocalDestination, error) {
	return foundation.GenerateLocalDestination()
}

func GenerateLegacyLocalDestination() (*LocalDestination, error) {
	return foundation.GenerateLegacyLocalDestination()
}

func GenerateEncryptedLocalDestination() (*LocalDestination, error) {
	return foundation.GenerateEncryptedLocalDestination()
}

func ImportLocalDestination(src []byte) (*LocalDestination, error) {
	return foundation.ImportLocalDestination(src)
}

func B32(hash Hash) string { return foundation.B32(hash) }

func EncodeI2PBase64(raw []byte) string { return foundation.EncodeI2PBase64(raw) }

func DecodeI2PBase64(encoded []byte) ([]byte, error) { return foundation.DecodeI2PBase64(encoded) }

func ParseDestination(encoded []byte) (Identity, error) { return foundation.ParseDestination(encoded) }

func GenerateAddress() (destination []byte, hash Hash, public ed25519.PublicKey, private ed25519.PrivateKey, err error) {
	return foundation.GenerateAddress()
}

func GenerateLocalAddress() (LocalAddress, error) { return foundation.GenerateLocalAddress() }

func GenerateLocalRouterAddress() (LocalRouterAddress, error) {
	return foundation.GenerateLocalRouterAddress()
}
