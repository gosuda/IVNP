// Package ivnp provides the stable public facade for IVNP's embedded router,
// client services, and I2P protocol primitives.
package ivnp

import (
	"crypto/ed25519"
	i2p "gosuda.org/ivnp/foundation"
	"time"
)

const (
	HashLength         = i2p.HashLength
	IdentityBaseLength = i2p.IdentityBaseLength
	CertificateHeader  = i2p.CertificateHeader

	CertificateNull     = i2p.CertificateNull
	CertificateHashCash = i2p.CertificateHashCash
	CertificateHidden   = i2p.CertificateHidden
	CertificateSigned   = i2p.CertificateSigned
	CertificateMultiple = i2p.CertificateMultiple
	CertificateKey      = i2p.CertificateKey

	SigningDSASHA1              = i2p.SigningDSASHA1
	SigningECDSASHA256P256      = i2p.SigningECDSASHA256P256
	SigningECDSASHA384P384      = i2p.SigningECDSASHA384P384
	SigningECDSASHA512P521      = i2p.SigningECDSASHA512P521
	SigningRSASHA256_2048       = i2p.SigningRSASHA256_2048
	SigningRSASHA384_3072       = i2p.SigningRSASHA384_3072
	SigningRSASHA512_4096       = i2p.SigningRSASHA512_4096
	SigningEdDSASHA512Ed25519   = i2p.SigningEdDSASHA512Ed25519
	SigningEdDSASHA512Ed25519ph = i2p.SigningEdDSASHA512Ed25519ph
	SigningGOSTR3410_256        = i2p.SigningGOSTR3410_256
	SigningGOSTR3410_512        = i2p.SigningGOSTR3410_512
	SigningRedDSASHA512Ed25519  = i2p.SigningRedDSASHA512Ed25519

	CryptoElGamal         = i2p.CryptoElGamal
	CryptoP256            = i2p.CryptoP256
	CryptoP384            = i2p.CryptoP384
	CryptoP521            = i2p.CryptoP521
	CryptoX25519          = i2p.CryptoX25519
	CryptoMLKEM768X25519  = i2p.CryptoMLKEM768X25519
	CryptoMLKEM1024X25519 = i2p.CryptoMLKEM1024X25519
)

var (
	ErrInvalidCertificate   = i2p.ErrInvalidCertificate
	ErrUnknownKeyType       = i2p.ErrUnknownKeyType
	ErrInvalidIdentity      = i2p.ErrInvalidIdentity
	ErrInvalidMapping       = i2p.ErrInvalidMapping
	ErrUnsortedMapping      = i2p.ErrUnsortedMapping
	ErrDestinationSmall     = i2p.ErrDestinationSmall
	ErrUnsupportedSignature = i2p.ErrUnsupportedSignature
	ErrMalformedSignature   = i2p.ErrMalformedSignature
	ErrEncryptedSigningKey  = i2p.ErrEncryptedSigningKey
)

type (
	Hash               = i2p.Hash
	CertificateType    = i2p.CertificateType
	Certificate        = i2p.Certificate
	SigningKeyType     = i2p.SigningKeyType
	CryptoKeyType      = i2p.CryptoKeyType
	Identity           = i2p.Identity
	Mapping            = i2p.Mapping
	MappingIterator    = i2p.MappingIterator
	MappingEntry       = i2p.MappingEntry
	LocalDestination   = i2p.LocalDestination
	LocalAddress       = i2p.LocalAddress
	LocalIdentityOwner = i2p.LocalIdentityOwner
	LocalRouterAddress = i2p.LocalRouterAddress
)

func Sum(src []byte) Hash { return i2p.Sum(src) }

func ParseCertificate(src []byte) (Certificate, int, error) { return i2p.ParseCertificate(src) }

func ParseIdentity(src []byte) (Identity, int, error) { return i2p.ParseIdentity(src) }

func ParseMapping(src []byte) (Mapping, int, error) { return i2p.ParseMapping(src) }

func MappingEncodedLen(entries []MappingEntry) (int, error) { return i2p.MappingEncodedLen(entries) }

func MarshalMappingTo(dst []byte, entries []MappingEntry) (int, error) {
	return i2p.MarshalMappingTo(dst, entries)
}

func VerifySignature(kind SigningKeyType, first, rest, message, signature []byte) (bool, error) {
	return i2p.VerifySignature(kind, first, rest, message, signature)
}

func VerifySignaturePrefixed(prefix byte, kind SigningKeyType, first, rest, message, signature []byte) (bool, error) {
	return i2p.VerifySignaturePrefixed(prefix, kind, first, rest, message, signature)
}

func GenerateRed25519Key() (public, private [32]byte, err error) {
	return i2p.GenerateRed25519Key()
}

func Red25519Sign(private [32]byte, message []byte) ([]byte, error) {
	return i2p.Red25519Sign(private, message)
}

func EncryptedLeaseSetAlpha(signingType SigningKeyType, public []byte, date time.Time, secret []byte) ([32]byte, error) {
	return i2p.EncryptedLeaseSetAlpha(signingType, public, date, secret)
}

func BlindEncryptedLeaseSetPublic(signingType SigningKeyType, public []byte, date time.Time, secret []byte) ([32]byte, error) {
	return i2p.BlindEncryptedLeaseSetPublic(signingType, public, date, secret)
}

func BlindEncryptedLeaseSetPrivate(signingType SigningKeyType, private, public []byte, date time.Time, secret []byte) ([32]byte, error) {
	return i2p.BlindEncryptedLeaseSetPrivate(signingType, private, public, date, secret)
}

func EncryptedLeaseSetSubcredential(signingType SigningKeyType, public, blinded []byte) ([32]byte, error) {
	return i2p.EncryptedLeaseSetSubcredential(signingType, public, blinded)
}

func GenerateLocalDestination() (*LocalDestination, error) { return i2p.GenerateLocalDestination() }

func GenerateLegacyLocalDestination() (*LocalDestination, error) {
	return i2p.GenerateLegacyLocalDestination()
}

func GenerateEncryptedLocalDestination() (*LocalDestination, error) {
	return i2p.GenerateEncryptedLocalDestination()
}

func ImportLocalDestination(src []byte) (*LocalDestination, error) {
	return i2p.ImportLocalDestination(src)
}

func B32(hash Hash) string { return i2p.B32(hash) }

func EncodeI2PBase64(raw []byte) string { return i2p.EncodeI2PBase64(raw) }

func DecodeI2PBase64(encoded []byte) ([]byte, error) { return i2p.DecodeI2PBase64(encoded) }

func ParseDestination(encoded []byte) (Identity, error) { return i2p.ParseDestination(encoded) }

func GenerateAddress() (destination []byte, hash Hash, public ed25519.PublicKey, private ed25519.PrivateKey, err error) {
	return i2p.GenerateAddress()
}

func GenerateLocalAddress() (LocalAddress, error) { return i2p.GenerateLocalAddress() }

func GenerateLocalRouterAddress() (LocalRouterAddress, error) {
	return i2p.GenerateLocalRouterAddress()
}
