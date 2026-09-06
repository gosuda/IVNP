package foundation

import (
	"crypto/ed25519"
	"time"

	"gosuda.org/ivnp/foundation/internal/identity"
)

type (
	Certificate        = identity.Certificate
	CertificateType    = identity.CertificateType
	CryptoKeyType      = identity.CryptoKeyType
	Hash               = identity.Hash
	Identity           = identity.Identity
	LocalAddress       = identity.LocalAddress
	LocalDestination   = identity.LocalDestination
	LocalIdentityOwner = identity.LocalIdentityOwner
	LocalRouterAddress = identity.LocalRouterAddress
	Mapping            = identity.Mapping
	MappingEntry       = identity.MappingEntry
	MappingIterator    = identity.MappingIterator
	OfflineSignature   = identity.OfflineSignature
	SigningKeyType     = identity.SigningKeyType
)

const (
	CertificateHashCash         = identity.CertificateHashCash
	CertificateHeader           = identity.CertificateHeader
	CertificateHidden           = identity.CertificateHidden
	CertificateKey              = identity.CertificateKey
	CertificateMultiple         = identity.CertificateMultiple
	CertificateNull             = identity.CertificateNull
	CertificateSigned           = identity.CertificateSigned
	CryptoElGamal               = identity.CryptoElGamal
	CryptoMLKEM1024X25519       = identity.CryptoMLKEM1024X25519
	CryptoMLKEM768X25519        = identity.CryptoMLKEM768X25519
	CryptoP256                  = identity.CryptoP256
	CryptoP384                  = identity.CryptoP384
	CryptoP521                  = identity.CryptoP521
	CryptoX25519                = identity.CryptoX25519
	HashLength                  = identity.HashLength
	IdentityBaseLength          = identity.IdentityBaseLength
	SigningDSASHA1              = identity.SigningDSASHA1
	SigningECDSASHA256P256      = identity.SigningECDSASHA256P256
	SigningECDSASHA384P384      = identity.SigningECDSASHA384P384
	SigningECDSASHA512P521      = identity.SigningECDSASHA512P521
	SigningEdDSASHA512Ed25519   = identity.SigningEdDSASHA512Ed25519
	SigningEdDSASHA512Ed25519ph = identity.SigningEdDSASHA512Ed25519ph
	SigningGOSTR3410_256        = identity.SigningGOSTR3410_256
	SigningGOSTR3410_512        = identity.SigningGOSTR3410_512
	SigningRSASHA256_2048       = identity.SigningRSASHA256_2048
	SigningRSASHA384_3072       = identity.SigningRSASHA384_3072
	SigningRSASHA512_4096       = identity.SigningRSASHA512_4096
	SigningRedDSASHA512Ed25519  = identity.SigningRedDSASHA512Ed25519
)

var (
	ErrDestinationSmall        = identity.ErrDestinationSmall
	ErrEncryptedSigningKey     = identity.ErrEncryptedSigningKey
	ErrInvalidCertificate      = identity.ErrInvalidCertificate
	ErrInvalidIdentity         = identity.ErrInvalidIdentity
	ErrInvalidMapping          = identity.ErrInvalidMapping
	ErrMalformedSignature      = identity.ErrMalformedSignature
	ErrOfflineSignatureExpired = identity.ErrOfflineSignatureExpired
	ErrUnknownKeyType          = identity.ErrUnknownKeyType
	ErrUnsortedMapping         = identity.ErrUnsortedMapping
	ErrUnsupportedSignature    = identity.ErrUnsupportedSignature
)

func GenerateLocalDestination() (*LocalDestination, error) {
	return identity.GenerateLocalDestination()
}

func GenerateLegacyLocalDestination() (*LocalDestination, error) {
	return identity.GenerateLegacyLocalDestination()
}

func GenerateEncryptedLocalDestination() (*LocalDestination, error) {
	return identity.GenerateEncryptedLocalDestination()
}

func ImportLocalDestination(src []byte) (*LocalDestination, error) {
	return identity.ImportLocalDestination(src)
}

func ImportLocalDestinationOffline(src []byte, offline OfflineSignature, transientPrivate []byte) (*LocalDestination, error) {
	return identity.ImportLocalDestinationOffline(src, offline, transientPrivate)
}

func B32(hash Hash) string {
	return identity.B32(hash)
}

func EncodeI2PBase64(raw []byte) string {
	return identity.EncodeI2PBase64(raw)
}

func DecodeI2PBase64(encoded []byte) ([]byte, error) {
	return identity.DecodeI2PBase64(encoded)
}

func ParseDestination(encoded []byte) (Identity, error) {
	return identity.ParseDestination(encoded)
}

func GenerateAddress() (destination []byte, hash Hash, public ed25519.PublicKey, private ed25519.PrivateKey, err error) {
	return identity.GenerateAddress()
}

func GenerateLocalAddress() (address LocalAddress, err error) {
	return identity.GenerateLocalAddress()
}

func GenerateLocalRouterAddress() (address LocalRouterAddress, err error) {
	return identity.GenerateLocalRouterAddress()
}

func GenerateRed25519Key() (public, private [32]byte, err error) {
	return identity.GenerateRed25519Key()
}

func Red25519Sign(private [32]byte, message []byte) ([]byte, error) {
	return identity.Red25519Sign(private, message)
}

func EncryptedLeaseSetAlpha(signingType SigningKeyType, public []byte, date time.Time, secret []byte) ([32]byte, error) {
	return identity.EncryptedLeaseSetAlpha(signingType, public, date, secret)
}

func BlindEncryptedLeaseSetPublic(signingType SigningKeyType, public []byte, date time.Time, secret []byte) ([32]byte, error) {
	return identity.BlindEncryptedLeaseSetPublic(signingType, public, date, secret)
}

func BlindEncryptedLeaseSetPrivate(signingType SigningKeyType, private []byte, public []byte, date time.Time, secret []byte) ([32]byte, error) {
	return identity.BlindEncryptedLeaseSetPrivate(signingType, private, public, date, secret)
}

func EncryptedLeaseSetSubcredential(signingType SigningKeyType, public []byte, blinded []byte) ([32]byte, error) {
	return identity.EncryptedLeaseSetSubcredential(signingType, public, blinded)
}

func VerifySignature(kind SigningKeyType, first, rest, message, signature []byte) (bool, error) {
	return identity.VerifySignature(kind, first, rest, message, signature)
}

func VerifySignaturePrefixed(prefix byte, kind SigningKeyType, first, rest, message, signature []byte) (bool, error) {
	return identity.VerifySignaturePrefixed(prefix, kind, first, rest, message, signature)
}

func Sum(src []byte) Hash {
	return identity.Sum(src)
}

func ParseCertificate(src []byte) (Certificate, int, error) {
	return identity.ParseCertificate(src)
}

func ParseIdentity(src []byte) (Identity, int, error) {
	return identity.ParseIdentity(src)
}

func ParseMapping(src []byte) (Mapping, int, error) {
	return identity.ParseMapping(src)
}

func MappingEncodedLen(entries []MappingEntry) (int, error) {
	return identity.MappingEncodedLen(entries)
}

func MarshalMappingTo(dst []byte, entries []MappingEntry) (int, error) {
	return identity.MarshalMappingTo(dst, entries)
}
