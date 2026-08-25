// Package ivnp implements the binary structures shared by I2P router protocols.
// Parsers are views over caller-owned input and do not allocate.
package ivnp

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"gosuda.org/ivnp/internal/wire"
)

const (
	HashLength         = 32
	IdentityBaseLength = 384
	CertificateHeader  = 3
)

var (
	ErrInvalidCertificate = errors.New("i2p: invalid certificate")
	ErrUnknownKeyType     = errors.New("i2p: unsupported key type")
	ErrInvalidIdentity    = errors.New("i2p: invalid identity")
	ErrInvalidMapping     = errors.New("i2p: invalid mapping")
	ErrUnsortedMapping    = errors.New("i2p: mapping keys are not strictly sorted")
	ErrDestinationSmall   = errors.New("i2p: destination buffer is too small")
)

// Hash is the SHA-256 identity used throughout I2P.
type Hash [HashLength]byte

// Sum returns the I2P hash of src.
func Sum(src []byte) Hash { return sha256.Sum256(src) }

// CertificateType identifies the payload in a Certificate.
type CertificateType uint8

const (
	CertificateNull     CertificateType = 0
	CertificateHashCash CertificateType = 1
	CertificateHidden   CertificateType = 2
	CertificateSigned   CertificateType = 3
	CertificateMultiple CertificateType = 4
	CertificateKey      CertificateType = 5
)

// Certificate is a zero-copy view of a wire certificate.
type Certificate struct {
	Type    CertificateType
	Payload []byte
}

func (c Certificate) EncodedLen() int { return CertificateHeader + len(c.Payload) }

// MarshalTo writes c in canonical Certificate form without allocating.
func (c Certificate) MarshalTo(dst []byte) (int, error) {
	if !validCertificate(c.Type, len(c.Payload)) {
		return 0, ErrInvalidCertificate
	}
	if len(dst) < c.EncodedLen() {
		return 0, ErrDestinationSmall
	}
	dst[0] = byte(c.Type)
	binary.BigEndian.PutUint16(dst[1:3], uint16(len(c.Payload)))
	copy(dst[3:], c.Payload)
	return c.EncodedLen(), nil
}

// ParseCertificate parses exactly one certificate from src. Payload aliases
// src; it is not safe to modify either while the Certificate is in use.
func ParseCertificate(src []byte) (Certificate, int, error) {
	if len(src) < CertificateHeader {
		return Certificate{}, 0, wire.ErrShortBuffer
	}
	kind := CertificateType(src[0])
	length := int(binary.BigEndian.Uint16(src[1:3]))
	if length > len(src)-CertificateHeader {
		return Certificate{}, 0, wire.ErrShortBuffer
	}
	if !validCertificate(kind, length) {
		return Certificate{}, 0, ErrInvalidCertificate
	}
	return Certificate{Type: kind, Payload: src[CertificateHeader : CertificateHeader+length]}, CertificateHeader + length, nil
}

func validCertificate(kind CertificateType, payloadLen int) bool {
	if payloadLen < 0 || payloadLen > 0xffff {
		return false
	}
	switch kind {
	case CertificateNull, CertificateHidden:
		return payloadLen == 0
	case CertificateHashCash, CertificateMultiple:
		return true
	case CertificateSigned:
		return payloadLen == 40 || payloadLen == 72
	case CertificateKey:
		return payloadLen >= 4
	default:
		return false
	}
}

// SigningKeyType identifies the signature and signing-public-key encoding.
type SigningKeyType uint16

const (
	SigningDSASHA1              SigningKeyType = 0
	SigningECDSASHA256P256      SigningKeyType = 1
	SigningECDSASHA384P384      SigningKeyType = 2
	SigningECDSASHA512P521      SigningKeyType = 3
	SigningRSASHA256_2048       SigningKeyType = 4
	SigningRSASHA384_3072       SigningKeyType = 5
	SigningRSASHA512_4096       SigningKeyType = 6
	SigningEdDSASHA512Ed25519   SigningKeyType = 7
	SigningEdDSASHA512Ed25519ph SigningKeyType = 8
	SigningGOSTR3410_256        SigningKeyType = 9
	SigningGOSTR3410_512        SigningKeyType = 10
	SigningRedDSASHA512Ed25519  SigningKeyType = 11
)

// PublicKeyLen returns the wire length of the signing public key.
func (t SigningKeyType) PublicKeyLen() (int, bool) {
	switch t {
	case SigningDSASHA1:
		return 128, true
	case SigningECDSASHA256P256:
		return 64, true
	case SigningECDSASHA384P384:
		return 96, true
	case SigningECDSASHA512P521:
		return 132, true
	case SigningRSASHA256_2048:
		return 256, true
	case SigningRSASHA384_3072:
		return 384, true
	case SigningRSASHA512_4096:
		return 512, true
	case SigningEdDSASHA512Ed25519, SigningEdDSASHA512Ed25519ph, SigningRedDSASHA512Ed25519:
		return 32, true
	case SigningGOSTR3410_256:
		return 64, true
	case SigningGOSTR3410_512:
		return 128, true
	default:
		return 0, false
	}
}

// SignatureLen returns the fixed signature length for t.
func (t SigningKeyType) SignatureLen() (int, bool) {
	switch t {
	case SigningDSASHA1:
		return 40, true
	case SigningECDSASHA256P256:
		return 64, true
	case SigningECDSASHA384P384:
		return 96, true
	case SigningECDSASHA512P521:
		return 132, true
	case SigningRSASHA256_2048:
		return 256, true
	case SigningRSASHA384_3072:
		return 384, true
	case SigningRSASHA512_4096:
		return 512, true
	case SigningEdDSASHA512Ed25519, SigningEdDSASHA512Ed25519ph, SigningRedDSASHA512Ed25519:
		return 64, true
	case SigningGOSTR3410_256:
		return 64, true
	case SigningGOSTR3410_512:
		return 128, true
	default:
		return 0, false
	}
}

// CryptoKeyType identifies the encryption public-key encoding.
type CryptoKeyType uint16

const (
	CryptoElGamal         CryptoKeyType = 0
	CryptoP256            CryptoKeyType = 1
	CryptoP384            CryptoKeyType = 2
	CryptoP521            CryptoKeyType = 3
	CryptoX25519          CryptoKeyType = 4
	CryptoMLKEM768X25519  CryptoKeyType = 6
	CryptoMLKEM1024X25519 CryptoKeyType = 7
)

// PublicKeyLen returns the wire length of the encryption public key.
func (t CryptoKeyType) PublicKeyLen() (int, bool) {
	switch t {
	case CryptoElGamal:
		return 256, true
	case CryptoP256:
		return 64, true
	case CryptoP384:
		return 96, true
	case CryptoP521:
		return 132, true
	case CryptoX25519, CryptoMLKEM768X25519, CryptoMLKEM1024X25519:
		return 32, true
	default:
		return 0, false
	}
}

// Identity is a zero-copy parsed RouterIdentity or Destination. The full wire
// representation remains available because all identity hashes include padding
// and certificate data.
type Identity struct {
	raw          []byte
	certificate  Certificate
	signingType  SigningKeyType
	cryptoType   CryptoKeyType
	cryptoFirst  []byte
	cryptoRest   []byte
	signingFirst []byte
	signingRest  []byte
}

// ParseIdentity parses a KeysAndCert structure. It validates key-certificate
// lengths and returns key material as slices into src.
func ParseIdentity(src []byte) (Identity, int, error) {
	if len(src) < IdentityBaseLength+CertificateHeader {
		return Identity{}, 0, wire.ErrShortBuffer
	}
	cert, certLen, err := ParseCertificate(src[IdentityBaseLength:])
	if err != nil {
		return Identity{}, 0, err
	}
	total := IdentityBaseLength + certLen
	id := Identity{raw: src[:total], certificate: cert, signingType: SigningDSASHA1, cryptoType: CryptoElGamal}
	if cert.Type != CertificateKey {
		id.cryptoFirst = src[:256]
		id.signingFirst = src[256:384]
		return id, total, nil
	}

	id.signingType = SigningKeyType(binary.BigEndian.Uint16(cert.Payload[:2]))
	id.cryptoType = CryptoKeyType(binary.BigEndian.Uint16(cert.Payload[2:4]))
	signingLen, ok := id.signingType.PublicKeyLen()
	if !ok {
		return Identity{}, 0, fmt.Errorf("%w: signing type %d", ErrUnknownKeyType, id.signingType)
	}
	cryptoLen, ok := id.cryptoType.PublicKeyLen()
	if !ok {
		return Identity{}, 0, fmt.Errorf("%w: crypto type %d", ErrUnknownKeyType, id.cryptoType)
	}
	signingExcess := max(signingLen-128, 0)
	cryptoExcess := max(cryptoLen-256, 0)
	if len(cert.Payload) != 4+signingExcess+cryptoExcess {
		return Identity{}, 0, ErrInvalidIdentity
	}
	cryptoInline := min(cryptoLen, 256)
	signingInline := min(signingLen, 128)
	id.cryptoFirst = src[:cryptoInline]
	id.signingFirst = src[IdentityBaseLength-signingInline : IdentityBaseLength]
	off := 4
	id.signingRest = cert.Payload[off : off+signingExcess]
	off += signingExcess
	id.cryptoRest = cert.Payload[off : off+cryptoExcess]
	return id, total, nil
}

func (i Identity) EncodedLen() int                { return len(i.raw) }
func (i Identity) Bytes() []byte                  { return i.raw }
func (i Identity) Certificate() Certificate       { return i.certificate }
func (i Identity) SigningKeyType() SigningKeyType { return i.signingType }
func (i Identity) CryptoKeyType() CryptoKeyType   { return i.cryptoType }

// CryptoKeyParts returns the inline key data followed by certificate overflow.
// They must be concatenated only for algorithms with a key exceeding 256 bytes.
func (i Identity) CryptoKeyParts() ([]byte, []byte) { return i.cryptoFirst, i.cryptoRest }

// SigningKeyParts returns the inline key data followed by certificate overflow.
func (i Identity) SigningKeyParts() ([]byte, []byte) { return i.signingFirst, i.signingRest }

// Hash returns SHA-256 over the complete encoded identity.
func (i Identity) Hash() Hash { return Sum(i.raw) }

// MarshalTo copies the verified encoded identity into dst.
func (i Identity) MarshalTo(dst []byte) (int, error) {
	if len(dst) < len(i.raw) {
		return 0, ErrDestinationSmall
	}
	copy(dst, i.raw)
	return len(i.raw), nil
}

// Mapping is a zero-copy mapping including its two-byte length prefix.
type Mapping struct{ raw []byte }

// ParseMapping parses a mapping and validates every wire delimiter and length.
func ParseMapping(src []byte) (Mapping, int, error) {
	if len(src) < 2 {
		return Mapping{}, 0, wire.ErrShortBuffer
	}
	size := int(binary.BigEndian.Uint16(src[:2]))
	if size > len(src)-2 {
		return Mapping{}, 0, wire.ErrShortBuffer
	}
	m := Mapping{raw: src[:2+size]}
	it := m.Iterator()
	for {
		_, _, ok, err := it.Next()
		if err != nil {
			return Mapping{}, 0, err
		}
		if !ok {
			break
		}
	}
	return m, len(m.raw), nil
}

func (m Mapping) EncodedLen() int { return len(m.raw) }
func (m Mapping) Bytes() []byte   { return m.raw }

// MappingIterator walks mapping entries without creating a map or copying keys.
type MappingIterator struct{ rest []byte }

func (m Mapping) Iterator() MappingIterator {
	if len(m.raw) < 2 {
		return MappingIterator{}
	}
	return MappingIterator{rest: m.raw[2:]}
}

// Next returns one key/value pair. A false ok with nil error marks exhaustion.
func (it *MappingIterator) Next() (key, value []byte, ok bool, err error) {
	if len(it.rest) == 0 {
		return nil, nil, false, nil
	}
	keyLen := int(it.rest[0])
	if keyLen > len(it.rest)-1 {
		return nil, nil, false, ErrInvalidMapping
	}
	key = it.rest[1 : 1+keyLen]
	rest := it.rest[1+keyLen:]
	if len(rest) < 2 || rest[0] != '=' {
		return nil, nil, false, ErrInvalidMapping
	}
	valueLen := int(rest[1])
	rest = rest[2:]
	if valueLen > len(rest)-1 || rest[valueLen] != ';' {
		return nil, nil, false, ErrInvalidMapping
	}
	value = rest[:valueLen]
	it.rest = rest[valueLen+1:]
	return key, value, true, nil
}

// ValidateCanonical requires strictly ascending, unique bytewise keys.
func (m Mapping) ValidateCanonical() error {
	it := m.Iterator()
	var previous []byte
	for {
		key, _, ok, err := it.Next()
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if previous != nil && bytes.Compare(previous, key) >= 0 {
			return ErrUnsortedMapping
		}
		previous = key
	}
}

// MappingEntry is a caller-owned, already-sorted mapping entry.
type MappingEntry struct {
	Key   []byte
	Value []byte
}

// MappingEncodedLen validates entries and returns their encoded byte count.
func MappingEncodedLen(entries []MappingEntry) (int, error) {
	n := 2
	var previous []byte
	for _, entry := range entries {
		if len(entry.Key) > 255 || len(entry.Value) > 255 {
			return 0, ErrInvalidMapping
		}
		if previous != nil && bytes.Compare(previous, entry.Key) >= 0 {
			return 0, ErrUnsortedMapping
		}
		previous = entry.Key
		entryLen := len(entry.Key) + len(entry.Value) + 4
		if entryLen > 0xffff-(n-2) {
			return 0, ErrInvalidMapping
		}
		n += entryLen
	}
	return n, nil
}

// MarshalMappingTo writes sorted entries without allocating.
func MarshalMappingTo(dst []byte, entries []MappingEntry) (int, error) {
	n, err := MappingEncodedLen(entries)
	if err != nil {
		return 0, err
	}
	if len(dst) < n {
		return 0, ErrDestinationSmall
	}
	binary.BigEndian.PutUint16(dst[:2], uint16(n-2))
	off := 2
	for _, entry := range entries {
		dst[off] = byte(len(entry.Key))
		off++
		off += copy(dst[off:], entry.Key)
		dst[off] = '='
		off++
		dst[off] = byte(len(entry.Value))
		off++
		off += copy(dst[off:], entry.Value)
		dst[off] = ';'
		off++
	}
	return off, nil
}
