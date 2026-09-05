package foundation

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strings"
	"sync"
	"time"

	"filippo.io/edwards25519"
	"gosuda.org/ivnp/cryptography"
)

const i2pBase64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~"

const localDestinationCryptoCapabilities = byte(1<<0 | 1<<1 | 1<<2)

// LocalDestination holds static private/public keys and encryption capabilities for a local I2P destination
// (ECIES-X25519, ML-KEM-768/X25519, ML-KEM-1024/X25519).
type LocalDestination struct {
	mu                 sync.RWMutex
	destination        []byte
	hash               Hash
	signingType        SigningKeyType
	signingPublic      ed25519.PublicKey
	signingPrivate     []byte // Ed25519 expanded private key or Red25519 scalar
	x25519Public       [32]byte
	x25519Private      [32]byte
	identityCryptoType CryptoKeyType
	elgamalPrivate     cryptography.ElGamalPrivateKey
	cryptoCapabilities byte
	offline            *offlineSigning
	released           bool
}

// GenerateLocalDestination generates a new standard ECIES-X25519 destination with Ed25519 signing keys.
func GenerateLocalDestination() (*LocalDestination, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return generateLocalDestination(SigningEdDSASHA512Ed25519, public, private)
}

// GenerateLegacyLocalDestination creates a legacy ElGamal/Ed25519 destination with an X25519 key for LeaseSet2.
// This maintains backward address compatibility with legacy Java I2P routers.
func GenerateLegacyLocalDestination() (*LocalDestination, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return generateLegacyLocalDestination(SigningEdDSASHA512Ed25519, public, private)
}

// GenerateEncryptedLocalDestination creates a Red25519 (type 11) destination for encrypted LeaseSet2 services.
func GenerateEncryptedLocalDestination() (*LocalDestination, error) {
	public, private, err := GenerateRed25519Key()
	if err != nil {
		return nil, err
	}
	return generateLegacyLocalDestination(SigningRedDSASHA512Ed25519, ed25519.PublicKey(public[:]), private[:])
}

func generateLocalDestination(signingType SigningKeyType, signingPublic ed25519.PublicKey, signingPrivate []byte) (*LocalDestination, error) {
	if len(signingPublic) != ed25519.PublicKeySize || (signingType != SigningEdDSASHA512Ed25519 && signingType != SigningRedDSASHA512Ed25519) {
		return nil, ErrInvalidIdentity
	}
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		clear(signingPrivate)
		return nil, err
	}
	d := &LocalDestination{
		signingType:        signingType,
		signingPublic:      append(ed25519.PublicKey(nil), signingPublic...),
		signingPrivate:     append([]byte(nil), signingPrivate...),
		cryptoCapabilities: localDestinationCryptoCapabilities,
		identityCryptoType: CryptoX25519,
	}
	copy(d.x25519Private[:], x25519.Bytes())
	copy(d.x25519Public[:], x25519.PublicKey().Bytes())

	// X25519 occupies the leading bytes of the historical 256-byte crypto
	// field and the signing key remains right aligned in the signing field.
	raw := make([]byte, IdentityBaseLength+CertificateHeader+4)
	if _, err := io.ReadFull(rand.Reader, raw[:IdentityBaseLength]); err != nil {
		d.ReleaseSensitive()
		return nil, err
	}
	copy(raw, d.x25519Public[:])
	copy(raw[IdentityBaseLength-ed25519.PublicKeySize:IdentityBaseLength], d.signingPublic)
	raw[IdentityBaseLength] = byte(CertificateKey)
	binary.BigEndian.PutUint16(raw[IdentityBaseLength+1:IdentityBaseLength+3], 4)
	binary.BigEndian.PutUint16(raw[IdentityBaseLength+3:IdentityBaseLength+5], uint16(signingType))
	binary.BigEndian.PutUint16(raw[IdentityBaseLength+5:IdentityBaseLength+7], uint16(CryptoX25519))
	identity, consumed, err := ParseIdentity(raw)
	if err != nil || consumed != len(raw) || identity.CryptoKeyType() != CryptoX25519 || identity.SigningKeyType() != signingType {
		d.ReleaseSensitive()
		return nil, ErrInvalidIdentity
	}
	d.hash = identity.Hash()
	d.destination = make([]byte, base64.NewEncoding(i2pBase64Alphabet).EncodedLen(len(raw)))
	base64.NewEncoding(i2pBase64Alphabet).Encode(d.destination, raw)

	return d, nil
}

func generateLegacyLocalDestination(signingType SigningKeyType, signingPublic ed25519.PublicKey, signingPrivate []byte) (*LocalDestination, error) {
	if len(signingPublic) != ed25519.PublicKeySize || (signingType != SigningEdDSASHA512Ed25519 && signingType != SigningRedDSASHA512Ed25519) {
		clear(signingPrivate)
		return nil, ErrInvalidIdentity
	}
	encryptionPublic, encryptionPrivate, err := cryptography.GenerateElGamalKeyPair()
	if err != nil {
		clear(signingPrivate)
		return nil, err
	}
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		clear(signingPrivate)
		clear(encryptionPrivate[:])
		return nil, err
	}
	d := &LocalDestination{
		signingType:        signingType,
		signingPublic:      append(ed25519.PublicKey(nil), signingPublic...),
		signingPrivate:     append([]byte(nil), signingPrivate...),
		identityCryptoType: CryptoElGamal,
		elgamalPrivate:     encryptionPrivate,
		cryptoCapabilities: localDestinationCryptoCapabilities,
	}
	copy(d.x25519Private[:], x25519.Bytes())
	copy(d.x25519Public[:], x25519.PublicKey().Bytes())
	clear(signingPrivate)
	clear(encryptionPrivate[:])

	raw := make([]byte, IdentityBaseLength+CertificateHeader+4)
	if _, err = io.ReadFull(rand.Reader, raw[:IdentityBaseLength]); err != nil {
		d.ReleaseSensitive()
		return nil, err
	}
	copy(raw[:cryptography.ElGamalPublicKeySize], encryptionPublic[:])
	copy(raw[IdentityBaseLength-ed25519.PublicKeySize:IdentityBaseLength], d.signingPublic)
	raw[IdentityBaseLength] = byte(CertificateKey)
	binary.BigEndian.PutUint16(raw[IdentityBaseLength+1:IdentityBaseLength+3], 4)
	binary.BigEndian.PutUint16(raw[IdentityBaseLength+3:IdentityBaseLength+5], uint16(signingType))
	binary.BigEndian.PutUint16(raw[IdentityBaseLength+5:IdentityBaseLength+7], uint16(CryptoElGamal))
	identity, consumed, parseErr := ParseIdentity(raw)
	if parseErr != nil || consumed != len(raw) || identity.CryptoKeyType() != CryptoElGamal || identity.SigningKeyType() != signingType {
		d.ReleaseSensitive()
		return nil, ErrInvalidIdentity
	}
	d.hash = identity.Hash()
	d.destination = make([]byte, base64.NewEncoding(i2pBase64Alphabet).EncodedLen(len(raw)))
	base64.NewEncoding(i2pBase64Alphabet).Encode(d.destination, raw)
	return d, nil
}

// Identity parses and returns the public Identity of this destination.
func (d *LocalDestination) Identity() (Identity, error) {
	if d == nil {
		return Identity{}, ErrInvalidIdentity
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return ParseDestination(d.destination)
}

func (d *LocalDestination) IdentityHash() Hash {
	if d == nil {
		return Hash{}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.hash
}

// Hash returns the destination's SHA-256 hash.
func (d *LocalDestination) Hash() Hash { return d.IdentityHash() }

func (d *LocalDestination) B32() string { return B32(d.IdentityHash()) }

// Destination returns a copy of the base64-encoded destination.
func (d *LocalDestination) Destination() []byte {
	if d == nil {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append([]byte(nil), d.destination...)
}

func (d *LocalDestination) X25519Public() [32]byte {
	if d == nil {
		return [32]byte{}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.x25519Public
}

// CopyX25519Private copies the static X25519 private key into dst.
func (d *LocalDestination) CopyX25519Private(dst []byte) error {
	if len(dst) != 32 {
		return ErrDestinationSmall
	}
	if d == nil {
		return cryptography.ErrSensitiveReleased
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released {
		return cryptography.ErrSensitiveReleased
	}
	copy(dst, d.x25519Private[:])
	return nil
}

// CopyElGamalPrivate copies the legacy ElGamal private key into dst.
func (d *LocalDestination) CopyElGamalPrivate(dst []byte) error {
	if len(dst) != cryptography.ElGamalPrivateKeySize {
		return ErrDestinationSmall
	}
	if d == nil {
		return cryptography.ErrSensitiveReleased
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released {
		return cryptography.ErrSensitiveReleased
	}
	if d.identityCryptoType != CryptoElGamal {
		return ErrInvalidIdentity
	}
	copy(dst, d.elgamalPrivate[:])
	return nil
}

// CryptoTypes returns supported encryption algorithms in order of preference.
func (d *LocalDestination) CryptoTypes() [3]CryptoKeyType {
	if d == nil {
		return [3]CryptoKeyType{}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.cryptoCapabilities != localDestinationCryptoCapabilities {
		return [3]CryptoKeyType{}
	}
	return [3]CryptoKeyType{CryptoMLKEM1024X25519, CryptoMLKEM768X25519, CryptoX25519}
}

// CryptoPublic returns the static public key for the requested crypto type.
func (d *LocalDestination) CryptoPublic(cryptoType CryptoKeyType) ([32]byte, error) {
	if d == nil {
		return [32]byte{}, ErrInvalidIdentity
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	cryptoPublicRejected := d.cryptoCapabilities != localDestinationCryptoCapabilities
	if !cryptoPublicRejected {
		cryptoPublicRejected = (cryptoType != CryptoX25519 && cryptoType != CryptoMLKEM768X25519 && cryptoType != CryptoMLKEM1024X25519)
	}
	if cryptoPublicRejected {
		return [32]byte{}, ErrInvalidIdentity
	}
	return d.x25519Public, nil
}

// CopyCryptoPrivate copies the static private key for the requested crypto type into dst.
func (d *LocalDestination) CopyCryptoPrivate(cryptoType CryptoKeyType, dst []byte) error {
	if d == nil || len(dst) != 32 {
		return ErrDestinationSmall
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released {
		return cryptography.ErrSensitiveReleased
	}
	copyCryptoPrivateRejected := d.cryptoCapabilities != localDestinationCryptoCapabilities
	if !copyCryptoPrivateRejected {
		copyCryptoPrivateRejected = (cryptoType != CryptoX25519 && cryptoType != CryptoMLKEM768X25519 && cryptoType != CryptoMLKEM1024X25519)
	}
	if copyCryptoPrivateRejected {
		return ErrInvalidIdentity
	}
	copy(dst, d.x25519Private[:])
	return nil
}

func (d *LocalDestination) Sign(message []byte) ([]byte, error) {
	if d == nil {
		return nil, cryptography.ErrSensitiveReleased
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released {
		return nil, cryptography.ErrSensitiveReleased
	}
	if d.offline != nil {
		if uint32(time.Now().Unix()) > d.offline.expires {
			return nil, ErrOfflineSignatureExpired
		}
		switch d.offline.keyType {
		case SigningEdDSASHA512Ed25519:
			return ed25519.Sign(ed25519.NewKeyFromSeed(d.offline.private), message), nil
		case SigningRedDSASHA512Ed25519:
			var private [32]byte
			copy(private[:], d.offline.private)
			return Red25519Sign(private, message)
		default:
			return nil, ErrEncryptedSigningKey
		}
	}
	switch d.signingType {
	case SigningEdDSASHA512Ed25519:
		return ed25519.Sign(ed25519.PrivateKey(d.signingPrivate), message), nil
	case SigningRedDSASHA512Ed25519:
		var private [32]byte
		copy(private[:], d.signingPrivate)
		return Red25519Sign(private, message)
	default:
		return nil, ErrEncryptedSigningKey
	}
}

func (d *LocalDestination) SigningPublic() ed25519.PublicKey {
	if d == nil {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append(ed25519.PublicKey(nil), d.signingPublic...)
}

// SigningKeyType returns the destination's signing key type.
func (d *LocalDestination) SigningKeyType() SigningKeyType {
	if d == nil {
		return 0
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.signingType
}

// EncryptedLeaseSetBlinding derives blinded Red25519 signing keys for encrypted LeaseSets on the given date.
func (d *LocalDestination) EncryptedLeaseSetBlinding(date time.Time, secret []byte) (private, public [32]byte, err error) {
	if d == nil {
		return private, public, cryptography.ErrSensitiveReleased
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released {
		return private, public, cryptography.ErrSensitiveReleased
	}
	private, err = BlindEncryptedLeaseSetPrivate(d.signingType, d.signingPrivate, d.signingPublic, date, secret)
	if err != nil {
		return private, public, err
	}
	scalar, scalarErr := new(edwards25519.Scalar).SetCanonicalBytes(private[:])
	if scalarErr != nil {
		clear(private[:])
		return private, public, ErrEncryptedSigningKey
	}
	copy(public[:], new(edwards25519.Point).ScalarBaseMult(scalar).Bytes())
	return private, public, nil
}

// Clone creates an independent copy of the local destination.
func (d *LocalDestination) Clone() (*LocalDestination, error) {
	if d == nil {
		return nil, ErrInvalidIdentity
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released {
		return nil, cryptography.ErrSensitiveReleased
	}
	clone := &LocalDestination{
		destination:        append([]byte(nil), d.destination...),
		hash:               d.hash,
		signingType:        d.signingType,
		signingPublic:      append(ed25519.PublicKey(nil), d.signingPublic...),
		signingPrivate:     append([]byte(nil), d.signingPrivate...),
		x25519Public:       d.x25519Public,
		x25519Private:      d.x25519Private,
		cryptoCapabilities: d.cryptoCapabilities,
		identityCryptoType: d.identityCryptoType,
		elgamalPrivate:     d.elgamalPrivate,
	}
	if d.offline != nil {
		clone.offline = &offlineSigning{
			expires:   d.offline.expires,
			keyType:   d.offline.keyType,
			public:    append([]byte(nil), d.offline.public...),
			signature: append([]byte(nil), d.offline.signature...),
			private:   append([]byte(nil), d.offline.private...),
		}
	}
	return clone, nil
}

// ReleaseSensitive securely zeroes private keys and marks the destination as released.
func (d *LocalDestination) ReleaseSensitive() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if !d.released {
		clear(d.signingPrivate)
		clear(d.x25519Private[:])
		clear(d.elgamalPrivate[:])
		if d.offline != nil {
			d.offline.clear()
			d.offline = nil
		}
		d.released = true
	}
	d.mu.Unlock()
}

func (d *LocalDestination) PrivateEncodedLen() int {
	if d == nil {
		return 0
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	n := 2 + len(d.destination) + len(d.signingPrivate) + 32 + 1
	if d.identityCryptoType == CryptoElGamal {
		n += cryptography.ElGamalPrivateKeySize
	}
	return n
}

// MarshalPrivateTo serializes the private destination for encrypted persistent storage.
func (d *LocalDestination) MarshalPrivateTo(dst []byte) (int, error) {
	if d == nil {
		return 0, cryptography.ErrSensitiveReleased
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released {
		return 0, cryptography.ErrSensitiveReleased
	}
	n := 2 + len(d.destination) + len(d.signingPrivate) + 32 + 1
	if d.identityCryptoType == CryptoElGamal {
		n += cryptography.ElGamalPrivateKeySize
	}
	if len(dst) < n || len(d.destination) > 0xffff || d.cryptoCapabilities != localDestinationCryptoCapabilities {
		return 0, ErrDestinationSmall
	}
	binary.BigEndian.PutUint16(dst[:2], uint16(len(d.destination)))
	off := 2 + copy(dst[2:], d.destination)
	off += copy(dst[off:], d.signingPrivate)
	off += copy(dst[off:], d.x25519Private[:])
	if d.identityCryptoType == CryptoElGamal {
		off += copy(dst[off:], d.elgamalPrivate[:])
	}
	dst[off] = d.cryptoCapabilities
	return off + 1, nil
}

// ImportLocalDestination reconstructs and validates a LocalDestination from serialized private state bytes.
func ImportLocalDestination(src []byte) (*LocalDestination, error) {
	return importLocalDestination(src, nil)
}

// ImportLocalDestinationOffline reconstructs a LocalDestination whose long-term
// signing private key is absent (all zero in src) and replaced by an authorized
// transient signing key. The authorization signature is verified against the
// destination identity.
func ImportLocalDestinationOffline(src []byte, offline OfflineSignature, transientPrivate []byte) (*LocalDestination, error) {
	if len(src) < 2 {
		return nil, ErrInvalidIdentity
	}
	n := int(binary.BigEndian.Uint16(src[:2]))
	if n == 0 || len(src) < 2+n {
		return nil, ErrInvalidIdentity
	}
	identity, err := ParseDestination(src[2 : 2+n])
	if err != nil {
		return nil, ErrInvalidIdentity
	}
	signing, err := parseOfflineSigning(identity, offline, transientPrivate)
	if err != nil {
		return nil, err
	}
	destination, err := importLocalDestination(src, signing)
	if err != nil {
		signing.clear()
		return nil, err
	}
	return destination, nil
}

func importLocalDestination(src []byte, offline *offlineSigning) (*LocalDestination, error) {
	if len(src) < 2 {
		return nil, ErrInvalidIdentity
	}
	n := int(binary.BigEndian.Uint16(src[:2]))
	if n == 0 || len(src) < 2+n+32 {
		return nil, ErrInvalidIdentity
	}
	identity, err := ParseDestination(src[2 : 2+n])
	if err != nil || (identity.CryptoKeyType() != CryptoX25519 && identity.CryptoKeyType() != CryptoElGamal) {
		return nil, ErrInvalidIdentity
	}
	signingType := identity.SigningKeyType()
	privateLen := 0
	switch signingType {
	case SigningEdDSASHA512Ed25519:
		privateLen = ed25519.PrivateKeySize
	case SigningRedDSASHA512Ed25519:
		privateLen = 32
	default:
		return nil, ErrInvalidIdentity
	}
	elgamalLen := 0
	if identity.CryptoKeyType() == CryptoElGamal {
		elgamalLen = cryptography.ElGamalPrivateKeySize
	}
	privateEnd := 2 + n + privateLen + 32 + elgamalLen
	if len(src) != privateEnd && len(src) != privateEnd+1 {
		return nil, ErrInvalidIdentity
	}
	capabilities := localDestinationCryptoCapabilities
	if len(src) == privateEnd+1 && src[privateEnd] != localDestinationCryptoCapabilities {
		return nil, ErrInvalidIdentity
	}
	off := 2 + n
	private := append([]byte(nil), src[off:off+privateLen]...)
	var public ed25519.PublicKey
	if offline != nil {
		// The long-term signing private key stays offline; only zero padding
		// occupies its slot in the serialized state.
		for _, value := range private {
			if value != 0 {
				clear(private)
				return nil, ErrInvalidIdentity
			}
		}
		signing, rest := identity.SigningKeyParts()
		if len(rest) != 0 {
			clear(private)
			return nil, ErrInvalidIdentity
		}
		public = append(ed25519.PublicKey(nil), signing...)
	} else {
		switch signingType {
		case SigningEdDSASHA512Ed25519:
			public = ed25519.PrivateKey(private).Public().(ed25519.PublicKey)
		case SigningRedDSASHA512Ed25519:
			scalar, scalarErr := new(edwards25519.Scalar).SetCanonicalBytes(private)
			if scalarErr != nil {
				clear(private)
				return nil, ErrInvalidIdentity
			}
			public = append(ed25519.PublicKey(nil), new(edwards25519.Point).ScalarBaseMult(scalar).Bytes()...)
		}
		signing, rest := identity.SigningKeyParts()
		if len(rest) != 0 || !bytes.Equal(signing, public) {
			clear(private)
			return nil, ErrInvalidIdentity
		}
	}
	off += privateLen
	x25519, err := ecdh.X25519().NewPrivateKey(src[off : off+32])
	if err != nil {
		clear(private)
		return nil, ErrInvalidIdentity
	}
	off += 32
	var elgamalPrivate cryptography.ElGamalPrivateKey
	crypto, rest := identity.CryptoKeyParts()
	switch identity.CryptoKeyType() {
	case CryptoX25519:
		if len(rest) != 0 || !bytes.Equal(crypto, x25519.PublicKey().Bytes()) {
			clear(private)
			return nil, ErrInvalidIdentity
		}
	case CryptoElGamal:
		copy(elgamalPrivate[:], src[off:off+cryptography.ElGamalPrivateKeySize])
		derived, deriveErr := cryptography.ElGamalPublicFromPrivate(elgamalPrivate)
		if deriveErr != nil || len(rest) != 0 || !bytes.Equal(crypto, derived[:]) {
			clear(private)
			clear(elgamalPrivate[:])
			return nil, ErrInvalidIdentity
		}
	}
	d := &LocalDestination{
		destination:        append([]byte(nil), src[2:2+n]...),
		hash:               identity.Hash(),
		signingType:        signingType,
		signingPublic:      append(ed25519.PublicKey(nil), public...),
		signingPrivate:     private,
		x25519Public:       [32]byte(x25519.PublicKey().Bytes()),
		identityCryptoType: identity.CryptoKeyType(),
		elgamalPrivate:     elgamalPrivate,
		cryptoCapabilities: capabilities,
		offline:            offline,
	}
	copy(d.x25519Private[:], x25519.Bytes())
	return d, nil
}

// LocalAddress holds key material for a local legacy ElGamal/Ed25519 destination.
type LocalAddress struct {
	Destination       []byte
	Hash              Hash
	SigningPublic     ed25519.PublicKey
	SigningPrivate    ed25519.PrivateKey
	EncryptionPublic  cryptography.ElGamalPublicKey
	EncryptionPrivate cryptography.ElGamalPrivateKey
}

// LocalIdentityOwner represents an identity with signing capabilities.
type LocalIdentityOwner interface {
	Identity() (Identity, error)
	IdentityHash() Hash
	SigningKeyPair() (ed25519.PublicKey, ed25519.PrivateKey)
}

// Identity parses the destination's Identity structure.
func (a LocalAddress) Identity() (Identity, error) {
	return ParseDestination(a.Destination)
}

// IdentityHash returns the destination's hash.
func (a LocalAddress) IdentityHash() Hash { return a.Hash }

// SigningKeyPair returns the Ed25519 public and private signing keys.
func (a LocalAddress) SigningKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	return a.SigningPublic, a.SigningPrivate
}

// LocalRouterAddress holds keys and the wire identity for a local router.
type LocalRouterAddress struct {
	RouterIdentity []byte
	Hash           Hash
	SigningPublic  ed25519.PublicKey
	SigningPrivate ed25519.PrivateKey
	X25519Public   [32]byte
	X25519Private  [32]byte
}

// B32 returns the canonical .b32.i2p domain name for this router identity.
func (a LocalRouterAddress) B32() string { return B32(a.Hash) }

// Base64 returns the I2P Base64-encoded router identity.
func (a LocalRouterAddress) Base64() string { return EncodeI2PBase64(a.RouterIdentity) }

// Identity parses the raw RouterIdentity.
func (a LocalRouterAddress) Identity() (Identity, error) {
	identity, consumed, err := ParseIdentity(a.RouterIdentity)
	if err != nil || consumed != len(a.RouterIdentity) {
		return Identity{}, ErrInvalidIdentity
	}
	return identity, nil
}

// IdentityHash returns the router identity's hash.
func (a LocalRouterAddress) IdentityHash() Hash { return a.Hash }

// SigningKeyPair returns the Ed25519 public and private signing keys.
func (a LocalRouterAddress) SigningKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	return a.SigningPublic, a.SigningPrivate
}

// B32 returns the canonical .b32.i2p hostname corresponding to an identity hash.
func B32(hash Hash) string {
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])) + ".b32.i2p"
}

// B32 returns the canonical .b32.i2p hostname for this local destination.
func (a LocalAddress) B32() string { return B32(a.Hash) }

// EncodeI2PBase64 encodes data using the I2P Base64 alphabet (with - and ~).
func EncodeI2PBase64(raw []byte) string {
	return base64.NewEncoding(i2pBase64Alphabet).EncodeToString(raw)
}

// DecodeI2PBase64 decodes data in the I2P Base64 alphabet (with or without padding).
func DecodeI2PBase64(encoded []byte) ([]byte, error) {
	encoding := base64.NewEncoding(i2pBase64Alphabet)
	raw := make([]byte, encoding.DecodedLen(len(encoded)))
	n, err := encoding.Decode(raw, encoded)
	if err == nil {
		return raw[:n], nil
	}
	encoding = encoding.WithPadding(base64.NoPadding)
	raw = make([]byte, encoding.DecodedLen(len(encoded)))
	n, err = encoding.Decode(raw, encoded)
	if err != nil {
		return nil, err
	}
	return raw[:n], nil
}

// ParseDestination decodes and parses an I2P-Base64 encoded Destination string.
func ParseDestination(encoded []byte) (Identity, error) {
	raw, err := DecodeI2PBase64(encoded)
	if err != nil {
		return Identity{}, err
	}
	identity, consumed, err := ParseIdentity(raw)
	if err != nil || consumed != len(raw) {
		return Identity{}, ErrInvalidIdentity
	}
	return identity, nil
}

// GenerateAddress generates a new Ed25519 destination and returns its encoded form, hash, and keypair.
func GenerateAddress() (destination []byte, hash Hash, public ed25519.PublicKey, private ed25519.PrivateKey, err error) {
	address, err := GenerateLocalAddress()
	if err != nil {
		return nil, Hash{}, nil, nil, err
	}
	return address.Destination, address.Hash, address.SigningPublic, address.SigningPrivate, nil
}

// GenerateLocalAddress creates a local legacy ElGamal/Ed25519 destination.
func GenerateLocalAddress() (address LocalAddress, err error) {
	address.SigningPublic, address.SigningPrivate, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return LocalAddress{}, err
	}
	address.EncryptionPublic, address.EncryptionPrivate, err = cryptography.GenerateElGamalKeyPair()
	if err != nil {
		return LocalAddress{}, err
	}

	raw := make([]byte, IdentityBaseLength+CertificateHeader+4)
	if _, err = io.ReadFull(rand.Reader, raw[:IdentityBaseLength]); err != nil {
		return LocalAddress{}, err
	}
	copy(raw[:cryptography.ElGamalPublicKeySize], address.EncryptionPublic[:])
	copy(raw[IdentityBaseLength-ed25519.PublicKeySize:IdentityBaseLength], address.SigningPublic)
	raw[IdentityBaseLength] = byte(CertificateKey)
	binary.BigEndian.PutUint16(raw[IdentityBaseLength+1:IdentityBaseLength+3], 4)
	binary.BigEndian.PutUint16(raw[IdentityBaseLength+3:IdentityBaseLength+5], uint16(SigningEdDSASHA512Ed25519))
	binary.BigEndian.PutUint16(raw[IdentityBaseLength+5:IdentityBaseLength+7], uint16(CryptoElGamal))

	identity, n, parseErr := ParseIdentity(raw)
	if parseErr != nil || n != len(raw) || identity.Certificate().Type != CertificateKey ||
		identity.SigningKeyType() != SigningEdDSASHA512Ed25519 || identity.CryptoKeyType() != CryptoElGamal {
		return LocalAddress{}, ErrInvalidIdentity
	}

	address.Hash = identity.Hash()
	encoding := base64.NewEncoding(i2pBase64Alphabet)
	address.Destination = make([]byte, encoding.EncodedLen(len(raw)))
	encoding.Encode(address.Destination, raw)
	return address, nil
}

// GenerateLocalRouterAddress generates a local RouterIdentity with Ed25519 signing and X25519 encryption keys.
func GenerateLocalRouterAddress() (address LocalRouterAddress, err error) {
	address.SigningPublic, address.SigningPrivate, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return LocalRouterAddress{}, err
	}
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return LocalRouterAddress{}, err
	}
	copy(address.X25519Private[:], x25519.Bytes())
	copy(address.X25519Public[:], x25519.PublicKey().Bytes())

	raw := make([]byte, IdentityBaseLength+CertificateHeader+4)
	if _, err = io.ReadFull(rand.Reader, raw[:IdentityBaseLength]); err != nil {
		return LocalRouterAddress{}, err
	}
	copy(raw[:], address.X25519Public[:])
	copy(raw[IdentityBaseLength-ed25519.PublicKeySize:IdentityBaseLength], address.SigningPublic)
	raw[IdentityBaseLength] = byte(CertificateKey)
	binary.BigEndian.PutUint16(raw[IdentityBaseLength+1:IdentityBaseLength+3], 4)
	binary.BigEndian.PutUint16(raw[IdentityBaseLength+3:IdentityBaseLength+5], uint16(SigningEdDSASHA512Ed25519))
	binary.BigEndian.PutUint16(raw[IdentityBaseLength+5:IdentityBaseLength+7], uint16(CryptoX25519))

	identity, consumed, parseErr := ParseIdentity(raw)
	if parseErr != nil || consumed != len(raw) || identity.Certificate().Type != CertificateKey ||
		identity.SigningKeyType() != SigningEdDSASHA512Ed25519 || identity.CryptoKeyType() != CryptoX25519 {
		return LocalRouterAddress{}, ErrInvalidIdentity
	}
	address.RouterIdentity = raw
	address.Hash = identity.Hash()
	return address, nil
}
