package ivnp

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
	"gosuda.org/ivnp/crypto/cryptx"
)

const i2pBase64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~"

const localDestinationCryptoCapabilities = byte(1<<0 | 1<<1 | 1<<2)

// LocalDestination owns the persisted private/public static key and capability
// policy for ECIES-X25519 (4), ML-KEM-768/X25519 (6), and
// ML-KEM-1024/X25519 (7). All three formats bind the same static X25519 key;
// hybrid handshakes add one-use ML-KEM transcript sections.
//
// The public Destination encoding is immutable. Private material is never
// returned by reference and ReleaseSensitive makes all private-key operations
// fail deterministically.
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
	elgamalPrivate     cryptx.ElGamalPrivateKey
	cryptoCapabilities byte
	released           bool
}

// GenerateLocalDestination creates a public (Ed25519) ECIES-X25519
// Destination. Use GenerateEncryptedLocalDestination for a new ELS2 service.
func GenerateLocalDestination() (*LocalDestination, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return generateLocalDestination(SigningEdDSASHA512Ed25519, public, private)
}

// GenerateLegacyLocalDestination creates an Ed25519/ElGamal public
// Destination with an independent X25519 receive key for LS2 publication.
// The legacy identity remains address-compatible with Java I2P while session
// encryption uses the advertised modern LeaseSet key.
func GenerateLegacyLocalDestination() (*LocalDestination, error) {
	address, err := GenerateLocalAddress()
	if err != nil {
		return nil, err
	}
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		clear(address.SigningPrivate)
		clear(address.EncryptionPrivate[:])
		return nil, err
	}
	d := &LocalDestination{
		destination:        append([]byte(nil), address.Destination...),
		hash:               address.Hash,
		signingType:        SigningEdDSASHA512Ed25519,
		signingPublic:      append(ed25519.PublicKey(nil), address.SigningPublic...),
		signingPrivate:     append([]byte(nil), address.SigningPrivate...),
		identityCryptoType: CryptoElGamal,
		elgamalPrivate:     address.EncryptionPrivate,
		cryptoCapabilities: localDestinationCryptoCapabilities,
	}
	copy(d.x25519Private[:], x25519.Bytes())
	copy(d.x25519Public[:], x25519.PublicKey().Bytes())
	clear(address.SigningPrivate)
	clear(address.EncryptionPrivate[:])
	return d, nil
}

// GenerateEncryptedLocalDestination creates a Red25519 type-11 signing
// Destination suitable for publication as a new encrypted LeaseSet.
func GenerateEncryptedLocalDestination() (*LocalDestination, error) {
	public, private, err := GenerateRed25519Key()
	if err != nil {
		return nil, err
	}
	return generateLocalDestination(SigningRedDSASHA512Ed25519, ed25519.PublicKey(public[:]), private[:])
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

// Identity returns a parser view of the immutable public Destination.
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

// Hash returns this immutable Destination's hash.
func (d *LocalDestination) Hash() Hash { return d.IdentityHash() }

func (d *LocalDestination) B32() string { return B32(d.IdentityHash()) }

// Destination returns an owned public encoding copy.
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

// CopyX25519Private copies the private key only into caller-owned storage.
func (d *LocalDestination) CopyX25519Private(dst []byte) error {
	if len(dst) != 32 {
		return ErrDestinationSmall
	}
	if d == nil {
		return cryptx.ErrSensitiveReleased
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released {
		return cryptx.ErrSensitiveReleased
	}
	copy(dst, d.x25519Private[:])
	return nil
}

// CopyElGamalPrivate copies the legacy Destination private exponent. LS2
// sessions retain this key for standard SAM private-Destination round trips;
// their garlic receive key remains the independent X25519 key.
func (d *LocalDestination) CopyElGamalPrivate(dst []byte) error {
	if len(dst) != cryptx.ElGamalPrivateKeySize {
		return ErrDestinationSmall
	}
	if d == nil {
		return cryptx.ErrSensitiveReleased
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released {
		return cryptx.ErrSensitiveReleased
	}
	if d.identityCryptoType != CryptoElGamal {
		return ErrInvalidIdentity
	}
	copy(dst, d.elgamalPrivate[:])
	return nil
}

// CryptoTypes reports this Destination's persisted ECIES receive and
// publication capabilities in preference order.
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

// CryptoPublic returns the persisted static public key for a supported ECIES
// format. Hybrid ML-KEM material is one-use handshake state, not an LS2 key.
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

// CopyCryptoPrivate copies the persisted static private key for a supported
// ECIES format into caller-owned storage.
func (d *LocalDestination) CopyCryptoPrivate(cryptoType CryptoKeyType, dst []byte) error {
	if d == nil || len(dst) != 32 {
		return ErrDestinationSmall
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released {
		return cryptx.ErrSensitiveReleased
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
		return nil, cryptx.ErrSensitiveReleased
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released {
		return nil, cryptx.ErrSensitiveReleased
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

// SigningKeyType reports the immutable signing-key type in the Destination.
func (d *LocalDestination) SigningKeyType() SigningKeyType {
	if d == nil {
		return 0
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.signingType
}

// EncryptedLeaseSetBlinding derives the daily type-11 signing keypair without
// exposing this Destination's long-lived private key.
func (d *LocalDestination) EncryptedLeaseSetBlinding(date time.Time, secret []byte) (private, public [32]byte, err error) {
	if d == nil {
		return private, public, cryptx.ErrSensitiveReleased
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released {
		return private, public, cryptx.ErrSensitiveReleased
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

// Clone makes a separately releasable private-key owner.
func (d *LocalDestination) Clone() (*LocalDestination, error) {
	if d == nil {
		return nil, ErrInvalidIdentity
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released {
		return nil, cryptx.ErrSensitiveReleased
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
	return clone, nil
}

// ReleaseSensitive clears IVNP-owned private material. The public identity
// remains available for close/status paths.
func (d *LocalDestination) ReleaseSensitive() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if !d.released {
		clear(d.signingPrivate)
		clear(d.x25519Private[:])
		clear(d.elgamalPrivate[:])
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
		n += cryptx.ElGamalPrivateKeySize
	}
	return n
}

// MarshalPrivateTo copies the local private identity into caller storage. It
// is intended only for the encrypted state store.
func (d *LocalDestination) MarshalPrivateTo(dst []byte) (int, error) {
	if d == nil {
		return 0, cryptx.ErrSensitiveReleased
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released {
		return 0, cryptx.ErrSensitiveReleased
	}
	n := 2 + len(d.destination) + len(d.signingPrivate) + 32 + 1
	if d.identityCryptoType == CryptoElGamal {
		n += cryptx.ElGamalPrivateKeySize
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

// ImportLocalDestination imports the encrypted-state representation emitted by
// MarshalPrivateTo and verifies every public/private binding before retaining
// a separately owned key copy.
func ImportLocalDestination(src []byte) (*LocalDestination, error) {
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
		if identity.CryptoKeyType() != CryptoX25519 {
			return nil, ErrInvalidIdentity
		}
		privateLen = 32
	default:
		return nil, ErrInvalidIdentity
	}
	elgamalLen := 0
	if identity.CryptoKeyType() == CryptoElGamal {
		elgamalLen = cryptx.ElGamalPrivateKeySize
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
	off += privateLen
	x25519, err := ecdh.X25519().NewPrivateKey(src[off : off+32])
	if err != nil {
		clear(private)
		return nil, ErrInvalidIdentity
	}
	off += 32
	var elgamalPrivate cryptx.ElGamalPrivateKey
	crypto, rest := identity.CryptoKeyParts()
	switch identity.CryptoKeyType() {
	case CryptoX25519:
		if len(rest) != 0 || !bytes.Equal(crypto, x25519.PublicKey().Bytes()) {
			clear(private)
			return nil, ErrInvalidIdentity
		}
	case CryptoElGamal:
		copy(elgamalPrivate[:], src[off:off+cryptx.ElGamalPrivateKeySize])
		derived, deriveErr := cryptx.ElGamalPublicFromPrivate(elgamalPrivate)
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
	}
	copy(d.x25519Private[:], x25519.Bytes())
	return d, nil
}

// LocalAddress contains the private material for a locally-owned legacy
// ElGamal/Ed25519 Destination. All fields are caller-owned.
type LocalAddress struct {
	Destination       []byte
	Hash              Hash
	SigningPublic     ed25519.PublicKey
	SigningPrivate    ed25519.PrivateKey
	EncryptionPublic  cryptx.ElGamalPublicKey
	EncryptionPrivate cryptx.ElGamalPrivateKey
}

// LocalIdentityOwner supplies the private signing material for one locally
// owned Identity. LocalAddress owns a legacy Destination; LocalRouterAddress
// owns a RouterIdentity with a modern X25519 crypto key.
type LocalIdentityOwner interface {
	Identity() (Identity, error)
	IdentityHash() Hash
	SigningKeyPair() (ed25519.PublicKey, ed25519.PrivateKey)
}

// Identity decodes this legacy Destination's Identity.
func (a LocalAddress) Identity() (Identity, error) {
	return ParseDestination(a.Destination)
}

// IdentityHash returns this legacy Destination's Identity hash.
func (a LocalAddress) IdentityHash() Hash { return a.Hash }

// SigningKeyPair returns this Destination's Ed25519 signing keys.
func (a LocalAddress) SigningKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	return a.SigningPublic, a.SigningPrivate
}

// LocalRouterAddress contains the private material for a locally-owned modern
// RouterIdentity. RouterIdentity is the exact raw KeysAndCert encoding with
// Ed25519 signing and X25519 crypto keys. All fields are caller-owned.
type LocalRouterAddress struct {
	RouterIdentity []byte
	Hash           Hash
	SigningPublic  ed25519.PublicKey
	SigningPrivate ed25519.PrivateKey
	X25519Public   [32]byte
	X25519Private  [32]byte
}

// B32 returns the canonical b32.i2p hostname for this RouterIdentity.
func (a LocalRouterAddress) B32() string { return B32(a.Hash) }

// Base64 returns the canonical padded I2P Base64 RouterIdentity encoding.
func (a LocalRouterAddress) Base64() string { return EncodeI2PBase64(a.RouterIdentity) }

// Identity parses this RouterIdentity without decoding a Destination wrapper.
func (a LocalRouterAddress) Identity() (Identity, error) {
	identity, consumed, err := ParseIdentity(a.RouterIdentity)
	if err != nil || consumed != len(a.RouterIdentity) {
		return Identity{}, ErrInvalidIdentity
	}
	return identity, nil
}

// IdentityHash returns this RouterIdentity's hash.
func (a LocalRouterAddress) IdentityHash() Hash { return a.Hash }

// SigningKeyPair returns this RouterIdentity's Ed25519 signing keys.
func (a LocalRouterAddress) SigningKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	return a.SigningPublic, a.SigningPrivate
}

// B32 returns the canonical b32.i2p hostname for an identity hash.
func B32(hash Hash) string {
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])) + ".b32.i2p"
}

// B32 returns the canonical b32.i2p hostname for this locally-owned
// Destination.
func (a LocalAddress) B32() string { return B32(a.Hash) }

// EncodeI2PBase64 returns the canonical padded I2P `-~` Base64 encoding used
// for Destinations and RouterInfo transport options.
func EncodeI2PBase64(raw []byte) string {
	return base64.NewEncoding(i2pBase64Alphabet).EncodeToString(raw)
}

// DecodeI2PBase64 decodes the I2P `-~` Base64 alphabet. Both canonical padded
// values and unpadded transport option values are accepted. The result is
// caller-owned.
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

// ParseDestination decodes an I2P-Base64 Destination and validates that it
// contains exactly one Identity. The returned Identity aliases a new decoded
// buffer and is therefore independent of encoded.
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

// GenerateAddress creates an Ed25519 key-certificate Destination. destination
// is the exact I2P-Base64 encoding of the Destination wire bytes. The returned
// private key can sign data for the returned public key; this function does not
// publish a LeaseSet or create a router identity.
func GenerateAddress() (destination []byte, hash Hash, public ed25519.PublicKey, private ed25519.PrivateKey, err error) {
	address, err := GenerateLocalAddress()
	if err != nil {
		return nil, Hash{}, nil, nil, err
	}
	return address.Destination, address.Hash, address.SigningPublic, address.SigningPrivate, nil
}

// GenerateLocalAddress creates a locally-owned Ed25519 Destination and the
// matching legacy ElGamal private material needed to receive new sessions. It
// does not publish a LeaseSet or create a router identity.
func GenerateLocalAddress() (address LocalAddress, err error) {
	address.SigningPublic, address.SigningPrivate, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return LocalAddress{}, err
	}
	address.EncryptionPublic, address.EncryptionPrivate, err = cryptx.GenerateElGamalKeyPair()
	if err != nil {
		return LocalAddress{}, err
	}

	// A key certificate retains the legacy 256-byte ElGamal public-key field
	// and 128-byte signing-key field. Ed25519's 32-byte public key is right
	// aligned in the latter; the remaining bytes are cryptographic padding.
	raw := make([]byte, IdentityBaseLength+CertificateHeader+4)
	if _, err = io.ReadFull(rand.Reader, raw[:IdentityBaseLength]); err != nil {
		return LocalAddress{}, err
	}
	copy(raw[:cryptx.ElGamalPublicKeySize], address.EncryptionPublic[:])
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

// GenerateLocalRouterAddress creates a locally-owned RouterIdentity with an
// Ed25519 signing key and an X25519 crypto key. It does not create a legacy
// Destination or publish a RouterInfo.
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

	// Short crypto keys occupy the beginning of the legacy 256-byte crypto
	// field. Ed25519 remains right-aligned in the legacy signing-key field.
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
