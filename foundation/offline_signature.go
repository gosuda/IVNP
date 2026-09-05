package foundation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"time"

	"filippo.io/edwards25519"
)

// ErrOfflineSignatureExpired is returned when a transient signing key is used
// past the expiry authorized by the offline signature.
var ErrOfflineSignatureExpired = errors.New("i2p: offline signature is expired")

// OfflineSignature authorizes a transient signing key to act on behalf of a
// destination whose long-term signing private key is kept offline. It appears
// in SAM private destinations and protocol-19 Datagram2 packets.
type OfflineSignature struct {
	Expires   uint32
	Type      SigningKeyType
	PublicKey []byte
	Signature []byte
}

// Present reports whether the offline signature carries a transient public key.
func (o OfflineSignature) Present() bool { return o.PublicKey != nil }

// SignedContentLen returns the encoded length of the authorized content
// (expires, key type, public key) covered by the offline signature.
func (o OfflineSignature) SignedContentLen() int { return 6 + len(o.PublicKey) }

// MarshalSignedContentTo serializes the authorized content covered by the
// offline signature into dst without growing it.
func (o OfflineSignature) MarshalSignedContentTo(dst []byte) (int, error) {
	n := o.SignedContentLen()
	if len(dst) < n {
		return 0, ErrDestinationSmall
	}
	binary.BigEndian.PutUint32(dst[:4], o.Expires)
	binary.BigEndian.PutUint16(dst[4:6], uint16(o.Type))
	copy(dst[6:], o.PublicKey)
	return n, nil
}

// offlineTimeNow is the time source for offline signature expiry enforcement;
// tests override it (never in parallel) to pin expiry decisions.
var offlineTimeNow = time.Now

func offlineTransientPrivateLen(keyType SigningKeyType) (int, bool) {
	switch keyType {
	case SigningEdDSASHA512Ed25519, SigningRedDSASHA512Ed25519:
		return 32, true
	}
	return 0, false
}

func offlineTransientPublic(keyType SigningKeyType, private []byte) ([]byte, error) {
	switch keyType {
	case SigningEdDSASHA512Ed25519:
		return ed25519.NewKeyFromSeed(private).Public().(ed25519.PublicKey), nil
	case SigningRedDSASHA512Ed25519:
		scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(private)
		if err != nil {
			return nil, ErrInvalidIdentity
		}
		return new(edwards25519.Point).ScalarBaseMult(scalar).Bytes(), nil
	}
	return nil, ErrInvalidIdentity
}

type offlineSigning struct {
	expires   uint32
	keyType   SigningKeyType
	public    []byte
	signature []byte
	private   []byte
}

func (o *offlineSigning) meta() OfflineSignature {
	return OfflineSignature{
		Expires:   o.expires,
		Type:      o.keyType,
		PublicKey: append([]byte(nil), o.public...),
		Signature: append([]byte(nil), o.signature...),
	}
}

func (o *offlineSigning) clear() {
	o.public = nil
	o.signature = nil
	clear(o.private)
	o.private = nil
}

func parseOfflineSigning(identity Identity, offline OfflineSignature, transientPrivate []byte) (*offlineSigning, error) {
	publicLen, ok := offline.Type.PublicKeyLen()
	privateLen, privateOK := offlineTransientPrivateLen(offline.Type)
	if !ok || !privateOK || len(offline.PublicKey) != publicLen || len(transientPrivate) != privateLen {
		return nil, ErrInvalidIdentity
	}
	signatureLen, ok := identity.SigningKeyType().SignatureLen()
	if !ok || len(offline.Signature) != signatureLen {
		return nil, ErrInvalidIdentity
	}
	var content [6 + ed25519.PublicKeySize]byte
	if offline.SignedContentLen() > len(content) {
		return nil, ErrInvalidIdentity
	}
	n, err := offline.MarshalSignedContentTo(content[:])
	if err != nil {
		return nil, ErrInvalidIdentity
	}
	valid, err := identity.Verify(content[:n], offline.Signature)
	if err != nil || !valid {
		return nil, ErrInvalidIdentity
	}
	derived, err := offlineTransientPublic(offline.Type, transientPrivate)
	if err != nil || !bytes.Equal(derived, offline.PublicKey) {
		return nil, ErrInvalidIdentity
	}
	return &offlineSigning{
		expires:   offline.Expires,
		keyType:   offline.Type,
		public:    append([]byte(nil), offline.PublicKey...),
		signature: append([]byte(nil), offline.Signature...),
		private:   append([]byte(nil), transientPrivate...),
	}, nil
}

// OfflineSignature returns the offline signature authorizing this destination's
// transient signing key, or false when the destination holds its long-term key.
func (d *LocalDestination) OfflineSignature() (OfflineSignature, bool) {
	if d == nil {
		return OfflineSignature{}, false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released || d.offline == nil {
		return OfflineSignature{}, false
	}
	return d.offline.meta(), true
}

// OfflinePrivateEncodedLen returns the encoded length of the offline signature
// section including the transient private key, or 0 when absent.
func (d *LocalDestination) OfflinePrivateEncodedLen() int {
	if d == nil {
		return 0
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released || d.offline == nil {
		return 0
	}
	return 6 + len(d.offline.public) + len(d.offline.signature) + len(d.offline.private)
}

// MarshalOfflinePrivateTo serializes the offline signature section (expires,
// transient key type, transient public key, authorization signature, transient
// private key) into dst. Callers must wipe dst after use.
func (d *LocalDestination) MarshalOfflinePrivateTo(dst []byte) (int, error) {
	if d == nil {
		return 0, ErrInvalidIdentity
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.released || d.offline == nil {
		return 0, ErrInvalidIdentity
	}
	n := 6 + len(d.offline.public) + len(d.offline.signature) + len(d.offline.private)
	if len(dst) < n {
		return 0, ErrDestinationSmall
	}
	binary.BigEndian.PutUint32(dst[:4], d.offline.expires)
	binary.BigEndian.PutUint16(dst[4:6], uint16(d.offline.keyType))
	off := 6 + copy(dst[6:], d.offline.public)
	off += copy(dst[off:], d.offline.signature)
	copy(dst[off:], d.offline.private)
	return n, nil
}
