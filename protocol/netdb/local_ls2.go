package netdb

import (
	"encoding/binary"
	"errors"
	"sync"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/protocol/i2np"
)

var ErrLocalLeaseSet2 = errors.New("netdb: invalid local LeaseSet2")

// LocalLeaseSet2 owns the public identity and current inbound leases for one
// ECIES local Destination. It deliberately has no transport or tunnel-global
// state: its caller supplies only that Destination's inbound lease source.
type LocalLeaseSet2 struct {
	identity ivnp.Identity
	hash     ivnp.Hash
	public   [32]byte
	types    []ivnp.CryptoKeyType
	mu       sync.RWMutex
	leases   []Lease2
}

func NewLocalLeaseSet2(destination *ivnp.LocalDestination) (*LocalLeaseSet2, error) {
	return NewLocalLeaseSet2WithTypes(destination, nil)
}

// NewLocalLeaseSet2WithTypes publishes exactly the requested ordered subset of
// the destination's locally-supported encryption types.
func NewLocalLeaseSet2WithTypes(destination *ivnp.LocalDestination, requested []ivnp.CryptoKeyType) (*LocalLeaseSet2, error) {
	if destination == nil {
		return nil, ErrLocalLeaseSet2
	}
	identity, err := destination.Identity()
	if err != nil || (identity.CryptoKeyType() != ivnp.CryptoX25519 && identity.CryptoKeyType() != ivnp.CryptoElGamal) ||
		(identity.SigningKeyType() != ivnp.SigningEdDSASHA512Ed25519 && identity.SigningKeyType() != ivnp.SigningRedDSASHA512Ed25519) ||
		(identity.CryptoKeyType() == ivnp.CryptoElGamal && identity.SigningKeyType() != ivnp.SigningEdDSASHA512Ed25519) {
		return nil, ErrLocalLeaseSet2
	}
	raw := append([]byte(nil), identity.Bytes()...)
	owned, n, err := ivnp.ParseIdentity(raw)
	if err != nil || n != len(raw) {
		return nil, ErrLocalLeaseSet2
	}
	public, err := destination.CryptoPublic(ivnp.CryptoX25519)
	if err != nil {
		return nil, ErrLocalLeaseSet2
	}
	supported := destination.CryptoTypes()
	if supported != [3]ivnp.CryptoKeyType{ivnp.CryptoMLKEM1024X25519, ivnp.CryptoMLKEM768X25519, ivnp.CryptoX25519} {
		return nil, ErrLocalLeaseSet2
	}
	types := append([]ivnp.CryptoKeyType(nil), requested...)
	if len(types) == 0 {
		types = append(types, supported[:]...)
	}
	if len(types) > len(supported) {
		return nil, ErrLocalLeaseSet2
	}
	seen := make(map[ivnp.CryptoKeyType]bool, len(types))
	for _, cryptoType := range types {
		valid := cryptoType == supported[0] || cryptoType == supported[1] || cryptoType == supported[2]
		if !valid || seen[cryptoType] {
			return nil, ErrLocalLeaseSet2
		}
		seen[cryptoType] = true
	}
	return &LocalLeaseSet2{identity: owned, hash: owned.Hash(), public: public, types: types}, nil
}

func (s *LocalLeaseSet2) Hash() ivnp.Hash { return s.hash }

func (s *LocalLeaseSet2) ReplaceInboundLeases(leases []Lease) error {
	if s == nil || len(leases) > MaxLeases {
		return ErrLocalLeaseSet2
	}
	converted := make([]Lease2, 0, len(leases))
	for _, lease := range leases {
		if lease.TunnelID == 0 || lease.EndDate/1000 > uint64(^uint32(0)) {
			return ErrLocalLeaseSet2
		}
		converted = append(converted, Lease2{Gateway: lease.Gateway, TunnelID: lease.TunnelID, EndDate: uint32(lease.EndDate / 1000)})
	}
	s.mu.Lock()
	s.leases = converted
	s.mu.Unlock()
	return nil
}

// MarshalTo emits a canonical signed LS2 payload. The supplied clock is Unix
// milliseconds and is reduced to protocol seconds only at this wire boundary.
func (s *LocalLeaseSet2) MarshalTo(dst []byte, nowMillis uint64, sign func([]byte) ([]byte, error)) (int, error) {
	if s == nil || sign == nil {
		return 0, ErrLocalLeaseSet2
	}
	s.mu.RLock()
	identity := s.identity
	public := s.public
	types := append([]ivnp.CryptoKeyType(nil), s.types...)
	leases := append([]Lease2(nil), s.leases...)
	s.mu.RUnlock()
	if len(leases) == 0 || len(leases) > MaxLeases {
		return 0, ErrLocalLeaseSet2
	}
	published := nowMillis / 1000
	if published > uint64(^uint32(0)) {
		return 0, ErrLocalLeaseSet2
	}
	var latest uint32
	for _, lease := range leases {
		if lease.TunnelID == 0 || lease.EndDate <= uint32(published) {
			return 0, ErrLocalLeaseSet2
		}
		if lease.EndDate > latest {
			latest = lease.EndDate
		}
	}
	expires := uint64(latest) - published
	if expires == 0 || expires > uint64(^uint16(0)) {
		return 0, ErrLocalLeaseSet2
	}
	identityBytes := identity.Bytes()
	// Types 7, 6, and 4 share this Destination's persisted static X25519
	// public key. Hybrid New Sessions add their one-use ML-KEM section to the
	// authenticated transcript; the LeaseSet key remains the 32-byte static.
	keyCount := len(types)
	if keyCount == 0 || keyCount > 255 {
		return 0, ErrLocalLeaseSet2
	}
	unsignedLen := len(identityBytes) + 8 + 2 + 1 + keyCount*(4+32) + 1 + len(leases)*40
	signatureLen, ok := identity.SigningKeyType().SignatureLen()
	if !ok || len(dst) < unsignedLen+signatureLen {
		return 0, ivnp.ErrDestinationSmall
	}
	off := copy(dst, identityBytes)
	binary.BigEndian.PutUint32(dst[off:off+4], uint32(published))
	off += 4
	binary.BigEndian.PutUint16(dst[off:off+2], uint16(expires))
	off += 2
	binary.BigEndian.PutUint16(dst[off:off+2], 0)
	off += 2
	// Canonical empty mapping and every locally accepted encryption format in
	// local preference order, independent of a resolver's parser order.
	dst[off], dst[off+1] = 0, 0
	off += 2
	dst[off] = byte(keyCount)
	off++
	for _, cryptoType := range types {
		binary.BigEndian.PutUint16(dst[off:off+2], uint16(cryptoType))
		binary.BigEndian.PutUint16(dst[off+2:off+4], 32)
		copy(dst[off+4:off+36], public[:])
		off += 36
	}
	dst[off] = byte(len(leases))
	off++
	for _, lease := range leases {
		copy(dst[off:off+32], lease.Gateway[:])
		binary.BigEndian.PutUint32(dst[off+32:off+36], lease.TunnelID)
		binary.BigEndian.PutUint32(dst[off+36:off+40], lease.EndDate)
		off += 40
	}
	signed := make([]byte, off+1)
	signed[0] = byte(i2np.StoreLeaseSet2)
	copy(signed[1:], dst[:off])
	signature, err := sign(signed)
	clear(signed)
	if err != nil || len(signature) != signatureLen {
		return 0, ErrLocalLeaseSet2
	}
	copy(dst[off:], signature)
	return off + signatureLen, nil
}
