package netdb

import (
	"encoding/binary"
	"sync"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/wire"
)

// LocalLeaseSet holds locally published inbound-lease metadata. It does not
// retain encryption or signing private keys; callers supply public keys and a
// signer when they serialize a publication.
type LocalLeaseSet struct {
	mu       sync.RWMutex
	identity []byte
	hash     foundation.Hash
	leases   []Lease
	version  uint64
}

// LocalLeaseSetSnapshot is an immutable-at-return view of local inbound lease
// metadata. ExpiresAt is the earliest end date of the leases in Leases, or zero
// when no lease is current at the requested time.
type LocalLeaseSetSnapshot struct {
	Identity  foundation.Identity
	Leases    []Lease
	ExpiresAt uint64
	Version   uint64
}

// MarshalLegacy serializes the snapshot as a signed legacy LeaseSet. The
// supplied keys are public keys; sign receives precisely the unsigned LeaseSet
// prefix and must return a signature for Identity's signing key type.
func (s LocalLeaseSetSnapshot) MarshalLegacy(dst, encryptionKey, signingKey []byte, sign func([]byte) ([]byte, error)) (int, error) {
	identityBytes := s.Identity.Bytes()
	identity, identityLen, err := foundation.ParseIdentity(identityBytes)
	if err != nil {
		return 0, err
	}
	if identityLen != len(identityBytes) {
		return 0, ErrMalformed
	}
	if len(encryptionKey) != 256 {
		return 0, ErrInvalidKeyLength
	}
	signingKeyLen, ok := identity.SigningKeyType().PublicKeyLen()
	if !ok {
		return 0, foundation.ErrUnknownKeyType
	}
	if len(signingKey) != signingKeyLen {
		return 0, ErrInvalidKeyLength
	}
	signatureLen, ok := identity.SigningKeyType().SignatureLen()
	if !ok {
		return 0, foundation.ErrUnknownKeyType
	}
	if len(s.Leases) > MaxLeases {
		return 0, ErrTooManyItems
	}
	for _, lease := range s.Leases {
		if lease.TunnelID == 0 {
			return 0, ErrMalformed
		}
	}

	unsignedLen := identityLen + len(encryptionKey) + signingKeyLen + 1 + len(s.Leases)*44
	totalLen := unsignedLen + signatureLen
	if totalLen > MaxLeaseSetBytes {
		return 0, ErrStructureTooLarge
	}
	if len(dst) < totalLen {
		return 0, wire.ErrShortBuffer
	}
	if sign == nil {
		return 0, ErrMalformed
	}

	offset := copy(dst, identityBytes)
	offset += copy(dst[offset:], encryptionKey)
	offset += copy(dst[offset:], signingKey)
	dst[offset] = byte(len(s.Leases))
	offset++
	for _, lease := range s.Leases {
		copy(dst[offset:offset+foundation.HashLength], lease.Gateway[:])
		binary.BigEndian.PutUint32(dst[offset+foundation.HashLength:offset+foundation.HashLength+4], lease.TunnelID)
		binary.BigEndian.PutUint64(dst[offset+foundation.HashLength+4:offset+44], lease.EndDate)
		offset += 44
	}

	signature, err := sign(dst[:offset])
	if err != nil {
		return 0, err
	}
	if len(signature) != signatureLen {
		return 0, foundation.ErrMalformedSignature
	}
	copy(dst[offset:], signature)
	return totalLen, nil
}

// NewLocalLeaseSet creates local publication metadata for identity. The
// identity is copied so later mutation of identity's backing bytes cannot
// change locally published metadata.
func NewLocalLeaseSet(identity foundation.Identity) (*LocalLeaseSet, error) {
	encoded := append([]byte(nil), identity.Bytes()...)
	owned, n, err := foundation.ParseIdentity(encoded)
	if err != nil {
		return nil, err
	}
	if n != len(encoded) {
		return nil, ErrMalformed
	}
	return &LocalLeaseSet{identity: encoded, hash: owned.Hash()}, nil
}

// Hash returns the local destination hash.
func (s *LocalLeaseSet) Hash() foundation.Hash { return s.hash }

// ReplaceInboundLeases atomically replaces the locally published inbound
// leases. The protocol's LeaseSet limit applies before state is modified.
func (s *LocalLeaseSet) ReplaceInboundLeases(leases []Lease) error {
	if len(leases) > MaxLeases {
		return ErrTooManyItems
	}
	for _, lease := range leases {
		if lease.TunnelID == 0 {
			return ErrMalformed
		}
	}

	s.mu.Lock()
	s.leases = append(s.leases[:0], leases...)
	s.version++
	s.mu.Unlock()
	return nil
}

// Expire removes locally published leases whose end date is before nowMillis.
// A lease ending exactly at nowMillis remains current, matching netdb expiry
// handling for received LeaseSets.
func (s *LocalLeaseSet) Expire(nowMillis uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	kept := s.leases[:0]
	removed := 0
	for _, lease := range s.leases {
		if lease.EndDate < nowMillis {
			removed++
			continue
		}
		kept = append(kept, lease)
	}
	if removed != 0 {
		s.leases = kept
		s.version++
	}
	return removed
}

// Snapshot returns local metadata that is current at nowMillis. Its identity
// and lease slice are independent of both the builder and later replacements.
// The boolean is false only if the internally retained identity cannot be
// reparsed; callers must treat that as an unusable local publication.
func (s *LocalLeaseSet) Snapshot(nowMillis uint64) (LocalLeaseSetSnapshot, bool) {
	s.mu.RLock()
	identity := append([]byte(nil), s.identity...)
	leases := make([]Lease, 0, len(s.leases))
	var expiresAt uint64
	for _, lease := range s.leases {
		if lease.EndDate < nowMillis {
			continue
		}
		leases = append(leases, lease)
		if expiresAt == 0 || lease.EndDate < expiresAt {
			expiresAt = lease.EndDate
		}
	}
	version := s.version
	s.mu.RUnlock()

	identityView, _, err := foundation.ParseIdentity(identity)
	if err != nil {
		return LocalLeaseSetSnapshot{}, false
	}
	return LocalLeaseSetSnapshot{
		Identity:  identityView,
		Leases:    leases,
		ExpiresAt: expiresAt,
		Version:   version,
	}, true
}
