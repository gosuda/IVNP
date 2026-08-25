package netdb

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"sync"

	"gosuda.org/ivnp"
)

var ErrLocalRouterIdentity = errors.New("netdb: local RouterInfo identity does not match signing key")

// LocalRouterAddress describes one locally-advertised router transport address.
// Options must be in canonical ascending key order.
type LocalRouterAddress struct {
	Cost           uint8
	Expiration     uint64
	TransportStyle []byte
	Options        []ivnp.MappingEntry
}

// RouterInfoContacts is the mutable contact data of a locally-owned
// RouterInfo. The router identity and its signing key are intentionally not
// replaceable after construction.
type RouterInfoContacts struct {
	Addresses []LocalRouterAddress
	Peers     []ivnp.Hash
	Options   []ivnp.MappingEntry
}

// LocalRouterInfoConfig creates a local RouterInfo owner. Local supplies a
// locally-owned RouterIdentity or legacy Destination and its Ed25519 private
// signing key. Contacts may be replaced atomically before the next publication.
type LocalRouterInfoConfig struct {
	Local    ivnp.LocalIdentityOwner
	Contacts RouterInfoContacts
}

// LocalRouterInfo owns a RouterIdentity, its signing key, and the current
// local contact data. Publish creates and retains an exact signed RouterInfo;
// Snapshot always returns an independent wire copy, so callers cannot mutate
// the retained advertisement.
type LocalRouterInfo struct {
	mu        sync.RWMutex
	identity  []byte
	private   ed25519.PrivateKey
	hash      ivnp.Hash
	contacts  RouterInfoContacts
	raw       []byte
	published uint64
	version   uint64
}

// NewLocalRouterInfo validates and copies a locally-owned Ed25519 identity.
// It performs no network I/O or database insertion.
func NewLocalRouterInfo(config LocalRouterInfoConfig) (*LocalRouterInfo, error) {
	if config.Local == nil {
		return nil, ErrLocalRouterIdentity
	}
	identity, err := config.Local.Identity()
	if err != nil {
		return nil, ErrLocalRouterIdentity
	}
	signingPublic, signingPrivate := config.Local.SigningKeyPair()
	if len(signingPublic) != ed25519.PublicKeySize ||
		len(signingPrivate) != ed25519.PrivateKeySize {
		return nil, ErrLocalRouterIdentity
	}
	first, rest := identity.SigningKeyParts()
	privateProof := ed25519.Sign(signingPrivate, identity.Bytes())
	privateMatchesPublic := ed25519.Verify(first, identity.Bytes(), privateProof)
	clear(privateProof)
	if identity.SigningKeyType() != ivnp.SigningEdDSASHA512Ed25519 ||
		len(rest) != 0 ||
		identity.Hash() != config.Local.IdentityHash() ||
		!bytes.Equal(first, signingPublic) ||
		!bytes.Equal(signingPrivate.Public().(ed25519.PublicKey), signingPublic) ||
		!privateMatchesPublic {
		return nil, ErrLocalRouterIdentity
	}
	contacts, err := cloneRouterInfoContacts(config.Contacts)
	if err != nil {
		return nil, err
	}
	return &LocalRouterInfo{
		identity: append([]byte(nil), identity.Bytes()...),
		private:  append(ed25519.PrivateKey(nil), signingPrivate...),
		hash:     identity.Hash(),
		contacts: contacts,
	}, nil
}

// Hash returns the immutable RouterIdentity hash.
func (r *LocalRouterInfo) Hash() ivnp.Hash { return r.hash }

// Sign returns an Ed25519 signature made by this local RouterInfo's immutable
// router signing key. It is intended for authenticated router transport
// control messages such as SSU2 introductions.
func (r *LocalRouterInfo) Sign(message []byte) []byte {
	r.mu.RLock()
	signature := ed25519.Sign(r.private, message)
	r.mu.RUnlock()
	return signature
}

// Published returns the timestamp of the currently retained publication, or
// zero when Publish has not succeeded since construction or contact replacement.
func (r *LocalRouterInfo) Published() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.published
}

// Version increases after each successful contact replacement and publication.
func (r *LocalRouterInfo) Version() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.version
}

// ReplaceContacts atomically replaces contact data and invalidates the prior
// RouterInfo. The old signed advertisement remains owned by any recipient that
// already received it; Snapshot returns no value until the next Publish.
func (r *LocalRouterInfo) ReplaceContacts(contacts RouterInfoContacts) error {
	owned, err := cloneRouterInfoContacts(contacts)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.contacts = owned
	r.raw = nil
	r.published = 0
	r.version++
	r.mu.Unlock()
	return nil
}

// Publish signs and retains a RouterInfo with published expressed as Unix
// milliseconds. It does not transmit or insert the advertisement into netdb.
func (r *LocalRouterInfo) Publish(published uint64) (RouterInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	raw, err := marshalLocalRouterInfo(r.identity, r.private, published, r.contacts)
	if err != nil {
		return RouterInfo{}, err
	}
	r.raw = raw
	r.published = published
	r.version++
	return parseOwnedRouterInfo(raw)
}

// Snapshot returns a copy of the most recently published RouterInfo. It is
// false until Publish succeeds or after ReplaceContacts invalidates it.
func (r *LocalRouterInfo) Snapshot() (RouterInfo, bool) {
	r.mu.RLock()
	if len(r.raw) == 0 {
		r.mu.RUnlock()
		return RouterInfo{}, false
	}
	raw := append([]byte(nil), r.raw...)
	r.mu.RUnlock()
	info, err := ParseRouterInfo(raw)
	if err != nil {
		return RouterInfo{}, false
	}
	return info, true
}

func cloneRouterInfoContacts(contacts RouterInfoContacts) (RouterInfoContacts, error) {
	if len(contacts.Addresses) > MaxRouterAddresses || len(contacts.Peers) > MaxRouterPeers {
		return RouterInfoContacts{}, ErrTooManyItems
	}
	if _, err := ivnp.MappingEncodedLen(contacts.Options); err != nil {
		return RouterInfoContacts{}, err
	}
	owned := RouterInfoContacts{
		Addresses: make([]LocalRouterAddress, len(contacts.Addresses)),
		Peers:     append([]ivnp.Hash(nil), contacts.Peers...),
		Options:   cloneMappingEntries(contacts.Options),
	}
	for index, address := range contacts.Addresses {
		if len(address.TransportStyle) == 0 || len(address.TransportStyle) > 255 {
			return RouterInfoContacts{}, ErrMalformed
		}
		if _, err := ivnp.MappingEncodedLen(address.Options); err != nil {
			return RouterInfoContacts{}, err
		}
		owned.Addresses[index] = LocalRouterAddress{
			Cost:           address.Cost,
			Expiration:     address.Expiration,
			TransportStyle: append([]byte(nil), address.TransportStyle...),
			Options:        cloneMappingEntries(address.Options),
		}
	}
	return owned, nil
}

func cloneMappingEntries(entries []ivnp.MappingEntry) []ivnp.MappingEntry {
	owned := make([]ivnp.MappingEntry, len(entries))
	for index, entry := range entries {
		owned[index] = ivnp.MappingEntry{
			Key:   append([]byte(nil), entry.Key...),
			Value: append([]byte(nil), entry.Value...),
		}
	}
	return owned
}

func marshalLocalRouterInfo(identity []byte, private ed25519.PrivateKey, published uint64, contacts RouterInfoContacts) ([]byte, error) {
	parsedIdentity, consumed, err := ivnp.ParseIdentity(identity)
	if err != nil || consumed != len(identity) {
		return nil, ErrLocalRouterIdentity
	}
	signatureLen, ok := parsedIdentity.SigningKeyType().SignatureLen()
	if !ok {
		return nil, ivnp.ErrUnknownKeyType
	}

	n := len(identity) + 8 + 1 + 1 + len(contacts.Peers)*ivnp.HashLength + signatureLen
	optionsLen, err := ivnp.MappingEncodedLen(contacts.Options)
	if err != nil {
		return nil, err
	}
	n += optionsLen
	for _, address := range contacts.Addresses {
		optionsLen, err = ivnp.MappingEncodedLen(address.Options)
		if err != nil {
			return nil, err
		}
		n += 1 + 8 + 1 + len(address.TransportStyle) + optionsLen
	}
	if n > MaxRouterInfoBytes {
		return nil, ErrStructureTooLarge
	}

	raw := make([]byte, n)
	offset := copy(raw, identity)
	binary.BigEndian.PutUint64(raw[offset:offset+8], published)
	offset += 8
	raw[offset] = byte(len(contacts.Addresses))
	offset++
	for _, address := range contacts.Addresses {
		raw[offset] = address.Cost
		offset++
		binary.BigEndian.PutUint64(raw[offset:offset+8], address.Expiration)
		offset += 8
		raw[offset] = byte(len(address.TransportStyle))
		offset++
		offset += copy(raw[offset:], address.TransportStyle)
		written, err := ivnp.MarshalMappingTo(raw[offset:], address.Options)
		if err != nil {
			return nil, err
		}
		offset += written
	}
	raw[offset] = byte(len(contacts.Peers))
	offset++
	for _, peer := range contacts.Peers {
		offset += copy(raw[offset:], peer[:])
	}
	written, err := ivnp.MarshalMappingTo(raw[offset:], contacts.Options)
	if err != nil {
		return nil, err
	}
	offset += written
	copy(raw[offset:], ed25519.Sign(private, raw[:offset]))

	if offset+signatureLen != len(raw) {
		return nil, ErrMalformed
	}
	return raw, nil
}

func parseOwnedRouterInfo(raw []byte) (RouterInfo, error) {
	copyRaw := append([]byte(nil), raw...)
	info, err := ParseRouterInfo(copyRaw)
	if err != nil {
		return RouterInfo{}, err
	}
	return info, nil
}
