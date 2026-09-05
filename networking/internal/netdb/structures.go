// Package netdb parses and validates I2P network-database structures without
// copying their wire data. It deliberately separates parsing from signature
// verification so callers can apply admission policy before expensive crypto.
package netdb

import (
	"bytes"
	"encoding/binary"
	"errors"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/wire"
	"gosuda.org/ivnp/networking/internal/i2np"
)

const (
	MaxRouterInfoBytes            = 4 * 1024 // Java I2P RouterInfo.MAX_UNCOMPRESSED_SIZE
	MaxLeaseSetBytes              = i2np.I2PDMaxPayload
	MinEncryptedLeaseSetDataBytes = 24   // Java I2P EncryptedLeaseSet.MIN_ENCRYPTED_SIZE
	MaxEncryptedLeaseSetDataBytes = 4096 // Java I2P EncryptedLeaseSet.MAX_ENCRYPTED_SIZE
	MaxRouterAddresses            = 255  // one-byte address count
	MaxRouterPeers                = 255  // one-byte peer hash count
	MaxLeases                     = 16   // Java I2P LeaseSet.MAX_LEASES
	MaxLeaseSet2Keys              = 8    // Java I2P LeaseSet2.MAX_KEYS
)

var (
	ErrMalformed                = errors.New("netdb: malformed structure")
	ErrTooManyItems             = errors.New("netdb: count exceeds protocol limit")
	ErrInvalidKeyLength         = errors.New("netdb: key length disagrees with key type")
	ErrStructureTooLarge        = errors.New("netdb: structure exceeds protocol limit")
	ErrNoSupportedEncryptionKey = errors.New("netdb: no supported LeaseSet2 encryption key")
)

// RouterAddress is one contact endpoint in a RouterInfo.
type RouterAddress struct {
	Cost           uint8
	Expiration     uint64
	TransportStyle []byte
	Options        foundation.Mapping
	raw            []byte
}

func (a RouterAddress) Bytes() []byte { return a.raw }

// ParseRouterAddress parses one self-delimiting RouterAddress.
func ParseRouterAddress(src []byte) (RouterAddress, int, error) {
	cursor := wire.NewCursor(src)
	cost, err := cursor.ReadU8()
	if err != nil {
		return RouterAddress{}, 0, err
	}
	expiration, err := cursor.ReadU64()
	if err != nil {
		return RouterAddress{}, 0, err
	}
	styleLen, err := cursor.ReadU8()
	if err != nil {
		return RouterAddress{}, 0, err
	}
	if styleLen == 0 {
		return RouterAddress{}, 0, ErrMalformed
	}
	style, err := cursor.ReadBytes(int(styleLen))
	if err != nil {
		return RouterAddress{}, 0, err
	}
	options, n, err := foundation.ParseMapping(cursor.Bytes())
	if err != nil {
		return RouterAddress{}, 0, err
	}
	if err = options.ValidateCanonical(); err != nil {
		return RouterAddress{}, 0, err
	}
	if err = cursor.Skip(n); err != nil {
		return RouterAddress{}, 0, err
	}
	return RouterAddress{Cost: cost, Expiration: expiration, TransportStyle: style, Options: options, raw: src[:cursor.Offset()]}, cursor.Offset(), nil
}

// RouterAddressIterator parses the address region of a RouterInfo lazily.
type RouterAddressIterator struct {
	rest []byte
	left uint8
}

func (it *RouterAddressIterator) Next() (RouterAddress, bool, error) {
	if it.left == 0 {
		return RouterAddress{}, false, nil
	}
	address, n, err := ParseRouterAddress(it.rest)
	if err != nil {
		return RouterAddress{}, false, err
	}
	it.rest = it.rest[n:]
	it.left--
	return address, true, nil
}

// RouterInfo is a fully delimited signed netdb RouterInfo.
type RouterInfo struct {
	Identity     foundation.Identity
	Published    uint64
	addressCount uint8
	addresses    []byte
	PeerHashes   []byte
	Options      foundation.Mapping
	Signature    []byte
	Unsigned     []byte
	raw          []byte
}

func (r RouterInfo) Bytes() []byte         { return r.raw }
func (r RouterInfo) Hash() foundation.Hash { return r.Identity.Hash() }
func (r RouterInfo) AddressCount() int     { return int(r.addressCount) }
func (r RouterInfo) Addresses() RouterAddressIterator {
	return RouterAddressIterator{rest: r.addresses, left: r.addressCount}
}
func (r RouterInfo) PeerCount() int { return len(r.PeerHashes) / foundation.HashLength }

// IsFloodfill reports the RouterInfo capability defined by I2P: the `caps`
// option contains the ASCII capability letter `f`.
func IsFloodfill(r RouterInfo) bool {
	iterator := r.Options.Iterator()
	for {
		key, value, ok, err := iterator.Next()
		if err != nil || !ok {
			return false
		}
		if bytes.Equal(key, []byte("caps")) && bytes.IndexByte(value, 'f') >= 0 {
			return true
		}
	}
}

// Verify validates the RouterInfo signature with its RouterIdentity key.
func (r RouterInfo) Verify() (bool, error) {
	return r.Identity.Verify(r.Unsigned, r.Signature)
}

// ParseRouterInfo accepts exactly one complete, signed RouterInfo.
func ParseRouterInfo(src []byte) (RouterInfo, error) {
	if len(src) > MaxRouterInfoBytes {
		return RouterInfo{}, ErrStructureTooLarge
	}
	identity, n, err := foundation.ParseIdentity(src)
	if err != nil {
		return RouterInfo{}, err
	}
	cursor := wire.NewCursor(src[n:])
	published, err := cursor.ReadU64()
	if err != nil {
		return RouterInfo{}, err
	}
	addressCount, err := cursor.ReadU8()
	if err != nil {
		return RouterInfo{}, err
	}
	addressesStart := cursor.Offset()
	for range addressCount {
		_, used, err := ParseRouterAddress(cursor.Bytes())
		if err != nil {
			return RouterInfo{}, err
		}
		if err = cursor.Skip(used); err != nil {
			return RouterInfo{}, err
		}
	}
	addresses := src[n+addressesStart : n+cursor.Offset()]
	peerCount, err := cursor.ReadU8()
	if err != nil {
		return RouterInfo{}, err
	}
	peerBytes := int(peerCount) * foundation.HashLength
	peerHashes, err := cursor.ReadBytes(peerBytes)
	if err != nil {
		return RouterInfo{}, err
	}
	options, used, err := foundation.ParseMapping(cursor.Bytes())
	if err != nil {
		return RouterInfo{}, err
	}
	if err = options.ValidateCanonical(); err != nil {
		return RouterInfo{}, err
	}
	if err = cursor.Skip(used); err != nil {
		return RouterInfo{}, err
	}
	signingLen, ok := identity.SigningKeyType().SignatureLen()
	if !ok {
		return RouterInfo{}, foundation.ErrUnknownKeyType
	}
	unsignedEnd := n + cursor.Offset()
	signature, err := cursor.ReadBytes(signingLen)
	if err != nil {
		return RouterInfo{}, err
	}
	if !cursor.Done() {
		return RouterInfo{}, ErrMalformed
	}
	return RouterInfo{
		Identity:     identity,
		Published:    published,
		addressCount: addressCount,
		addresses:    addresses,
		PeerHashes:   peerHashes,
		Options:      options,
		Signature:    signature,
		Unsigned:     src[:unsignedEnd],
		raw:          src,
	}, nil
}

// Lease authorizes one inbound tunnel until EndDate milliseconds since epoch.
type Lease struct {
	Gateway  foundation.Hash
	TunnelID uint32
	EndDate  uint64
}

func parseLease(src []byte) (Lease, error) {
	if len(src) < 44 {
		return Lease{}, wire.ErrShortBuffer
	}
	var lease Lease
	copy(lease.Gateway[:], src[:32])
	lease.TunnelID = binary.BigEndian.Uint32(src[32:36])
	if lease.TunnelID == 0 {
		return Lease{}, ErrMalformed
	}
	lease.EndDate = binary.BigEndian.Uint64(src[36:44])
	return lease, nil
}

// LeaseIterator decodes a contiguous sequence of 44-byte legacy leases.
type LeaseIterator struct{ rest []byte }

func (it *LeaseIterator) Next() (Lease, bool, error) {
	if len(it.rest) == 0 {
		return Lease{}, false, nil
	}
	lease, err := parseLease(it.rest)
	if err != nil {
		return Lease{}, false, err
	}
	it.rest = it.rest[44:]
	return lease, true, nil
}

// LeaseSet is the legacy DatabaseStore type 1 payload.
type LeaseSet struct {
	Destination   foundation.Identity
	EncryptionKey []byte
	SigningKey    []byte
	leaseCount    uint8
	leases        []byte
	Signature     []byte
	Unsigned      []byte
	raw           []byte
}

func (s LeaseSet) Bytes() []byte         { return s.raw }
func (s LeaseSet) Hash() foundation.Hash { return s.Destination.Hash() }
func (s LeaseSet) LeaseCount() int       { return int(s.leaseCount) }
func (s LeaseSet) Leases() LeaseIterator { return LeaseIterator{rest: s.leases} }

// Verify validates the legacy LeaseSet signature with the destination key.
func (s LeaseSet) Verify() (bool, error) {
	return s.Destination.Verify(s.Unsigned, s.Signature)
}

// ParseLeaseSet parses the full, exact legacy LeaseSet payload.
func ParseLeaseSet(src []byte) (LeaseSet, error) {
	if len(src) > MaxLeaseSetBytes {
		return LeaseSet{}, ErrStructureTooLarge
	}
	destination, n, err := foundation.ParseIdentity(src)
	if err != nil {
		return LeaseSet{}, err
	}
	cursor := wire.NewCursor(src[n:])
	encryptionKey, err := cursor.ReadBytes(256)
	if err != nil {
		return LeaseSet{}, err
	}
	signingKeyLen, ok := destination.SigningKeyType().PublicKeyLen()
	if !ok {
		return LeaseSet{}, foundation.ErrUnknownKeyType
	}
	signingKey, err := cursor.ReadBytes(signingKeyLen)
	if err != nil {
		return LeaseSet{}, err
	}
	leaseCount, err := cursor.ReadU8()
	if err != nil {
		return LeaseSet{}, err
	}
	if leaseCount > MaxLeases {
		return LeaseSet{}, ErrTooManyItems
	}
	leases, err := cursor.ReadBytes(int(leaseCount) * 44)
	if err != nil {
		return LeaseSet{}, err
	}
	for offset := 0; offset < len(leases); offset += 44 {
		if _, err = parseLease(leases[offset:]); err != nil {
			return LeaseSet{}, err
		}
	}
	unsignedEnd := n + cursor.Offset()
	signatureLen, ok := destination.SigningKeyType().SignatureLen()
	if !ok {
		return LeaseSet{}, foundation.ErrUnknownKeyType
	}
	signature, err := cursor.ReadBytes(signatureLen)
	if err != nil {
		return LeaseSet{}, err
	}
	if !cursor.Done() {
		return LeaseSet{}, ErrMalformed
	}
	return LeaseSet{Destination: destination, EncryptionKey: encryptionKey, SigningKey: signingKey, leaseCount: leaseCount, leases: leases, Signature: signature, Unsigned: src[:unsignedEnd], raw: src}, nil
}

// LeaseSet2Header is the common signed-structure prefix for LS2 and MetaLS.
type LeaseSet2Header struct {
	Destination foundation.Identity
	Published   uint32
	Expires     uint16
	Flags       uint16
	Offline     OfflineSignature
}

const leaseSetOfflineFlag = 1

// OfflineSignature authorizes a transient signing public key.
type OfflineSignature struct {
	Expires   uint32
	Type      foundation.SigningKeyType
	PublicKey []byte
	Signature []byte
	Signed    []byte
}

func (o OfflineSignature) Present() bool { return o.PublicKey != nil }

func parseLeaseSet2Header(src []byte) (LeaseSet2Header, int, error) {
	destination, n, err := foundation.ParseIdentity(src)
	if err != nil {
		return LeaseSet2Header{}, 0, err
	}
	cursor := wire.NewCursor(src[n:])
	published, err := cursor.ReadU32()
	if err != nil {
		return LeaseSet2Header{}, 0, err
	}
	expires, err := cursor.ReadU16()
	if err != nil {
		return LeaseSet2Header{}, 0, err
	}
	flags, err := cursor.ReadU16()
	if err != nil {
		return LeaseSet2Header{}, 0, err
	}
	header := LeaseSet2Header{Destination: destination, Published: published, Expires: expires, Flags: flags}
	if flags&leaseSetOfflineFlag == 0 {
		return header, n + cursor.Offset(), nil
	}
	offlineStart := cursor.Offset()
	offlineExpires, err := cursor.ReadU32()
	if err != nil {
		return LeaseSet2Header{}, 0, err
	}
	typeID, err := cursor.ReadU16()
	if err != nil {
		return LeaseSet2Header{}, 0, err
	}
	offlineType := foundation.SigningKeyType(typeID)
	keyLen, ok := offlineType.PublicKeyLen()
	if !ok {
		return LeaseSet2Header{}, 0, foundation.ErrUnknownKeyType
	}
	publicKey, err := cursor.ReadBytes(keyLen)
	if err != nil {
		return LeaseSet2Header{}, 0, err
	}
	signatureLen, ok := destination.SigningKeyType().SignatureLen()
	if !ok {
		return LeaseSet2Header{}, 0, foundation.ErrUnknownKeyType
	}
	signature, err := cursor.ReadBytes(signatureLen)
	if err != nil {
		return LeaseSet2Header{}, 0, err
	}
	header.Offline = OfflineSignature{Expires: offlineExpires, Type: offlineType, PublicKey: publicKey, Signature: signature, Signed: src[n+offlineStart : n+cursor.Offset()-signatureLen]}
	return header, n + cursor.Offset(), nil
}

// Lease2 authorizes one inbound tunnel until EndDate seconds since epoch.
type Lease2 struct {
	Gateway  foundation.Hash
	TunnelID uint32
	EndDate  uint32
}

func parseLease2(src []byte) (Lease2, error) {
	if len(src) < 40 {
		return Lease2{}, wire.ErrShortBuffer
	}
	var lease Lease2
	copy(lease.Gateway[:], src[:32])
	lease.TunnelID = binary.BigEndian.Uint32(src[32:36])
	if lease.TunnelID == 0 {
		return Lease2{}, ErrMalformed
	}
	lease.EndDate = binary.BigEndian.Uint32(src[36:40])
	return lease, nil
}

// Lease2Iterator decodes a contiguous sequence of 40-byte Lease2 records.
type Lease2Iterator struct{ rest []byte }

func (it *Lease2Iterator) Next() (Lease2, bool, error) {
	if len(it.rest) == 0 {
		return Lease2{}, false, nil
	}
	lease, err := parseLease2(it.rest)
	if err != nil {
		return Lease2{}, false, err
	}
	it.rest = it.rest[40:]
	return lease, true, nil
}

// EncryptionKey is a self-delimiting LeaseSet2 encryption key.
type EncryptionKey struct {
	Type foundation.CryptoKeyType
	Data []byte
}

// EncryptionKeyIterator parses the exact key count announced by LeaseSet2.
type EncryptionKeyIterator struct {
	rest []byte
	left uint8
}

func (it *EncryptionKeyIterator) Next() (EncryptionKey, bool, error) {
	if it.left == 0 {
		return EncryptionKey{}, false, nil
	}
	if len(it.rest) < 4 {
		return EncryptionKey{}, false, wire.ErrShortBuffer
	}
	keyType := foundation.CryptoKeyType(binary.BigEndian.Uint16(it.rest[:2]))
	if keyType == foundation.CryptoKeyType(5) {
		return EncryptionKey{}, false, ErrNoSupportedEncryptionKey
	}
	keyLen := int(binary.BigEndian.Uint16(it.rest[2:4]))
	if keyLen > len(it.rest)-4 {
		return EncryptionKey{}, false, wire.ErrShortBuffer
	}
	if expected, known := keyType.PublicKeyLen(); known && expected != keyLen {
		return EncryptionKey{}, false, ErrInvalidKeyLength
	}
	key := EncryptionKey{Type: keyType, Data: it.rest[4 : 4+keyLen]}
	it.rest = it.rest[4+keyLen:]
	it.left--
	return key, true, nil
}

// LeaseSet2 is an exact unencrypted LS2 DatabaseStore type 3 payload.
type LeaseSet2 struct {
	Header     LeaseSet2Header
	Options    foundation.Mapping
	keyCount   uint8
	keys       []byte
	leaseCount uint8
	leases     []byte
	Signature  []byte
	Unsigned   []byte
	raw        []byte
}

func (s LeaseSet2) Bytes() []byte         { return s.raw }
func (s LeaseSet2) Hash() foundation.Hash { return s.Header.Destination.Hash() }
func (s LeaseSet2) KeyCount() int         { return int(s.keyCount) }
func (s LeaseSet2) Keys() EncryptionKeyIterator {
	return EncryptionKeyIterator{rest: s.keys, left: s.keyCount}
}

// SelectEncryptionKey returns the first supported type in caller preference
// order, independent of the order selected by the remote LeaseSet producer.
// Callers pass 7, 6, 4 to prefer ML-KEM-1024/X25519, then
// ML-KEM-768/X25519, then X25519.
func (s LeaseSet2) SelectEncryptionKey(supported ...foundation.CryptoKeyType) (EncryptionKey, error) {
	for _, preferred := range supported {
		iterator := s.Keys()
		for {
			key, ok, err := iterator.Next()
			if err != nil {
				return EncryptionKey{}, err
			}
			if !ok {
				break
			}
			if key.Type == preferred {
				return key, nil
			}
		}
	}
	return EncryptionKey{}, ErrNoSupportedEncryptionKey
}

// SelectUsableEncryptionKey selects by caller preference only when the LS2
// still has a live lease at nowMillis. It is the resolution boundary used by
// callers that must not downgrade an ELS2 to a plaintext/expired route.
func (s LeaseSet2) SelectUsableEncryptionKey(nowMillis uint64, supported ...foundation.CryptoKeyType) (EncryptionKey, error) {
	now := nowMillis / 1000
	leases := s.Leases()
	live := false
	for {
		lease, ok, err := leases.Next()
		if err != nil {
			return EncryptionKey{}, err
		}
		if !ok {
			break
		}
		if uint64(lease.EndDate) > now {
			live = true
			break
		}
	}
	if !live {
		return EncryptionKey{}, ErrELSExpired
	}
	return s.SelectEncryptionKey(supported...)
}
func (s LeaseSet2) LeaseCount() int        { return int(s.leaseCount) }
func (s LeaseSet2) Leases() Lease2Iterator { return Lease2Iterator{rest: s.leases} }

// Verify validates any offline-key authorization and then the LeaseSet2
// signature, whose signed input starts with DatabaseStore type byte 3.
func (s LeaseSet2) Verify() (bool, error) {
	signingType := s.Header.Destination.SigningKeyType()
	first, rest := s.Header.Destination.SigningKeyParts()
	if s.Header.Offline.Present() {
		valid, err := s.Header.Destination.Verify(s.Header.Offline.Signed, s.Header.Offline.Signature)
		if err != nil || !valid {
			return valid, err
		}
		leases := s.Leases()
		for {
			lease, ok, err := leases.Next()
			if err != nil {
				return false, err
			}
			if !ok {
				break
			}
			if uint64(lease.EndDate) > uint64(s.Header.Offline.Expires) {
				return false, nil
			}
		}
		signingType = s.Header.Offline.Type
		first, rest = s.Header.Offline.PublicKey, nil
	}
	return foundation.VerifySignaturePrefixed(byte(3), signingType, first, rest, s.Unsigned, s.Signature)
}

// ParseLeaseSet2 parses the full exact LS2 payload and validates canonical
// options, known key lengths, all count bounds, and each lease tunnel ID.
func ParseLeaseSet2(src []byte) (LeaseSet2, error) {
	if len(src) > MaxLeaseSetBytes {
		return LeaseSet2{}, ErrStructureTooLarge
	}
	header, n, err := parseLeaseSet2Header(src)
	if err != nil {
		return LeaseSet2{}, err
	}
	cursor := wire.NewCursor(src[n:])
	options, used, err := foundation.ParseMapping(cursor.Bytes())
	if err != nil {
		return LeaseSet2{}, err
	}
	if err = options.ValidateCanonical(); err != nil {
		return LeaseSet2{}, err
	}
	if err = cursor.Skip(used); err != nil {
		return LeaseSet2{}, err
	}
	keyCount, err := cursor.ReadU8()
	if err != nil {
		return LeaseSet2{}, err
	}
	if keyCount == 0 {
		return LeaseSet2{}, ErrMalformed
	}
	keysStart := cursor.Offset()
	keysIterator := EncryptionKeyIterator{rest: cursor.Bytes(), left: keyCount}
	for {
		_, ok, err := keysIterator.Next()
		if err != nil {
			return LeaseSet2{}, err
		}
		if !ok {
			break
		}
	}
	keysLen := len(cursor.Bytes()) - len(keysIterator.rest)
	if err = cursor.Skip(keysLen); err != nil {
		return LeaseSet2{}, err
	}
	keys := src[n+keysStart : n+cursor.Offset()]
	leaseCount, err := cursor.ReadU8()
	if err != nil {
		return LeaseSet2{}, err
	}
	if leaseCount == 0 || leaseCount > MaxLeases {
		return LeaseSet2{}, ErrTooManyItems
	}
	leases, err := cursor.ReadBytes(int(leaseCount) * 40)
	if err != nil {
		return LeaseSet2{}, err
	}
	for offset := 0; offset < len(leases); offset += 40 {
		if _, err = parseLease2(leases[offset:]); err != nil {
			return LeaseSet2{}, err
		}
	}
	unsignedEnd := n + cursor.Offset()
	signingType := header.Destination.SigningKeyType()
	if header.Offline.Present() {
		signingType = header.Offline.Type
	}
	signatureLen, ok := signingType.SignatureLen()
	if !ok {
		return LeaseSet2{}, foundation.ErrUnknownKeyType
	}
	signature, err := cursor.ReadBytes(signatureLen)
	if err != nil {
		return LeaseSet2{}, err
	}
	if !cursor.Done() {
		return LeaseSet2{}, ErrMalformed
	}
	return LeaseSet2{Header: header, Options: options, keyCount: keyCount, keys: keys, leaseCount: leaseCount, leases: leases, Signature: signature, Unsigned: src[:unsignedEnd], raw: src}, nil
}
