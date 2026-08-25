package netdb

import (
	"encoding/binary"
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/wire"
)

const (
	MaxMetaLeases  = 255
	MaxRevocations = 255
)

// MetaLease is the 40-byte encrypted-lease routing reference.
type MetaLease struct {
	Gateway ivnp.Hash
	Type    uint8
	Cost    uint8
	EndDate uint32
}

func parseMetaLease(src []byte) (MetaLease, error) {
	if len(src) < 40 {
		return MetaLease{}, wire.ErrShortBuffer
	}
	if src[32] != 0 || src[33] != 0 || src[34]&0xf0 != 0 {
		return MetaLease{}, ErrMalformed
	}
	entryType := src[34] & 0x0f
	if entryType != 0 && entryType != 1 && entryType != 3 && entryType != 5 {
		return MetaLease{}, ErrMalformed
	}
	var lease MetaLease
	copy(lease.Gateway[:], src[:32])
	lease.Type, lease.Cost, lease.EndDate = entryType, src[35], binary.BigEndian.Uint32(src[36:40])
	return lease, nil
}

type MetaLeaseIterator struct{ rest []byte }

func (it *MetaLeaseIterator) Next() (MetaLease, bool, error) {
	if len(it.rest) == 0 {
		return MetaLease{}, false, nil
	}
	lease, err := parseMetaLease(it.rest)
	if err != nil {
		return MetaLease{}, false, err
	}
	it.rest = it.rest[40:]
	return lease, true, nil
}

// MetaLeaseSet is DatabaseStore type 7.
type MetaLeaseSet struct {
	Header      LeaseSet2Header
	Options     ivnp.Mapping
	leaseCount  uint8
	leases      []byte
	Revocations []byte
	Signature   []byte
	Unsigned    []byte
	raw         []byte
}

func (s MetaLeaseSet) Bytes() []byte             { return s.raw }
func (s MetaLeaseSet) Hash() ivnp.Hash           { return s.Header.Destination.Hash() }
func (s MetaLeaseSet) LeaseCount() int           { return int(s.leaseCount) }
func (s MetaLeaseSet) Leases() MetaLeaseIterator { return MetaLeaseIterator{rest: s.leases} }
func (s MetaLeaseSet) RevocationCount() int      { return len(s.Revocations) / ivnp.HashLength }

func (s MetaLeaseSet) Verify() (bool, error) {
	signingType := s.Header.Destination.SigningKeyType()
	first, rest := s.Header.Destination.SigningKeyParts()
	if s.Header.Offline.Present() {
		valid, err := s.Header.Destination.Verify(s.Header.Offline.Signed, s.Header.Offline.Signature)
		if err != nil || !valid {
			return valid, err
		}
		signingType, first, rest = s.Header.Offline.Type, s.Header.Offline.PublicKey, nil
	}
	return ivnp.VerifySignaturePrefixed(byte(7), signingType, first, rest, s.Unsigned, s.Signature)
}

func ParseMetaLeaseSet(src []byte) (MetaLeaseSet, error) {
	if len(src) > MaxLeaseSetBytes {
		return MetaLeaseSet{}, ErrStructureTooLarge
	}
	header, n, err := parseLeaseSet2Header(src)
	if err != nil {
		return MetaLeaseSet{}, err
	}
	cursor := wire.NewCursor(src[n:])
	options, used, err := ivnp.ParseMapping(cursor.Bytes())
	if err != nil {
		return MetaLeaseSet{}, err
	}
	if err = options.ValidateCanonical(); err != nil {
		return MetaLeaseSet{}, err
	}
	if err = cursor.Skip(used); err != nil {
		return MetaLeaseSet{}, err
	}
	count, err := cursor.ReadU8()
	if err != nil {
		return MetaLeaseSet{}, err
	}
	if count == 0 {
		return MetaLeaseSet{}, ErrTooManyItems
	}
	leases, err := cursor.ReadBytes(int(count) * 40)
	if err != nil {
		return MetaLeaseSet{}, err
	}
	for offset := 0; offset < len(leases); offset += 40 {
		if _, err = parseMetaLease(leases[offset:]); err != nil {
			return MetaLeaseSet{}, err
		}
	}
	revocationCount, err := cursor.ReadU8()
	if err != nil {
		return MetaLeaseSet{}, err
	}
	revocations, err := cursor.ReadBytes(int(revocationCount) * ivnp.HashLength)
	if err != nil {
		return MetaLeaseSet{}, err
	}
	unsignedEnd := n + cursor.Offset()
	signingType := header.Destination.SigningKeyType()
	if header.Offline.Present() {
		signingType = header.Offline.Type
	}
	signatureLen, ok := signingType.SignatureLen()
	if !ok {
		return MetaLeaseSet{}, ivnp.ErrUnknownKeyType
	}
	signature, err := cursor.ReadBytes(signatureLen)
	if err != nil {
		return MetaLeaseSet{}, err
	}
	if !cursor.Done() {
		return MetaLeaseSet{}, ErrMalformed
	}
	return MetaLeaseSet{Header: header, Options: options, leaseCount: count, leases: leases, Revocations: revocations, Signature: signature, Unsigned: src[:unsignedEnd], raw: src}, nil
}

// EncryptedLeaseSet is DatabaseStore type 5. Its inner data remains opaque
// until encrypted-lease-set decryption has established the client context.
type EncryptedLeaseSet struct {
	SigningType      ivnp.SigningKeyType
	BlindedPublicKey []byte
	Published        uint32
	Expires          uint16
	Flags            uint16
	Offline          OfflineSignature
	EncryptedData    []byte
	Signature        []byte
	Unsigned         []byte
	raw              []byte
}

func (s EncryptedLeaseSet) Bytes() []byte { return s.raw }

// Hash is the encrypted LeaseSet DHT key: SHA-256(sigtype || blinded key).
func (s EncryptedLeaseSet) Hash() ivnp.Hash {
	var input [2 + 512]byte
	binary.BigEndian.PutUint16(input[:2], uint16(s.SigningType))
	copy(input[2:], s.BlindedPublicKey)
	return ivnp.Sum(input[:2+len(s.BlindedPublicKey)])
}

func (s EncryptedLeaseSet) Verify() (bool, error) {
	signingType, public := s.SigningType, s.BlindedPublicKey
	if s.Offline.Present() {
		valid, err := ivnp.VerifySignature(s.SigningType, s.BlindedPublicKey, nil, s.Offline.Signed, s.Offline.Signature)
		if err != nil || !valid {
			return valid, err
		}
		signingType, public = s.Offline.Type, s.Offline.PublicKey
	}
	return ivnp.VerifySignaturePrefixed(byte(5), signingType, public, nil, s.Unsigned, s.Signature)
}

func ParseEncryptedLeaseSet(src []byte) (EncryptedLeaseSet, error) {
	if len(src) > MaxLeaseSetBytes {
		return EncryptedLeaseSet{}, ErrStructureTooLarge
	}
	cursor := wire.NewCursor(src)
	typeID, err := cursor.ReadU16()
	if err != nil {
		return EncryptedLeaseSet{}, err
	}
	signingType := ivnp.SigningKeyType(typeID)
	keyLen, ok := signingType.PublicKeyLen()
	if !ok {
		return EncryptedLeaseSet{}, ivnp.ErrUnknownKeyType
	}
	publicKey, err := cursor.ReadBytes(keyLen)
	if err != nil {
		return EncryptedLeaseSet{}, err
	}
	published, err := cursor.ReadU32()
	if err != nil {
		return EncryptedLeaseSet{}, err
	}
	expires, err := cursor.ReadU16()
	if err != nil {
		return EncryptedLeaseSet{}, err
	}
	flags, err := cursor.ReadU16()
	if err != nil {
		return EncryptedLeaseSet{}, err
	}
	out := EncryptedLeaseSet{SigningType: signingType, BlindedPublicKey: publicKey, Published: published, Expires: expires, Flags: flags}
	if flags&leaseSetOfflineFlag != 0 {
		offlineStart := cursor.Offset()
		offlineExpires, err := cursor.ReadU32()
		if err != nil {
			return EncryptedLeaseSet{}, err
		}
		offlineTypeID, err := cursor.ReadU16()
		if err != nil {
			return EncryptedLeaseSet{}, err
		}
		offlineType := ivnp.SigningKeyType(offlineTypeID)
		offlineKeyLen, ok := offlineType.PublicKeyLen()
		if !ok {
			return EncryptedLeaseSet{}, ivnp.ErrUnknownKeyType
		}
		offlineKey, err := cursor.ReadBytes(offlineKeyLen)
		if err != nil {
			return EncryptedLeaseSet{}, err
		}
		signatureLen, ok := signingType.SignatureLen()
		if !ok {
			return EncryptedLeaseSet{}, ivnp.ErrUnknownKeyType
		}
		offlineSignature, err := cursor.ReadBytes(signatureLen)
		if err != nil {
			return EncryptedLeaseSet{}, err
		}
		out.Offline = OfflineSignature{Expires: offlineExpires, Type: offlineType, PublicKey: offlineKey, Signature: offlineSignature, Signed: src[offlineStart : cursor.Offset()-signatureLen]}
	}
	length, err := cursor.ReadU16()
	if err != nil {
		return EncryptedLeaseSet{}, err
	}
	if length == 0 {
		return EncryptedLeaseSet{}, ErrMalformed
	}
	encrypted, err := cursor.ReadBytes(int(length))
	if err != nil {
		return EncryptedLeaseSet{}, err
	}
	unsignedEnd := cursor.Offset()
	signingForPayload := signingType
	if out.Offline.Present() {
		signingForPayload = out.Offline.Type
	}
	signatureLen, ok := signingForPayload.SignatureLen()
	if !ok {
		return EncryptedLeaseSet{}, ivnp.ErrUnknownKeyType
	}
	signature, err := cursor.ReadBytes(signatureLen)
	if err != nil {
		return EncryptedLeaseSet{}, err
	}
	if !cursor.Done() {
		return EncryptedLeaseSet{}, ErrMalformed
	}
	out.EncryptedData, out.Signature, out.Unsigned, out.raw = encrypted, signature, src[:unsignedEnd], src
	return out, nil
}
