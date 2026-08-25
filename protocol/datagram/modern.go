package datagram

import (
	"encoding/binary"
	"time"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/internal/pool"
	"gosuda.org/ivnp/internal/wire"
)

const (
	flagVersionMask uint16 = 0x000f
	flagOptions     uint16 = 0x0010
	flagOffline     uint16 = 0x0020
	v2AllowedFlags         = flagVersionMask | flagOptions | flagOffline
	v3AllowedFlags         = flagVersionMask | flagOptions
)

// OfflineSignature authorizes V2's transient signing key. Signed aliases its
// expires/type/public-key wire fields; it is verified by From before the
// transient key is trusted.
type OfflineSignature struct {
	Expires   uint32
	Type      ivnp.SigningKeyType
	PublicKey []byte
	Signature []byte
	Signed    []byte
}

func (o OfflineSignature) Present() bool { return o.PublicKey != nil }

type V2 struct {
	From               ivnp.Identity
	Flags              [2]byte
	Options            ivnp.Mapping
	Offline            OfflineSignature
	Payload, Signature []byte
	signedRest         []byte
}

// ParseV2 parses protocol-19 Datagram2. The receiver's destination hash is
// intentionally not available here; callers must use VerifyTarget or
// VerifyTargetAt rather than guessing it from the sender.
func ParseV2(src []byte) (V2, error) {
	if len(src) > MaxWireSize {
		return V2{}, ErrDatagram
	}
	identity, n, err := ivnp.ParseIdentity(src)
	if err != nil {
		return V2{}, err
	}
	if len(src)-n < 2 {
		return V2{}, wire.ErrShortBuffer
	}
	flags := [2]byte{src[n], src[n+1]}
	word := binary.BigEndian.Uint16(flags[:])
	if word&flagVersionMask != 2 || word&^v2AllowedFlags != 0 {
		return V2{}, ErrDatagram
	}
	off := n + 2
	out := V2{From: identity, Flags: flags}
	if word&flagOptions != 0 {
		mapping, used, err := ivnp.ParseMapping(src[off:])
		if err != nil {
			return V2{}, err
		}
		if err = mapping.ValidateCanonical(); err != nil {
			return V2{}, err
		}
		out.Options, off = mapping, off+used
	}

	signingType := identity.SigningKeyType()
	if word&flagOffline != 0 {
		if len(src)-off < 6 {
			return V2{}, wire.ErrShortBuffer
		}
		offlineStart := off
		expires := binary.BigEndian.Uint32(src[off : off+4])
		offlineType := ivnp.SigningKeyType(binary.BigEndian.Uint16(src[off+4 : off+6]))
		offlineKeyLen, ok := offlineType.PublicKeyLen()
		if !ok {
			return V2{}, ivnp.ErrUnknownKeyType
		}
		originSignatureLen, ok := signingType.SignatureLen()
		if !ok {
			return V2{}, ivnp.ErrUnknownKeyType
		}
		off += 6
		if len(src)-off < offlineKeyLen+originSignatureLen {
			return V2{}, wire.ErrShortBuffer
		}
		publicKey := src[off : off+offlineKeyLen]
		off += offlineKeyLen
		offlineSignature := src[off : off+originSignatureLen]
		off += originSignatureLen
		out.Offline = OfflineSignature{
			Expires: expires, Type: offlineType, PublicKey: publicKey,
			Signature: offlineSignature, Signed: src[offlineStart : off-originSignatureLen],
		}
		signingType = offlineType
	}
	signatureLen, ok := signingType.SignatureLen()
	if !ok {
		return V2{}, ivnp.ErrUnknownKeyType
	}
	if len(src)-off < signatureLen {
		return V2{}, wire.ErrShortBuffer
	}
	end := len(src) - signatureLen
	out.Payload, out.Signature = src[off:end], src[end:]
	out.signedRest = src[n:end]
	return out, nil
}

// VerifyTarget verifies the Datagram2 target-binding and, where present, the
// offline-key authorization against the current Unix-second clock.
func (d V2) VerifyTarget(target ivnp.Hash) (bool, error) {
	return d.VerifyTargetAt(target, uint32(time.Now().Unix()))
}

// VerifyTargetAt is VerifyTarget with an injected Unix-second clock. It is
// useful to callers that already own a protocol clock and deterministic tests.
func (d V2) VerifyTargetAt(target ivnp.Hash, now uint32) (bool, error) {
	if d.Offline.Present() {
		if now > d.Offline.Expires {
			return false, ErrDatagram
		}
		valid, err := d.From.Verify(d.Offline.Signed, d.Offline.Signature)
		if err != nil || !valid {
			return valid, err
		}
	}
	signed, ok := pool.Acquire(len(target) + len(d.signedRest))
	if !ok {
		return false, ErrDatagram
	}
	copy(signed[:len(target)], target[:])
	copy(signed[len(target):], d.signedRest)
	defer pool.Release(signed)
	if d.Offline.Present() {
		return ivnp.VerifySignature(d.Offline.Type, d.Offline.PublicKey, nil, signed, d.Signature)
	}
	return d.From.Verify(signed, d.Signature)
}

// MarshalV2To writes a protocol-19 Datagram2 and signs the target-bound
// fields. If flagOffline is set, offline must contain a valid authorization by
// from and signer must sign using the authorized transient private key.
func MarshalV2To(dst []byte, target ivnp.Hash, from ivnp.Identity, flags uint16, options ivnp.Mapping, offline OfflineSignature, payload []byte, signer Signer) (int, error) {
	if signer == nil || len(payload) > MaxSize || flags&flagVersionMask != 2 || flags&^v2AllowedFlags != 0 {
		return 0, ErrDatagram
	}
	optionsPresent := flags&flagOptions != 0
	if optionsPresent != (options.EncodedLen() != 0) {
		return 0, ErrDatagram
	}
	if optionsPresent {
		if err := options.ValidateCanonical(); err != nil {
			return 0, err
		}
	}
	signingType := from.SigningKeyType()
	offlineLen := 0
	if flags&flagOffline != 0 {
		if !offline.Present() {
			return 0, ErrDatagram
		}
		keyLen, ok := offline.Type.PublicKeyLen()
		if !ok || len(offline.PublicKey) != keyLen {
			return 0, ErrDatagram
		}
		authorizationLen, ok := signingType.SignatureLen()
		if !ok || len(offline.Signature) != authorizationLen {
			return 0, ErrDatagram
		}
		offlineLen = 6 + keyLen + authorizationLen
		signingType = offline.Type
	} else if offline.Present() {
		return 0, ErrDatagram
	}
	signatureLen, ok := signingType.SignatureLen()
	if !ok {
		return 0, ivnp.ErrUnknownKeyType
	}
	total := from.EncodedLen() + 2 + options.EncodedLen() + offlineLen + len(payload) + signatureLen
	if total > MaxSize {
		return 0, ErrDatagram
	}
	if len(dst) < total {
		return 0, wire.ErrShortBuffer
	}
	off, err := from.MarshalTo(dst)
	if err != nil {
		return 0, err
	}
	binary.BigEndian.PutUint16(dst[off:off+2], flags)
	off += 2
	off += copy(dst[off:], options.Bytes())
	if flags&flagOffline != 0 {
		offlineStart := off
		binary.BigEndian.PutUint32(dst[off:off+4], offline.Expires)
		binary.BigEndian.PutUint16(dst[off+4:off+6], uint16(offline.Type))
		off += 6
		off += copy(dst[off:], offline.PublicKey)
		if valid, err := from.Verify(dst[offlineStart:off], offline.Signature); err != nil || !valid {
			return 0, ErrDatagram
		}
		off += copy(dst[off:], offline.Signature)
	}
	off += copy(dst[off:], payload)
	signed, ok := pool.Acquire(len(target) + off - from.EncodedLen())
	if !ok {
		return 0, ErrDatagram
	}
	copy(signed[:len(target)], target[:])
	copy(signed[len(target):], dst[from.EncodedLen():off])
	signature, err := signer(signed)
	pool.Release(signed)
	if err != nil {
		return 0, err
	}
	if len(signature) != signatureLen {
		return 0, ErrDatagram
	}
	copy(dst[off:off+signatureLen], signature)
	return total, nil
}

// MarshalV3To writes a protocol-20 Datagram3. The sender hash is metadata,
// not an authentication claim.
func MarshalV3To(dst []byte, from ivnp.Hash, flags uint16, options ivnp.Mapping, payload []byte) (int, error) {
	if len(payload) > MaxSize || flags&flagVersionMask != 3 || flags&^v3AllowedFlags != 0 {
		return 0, ErrDatagram
	}
	optionsPresent := flags&flagOptions != 0
	if optionsPresent != (options.EncodedLen() != 0) {
		return 0, ErrDatagram
	}
	if optionsPresent {
		if err := options.ValidateCanonical(); err != nil {
			return 0, err
		}
	}
	total := len(from) + 2 + options.EncodedLen() + len(payload)
	if total > MaxSize {
		return 0, ErrDatagram
	}
	if len(dst) < total {
		return 0, wire.ErrShortBuffer
	}
	copy(dst, from[:])
	binary.BigEndian.PutUint16(dst[len(from):len(from)+2], flags)
	off := len(from) + 2
	off += copy(dst[off:], options.Bytes())
	copy(dst[off:], payload)
	return total, nil
}

type V3 struct {
	From    ivnp.Hash
	Flags   [2]byte
	Options ivnp.Mapping
	Payload []byte
}

// ParseV3 parses protocol-20 Datagram3. V3 is deliberately unauthenticated;
// a parsed From hash is a routing hint, never proof of origin.
func ParseV3(src []byte) (V3, error) {
	if len(src) > MaxWireSize {
		return V3{}, ErrDatagram
	}
	if len(src) < 34 {
		return V3{}, wire.ErrShortBuffer
	}
	var out V3
	copy(out.From[:], src[:32])
	out.Flags = [2]byte{src[32], src[33]}
	word := binary.BigEndian.Uint16(out.Flags[:])
	if word&flagVersionMask != 3 || word&^v3AllowedFlags != 0 {
		return V3{}, ErrDatagram
	}
	off := 34
	if word&flagOptions != 0 {
		mapping, used, err := ivnp.ParseMapping(src[off:])
		if err != nil {
			return V3{}, err
		}
		if err = mapping.ValidateCanonical(); err != nil {
			return V3{}, err
		}
		out.Options, off = mapping, off+used
	}
	out.Payload = src[off:]
	return out, nil
}

// ParseRaw validates protocol-18 raw datagram policy and returns a borrowed
// view. It never invents source, integrity, or reply semantics.
func ParseRaw(src []byte) ([]byte, error) {
	if len(src) > MaxWireSize {
		return nil, ErrDatagram
	}
	return src, nil
}
