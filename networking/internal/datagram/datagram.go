// Package datagram parses and serializes I2P datagram v1, v2, v3, and raw payloads.
package datagram

import (
	"errors"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/wire"
	"gosuda.org/ivnp/networking/internal/i2np"
)

const (
	ProtocolDatagram1 uint8 = 17
	ProtocolRaw       uint8 = 18
	ProtocolDatagram2 uint8 = 19
	ProtocolDatagram3 uint8 = 20

	MaxWireSize = i2np.I2PDMaxPayload
	MaxI2PDSize = 32_768
	MaxSize     = MaxI2PDSize
)

var (
	ErrDatagram = errors.New("datagram: malformed datagram")
	ErrProtocol = errors.New("datagram: unsupported datagram protocol")
)

type V1 struct {
	From      foundation.Identity
	Signature []byte
	Payload   []byte
}

// Packet represents a parsed datagram with its selected protocol format.
type Packet struct {
	Protocol uint8
	Raw      []byte
	V1       V1
	V2       V2
	V3       V3
}

// ParsePacket decodes a datagram according to the given protocol number.
func ParsePacket(protocol uint8, src []byte) (Packet, error) {
	packet := Packet{Protocol: protocol}
	switch protocol {
	case ProtocolDatagram1:
		value, err := ParseV1(src)
		packet.V1 = value
		return packet, err
	case ProtocolRaw:
		value, err := ParseRaw(src)
		packet.Raw = value
		return packet, err
	case ProtocolDatagram2:
		value, err := ParseV2(src)
		packet.V2 = value
		return packet, err
	case ProtocolDatagram3:
		value, err := ParseV3(src)
		packet.V3 = value
		return packet, err
	default:
		return Packet{}, ErrProtocol
	}
}

// Signer signs exactly the wire input required by the selected datagram
// format. It returns the fixed-width I2P signature without retaining input.
type Signer func([]byte) ([]byte, error)

func (d V1) EncodedLen() int {
	return d.From.EncodedLen() + len(d.Signature) + len(d.Payload)
}

// MarshalV1To writes a protocol-17 Datagram1. For DSA-SHA1 the signer gets
// SHA-256(payload); every other signing type receives payload directly.
func MarshalV1To(dst []byte, from foundation.Identity, payload []byte, signer Signer) (int, error) {
	if signer == nil || len(payload) > MaxSize {
		return 0, ErrDatagram
	}
	signatureLen, ok := from.SigningKeyType().SignatureLen()
	if !ok {
		return 0, foundation.ErrUnknownKeyType
	}
	total := from.EncodedLen() + signatureLen + len(payload)
	if total > MaxSize {
		return 0, ErrDatagram
	}
	if len(dst) < total {
		return 0, wire.ErrShortBuffer
	}
	signingInput := payload
	var digest foundation.Hash
	if from.SigningKeyType() == foundation.SigningDSASHA1 {
		digest = foundation.Sum(payload)
		signingInput = digest[:]
	}
	signature, err := signer(signingInput)
	if err != nil {
		return 0, err
	}
	if len(signature) != signatureLen {
		return 0, ErrDatagram
	}
	n, err := from.MarshalTo(dst)
	if err != nil {
		return 0, err
	}
	copy(dst[n:n+signatureLen], signature)
	copy(dst[n+signatureLen:total], payload)
	return total, nil
}

// MarshalRawTo writes a protocol-18 raw datagram exactly as supplied. Raw
// datagrams carry no source, framing, authenticity, or replay semantics.
func MarshalRawTo(dst, payload []byte) (int, error) {
	if len(payload) > MaxSize {
		return 0, ErrDatagram
	}
	if len(dst) < len(payload) {
		return 0, wire.ErrShortBuffer
	}
	copy(dst, payload)
	return len(payload), nil
}

func ParseV1(src []byte) (V1, error) {
	if len(src) > MaxWireSize {
		return V1{}, ErrDatagram
	}
	identity, n, err := foundation.ParseIdentity(src)
	if err != nil {
		return V1{}, err
	}
	signatureLen, ok := identity.SigningKeyType().SignatureLen()
	if !ok {
		return V1{}, foundation.ErrUnknownKeyType
	}
	if len(src)-n < signatureLen {
		return V1{}, wire.ErrShortBuffer
	}
	return V1{From: identity, Signature: src[n : n+signatureLen], Payload: src[n+signatureLen:]}, nil
}

func (d V1) Verify() (bool, error) {
	if d.From.SigningKeyType() == foundation.SigningDSASHA1 {
		hash := foundation.Sum(d.Payload)
		return d.From.Verify(hash[:], d.Signature)
	}
	return d.From.Verify(d.Payload, d.Signature)
}
