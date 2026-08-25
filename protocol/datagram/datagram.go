// Package datagram parses I2P datagram v1 payloads.
package datagram

import (
	"errors"
	ivnp "gosuda.org/ivnp/i2p"
	"gosuda.org/ivnp/internal/wire"
	"gosuda.org/ivnp/protocol/i2np"
)

const (
	// ProtocolDatagram1, ProtocolRaw, ProtocolDatagram2, and
	// ProtocolDatagram3 select formats at the I2CP/SAM boundary. A payload's
	// bytes never identify its format.
	ProtocolDatagram1 uint8 = 17
	ProtocolRaw       uint8 = 18
	ProtocolDatagram2 uint8 = 19
	ProtocolDatagram3 uint8 = 20

	// MaxWireSize is the i2pd-compatible I2NP payload framing ceiling for
	// parsing an incoming datagram before its enclosing Data/Garlic policy.
	MaxWireSize = i2np.I2PDMaxPayload

	// MaxI2PDSize is i2pd's DatagramDestination inflate buffer capacity.
	// Outbound encoder defaults use this conservative peer-compatible ceiling.
	MaxI2PDSize = 32_768

	// MaxSize remains the default outbound i2pd compatibility policy. Use
	// MaxWireSize only for inbound parsing, never to infer peer send support.
	MaxSize = MaxI2PDSize
)

var (
	ErrDatagram = errors.New("datagram: malformed datagram")
	ErrProtocol = errors.New("datagram: unsupported datagram protocol")
)

type V1 struct {
	From      ivnp.Identity
	Signature []byte
	Payload   []byte
}

// Packet is a protocol-selected datagram view. Exactly the field for Protocol
// is populated. Its bytes alias caller input and remain valid under the same
// ownership rules as ParseV1/ParseV2/ParseV3/ParseRaw.
type Packet struct {
	Protocol uint8
	Raw      []byte
	V1       V1
	V2       V2
	V3       V3
}

// ParsePacket selects the format from I2CP/SAM protocol metadata. It never
// attempts wire-content autodetection because I2P datagram formats do not
// share a discriminating header.
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
func MarshalV1To(dst []byte, from ivnp.Identity, payload []byte, signer Signer) (int, error) {
	if signer == nil || len(payload) > MaxSize {
		return 0, ErrDatagram
	}
	signatureLen, ok := from.SigningKeyType().SignatureLen()
	if !ok {
		return 0, ivnp.ErrUnknownKeyType
	}
	total := from.EncodedLen() + signatureLen + len(payload)
	if total > MaxSize {
		return 0, ErrDatagram
	}
	if len(dst) < total {
		return 0, wire.ErrShortBuffer
	}
	signingInput := payload
	var digest ivnp.Hash
	if from.SigningKeyType() == ivnp.SigningDSASHA1 {
		digest = ivnp.Sum(payload)
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
	identity, n, err := ivnp.ParseIdentity(src)
	if err != nil {
		return V1{}, err
	}
	signatureLen, ok := identity.SigningKeyType().SignatureLen()
	if !ok {
		return V1{}, ivnp.ErrUnknownKeyType
	}
	if len(src)-n < signatureLen {
		return V1{}, wire.ErrShortBuffer
	}
	return V1{From: identity, Signature: src[n : n+signatureLen], Payload: src[n+signatureLen:]}, nil
}

func (d V1) Verify() (bool, error) {
	if d.From.SigningKeyType() == ivnp.SigningDSASHA1 {
		hash := ivnp.Sum(d.Payload)
		return d.From.Verify(hash[:], d.Signature)
	}
	return d.From.Verify(d.Payload, d.Signature)
}
