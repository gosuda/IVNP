// Package garlic parses authenticated/decrypted legacy Garlic clove sets.
package garlic

import (
	"encoding/binary"
	"errors"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/internal/wire"
	"gosuda.org/ivnp/protocol/i2np"
)

var (
	ErrDelivery = errors.New("garlic: invalid delivery instructions")
	ErrClove    = errors.New("garlic: invalid clove")
)

type DeliveryType uint8

const (
	DeliveryLocal DeliveryType = iota
	DeliveryDestination
	DeliveryRouter
	DeliveryTunnel
)

// Delivery is a zero-copy Garlic clove delivery instruction.
type Delivery struct {
	Type       DeliveryType
	Encrypted  bool
	SessionKey []byte
	To         ivnp.Hash
	TunnelID   uint32
	Delay      uint32
}

func ParseDelivery(src []byte) (Delivery, int, error) {
	if len(src) < 1 {
		return Delivery{}, 0, wire.ErrShortBuffer
	}
	flags := src[0]
	if flags&0x0f != 0 {
		return Delivery{}, 0, ErrDelivery
	}
	out := Delivery{Encrypted: flags&0x80 != 0, Type: DeliveryType((flags >> 5) & 3)}
	off := 1
	if out.Encrypted {
		if len(src)-off < 32 {
			return Delivery{}, 0, wire.ErrShortBuffer
		}
		out.SessionKey = src[off : off+32]
		off += 32
	}
	if out.Type != DeliveryLocal {
		if len(src)-off < 32 {
			return Delivery{}, 0, wire.ErrShortBuffer
		}
		copy(out.To[:], src[off:off+32])
		off += 32
	}
	if out.Type == DeliveryTunnel {
		if len(src)-off < 4 {
			return Delivery{}, 0, wire.ErrShortBuffer
		}
		out.TunnelID = binary.BigEndian.Uint32(src[off : off+4])
		if out.TunnelID == 0 {
			return Delivery{}, 0, ErrDelivery
		}
		off += 4
	}
	if flags&0x10 != 0 {
		if len(src)-off < 4 {
			return Delivery{}, 0, wire.ErrShortBuffer
		}
		out.Delay = binary.BigEndian.Uint32(src[off : off+4])
		off += 4
	}
	return out, off, nil
}

// Clove carries one complete standard I2NP message plus routing metadata.
type Clove struct {
	Delivery   Delivery
	Message    i2np.Message
	ID         uint32
	Expiration uint64
}

func ParseClove(src []byte) (Clove, int, error) {
	delivery, n, err := ParseDelivery(src)
	if err != nil {
		return Clove{}, 0, err
	}
	message, used, err := i2np.ParseUnchecked(src[n:])
	if err != nil {
		return Clove{}, 0, err
	}
	off := n + used
	if len(src)-off < 15 {
		return Clove{}, 0, wire.ErrShortBuffer
	}
	id := binary.BigEndian.Uint32(src[off : off+4])
	expiration := binary.BigEndian.Uint64(src[off+4 : off+12])
	certificate, certLen, err := ivnp.ParseCertificate(src[off+12:])
	if err != nil {
		return Clove{}, 0, err
	}
	if certificate.Type != ivnp.CertificateNull {
		return Clove{}, 0, ErrClove
	}
	return Clove{Delivery: delivery, Message: message, ID: id, Expiration: expiration}, off + 12 + certLen, nil
}

// CloveSet is the decrypted payload of a legacy Garlic message.
type CloveSet struct {
	count      uint8
	cloves     []byte
	MessageID  uint32
	Expiration uint64
}

func (s CloveSet) Count() int       { return int(s.count) }
func (s CloveSet) Cloves() Iterator { return Iterator{rest: s.cloves, left: s.count} }

type Iterator struct {
	rest []byte
	left uint8
}

func (it *Iterator) Next() (Clove, bool, error) {
	if it.left == 0 {
		return Clove{}, false, nil
	}
	clove, n, err := ParseClove(it.rest)
	if err != nil {
		return Clove{}, false, err
	}
	it.rest = it.rest[n:]
	it.left--
	return clove, true, nil
}

func ParseCloveSet(src []byte) (CloveSet, error) {
	if len(src) < 1 {
		return CloveSet{}, wire.ErrShortBuffer
	}
	count := src[0]
	off := 1
	for range count {
		_, n, err := ParseClove(src[off:])
		if err != nil {
			return CloveSet{}, err
		}
		off += n
	}
	if len(src)-off != 15 {
		return CloveSet{}, ErrClove
	}
	certificate, n, err := ivnp.ParseCertificate(src[off:])
	if err != nil || certificate.Type != ivnp.CertificateNull || n != 3 {
		return CloveSet{}, ErrClove
	}
	return CloveSet{count: count, cloves: src[1:off], MessageID: binary.BigEndian.Uint32(src[off+3 : off+7]), Expiration: binary.BigEndian.Uint64(src[off+7 : off+15])}, nil
}
