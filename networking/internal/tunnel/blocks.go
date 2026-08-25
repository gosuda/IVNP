package tunnel

import (
	"encoding/binary"
	"errors"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/wire"
)

var ErrBlock = errors.New("tunnel: malformed delivery block")

type DeliveryType uint8

const (
	DeliveryLocal DeliveryType = iota
	DeliveryTunnel
	DeliveryRouter
)

type Block struct {
	Delivery       DeliveryType
	Gateway        foundation.Hash
	TunnelID       uint32
	MessageID      uint32
	Fragment       uint8
	FollowOn, Last bool
	Data           []byte
}

type BlockIterator struct{ rest []byte }

func NewBlockIterator(payload []byte) BlockIterator { return BlockIterator{rest: payload} }
func (it *BlockIterator) Next() (Block, bool, error) {
	if len(it.rest) == 0 {
		return Block{}, false, nil
	}
	flag := it.rest[0]
	it.rest = it.rest[1:]
	out := Block{FollowOn: flag&0x80 != 0, Last: true}
	if out.FollowOn {
		if len(it.rest) < 6 {
			return Block{}, false, wire.ErrShortBuffer
		}
		out.MessageID = binary.BigEndian.Uint32(it.rest[:4])
		out.Fragment = (flag >> 1) & 0x3f
		if out.Fragment == 0 {
			return Block{}, false, ErrBlock
		}
		out.Last = flag&1 != 0
		it.rest = it.rest[4:]
	} else {
		if flag&0x17 != 0 { // delay, extended options, and reserved bits
			return Block{}, false, ErrBlock
		}
		out.Delivery = DeliveryType((flag >> 5) & 3)
		if out.Delivery == 3 {
			return Block{}, false, ErrBlock
		}
		if out.Delivery == DeliveryTunnel {
			if len(it.rest) < 36 {
				return Block{}, false, wire.ErrShortBuffer
			}
			out.TunnelID = binary.BigEndian.Uint32(it.rest[:4])
			if out.TunnelID == 0 {
				return Block{}, false, ErrBlock
			}
			copy(out.Gateway[:], it.rest[4:36])
			it.rest = it.rest[36:]
		} else if out.Delivery == DeliveryRouter {
			if len(it.rest) < 32 {
				return Block{}, false, wire.ErrShortBuffer
			}
			copy(out.Gateway[:], it.rest[:32])
			it.rest = it.rest[32:]
		}
		if flag&0x08 != 0 {
			if len(it.rest) < 4 {
				return Block{}, false, wire.ErrShortBuffer
			}
			out.MessageID = binary.BigEndian.Uint32(it.rest[:4])
			it.rest = it.rest[4:]
			out.Last = false
		}
	}
	if len(it.rest) < 2 {
		return Block{}, false, wire.ErrShortBuffer
	}
	n := int(binary.BigEndian.Uint16(it.rest[:2]))
	it.rest = it.rest[2:]
	if n == 0 {
		return Block{}, false, ErrBlock
	}
	if n > len(it.rest) {
		return Block{}, false, ErrBlock
	}
	out.Data = it.rest[:n]
	it.rest = it.rest[n:]
	return out, true, nil
}
