package streaming

import (
	"encoding/binary"

	"gosuda.org/ivnp/internal/wire"
)

// EncodedLen returns the size of p's streaming protocol wire representation.
// It returns -1 when p cannot be represented on the wire.
func (p Packet) EncodedLen() int {
	nacksLen := len(p.NACKs)
	if nacksLen%4 != 0 || nacksLen/4 > 255 || len(p.Options) > 0xffff {
		return -1
	}
	encodedLen := HeaderLen + nacksLen + len(p.Options) + len(p.Payload)
	if encodedLen > MaxPacketSize {
		return -1
	}
	return encodedLen
}

// MarshalTo serializes p into dst using the i2pd streaming packet layout.
// dst remains caller-owned, and the method does not allocate.
func (p Packet) MarshalTo(dst []byte) (int, error) {
	encodedLen := p.EncodedLen()
	if encodedLen < HeaderLen {
		return 0, ErrPacket
	}
	if len(dst) < encodedLen {
		return 0, wire.ErrShortBuffer
	}

	binary.BigEndian.PutUint32(dst[:4], p.SendStreamID)
	binary.BigEndian.PutUint32(dst[4:8], p.ReceiveStreamID)
	binary.BigEndian.PutUint32(dst[8:12], p.Sequence)
	binary.BigEndian.PutUint32(dst[12:16], p.AckThrough)
	dst[16] = uint8(len(p.NACKs) / 4)
	off := 17
	off += copy(dst[off:], p.NACKs)
	dst[off] = p.ResendDelay
	binary.BigEndian.PutUint16(dst[off+1:off+3], p.Flags)
	binary.BigEndian.PutUint16(dst[off+3:off+5], uint16(len(p.Options)))
	off += 5
	off += copy(dst[off:], p.Options)
	copy(dst[off:], p.Payload)
	return encodedLen, nil
}
