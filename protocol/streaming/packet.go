// Package streaming parses I2P streaming protocol packets without allocation.
package streaming

import (
	"encoding/binary"
	"errors"

	"gosuda.org/ivnp/internal/wire"
)

const (
	HeaderLen     = 22 // no NACKs: 17-byte prefix + resend/flags/options-size
	MaxPacketSize = 3072
)

var ErrPacket = errors.New("streaming: malformed packet")

type Packet struct {
	SendStreamID    uint32
	ReceiveStreamID uint32
	Sequence        uint32
	AckThrough      uint32
	NACKCount       uint8
	ResendDelay     uint8
	Flags           uint16
	Options         []byte
	NACKs           []byte
	Payload         []byte
}

func Parse(src []byte) (Packet, error) {
	if len(src) > MaxPacketSize {
		return Packet{}, ErrPacket
	}
	if len(src) < HeaderLen {
		return Packet{}, wire.ErrShortBuffer
	}
	nacksLen := int(src[16]) * 4
	if nacksLen > len(src)-17-5 {
		return Packet{}, ErrPacket
	}
	off := 17 + nacksLen
	optionsLen := int(binary.BigEndian.Uint16(src[off+3 : off+5]))
	if optionsLen > len(src)-(off+5) {
		return Packet{}, ErrPacket
	}
	packet := Packet{
		SendStreamID: binary.BigEndian.Uint32(src[:4]), ReceiveStreamID: binary.BigEndian.Uint32(src[4:8]),
		Sequence: binary.BigEndian.Uint32(src[8:12]), AckThrough: binary.BigEndian.Uint32(src[12:16]),
		NACKCount: src[16], ResendDelay: src[off], Flags: binary.BigEndian.Uint16(src[off+1 : off+3]),
		NACKs: src[17:off],
	}
	packet.Options = src[off+5 : off+5+optionsLen]
	packet.Payload = src[off+5+optionsLen:]
	return packet, nil
}
