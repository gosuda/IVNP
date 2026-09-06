package streaming

import (
	"encoding/binary"
	"testing"
)

func TestParseStreamingPacket(t *testing.T) {
	wire := make([]byte, HeaderLen+4+2+3)
	binary.BigEndian.PutUint32(wire[:4], 1)
	binary.BigEndian.PutUint32(wire[4:8], 2)
	binary.BigEndian.PutUint32(wire[8:12], 3)
	binary.BigEndian.PutUint32(wire[12:16], 4)
	wire[16] = 1
	binary.BigEndian.PutUint32(wire[17:21], 9)
	wire[21] = 1
	binary.BigEndian.PutUint16(wire[22:24], 0x0040)
	binary.BigEndian.PutUint16(wire[24:26], 2)
	copy(wire[26:28], []byte{1, 2})
	copy(wire[28:], []byte{3, 4, 5})
	packet, err := Parse(wire)
	parseStreamingPacketRejected := err != nil || packet.SendStreamID != 1 || packet.ReceiveStreamID != 2 || len(packet.NACKs) != 4 || len(packet.Options) != 2
	if !parseStreamingPacketRejected {
		parseStreamingPacketRejected = len(packet.Payload) != 3
	}
	if parseStreamingPacketRejected {
		t.Fatalf("Parse() = %#v, %v", packet, err)
	}
}
