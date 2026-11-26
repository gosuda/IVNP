package datagram

import (
	"testing"
)

func FuzzParseDatagram(f *testing.F) {
	f.Add([]byte{}, uint8(17))
	f.Add(make([]byte, 512), uint8(19))
	f.Fuzz(func(t *testing.T, data []byte, protocol uint8) {
		_, _ = ParsePacket(protocol, data)
		_, _ = ParseV1(data)
		_, _ = ParseV2(data)
		_, _ = ParseV3(data)
		_, _ = ParseRaw(data)
	})
}
