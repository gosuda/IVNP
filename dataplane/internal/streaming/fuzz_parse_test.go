package streaming

import (
	"testing"
)

func FuzzParseStreamingPacket(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 22))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}
