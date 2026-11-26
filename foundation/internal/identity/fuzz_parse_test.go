package identity

import (
	"testing"
)

func FuzzParseIdentity(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 387))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ParseCertificate(data)
		_, _, _ = ParseIdentity(data)
		_, _, _ = ParseMapping(data)
		_, _ = DecodeI2PBase64(data)
		_, _ = ParseDestination(data)
	})
}
