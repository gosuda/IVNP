package netdb

import (
	"testing"
)

func FuzzParseNetDB(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 391))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ParseRouterAddress(data)
		_, _ = ParseRouterInfo(data)
		_, _ = ParseLeaseSet(data)
		_, _ = ParseLeaseSet2(data)
		_, _ = ParseMetaLeaseSet(data)
		_, _ = ParseEncryptedLeaseSet(data)
	})
}
