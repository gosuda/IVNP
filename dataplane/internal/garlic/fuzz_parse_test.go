package garlic

import (
	"testing"
)

func FuzzParseGarlic(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ParseDelivery(data)
		_, _, _ = ParseClove(data)
		_, _ = ParseCloveSet(data)
	})
}
