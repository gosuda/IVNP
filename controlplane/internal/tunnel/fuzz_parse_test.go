package tunnel

import (
	"testing"
)

func FuzzParseBuildRequest(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 222))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseShortBuildRequest(data)
		_, _ = ParseElGamalBuildRequest(data)
		_, _ = ParseLongECIESBuildRequest(data)
	})
}
