package configuration

import (
	"testing"
)

func FuzzParseConfiguration(f *testing.F) {
	f.Add("")
	f.Add("[network]\nid = 2\nprofile = public\n")
	f.Fuzz(func(t *testing.T, text string) {
		_, _ = Parse(text)
		_, _ = ParseOperating(text, "fuzz.conf")
	})
}
