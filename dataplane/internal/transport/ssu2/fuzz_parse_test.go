package ssu2

import (
	"testing"
)

func FuzzParseSSU2Blocks(f *testing.F) {
	f.Add([]byte{}, uint8(2))
	f.Add(make([]byte, 32), uint8(2))
	f.Fuzz(func(t *testing.T, data []byte, network uint8) {
		_, _ = ParseACKRanges(data, nil)
		_, _ = ParsePeerTestBlock(data)
		_, _ = ParseLongHeader(data, network)
		_, _ = ParseShortHeader(data)
		_, _ = ParseRelayTagRequestBlock(data)
		_, _ = ParseRelayTagBlock(data)
		_, _ = ParseNewTokenBlock(data)
		_, _ = ParsePathChallengeBlock(data)
		_, _ = ParsePathResponseBlock(data)
		_, _ = ParseRelayRequestBlock(data)
		_, _ = ParseRelayIntroBlock(data)
		_, _ = ParseRelayResponseBlock(data)
	})
}
