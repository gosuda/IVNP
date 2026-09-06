package ssu2

import (
	"bytes"
	"testing"
)

func TestExtensionBlocksRoundTripAndValidateLengths(t *testing.T) {
	tagWire, err := MarshalRelayTagBlock(nil, RelayTag{Tag: 7, Expiration: 9})
	if err != nil {
		t.Fatal(err)
	}
	tag, err := ParseRelayTagBlock(tagWire[3:])
	if err != nil || tag.Tag != 7 || tag.Expiration != 9 {
		t.Fatalf("relay tag = %#v, %v", tag, err)
	}
	tokenWire, err := MarshalNewTokenBlock(nil, NewToken{Token: 11, Expiration: 13})
	if err != nil {
		t.Fatal(err)
	}
	token, err := ParseNewTokenBlock(tokenWire[3:])
	if err != nil || token.Token != 11 || token.Expiration != 13 {
		t.Fatalf("new token = %#v, %v", token, err)
	}
	challenge := PathChallenge{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	challengeWire, err := MarshalPathChallengeBlock(nil, challenge)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePathChallengeBlock(challengeWire[3:])
	if err != nil || !bytes.Equal(parsed.Data[:], challenge.Data[:]) {
		t.Fatalf("challenge = %#v, %v", parsed, err)
	}
	if _, err := ParseRelayTagBlock([]byte{0}); err == nil {
		t.Fatal("short relay tag accepted")
	}
	if _, err := ParseNewTokenBlock(make([]byte, 11)); err == nil {
		t.Fatal("short new token accepted")
	}
	if _, err := ParsePathResponseBlock(make([]byte, 7)); err == nil {
		t.Fatal("short path response accepted")
	}
}
