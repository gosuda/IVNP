package cryptography

import (
	"encoding/hex"
	"testing"
)

func TestGOST256VerificationMatchesRFC7091(t *testing.T) {
	testCurve := newCurve([6]string{
		"7",
		"5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E",
		"8000000000000000000000000000000000000000000000000000000000000431",
		"8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3",
		"2",
		"8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8",
	})
	decode := func(name, value string) []byte {
		t.Helper()
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		return decoded
	}

	// RFC 7091, Section 7, publishes the curve, digest scalar, public key,
	// and signature independently of this implementation.
	public := decode("public key",
		"7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B"+
			"26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA")
	digest := decode("digest", "2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5")
	r := decode("r", "41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493")
	s := decode("s", "01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40")

	if !testCurve.verify(public, digest, r, s) {
		t.Fatal("GOST R 34.10-2012 RFC 7091 vector verification failed")
	}
}
