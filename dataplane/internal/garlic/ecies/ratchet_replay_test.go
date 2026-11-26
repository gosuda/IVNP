package garlicecies

import (
	"errors"
	"math/big"
	"testing"
)

// alternateNewSessionEncodings returns the seven other Elligator2 encodings of
// the ephemeral key in packet: the two unused high bits, and the second
// representative 1/(2r) with every high-bit pattern.
func alternateNewSessionEncodings(t testing.TB, packet []byte) [][]byte {
	t.Helper()
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	half := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	var bigEndian [32]byte
	for i := range 32 {
		bigEndian[31-i] = packet[i]
	}
	bigEndian[0] &= 0x3f
	r := new(big.Int).SetBytes(bigEndian[:])
	other := new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Lsh(r, 1), p), p)
	if other.Cmp(half) > 0 {
		other.Sub(p, other)
	}
	if other.Cmp(r) == 0 {
		t.Fatal("representative is its own alternate")
	}
	otherBytes := other.FillBytes(make([]byte, 32))
	var out [][]byte
	for _, mask := range []byte{0x00, 0x40, 0x80, 0xc0} {
		if mask != packet[31]&0xc0 {
			flipped := append([]byte(nil), packet...)
			flipped[31] = flipped[31]&0x3f | mask
			out = append(out, flipped)
		}
		alternate := append([]byte(nil), packet...)
		for i := range 32 {
			alternate[i] = otherBytes[31-i]
		}
		alternate[31] |= mask
		out = append(out, alternate)
	}
	if len(out) != 7 {
		t.Fatalf("alternate encodings = %d, want 7", len(out))
	}
	return out
}

func TestRatchetNewSessionReplayRejectsAlternateEncodings(t *testing.T) {
	a, b, _, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	unbound, err := a.EncryptUnbound(make([]byte, 2048), ratchetPublic(t, b), 4, clove("pay"), now)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := a.Encrypt(make([]byte, 2048), bPeer, ratchetPublic(t, b), 4, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, packet := range [][]byte{unbound, bound} {
		result, receiveErr := b.Receive(make([]byte, 2048), make([]byte, 2048), packet, now)
		if receiveErr != nil {
			t.Fatal(receiveErr)
		}
		result.Candidate.Discard()
		for index, replay := range alternateNewSessionEncodings(t, packet) {
			result, receiveErr = b.Receive(make([]byte, 2048), make([]byte, 2048), replay, now+1)
			result.Candidate.Discard()
			if !errors.Is(receiveErr, ErrRatchetReplay) {
				t.Fatalf("alternate encoding %d: err = %v, want %v", index, receiveErr, ErrRatchetReplay)
			}
		}
	}
}

func TestRatchetNewSessionReplayCoversTimestampWindow(t *testing.T) {
	a, b, _, _, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	// The sender clock leads by the full 120 s future allowance, so the
	// timestamp stays acceptable until 420 s after first receipt.
	ns, err := a.EncryptUnbound(make([]byte, 2048), ratchetPublic(t, b), 4, clove("pay"), now+120_000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 2048), make([]byte, 2048), ns, now); err != nil {
		t.Fatal(err)
	}
	for _, later := range []uint64{now + 301_000, now + 420_999} {
		if _, err = b.Receive(make([]byte, 2048), make([]byte, 2048), ns, later); !errors.Is(err, ErrRatchetReplay) {
			t.Fatalf("replay at +%d ms: err = %v, want %v", later-now, err, ErrRatchetReplay)
		}
	}
	// The reservation may outlast the window by one bucket span; either
	// rejection is correct once the timestamp itself has expired.
	if _, err = b.Receive(make([]byte, 2048), make([]byte, 2048), ns, now+421_000); !errors.Is(err, ErrRatchetExpired) && !errors.Is(err, ErrRatchetReplay) {
		t.Fatalf("replay after timestamp window: err = %v, want %v or %v", err, ErrRatchetExpired, ErrRatchetReplay)
	}
}
