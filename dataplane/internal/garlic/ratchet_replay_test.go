package garlic

import (
	"errors"
	"math/big"
	"runtime"
	"testing"

	dataplanegarlicecies "gosuda.org/ivnp/dataplane/internal/garlic/ecies"
)

// alternateNewSessionEncodings returns the seven other Elligator2 encodings of
// the ephemeral key in packet.
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
	return out
}

func TestRatchetManagerRoutesNewSessionReplaysByDecodedKey(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	local := ratchetShardDestination(t)
	remote := ratchetShardDestination(t)
	manager, err := NewRatchetManager(local, RatchetConfig{MaxSessions: 4, MaxInboundTags: 64, TagLookahead: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.ReleaseSensitive)
	if len(manager.shards) != 4 {
		t.Fatalf("ratchet shards = %d, want 4", len(manager.shards))
	}
	sender, err := dataplanegarlicecies.NewRatchetManager(remote, RatchetConfig{TagLookahead: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.ReleaseSensitive)
	localPublic := local.X25519Public()
	const now = 1_800_000_000_000
	for range 4 {
		ns, encryptErr := sender.EncryptUnbound(make([]byte, 2048), localPublic[:], 4, nil, now)
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		if _, err = manager.Receive(make([]byte, 2048), make([]byte, 2048), ns, now); err != nil {
			t.Fatal(err)
		}
		want, _ := manager.packetShard(ns)
		for index, replay := range alternateNewSessionEncodings(t, ns) {
			if got, _ := manager.packetShard(replay); got != want {
				t.Fatalf("alternate encoding %d routed to shard %d, want %d", index, got, want)
			}
			if _, err = manager.Receive(make([]byte, 2048), make([]byte, 2048), replay, now+1); !errors.Is(err, ErrRatchetReplay) {
				t.Fatalf("alternate encoding %d: err = %v, want %v", index, err, ErrRatchetReplay)
			}
		}
	}
}
