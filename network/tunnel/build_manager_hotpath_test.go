package tunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"testing"
)

// randomPositions returns one owned pending-build descriptor. The injected
// io.Reader interface may make each four-byte shuffle read escape; keep the
// complete bounded shuffle at no more than four allocations.
func TestBuildRequestSetAllocationBudget(t *testing.T) {
	manager := &BuildManager{random: new(buildCounterReader)}
	if got := testing.AllocsPerRun(100, func() {
		positions, err := manager.randomPositions(3, 4)
		if err != nil {
			t.Fatal(err)
		}
		buildHotPathPositions = positions
	}); got > 4 {
		t.Fatalf("build request position allocations = %v, want at most 4", got)
	}
}

func BenchmarkBuildManagerRequestSet(b *testing.B) {
	manager, build := newBuildHotPathManager(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		replyID, err := manager.StartOutbound(context.Background(), build)
		if err != nil {
			b.Fatal(err)
		}
		manager.removePending(replyID)
	}
}

var buildHotPathPositions []uint8

type buildHotPathReplyRegistry struct{ entries map[[8]byte]GarlicReplyKey }

func (r *buildHotPathReplyRegistry) RegisterGarlicReplyKey(key GarlicReplyKey) error {
	r.entries[key.Tag] = key
	return nil
}
func (r *buildHotPathReplyRegistry) RemoveGarlicReplyKey(tag [8]byte) { delete(r.entries, tag) }

func newBuildHotPathManager(tb testing.TB) (*BuildManager, OutboundBuild) {
	tb.Helper()
	const now = uint64(1_700_000_000_000)
	replies := &buildHotPathReplyRegistry{entries: make(map[[8]byte]GarlicReplyKey)}
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: NewRuntime(RuntimeConfig{Sender: discardTunnelSender{}, Now: func() uint64 { return now }}),
		Sender:  discardTunnelSender{}, ReplyKeys: replies, Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		tb.Fatal(err)
	}
	build := OutboundBuild{
		CircuitID: 91, ReplyRouter: sha256.Sum256([]byte("reply-router")), ReplyTunnelID: 92,
		ExpiresAt: now + 10*60*1000, Hops: make([]ShortBuildHop, 3),
	}
	for index := range build.Hops {
		privateBytes := make([]byte, 32)
		for offset := range privateBytes {
			privateBytes[offset] = byte(1 + index*32 + offset)
		}
		private, keyErr := ecdh.X25519().NewPrivateKey(privateBytes)
		if keyErr != nil {
			tb.Fatal(keyErr)
		}
		build.Hops[index] = ShortBuildHop{
			Router: sha256.Sum256([]byte{byte(index + 1)}), ReceiveTunnelID: uint32(100 + index),
		}
		copy(build.Hops[index].StaticKey[:], private.PublicKey().Bytes())
	}
	return manager, build
}
