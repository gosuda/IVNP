package tunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"testing"

	"gosuda.org/ivnp/dataplane"
)

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

type buildHotPathReplyRegistry struct {
	entries map[[8]byte]dataplane.GarlicReplyKey
}

func (r *buildHotPathReplyRegistry) RegisterGarlicReplyKey(key dataplane.GarlicReplyKey) error {
	r.entries[key.Tag] = key
	return nil
}
func (r *buildHotPathReplyRegistry) RemoveGarlicReplyKey(tag [8]byte) { delete(r.entries, tag) }

func newBuildHotPathManager(tb testing.TB) (*BuildManager, OutboundBuild) {
	tb.Helper()
	const now = uint64(1_700_000_000_000)
	replies := &buildHotPathReplyRegistry{entries: make(map[[8]byte]dataplane.GarlicReplyKey)}
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: buildDiscardSender{}, Now: func() uint64 { return now }}),
		Sender:  buildDiscardSender{}, ReplyKeys: replies, Now: func() uint64 { return now }, Random: new(buildCounterReader),
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
