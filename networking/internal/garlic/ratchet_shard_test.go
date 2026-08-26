package garlic

import (
	"errors"
	"fmt"
	"runtime"
	"testing"

	"gosuda.org/ivnp/foundation"
	garlicecies "gosuda.org/ivnp/networking/internal/garlic/ecies"
)

func establishRatchetShard(shard *garlicecies.RatchetManager, peer foundation.Hash, remote *foundation.LocalDestination, now uint64) error {
	remoteManager, err := garlicecies.NewRatchetManager(remote, garlicecies.RatchetConfig{TagLookahead: 4, MaxInboundTags: 64})
	if err != nil {
		return err
	}
	defer remoteManager.ReleaseSensitive()
	remotePublic := remote.X25519Public()
	packet, err := shard.Encrypt(make([]byte, 2048), peer, remotePublic[:], 4, nil, now)
	if err != nil {
		return err
	}
	result, err := remoteManager.Receive(make([]byte, 2048), make([]byte, 2048), packet, now)
	if err != nil {
		return err
	}
	if !result.NewSession || len(result.Reply) == 0 {
		return fmt.Errorf("unexpected new-session result: %#v", result)
	}
	if _, err = shard.Receive(make([]byte, 2048), make([]byte, 1), result.Reply, now); err != nil {
		return err
	}
	if !shard.HasPeer(peer) {
		return errors.New("initiator session was not established")
	}
	return nil
}

func TestRatchetManagerRejectsCrossShardBindDuplicate(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })

	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer local.ReleaseSensitive()
	manager, err := NewRatchetManager(local, RatchetConfig{MaxSessions: 4, MaxInboundTags: 64, TagLookahead: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.ReleaseSensitive()
	if len(manager.shards) != 2 {
		t.Fatalf("ratchet shards = %d, want 2", len(manager.shards))
	}

	remotes := make([]*foundation.LocalDestination, 2)
	for index := range remotes {
		remotes[index], err = foundation.GenerateLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		defer remotes[index].ReleaseSensitive()
	}
	observed, peer := foundation.Hash{0xa1}, foundation.Hash{0xb2}
	results := make(chan error, 2)
	go func() { results <- establishRatchetShard(manager.shards[0], observed, remotes[0], 1_000) }()
	go func() { results <- establishRatchetShard(manager.shards[1], peer, remotes[1], 1_000) }()
	for range 2 {
		if err = <-results; err != nil {
			t.Fatal(err)
		}
	}

	if err = manager.BindPeer(observed, peer); !errors.Is(err, ErrRatchet) {
		t.Fatalf("cross-shard BindPeer() = %v, want ErrRatchet", err)
	}
	if !manager.shards[0].HasPeer(observed) || manager.shards[0].HasPeer(peer) || !manager.shards[1].HasPeer(peer) {
		t.Fatal("rejected bind changed cross-shard session ownership")
	}
}
func TestRatchetManagerIndexesOneTimeReceiveTags(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })

	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer local.ReleaseSensitive()
	remote, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer remote.ReleaseSensitive()
	manager, err := NewRatchetManager(local, RatchetConfig{MaxSessions: 4, MaxInboundTags: 64, TagLookahead: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.ReleaseSensitive()
	remoteManager, err := garlicecies.NewRatchetManager(remote, garlicecies.RatchetConfig{MaxSessions: 4, MaxInboundTags: 64, TagLookahead: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer remoteManager.ReleaseSensitive()

	peer := foundation.Hash{0x7a}
	remotePublic := remote.X25519Public()
	packet, err := manager.Encrypt(make([]byte, 2048), peer, remotePublic[:], 4, nil, 1_000)
	if err != nil {
		t.Fatal(err)
	}
	remoteResult, err := remoteManager.Receive(make([]byte, 2048), make([]byte, 2048), packet, 1_000)
	if err != nil {
		t.Fatal(err)
	}
	var replyTag garlicecies.SessionTag
	copy(replyTag[:], remoteResult.Reply[:len(replyTag)])
	manager.tagMu.RLock()
	_, indexed := manager.tagRoutes[replyTag]
	manager.tagMu.RUnlock()
	if !indexed {
		t.Fatal("pending New Session Reply tag was not indexed")
	}
	if _, err = manager.Receive(make([]byte, 2048), make([]byte, 1), remoteResult.Reply, 1_000); err != nil {
		t.Fatal(err)
	}
	manager.tagMu.RLock()
	_, pendingRetained := manager.tagRoutes[replyTag]
	manager.tagMu.RUnlock()
	if pendingRetained {
		t.Fatal("consumed New Session Reply tag remained indexed")
	}

	existing, err := remoteManager.EncryptExisting(make([]byte, 256), remoteResult.Peer, nil, garlicecies.RatchetOptions{}, 1_001)
	if err != nil {
		t.Fatal(err)
	}
	var existingTag garlicecies.SessionTag
	copy(existingTag[:], existing[:len(existingTag)])
	manager.tagMu.RLock()
	_, indexed = manager.tagRoutes[existingTag]
	manager.tagMu.RUnlock()
	if !indexed {
		t.Fatal("established receive tag was not indexed")
	}
	if _, err = manager.Receive(make([]byte, 256), make([]byte, 1), existing, 1_001); err != nil {
		t.Fatal(err)
	}
	manager.tagMu.RLock()
	_, consumedRetained := manager.tagRoutes[existingTag]
	manager.tagMu.RUnlock()
	if consumedRetained {
		t.Fatal("consumed established tag remained indexed")
	}
}

func TestRatchetManagerRoutesUnindexedTagsByPacketHash(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer local.ReleaseSensitive()
	manager, err := NewRatchetManager(local, RatchetConfig{MaxSessions: 4, MaxInboundTags: 64, TagLookahead: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.ReleaseSensitive()

	packet := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	index, shard := manager.packetShard(packet)
	if index != 1 || shard != manager.shards[1] {
		t.Fatalf("unindexed packet routed to shard %d, want 1", index)
	}
}

func TestRatchetManagerPeerChurnRemainsBounded(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })

	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer local.ReleaseSensitive()
	remote, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer remote.ReleaseSensitive()
	const maxSessions = 8
	manager, err := NewRatchetManager(local, RatchetConfig{
		MaxSessions: maxSessions, MaxInboundTags: 128, TagLookahead: 4,
		SessionLifetime: 2, ReplayLifetime: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.ReleaseSensitive()
	remoteManager, err := garlicecies.NewRatchetManager(remote, garlicecies.RatchetConfig{
		MaxSessions: maxSessions, MaxInboundTags: 128, TagLookahead: 4,
		SessionLifetime: 2, ReplayLifetime: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remoteManager.ReleaseSensitive()
	remotePublic := remote.X25519Public()
	for index := range 64 {
		peer := foundation.Hash{byte(index + 1)}
		now := uint64(1_000 + 10*index)
		packet, encryptErr := manager.Encrypt(make([]byte, 2048), peer, remotePublic[:], 4, nil, now)
		if encryptErr != nil {
			t.Fatalf("peer %d encrypt: %v", index, encryptErr)
		}
		result, receiveErr := remoteManager.Receive(make([]byte, 2048), make([]byte, 2048), packet, now)
		if receiveErr != nil {
			t.Fatalf("peer %d remote receive: %v", index, receiveErr)
		}
		if _, receiveErr = manager.Receive(make([]byte, 2048), make([]byte, 1), result.Reply, now); receiveErr != nil {
			t.Fatalf("peer %d reply receive: %v", index, receiveErr)
		}
	}
	if stats := manager.Stats(); stats.Sessions > maxSessions {
		t.Fatalf("peer churn retained %d sessions, limit %d", stats.Sessions, maxSessions)
	}
}
