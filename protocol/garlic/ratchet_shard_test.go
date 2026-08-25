package garlic

import (
	"errors"
	"fmt"
	ivnp "gosuda.org/ivnp/i2p"
	"gosuda.org/ivnp/protocol/garlic/ecies"
	"runtime"
	"testing"
)

func establishRatchetShard(shard *ecies.RatchetManager, peer ivnp.Hash, remote *ivnp.LocalDestination, now uint64) error {
	remoteManager, err := ecies.NewRatchetManager(remote, ecies.RatchetConfig{TagLookahead: 4, MaxInboundTags: 64})
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

	local, err := ivnp.GenerateLocalDestination()
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

	remotes := make([]*ivnp.LocalDestination, 2)
	for index := range remotes {
		remotes[index], err = ivnp.GenerateLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		defer remotes[index].ReleaseSensitive()
	}
	observed, peer := ivnp.Hash{0xa1}, ivnp.Hash{0xb2}
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
func TestRatchetManagerPeerChurnRemainsBounded(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })

	local, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer local.ReleaseSensitive()
	remote, err := ivnp.GenerateLocalDestination()
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
	remoteManager, err := ecies.NewRatchetManager(remote, ecies.RatchetConfig{
		MaxSessions: maxSessions, MaxInboundTags: 128, TagLookahead: 4,
		SessionLifetime: 2, ReplayLifetime: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remoteManager.ReleaseSensitive()
	remotePublic := remote.X25519Public()
	for index := range 64 {
		peer := ivnp.Hash{byte(index + 1)}
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
