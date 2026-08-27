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
	if !result.NewSession || result.Candidate == nil || len(result.Reply) == 0 {
		return fmt.Errorf("unexpected new-session result: %#v", result)
	}
	if _, err = remoteManager.CommitNewSession(result.Candidate, result.Peer, now); err != nil {
		return err
	}
	if _, err = shard.Receive(make([]byte, 2048), make([]byte, 1), result.Reply, now); err != nil {
		return err
	}
	if !shard.HasPeer(peer) {
		return errors.New("initiator session was not established")
	}
	return nil
}

func TestRatchetManagerDuplicateNewDoesNotEvictCandidateShardVictim(t *testing.T) {
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
	if len(manager.shards) != 2 {
		t.Fatalf("ratchet shards = %d, want 2", len(manager.shards))
	}
	remotePublic := remote.X25519Public()
	observed := foundation.Sum(remotePublic[:])
	if err = establishRatchetShard(manager.shards[0], observed, remote, 1_000); err != nil {
		t.Fatal(err)
	}
	victimPeers := [...]foundation.Hash{{0xa1}, {0xa2}}
	for index, peer := range victimPeers {
		victimRemote, generateErr := foundation.GenerateLocalDestination()
		if generateErr != nil {
			t.Fatal(generateErr)
		}
		defer victimRemote.ReleaseSensitive()
		if err = establishRatchetShard(manager.shards[1], peer, victimRemote, uint64(1_000+index)); err != nil {
			t.Fatal(err)
		}
	}
	before := manager.shards[1].Stats()
	sender, err := garlicecies.NewRatchetManager(remote, garlicecies.RatchetConfig{MaxSessions: 64, MaxInboundTags: 256, TagLookahead: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.ReleaseSensitive()
	localPublic := local.X25519Public()
	var packet []byte
	for range 64 {
		packet, err = sender.Encrypt(make([]byte, 2048), foundation.Hash{0xbb}, localPublic[:], 4, nil, 2_000)
		if err != nil {
			t.Fatal(err)
		}
		if index, _ := manager.packetShard(packet); index == 1 {
			break
		}
		packet = nil
	}
	if packet == nil {
		t.Fatal("could not route duplicate New Session to full candidate shard")
	}
	result, receiveErr := manager.Receive(make([]byte, 2048), make([]byte, 2048), packet, 2_000)
	if receiveErr != nil {
		t.Fatal(receiveErr)
	}
	if result.Candidate == nil {
		t.Fatal("duplicate New Session did not return an admission candidate")
	}
	afterReceive := manager.shards[1].Stats()
	if afterReceive.Sessions != before.Sessions || afterReceive.InboundTags != before.InboundTags {
		t.Fatalf("Receive mutated full candidate shard: before=%+v after=%+v", before, afterReceive)
	}
	commit, commitErr := manager.CommitNew(result.Candidate, observed, 2_000)
	if commitErr != nil || commit != NewSessionRetained {
		t.Fatalf("duplicate New Session commit = %v, %v", commit, commitErr)
	}
	afterCommit := manager.shards[1].Stats()
	if afterCommit.Sessions != before.Sessions || afterCommit.InboundTags != before.InboundTags {
		t.Fatalf("retained duplicate mutated full candidate shard: before=%+v after=%+v", before, afterCommit)
	}
	for _, peer := range victimPeers {
		if !manager.shards[1].HasPeer(peer) {
			t.Fatalf("duplicate New Session evicted unrelated peer %x", peer)
		}
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
	if remoteResult.Candidate == nil {
		t.Fatal("remote New Session did not return an admission candidate")
	}
	if _, err = remoteManager.CommitNewSession(remoteResult.Candidate, remoteResult.Peer, 1_000); err != nil {
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
	const maxSessions = 8
	manager, err := NewRatchetManager(local, RatchetConfig{
		MaxSessions: maxSessions, MaxInboundTags: 128, TagLookahead: 4,
		SessionLifetime: 2, ReplayLifetime: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.ReleaseSensitive()
	for index := range 64 {
		func() {
			remote, generateErr := foundation.GenerateLocalDestination()
			if generateErr != nil {
				t.Fatal(generateErr)
			}
			defer remote.ReleaseSensitive()
			remoteManager, managerErr := garlicecies.NewRatchetManager(remote, garlicecies.RatchetConfig{
				MaxSessions: maxSessions, MaxInboundTags: 128, TagLookahead: 4,
				SessionLifetime: 2, ReplayLifetime: 2,
			})
			if managerErr != nil {
				t.Fatal(managerErr)
			}
			defer remoteManager.ReleaseSensitive()
			peer := foundation.Hash{byte(index + 1)}
			now := uint64(1_000 + 10*index)
			remotePublic := remote.X25519Public()
			packet, encryptErr := manager.Encrypt(make([]byte, 2048), peer, remotePublic[:], 4, nil, now)
			if encryptErr != nil {
				t.Fatalf("peer %d encrypt: %v", index, encryptErr)
			}
			result, receiveErr := remoteManager.Receive(make([]byte, 2048), make([]byte, 2048), packet, now)
			if receiveErr != nil {
				t.Fatalf("peer %d remote receive: %v", index, receiveErr)
			}
			if _, receiveErr = remoteManager.CommitNewSession(result.Candidate, result.Peer, now); receiveErr != nil {
				t.Fatalf("peer %d remote commit: %v", index, receiveErr)
			}
			if _, receiveErr = manager.Receive(make([]byte, 2048), make([]byte, 1), result.Reply, now); receiveErr != nil {
				t.Fatalf("peer %d reply receive: %v", index, receiveErr)
			}
		}()
	}
	if stats := manager.Stats(); stats.Sessions > maxSessions {
		t.Fatalf("peer churn retained %d sessions, limit %d", stats.Sessions, maxSessions)
	}
}
