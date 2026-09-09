package garlic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"

	dataplanegarlicecies "gosuda.org/ivnp/dataplane/internal/garlic/ecies"
	"gosuda.org/ivnp/foundation"
)

func establishRatchetShard(shard *dataplanegarlicecies.RatchetManager, peer foundation.Hash, remote *foundation.LocalDestination, now uint64) error {
	remoteManager, err := dataplanegarlicecies.NewRatchetManager(remote, dataplanegarlicecies.RatchetConfig{TagLookahead: 4, MaxInboundTags: 64})
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
	sender, err := dataplanegarlicecies.NewRatchetManager(remote, dataplanegarlicecies.RatchetConfig{MaxSessions: 64, MaxInboundTags: 256, TagLookahead: 4})
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
	retained, retainErr := manager.RetainNew(result.Candidate, observed, 2_000)
	if retainErr != nil || !retained {
		t.Fatalf("duplicate New Session retention = %t, %v", retained, retainErr)
	}
	if _, err := manager.CommitNew(result.Candidate, observed, 2_000); !errors.Is(err, ErrRatchet) {
		t.Fatalf("retained candidate remained committable: %v", err)
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
	remoteManager, err := dataplanegarlicecies.NewRatchetManager(remote, dataplanegarlicecies.RatchetConfig{MaxSessions: 4, MaxInboundTags: 64, TagLookahead: 4})
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
	var replyTag dataplanegarlicecies.SessionTag
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

	existing, err := remoteManager.EncryptExisting(make([]byte, 256), remoteResult.Peer, nil, dataplanegarlicecies.RatchetOptions{}, 1_001)
	if err != nil {
		t.Fatal(err)
	}
	var existingTag dataplanegarlicecies.SessionTag
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
			remoteManager, managerErr := dataplanegarlicecies.NewRatchetManager(remote, dataplanegarlicecies.RatchetConfig{
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

func ratchetShardDestination(t *testing.T) *foundation.LocalDestination {
	t.Helper()
	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.ReleaseSensitive)
	return local
}

func ratchetShardPair(t *testing.T, config RatchetConfig) (*RatchetManager, *dataplanegarlicecies.RatchetManager, foundation.Hash, foundation.Hash) {
	t.Helper()
	local := ratchetShardDestination(t)
	remote := ratchetShardDestination(t)
	manager, err := NewRatchetManager(local, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.ReleaseSensitive)
	remoteManager, err := dataplanegarlicecies.NewRatchetManager(remote, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remoteManager.ReleaseSensitive)
	peer := foundation.Hash{1}
	remotePublic := remote.X25519Public()
	packet, err := manager.Encrypt(make([]byte, 2048), peer, remotePublic[:], 4, nil, 1_000)
	if err != nil {
		t.Fatal(err)
	}
	result, err := remoteManager.Receive(make([]byte, 2048), make([]byte, 2048), packet, 1_000)
	if err != nil {
		t.Fatal(err)
	}
	if result.Candidate == nil {
		t.Fatal("New Session did not return an admission candidate")
	}
	if _, err = remoteManager.CommitNewSession(result.Candidate, result.Peer, 1_000); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Receive(make([]byte, 2048), nil, result.Reply, 1_000); err != nil {
		t.Fatal(err)
	}
	return manager, remoteManager, peer, result.Peer
}

func TestRatchetManagerDividesInboundTagBudgetExactly(t *testing.T) {
	previous := runtime.GOMAXPROCS(3)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	local := ratchetShardDestination(t)
	remote := ratchetShardDestination(t)
	manager, err := NewRatchetManager(local, RatchetConfig{MaxSessions: 96, MaxInboundTags: 49, TagLookahead: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.ReleaseSensitive)
	if len(manager.shards) != 3 {
		t.Fatalf("shards = %d, want 3", len(manager.shards))
	}
	for index, capacity := range []int{17, 16, 16} {
		shard := manager.shards[index]
		for session := range capacity {
			if err = establishRatchetShard(shard, foundation.Hash{byte(session + 1)}, remote, 1_000); err != nil {
				t.Fatalf("shard %d session %d: %v", index, session, err)
			}
		}
		if err = establishRatchetShard(shard, foundation.Hash{0xff}, remote, 1_000); !errors.Is(err, dataplanegarlicecies.ErrRatchetTagExhausted) {
			t.Fatalf("shard %d exceeding %d tags: %v", index, capacity, err)
		}
		if got := shard.Stats().InboundTags; got != capacity {
			t.Errorf("shard %d tags = %d, want %d", index, got, capacity)
		}
	}
	if got := manager.Stats().InboundTags; got != 49 {
		t.Fatalf("aggregate tags = %d, want 49", got)
	}
}

func TestRatchetManagerDividesSessionBudgetExactly(t *testing.T) {
	previous := runtime.GOMAXPROCS(3)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	local := ratchetShardDestination(t)
	remote := ratchetShardDestination(t)
	manager, err := NewRatchetManager(local, RatchetConfig{MaxSessions: 5, MaxInboundTags: 97, TagLookahead: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.ReleaseSensitive)
	if len(manager.shards) != 3 {
		t.Fatalf("shards = %d, want 3", len(manager.shards))
	}
	for index, capacity := range []int{2, 2, 1} {
		shard := manager.shards[index]
		for session := range 3 {
			if err = establishRatchetShard(shard, foundation.Hash{byte(session + 1)}, remote, uint64(1_000+session)); err != nil {
				t.Fatalf("shard %d session %d: %v", index, session, err)
			}
		}
		if got := shard.Stats().Sessions; got != capacity {
			t.Errorf("shard %d sessions = %d, want %d", index, got, capacity)
		}
	}
	if got := manager.Stats().Sessions; got != 5 {
		t.Fatalf("aggregate sessions = %d, want 5", got)
	}
}

func TestRatchetManagerRejectsInvalidLookaheadBeforeSharding(t *testing.T) {
	local := ratchetShardDestination(t)
	maxInt := int(^uint(0) >> 1)
	for _, config := range []RatchetConfig{
		{TagLookahead: 65537, MaxInboundTags: maxInt},
		{TagLookahead: maxInt, MaxInboundTags: maxInt},
		{TagLookahead: 33, MaxInboundTags: 32},
		{MaxInboundTags: 511},
	} {
		manager, err := NewRatchetManager(local, config)
		if manager != nil {
			manager.ReleaseSensitive()
		}
		if !errors.Is(err, ErrRatchet) {
			t.Errorf("config %+v: error = %v, want ErrRatchet", config, err)
		}
	}
}

func TestRatchetManagerSupportsSingleLookaheadBudget(t *testing.T) {
	previous := runtime.GOMAXPROCS(8)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	manager, remote, peer, remotePeer := ratchetShardPair(t, RatchetConfig{TagLookahead: 4, MaxInboundTags: 4})
	if len(manager.shards) != 1 {
		t.Fatalf("shards = %d, want 1", len(manager.shards))
	}
	for range 8 {
		packet, err := remote.EncryptExisting(make([]byte, 256), remotePeer, nil, RatchetOptions{}, 1_001)
		if err != nil {
			t.Fatal(err)
		}
		result, err := manager.Receive(make([]byte, 256), nil, packet, 1_001)
		if err != nil || result.Peer != peer {
			t.Fatalf("single-window receive = %+v, %v", result, err)
		}
		if got := manager.Stats().InboundTags; got != 4 {
			t.Fatalf("single-window tags = %d, want 4", got)
		}
	}
}

func TestRatchetManagerDefaultWindowAdmitsDHReplacement(t *testing.T) {
	previous := runtime.GOMAXPROCS(64)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	manager, remote, peer, remotePeer := ratchetShardPair(t, RatchetConfig{})
	if got := manager.Stats().InboundTags; got != 512 {
		t.Fatalf("initial inbound tags = %d, want 512", got)
	}
	var packet []byte
	var err error
	for range 512 {
		packet, err = remote.EncryptExisting(make([]byte, 256), remotePeer, nil, RatchetOptions{}, 1_001)
		if err != nil {
			t.Fatal(err)
		}
	}
	if result, err := manager.Receive(make([]byte, 256), nil, packet, 1_001); err != nil || result.Peer != peer {
		t.Fatalf("receive at default lookahead edge = %+v, %v", result, err)
	}
	packet, err = remote.EncryptExisting(make([]byte, 256), remotePeer, nil, RatchetOptions{RequestDH: true}, 1_002)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := manager.Receive(make([]byte, 256), nil, packet, 1_002); err != nil || !result.DHStep {
		t.Fatalf("incoming DH replacement = %+v, %v", result, err)
	}
	reverse, err := manager.EncryptExisting(make([]byte, 256), peer, nil, RatchetOptions{}, 1_003)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := remote.Receive(make([]byte, 256), nil, reverse, 1_003); err != nil || !result.DHStep {
		t.Fatalf("reverse DH = %+v, %v", result, err)
	}
	packet, err = remote.EncryptExisting(make([]byte, 256), remotePeer, nil, RatchetOptions{ACKRequest: true}, 1_004)
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Receive(make([]byte, 256), nil, packet, 1_004)
	if err != nil || result.Peer != peer || len(result.ACKRequests) != 1 {
		t.Fatalf("replacement-window receive = %+v, %v", result, err)
	}
	if got := manager.Stats().InboundTags; got > 8192 {
		t.Fatalf("default inbound tags = %d, limit 8192", got)
	}
}

func TestRatchetTagObserverRemovesAllCollisionOwners(t *testing.T) {
	manager := &RatchetManager{
		tagRoutes: make(map[dataplanegarlicecies.SessionTag]int),
		shards:    make([]*dataplanegarlicecies.RatchetManager, 4),
	}
	tag := dataplanegarlicecies.SessionTag{3}
	observers := []ratchetTagObserver{
		{manager: manager, shard: 0},
		{manager: manager, shard: 1},
		{manager: manager, shard: 2},
	}
	assertOwner := func(want int) {
		t.Helper()
		if got, _ := manager.packetShard(tag[:]); got != want {
			t.Fatalf("tag routed to shard %d, want %d", got, want)
		}
	}
	observers[2].TagAdded(tag)
	observers[2].TagAdded(tag)
	observers[1].TagRemoved(tag)
	assertOwner(2)
	observers[0].TagAdded(tag)
	observers[1].TagAdded(tag)
	observers[1].TagAdded(tag)
	assertOwner(0)
	observers[2].TagRemoved(tag)
	assertOwner(0)
	observers[0].TagRemoved(tag)
	assertOwner(1)
	observers[1].TagRemoved(tag)
	assertOwner(3)
	if len(manager.tagRoutes) != 0 || len(manager.tagCollisions) != 0 {
		t.Fatalf("removed collision retained routes=%d collisions=%d", len(manager.tagRoutes), len(manager.tagCollisions))
	}
	observers[0].TagRemoved(tag)
	observers[2].TagAdded(tag)
	assertOwner(2)
	observers[2].TagRemoved(tag)
	assertOwner(3)
}

func TestRatchetTagObserverConcurrentOwnership(t *testing.T) {
	manager := &RatchetManager{
		tagRoutes: make(map[dataplanegarlicecies.SessionTag]int),
		shards:    make([]*dataplanegarlicecies.RatchetManager, 8),
	}
	tag := dataplanegarlicecies.SessionTag{7}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for owner := range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			observer := ratchetTagObserver{manager: manager, shard: owner}
			<-start
			for range 128 {
				observer.TagAdded(tag)
				observer.TagAdded(tag)
				if got, _ := manager.packetShard(tag[:]); got < 0 || got >= 4 {
					t.Errorf("live tag routed to nonowner shard %d", got)
				}
				observer.TagRemoved(tag)
				observer.TagRemoved(tag)
			}
		}()
	}
	close(start)
	workers.Wait()
	if len(manager.tagRoutes) != 0 || len(manager.tagCollisions) != 0 {
		t.Fatalf("completed owners retained routes=%d collisions=%d", len(manager.tagRoutes), len(manager.tagCollisions))
	}
	if got, _ := manager.packetShard(tag[:]); got != 7 {
		t.Fatalf("removed tag routed to shard %d, want packet-hash shard 7", got)
	}
}

func TestRatchetManagerPrunesAndExpiresIndexedTags(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	manager, remote, peer, remotePeer := ratchetShardPair(t, RatchetConfig{
		MaxSessions: 4, MaxInboundTags: 64, TagLookahead: 4, SessionLifetime: 10,
	})
	var packets [8][]byte
	for index := range packets {
		var err error
		packets[index], err = remote.EncryptExisting(make([]byte, 256), remotePeer, nil, RatchetOptions{}, 1_001)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, index := range []int{3, 7} {
		if _, err := manager.Receive(make([]byte, 256), nil, packets[index], 1_001); err != nil {
			t.Fatalf("receive index %d: %v", index, err)
		}
	}
	for _, index := range []int{0, 3, 7} {
		tag := dataplanegarlicecies.SessionTag(packets[index][:8])
		if _, indexed := manager.tagRoutes[tag]; indexed {
			t.Errorf("pruned or consumed index %d remained routed", index)
		}
		want := int(binary.LittleEndian.Uint64(tag[:]) % uint64(len(manager.shards)))
		if got, _ := manager.packetShard(packets[index]); got != want {
			t.Errorf("removed index %d routed to shard %d, want packet-hash shard %d", index, got, want)
		}
	}
	if got, _ := manager.packetShard(packets[4]); got != 1 {
		t.Fatalf("retained historical tag routed to shard %d, want 1", got)
	}
	if result, err := manager.Receive(make([]byte, 256), nil, packets[4], 1_002); err != nil || result.Peer != peer {
		t.Fatalf("retained historical receive = %+v, %v", result, err)
	}
	if _, err := manager.Receive(make([]byte, 256), nil, packets[6], 2_000); err == nil {
		t.Fatal("expired tag authenticated")
	}
	if len(manager.tagRoutes) != 0 || len(manager.tagCollisions) != 0 || manager.Stats().InboundTags != 0 {
		t.Fatalf("expiry retained routes=%d collisions=%d stats=%+v", len(manager.tagRoutes), len(manager.tagCollisions), manager.Stats())
	}
}

func TestRatchetManagerReleaseClearsCollidingRoutes(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	manager, _, peer, _ := ratchetShardPair(t, RatchetConfig{MaxSessions: 4, MaxInboundTags: 64, TagLookahead: 4})
	tag := dataplanegarlicecies.SessionTag{0xfe}
	ratchetTagObserver{manager: manager, shard: 0}.TagAdded(tag)
	ratchetTagObserver{manager: manager, shard: 1}.TagAdded(tag)
	manager.ReleaseSensitive()
	manager.ReleaseSensitive()
	if len(manager.tagRoutes) != 0 || len(manager.tagCollisions) != 0 {
		t.Fatalf("release retained routes=%d collisions=%d", len(manager.tagRoutes), len(manager.tagCollisions))
	}
	if _, err := manager.EncryptExisting(make([]byte, 256), peer, nil, RatchetOptions{}, 1_001); !errors.Is(err, ErrRatchetClosed) {
		t.Fatalf("released manager encrypt error = %v, want ErrRatchetClosed", err)
	}
}

func TestRatchetManagerConsumesIndexedTagOnAuthenticationFailure(t *testing.T) {
	manager, remote, _, remotePeer := ratchetShardPair(t, RatchetConfig{MaxSessions: 4, MaxInboundTags: 64, TagLookahead: 4})
	packet, err := remote.EncryptExisting(make([]byte, 256), remotePeer, nil, RatchetOptions{}, 1_001)
	if err != nil {
		t.Fatal(err)
	}
	tag := dataplanegarlicecies.SessionTag(packet[:8])
	if _, indexed := manager.tagRoutes[tag]; !indexed {
		t.Fatal("live receive tag was not indexed")
	}
	before := manager.Stats().InboundTags
	corrupted := append([]byte(nil), packet...)
	corrupted[len(corrupted)-1] ^= 1
	if _, err = manager.Receive(make([]byte, 256), nil, corrupted, 1_001); err == nil {
		t.Fatal("corrupted packet authenticated")
	}
	if _, indexed := manager.tagRoutes[tag]; indexed {
		t.Fatal("tag consumed by failed authentication remained routed")
	}
	if got := manager.Stats().InboundTags; got != before-1 {
		t.Fatalf("tags after failed authentication = %d, want %d", got, before-1)
	}
	if _, err = manager.Receive(make([]byte, 256), nil, packet, 1_001); err == nil {
		t.Fatal("original packet authenticated after its tag was consumed")
	}
}
