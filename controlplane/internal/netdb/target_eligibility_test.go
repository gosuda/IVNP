package netdb

import (
	"context"
	"testing"

	"gosuda.org/ivnp/foundation"
)

type selectiveRequestSender struct {
	requestTestSender
	allowed foundation.Hash
}

func (s *selectiveRequestSender) Eligible(peer RouterRef) bool { return peer.Hash == s.allowed }

func addEligibleFloodfillBeyondNearest(database *Database, key foundation.Hash, now uint64) foundation.Hash {
	routing := RoutingKey(key, now)
	for distance := byte(0); distance < 16; distance++ {
		peer := routing
		peer[31] ^= distance
		addRequestTestFloodfill(database, peer)
	}
	allowed := routing
	allowed[31] ^= 32
	addRequestTestFloodfill(database, allowed)
	return allowed
}

func TestLookupSkipsIneligiblePeersBeforeCandidateLimit(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	key := foundation.Hash{9}
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	sender := &selectiveRequestSender{allowed: addEligibleFloodfillBeyondNearest(database, key, now)}
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: foundation.Hash{1}}, RequestManagerConfig{Capacity: 1, MaxCandidates: 4, TimeoutMillis: 60000, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := manager.LookupRouterInfo(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	manager.active.Wait()
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.peers) != 1 || sender.peers[0] != sender.allowed {
		t.Fatalf("lookup targets=%v, want only eligible peer %v", sender.peers, sender.allowed)
	}
}

func TestPublicationSkipsIneligiblePeersBeforeSnapshotLimit(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	key := foundation.Hash{9}
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	sender := &selectiveRequestSender{allowed: addEligibleFloodfillBeyondNearest(database, key, now)}
	publication := newConfirmedPublication(database, sender, publicationTestRoute{gateway: foundation.Hash{1}}, nil, func() uint64 { return now }, func() uint32 { return 23 }, key, foundation.I2NPStoreLeaseSet2, nil, 0, nil)
	t.Cleanup(publication.close)
	publication.replace([]byte{1})
	if sent, err := publication.maintain(context.Background(), true); err != nil || sent != 1 {
		t.Fatalf("publication sent=%d error=%v, want one eligible target", sent, err)
	}
	if len(sender.peers) != 1 || sender.peers[0] != sender.allowed {
		t.Fatalf("publication targets=%v, want only eligible peer %v", sender.peers, sender.allowed)
	}
}

type refreshedRequestSender struct{ requestTestSender }

func (*refreshedRequestSender) Eligible(peer RouterRef) bool { return peer.Info.Published != 0 }

func TestLookupRefreshesIneligibleCachedReferral(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	first, referred, key := foundation.Hash{1}, foundation.Hash{2}, foundation.Hash{9}
	addRequestTestFloodfill(database, referred)
	markFresh := func(peer foundation.Hash) {
		table := database.Routers()
		table.mu.Lock()
		table.routers[peer] = routerEntry{floodfill: true, info: foundation.NetworkDatabaseRouterInfo{Published: 100}}
		table.mu.Unlock()
	}
	markFresh(first)
	sender := new(refreshedRequestSender)
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: foundation.Hash{8}}, RequestManagerConfig{Capacity: 2, MaxCandidates: 4, TimeoutMillis: 60000, Now: func() uint64 { return 100 }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := manager.LookupLeaseSet(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	manager.active.Wait()
	manager.HandleDatabaseSearchReply(t.Context(), foundation.I2NPDatabaseSearchReplyMessage{Key: key, From: first, Peers: referred[:]})
	manager.active.Wait()
	messages := sender.snapshot()
	if len(messages) != 2 {
		t.Fatalf("cached ineligible referral produced %d requests, want parent plus RouterInfo refresh", len(messages))
	}
	refresh, err := foundation.I2NPParseDatabaseLookup(messages[1].Payload)
	if err != nil || refresh.Key != referred || refresh.LookupType() != uint8(RouterInfoLookup) {
		t.Fatalf("referral refresh = %+v, %v", refresh, err)
	}
	markFresh(referred)
	manager.HandleDatabaseStore(t.Context(), foundation.I2NPDatabaseStoreMessage{Key: referred, Type: foundation.I2NPStoreRouterInfo})
	manager.active.Wait()
	messages = sender.snapshot()
	if len(messages) != 3 {
		t.Fatalf("refreshed referral produced %d requests, want resumed LeaseSet lookup", len(messages))
	}
	resumed, err := foundation.I2NPParseDatabaseLookup(messages[2].Payload)
	if err != nil || resumed.Key != key || resumed.LookupType() != uint8(LeaseSetLookup) {
		t.Fatalf("resumed lookup = %+v, %v", resumed, err)
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.peers[2] != referred {
		t.Fatalf("resumed lookup target = %v, want refreshed %v", sender.peers[2], referred)
	}
}
