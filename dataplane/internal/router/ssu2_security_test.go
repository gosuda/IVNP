package router

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

func TestSSU2InstallSessionEnforcesLiveAndDrainingLimits(t *testing.T) {
	peer := foundation.Hash{1}
	manager := &SSU2Manager{
		started:        true,
		ctx:            context.Background(),
		maxSessions:    2,
		sessionsByPeer: make(map[foundation.Hash]*ssu2TransportSession),
		sessionsByID:   make(map[uint64]*ssu2TransportSession),
	}
	canonical := &ssu2TransportSession{peer: peer, receiveID: 1}
	if displaced, ok := manager.installSessionLocked(canonical); !ok || displaced != nil {
		t.Fatal("first session was not installed")
	}
	draining := &ssu2TransportSession{peer: peer, receiveID: 2, inbound: true}
	if displaced, ok := manager.installSessionLocked(draining); !ok || displaced != nil {
		t.Fatal("one crossed-handshake session must remain live")
	}
	if manager.sessionsByPeer[peer] != canonical {
		t.Fatal("non-preferred session displaced the canonical session")
	}

	// The peer-specific limit must still apply when global capacity remains.
	manager.maxSessions = 4
	for id := uint64(3); id < 32; id++ {
		if _, ok := manager.installSessionLocked(&ssu2TransportSession{peer: peer, receiveID: id, inbound: true}); ok {
			t.Fatalf("admitted a second draining session with connection ID %d", id)
		}
	}
	manager.maxSessions = 2
	if _, ok := manager.installSessionLocked(&ssu2TransportSession{peer: foundation.Hash{2}, receiveID: 32}); ok {
		t.Fatal("new peer bypassed the global live-session limit")
	}

	// Replacing the canonical session frees its old slot, even at capacity.
	replacement := &ssu2TransportSession{peer: peer, receiveID: 33}
	displaced, ok := manager.installSessionLocked(replacement)
	if !ok || displaced != canonical {
		t.Fatal("canonical replacement at capacity failed")
	}
	if manager.sessionsByPeer[peer] != replacement ||
		manager.sessionsByID[canonical.receiveID] != nil ||
		manager.sessionsByID[draining.receiveID] != draining ||
		manager.sessionsByID[replacement.receiveID] != replacement ||
		len(manager.sessionsByID) != 2 {
		t.Fatal("canonical replacement violated live-session accounting")
	}
	if _, ok := manager.installSessionLocked(&ssu2TransportSession{peer: peer, receiveID: 34, inbound: true}); ok {
		t.Fatal("replacement session bypassed global capacity")
	}
}

func TestSSU2IssuedNewTokenIsEndpointBoundAndSingleUse(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:12345"))
	otherPort := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:12346"))
	otherIP := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.2:12345"))
	manager := &SSU2Manager{
		tokenLifetime:   time.Minute,
		bindings:        TransportBindings{Clock: transportTestClock{now: now}},
		issuedNewTokens: make(map[uint64]ssu2IssuedNewToken),
	}
	token, err := manager.newNewTokenLocked(remote)
	if err != nil || token.Token == 0 {
		t.Fatalf("issue NewToken: %v", err)
	}
	if manager.consumeNewTokenLocked(token.Token, otherPort) ||
		manager.consumeNewTokenLocked(token.Token, otherIP) {
		t.Fatal("NewToken accepted an unbound remote endpoint")
	}
	if !manager.consumeNewTokenLocked(token.Token, remote) {
		t.Fatal("NewToken was not accepted by its bound endpoint")
	}
	if manager.consumeNewTokenLocked(token.Token, remote) || len(manager.issuedNewTokens) != 0 {
		t.Fatal("consumed NewToken was reusable")
	}

	expiring, err := manager.newNewTokenLocked(remote)
	if err != nil || expiring.Token == token.Token {
		t.Fatalf("fresh NewToken collision: %v", err)
	}
	manager.bindings.Clock = transportTestClock{now: now.Add(time.Minute)}
	if manager.consumeNewTokenLocked(expiring.Token, remote) || len(manager.issuedNewTokens) != 0 {
		t.Fatal("expired NewToken was accepted or retained")
	}
}

func TestSSU2IssuedNewTokenCapacityAndExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:12345"))
	manager := &SSU2Manager{
		tokenLifetime:   time.Minute,
		bindings:        TransportBindings{Clock: transportTestClock{now: now}},
		issuedNewTokens: make(map[uint64]ssu2IssuedNewToken),
	}
	for range ssu2MaxNewTokens {
		if _, err := manager.newNewTokenLocked(remote); err != nil {
			t.Fatalf("issue token before capacity: %v", err)
		}
	}
	if len(manager.issuedNewTokens) != ssu2MaxNewTokens {
		t.Fatalf("issued token count = %d, want %d", len(manager.issuedNewTokens), ssu2MaxNewTokens)
	}
	if _, err := manager.newNewTokenLocked(remote); !errors.Is(err, ErrSSU2Session) {
		t.Fatalf("issued token overflow = %v, want ErrSSU2Session", err)
	}
	manager.bindings.Clock = transportTestClock{now: now.Add(2 * time.Minute)}
	if _, err := manager.newNewTokenLocked(remote); err != nil || len(manager.issuedNewTokens) != 1 {
		t.Fatalf("expired token capacity was not reclaimed: %v, count=%d", err, len(manager.issuedNewTokens))
	}
}
