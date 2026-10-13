package router

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

func TestSSU2InstallSessionEnforcesLiveSessionBudget(t *testing.T) {
	var peer foundation.Hash
	peer[0] = 1
	newManager := func(limit int) *SSU2Manager {
		return &SSU2Manager{
			started:        true,
			ctx:            context.Background(),
			maxSessions:    limit,
			sessionsByID:   make(map[uint64]*ssu2TransportSession),
			sessionsByPeer: make(map[foundation.Hash]*ssu2TransportSession),
		}
	}

	t.Run("reject nonpreferred session at limit, allow replacement", func(t *testing.T) {
		manager := newManager(1)
		canonical := &ssu2TransportSession{peer: peer, receiveID: 1}
		if _, ok := manager.installSessionLocked(canonical); !ok {
			t.Fatal("first session was denied")
		}
		nonpreferred := &ssu2TransportSession{peer: peer, receiveID: 2, inbound: true}
		if displaced, ok := manager.installSessionLocked(nonpreferred); ok || displaced != nil {
			t.Fatal("nonpreferred session exceeded MaxSessions")
		}
		replacement := &ssu2TransportSession{peer: peer, receiveID: 3}
		displaced, ok := manager.installSessionLocked(replacement)
		if !ok || displaced != canonical || len(manager.sessionsByID) != 1 ||
			manager.sessionsByID[replacement.receiveID] != replacement ||
			manager.sessionsByPeer[peer] != replacement {
			t.Fatal("canonical replacement did not preserve the live session limit")
		}
		var secondPeer foundation.Hash
		secondPeer[0] = 2
		if _, ok := manager.installSessionLocked(&ssu2TransportSession{peer: secondPeer, receiveID: 4}); ok {
			t.Fatal("new peer bypassed MaxSessions")
		}
	})

	t.Run("at most one nonpreferred draining session per peer", func(t *testing.T) {
		manager := newManager(3)
		canonical := &ssu2TransportSession{peer: peer, receiveID: 1}
		draining := &ssu2TransportSession{peer: peer, receiveID: 2, inbound: true}
		if _, ok := manager.installSessionLocked(canonical); !ok {
			t.Fatal("canonical session was denied")
		}
		if _, ok := manager.installSessionLocked(draining); !ok {
			t.Fatal("first draining session was denied")
		}
		if _, ok := manager.installSessionLocked(&ssu2TransportSession{peer: peer, receiveID: 3, inbound: true}); ok {
			t.Fatal("second draining session was accepted despite an available global slot")
		}
		if len(manager.sessionsByID) != 2 || manager.sessionsByPeer[peer] != canonical ||
			manager.sessionsByID[draining.receiveID] != draining {
			t.Fatal("rejected session modified the live indexes")
		}
	})

	t.Run("detached canonical still counts toward peer budget", func(t *testing.T) {
		manager := newManager(3)
		manager.sessionsByID[1] = &ssu2TransportSession{peer: peer, receiveID: 1}
		manager.sessionsByID[2] = &ssu2TransportSession{peer: peer, receiveID: 2}
		if _, ok := manager.installSessionLocked(&ssu2TransportSession{peer: peer, receiveID: 3}); ok {
			t.Fatal("detached sessions bypassed the per-peer budget")
		}
		if len(manager.sessionsByID) != 2 || manager.sessionsByPeer[peer] != nil {
			t.Fatal("rejected detached-session replacement changed the indexes")
		}
	})
}

func TestSSU2IssuedNewTokenIsSingleUseAndEndpointBound(t *testing.T) {
	manager := &SSU2Manager{
		tokenLifetime:   time.Minute,
		issuedNewTokens: make(map[uint64]ssu2IssuedNewTokenLease),
		bindings:        TransportBindings{Clock: WallClock{}},
	}
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	other := &net.UDPAddr{IP: remote.IP, Port: 1235}
	first, err := manager.newNewTokenLocked(remote)
	if err != nil || first.Token == 0 {
		t.Fatalf("issue first NewToken: %v", err)
	}
	second, err := manager.newNewTokenLocked(remote)
	if err != nil || second.Token == first.Token {
		t.Fatalf("issue distinct second NewToken: %v", err)
	}
	if manager.consumeNewTokenLocked(first.Token, other) {
		t.Fatal("NewToken accepted from a different endpoint")
	}
	if !manager.consumeNewTokenLocked(first.Token, remote) {
		t.Fatal("NewToken rejected on its first valid use")
	}
	if manager.consumeNewTokenLocked(first.Token, remote) {
		t.Fatal("NewToken was replayed across connection IDs")
	}
	if !manager.consumeNewTokenLocked(second.Token, remote) {
		t.Fatal("a separately issued NewToken was rejected")
	}
	third, err := manager.newNewTokenLocked(remote)
	if err != nil {
		t.Fatal(err)
	}
	lease := manager.issuedNewTokens[third.Token]
	lease.expires = time.Now().Add(-time.Second)
	manager.issuedNewTokens[third.Token] = lease
	if manager.consumeNewTokenLocked(third.Token, remote) {
		t.Fatal("expired NewToken was accepted")
	}
	if _, exists := manager.issuedNewTokens[third.Token]; exists {
		t.Fatal("expired NewToken lease was retained")
	}
}

func TestSSU2IssuedNewTokensAreBounded(t *testing.T) {
	manager := &SSU2Manager{
		tokenLifetime:   time.Minute,
		issuedNewTokens: make(map[uint64]ssu2IssuedNewTokenLease),
		bindings:        TransportBindings{Clock: WallClock{}},
	}
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	endpoint, ok := addrPortKey(remote)
	if !ok {
		t.Fatal("invalid test endpoint")
	}
	lease := ssu2IssuedNewTokenLease{endpoint: endpoint, expires: time.Now().Add(time.Minute)}
	for i := 1; i <= ssu2MaxNewTokens; i++ {
		manager.issuedNewTokens[uint64(i)] = lease
	}
	if _, err := manager.newNewTokenLocked(remote); !errors.Is(err, ErrSSU2Session) {
		t.Fatalf("NewToken issued with full token budget: %v", err)
	}
	lease.expires = time.Now().Add(-time.Second)
	manager.issuedNewTokens[1] = lease
	if _, err := manager.newNewTokenLocked(remote); err != nil {
		t.Fatalf("expired token slot could not be reclaimed: %v", err)
	}
	if len(manager.issuedNewTokens) != ssu2MaxNewTokens {
		t.Fatalf("outstanding NewToken count = %d, want %d", len(manager.issuedNewTokens), ssu2MaxNewTokens)
	}
}
