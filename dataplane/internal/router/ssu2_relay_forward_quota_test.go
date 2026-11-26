package router

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	dataplanessu2 "gosuda.org/ivnp/dataplane/internal/transport/ssu2"
)

// +checklocksignore
func TestSSU2RelayForwardsAreCappedPerAliceSource(t *testing.T) {
	bob, bobStatic, bobIntro := newSSU2TestLocal(t, "192.0.2.10:23456")
	alice, _, _ := newSSU2TestLocal(t, "198.51.100.7:23456")
	charlie, _, _ := newSSU2TestLocal(t, "203.0.113.9:23456")
	peers := newTransportTestPeers()
	if err := peers.AdmitRouterInfo(alice.Snapshot(), uint64(time.Now().UnixMilli())); err != nil {
		t.Fatalf("admit Alice RouterInfo: %v", err)
	}
	manager, err := NewSSU2Manager(SSU2ManagerConfig{
		NetworkID:     2,
		Peers:         peers,
		StaticPrivate: bobStatic,
		IntroKey:      bobIntro,
		SignControl: func(message []byte) ([]byte, error) {
			return bob.Sign(message), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	const relayTag = 77
	charlieSession := &ssu2TransportSession{peer: charlie.Hash(), receiveID: 1}
	manager.mu.Lock()
	manager.started = true
	manager.ctx = ctx
	manager.bindings = TransportBindings{LocalInfo: bob, Clock: WallClock{}}
	manager.relayStoreJobs = make(chan ssu2RelayStoreJob, manager.maxPending)
	manager.sessionsByID[charlieSession.receiveID] = charlieSession
	manager.sessionsByPeer[charlie.Hash()] = charlieSession
	manager.introducers[relayTag] = charlie.Hash()
	manager.mu.Unlock()

	bobHash, charlieHash := bob.Hash(), charlie.Hash()
	request := func(nonce uint32) dataplanessu2.RelayRequest {
		t.Helper()
		relay := dataplanessu2.RelayRequest{
			Nonce:     nonce,
			RelayTag:  relayTag,
			Timestamp: uint32(time.Now().Unix()),
			Endpoint:  netip.MustParseAddrPort("198.51.100.7:23456"),
		}
		input, err := dataplanessu2.RelayRequestSignatureInput(nil, bobHash[:], charlieHash[:], relay)
		if err != nil {
			t.Fatal(err)
		}
		relay.Signature = alice.Sign(input)
		return relay
	}
	aliceAt := func(ip string, port int) *ssu2TransportSession {
		return &ssu2TransportSession{peer: alice.Hash(), remote: &net.UDPAddr{IP: net.ParseIP(ip), Port: port}}
	}
	forwards := func() int {
		manager.mu.RLock()
		defer manager.mu.RUnlock()
		return len(manager.relayForwards)
	}

	nonce := uint32(1)
	for index := range manager.maxPending {
		manager.handleRelayRequest(aliceAt("198.51.100.7", 20000+index), request(nonce))
		nonce++
	}
	fromOneIPv4 := forwards()
	if fromOneIPv4 != ssu2MaxRelayForwardsPerSource {
		t.Fatalf("one IPv4 Alice source holds %d of %d relay forwards, want %d", fromOneIPv4, manager.maxPending, ssu2MaxRelayForwardsPerSource)
	}

	for index := range manager.maxPending {
		manager.handleRelayRequest(aliceAt("2001:db8:1:2::"+string(rune('a'+index%6)), 20000+index), request(nonce))
		nonce++
	}
	fromOneIPv6Prefix := forwards() - fromOneIPv4
	if fromOneIPv6Prefix != ssu2MaxRelayForwardsPerSource {
		t.Fatalf("one IPv6 /64 Alice source holds %d relay forwards, want %d", fromOneIPv6Prefix, ssu2MaxRelayForwardsPerSource)
	}

	before := forwards()
	manager.handleRelayRequest(aliceAt("198.51.100.8", 20000), request(nonce))
	if forwards() != before+1 {
		t.Fatal("a relay request from a distinct Alice source was rejected")
	}
}
