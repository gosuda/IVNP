//go:build dst || synctest

package router

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/simnet"
)

// TestSSU2SimnetSessionExchange runs the same reliable-delivery workload as
// TestSSU2DeliversExpectedMessagesIntact over simnet virtual UDP sockets
// inside a synctest bubble — isolating SSU2 session data and ACK flow from
// kernel networking.
func TestSSU2SimnetSessionExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := simnet.NewNetwork(simnet.Config{Seed: 3})
		defer net_.Close()
		net_.SetBidirectional(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), simnet.LinkConfig{Latency: time.Millisecond})
		aliceHost := net_.HostAt("alice", netip.MustParseAddr("192.0.2.1"))
		bobHost := net_.HostAt("bob", netip.MustParseAddr("192.0.2.2"))

		aliceConn, err := aliceHost.ListenUDP(netip.MustParseAddrPort("192.0.2.1:40002"))
		if err != nil {
			t.Fatal(err)
		}
		bobConn, err := bobHost.ListenUDP(netip.MustParseAddrPort("192.0.2.2:40002"))
		if err != nil {
			t.Fatal(err)
		}
		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		aliceDB := newTransportTestPeers()
		bobDB := newTransportTestPeers()
		now := uint64(time.Now().UnixMilli())
		if err := aliceDB.AdmitRouterInfo(bob.Snapshot(), now); err != nil {
			t.Fatal(err)
		}
		if err := bobDB.AdmitRouterInfo(alice.Snapshot(), now); err != nil {
			t.Fatal(err)
		}
		aliceManager := newSSU2LiveManager(t, aliceDB, aliceStatic, aliceIntro, time.Minute, time.Minute)
		bobManager := newSSU2LiveManager(t, bobDB, bobStatic, bobIntro, time.Minute, time.Minute)

		ctx, cancel := context.WithCancel(t.Context())
		const messages = 64
		expected := make(map[uint32]string, messages)
		outbound := make([]foundation.I2NPMessage, messages)
		for i := range outbound {
			id := uint32(901 + i)
			payload := fmt.Sprintf("sim SSU2 message %d", id)
			expected[id] = payload
			outbound[i] = ssu2LiveMessage(id)
			outbound[i].Payload = []byte(payload)
		}
		var deliveredMu sync.Mutex
		delivered := make(map[uint32]bool, len(expected))
		startSSU2SimManager(t, ctx, aliceManager, aliceConn, alice, nil)
		startSSU2SimManager(t, ctx, bobManager, bobConn, bob, func(message foundation.I2NPMessage, _ uint64, _ bool) error {
			want, ok := expected[message.Header.ID]
			if !ok {
				t.Errorf("unexpected message ID %d", message.Header.ID)
				return nil
			}
			if string(message.Payload) != want {
				t.Errorf("message %d payload = %q, want %q", message.Header.ID, message.Payload, want)
				return nil
			}
			deliveredMu.Lock()
			delivered[message.Header.ID] = true
			deliveredMu.Unlock()
			return nil
		})
		t.Cleanup(func() {
			cancel()
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		if err = aliceManager.EnsureSession(ctx, bob.Hash()); err != nil {
			t.Fatal(err)
		}
		for _, message := range outbound {
			if err = aliceManager.Send(ctx, bob.Hash(), message); err != nil {
				t.Fatal(err)
			}
		}
		waitForSSU2Live(t, 30*time.Second, func() bool {
			deliveredMu.Lock()
			defer deliveredMu.Unlock()
			return len(delivered) == messages
		}, "all simnet SSU2 messages delivered")
		waitForSSU2Live(t, 30*time.Second, func() bool {
			aliceManager.mu.RLock()
			session := aliceManager.sessionsByPeer[bob.Hash()]
			aliceManager.mu.RUnlock()
			if session == nil {
				return false
			}
			session.sendMu.Lock()
			defer session.sendMu.Unlock()
			return len(session.sent) == 0
		}, "all simnet SSU2 sends acknowledged")
	})
}

func startSSU2SimManager(t *testing.T, ctx context.Context, manager *SSU2Manager, conn *simnet.UDPConn, local *transportTestLocal, handle func(foundation.I2NPMessage, uint64, bool) error) {
	t.Helper()
	if handle == nil {
		handle = func(foundation.I2NPMessage, uint64, bool) error { return nil }
	}
	if err := manager.Start(ctx, TransportBindings{
		SSU2: conn, LocalInfo: local, Clock: WallClock{},
		HandleI2NPContext: func(_ context.Context, _ foundation.Hash, message foundation.I2NPMessage, now uint64, floodfill bool) error {
			return handle(message, now, floodfill)
		},
	}); err != nil {
		t.Fatal(err)
	}
}

var _ net.PacketConn = (*simnet.UDPConn)(nil)
