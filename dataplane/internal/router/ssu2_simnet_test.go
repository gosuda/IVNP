package router

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/simnet"
)

func newSSU2SimNetwork(t *testing.T) *simnet.Network {
	t.Helper()
	seed := uint64(3)
	if env := cmp.Or(os.Getenv("DST_SEED"), os.Getenv("IVNP_DST_SEED")); env != "" {
		if s, err := strconv.ParseUint(env, 10, 64); err == nil {
			seed = s
		}
	}
	net_ := simnet.NewNetwork(simnet.Config{
		Seed:        seed,
		DefaultLink: simnet.LinkConfig{Latency: time.Millisecond},
	})
	t.Cleanup(func() { _ = net_.Close() })
	return net_
}

func newSSU2SimConn(t *testing.T, net_ *simnet.Network, name string) *simnet.UDPConn {
	t.Helper()
	host := net_.Host(name)
	conn, err := host.ListenUDP(netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestSSU2SimnetSessionExchange runs the same reliable-delivery workload as
// TestSSU2DeliversExpectedMessagesIntact over simnet virtual UDP sockets
// inside a synctest bubble, isolating SSU2 session data and ACK flow from
// kernel networking.
func TestSSU2SimnetSessionExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
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
		allDelivered := make(chan struct{})
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
			done := len(delivered) == messages
			deliveredMu.Unlock()
			if done {
				select {
				case <-allDelivered:
				default:
					close(allDelivered)
				}
			}
			return nil
		})
		t.Cleanup(func() {
			cancel()
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		if err := aliceManager.EnsureSession(ctx, bob.Hash()); err != nil {
			t.Fatal(err)
		}
		for _, message := range outbound {
			if err := aliceManager.Send(ctx, bob.Hash(), message); err != nil {
				t.Fatal(err)
			}
		}
		<-allDelivered
		net_.Advance(50 * time.Millisecond)

		var retransmitted atomic.Int64
		aliceIP := net_.Host("alice").Addr()
		net_.SetHook(func(ev simnet.Event) {
			if ev.Kind == simnet.EventSent && ev.From.Addr() == aliceIP {
				retransmitted.Add(1)
			}
		})
		net_.Advance(time.Second)
		net_.SetHook(nil)
		if got := retransmitted.Load(); got != 0 {
			t.Fatalf("alice retransmitted %d packets after all messages were delivered and acknowledged", got)
		}
	})
}

func startSSU2SimManager(t *testing.T, ctx context.Context, manager *SSU2Manager, conn UDPSocket, local *transportTestLocal, handle func(foundation.I2NPMessage, uint64, bool) error) {
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
