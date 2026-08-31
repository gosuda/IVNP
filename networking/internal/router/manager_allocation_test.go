//go:build !race

package router

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/netdb"
	"gosuda.org/ivnp/networking/internal/transport/ntcp2"
	"gosuda.org/ivnp/networking/internal/transport/ssu2"
	"gosuda.org/ivnp/observability"
)

// The allocation ceilings document the deliberate ownership boundary: framing
// writes into supplied buffers, while an authenticated I2NP delivery owns one
// payload copy after the receive datagram is reused.
func TestManagerHotPathAllocationBudgets(t *testing.T) {
	message := managerHotPathMessage()
	ntcpFrame := make([]byte, i2np.TransportHeaderLen+len(message.Payload))
	if got := testing.AllocsPerRun(100, func() {
		if err := marshalNTCP2I2NPTo(ntcpFrame, message); err != nil {
			t.Fatal(err)
		}
	}); got != 0 {
		t.Fatalf("NTCP2 caller-buffer marshal allocations = %v, want 0", got)
	}
	direction, err := ntcp2.NewDirection(make([]byte, 32), make([]byte, 16), make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	session := ntcp2.NewSession(&managerHotPathStreamConn{}, direction, nil)
	defer func() { _ = session.Close() }()
	if got := testing.AllocsPerRun(100, func() {
		if err := writeNTCP2I2NP(session, message); err != nil {
			t.Fatal(err)
		}
	}); got != 0 {
		t.Fatalf("NTCP2 framed write allocations = %v, want 0", got)
	}

	var ssuFrame [ssu2.MaxIPv4PacketLen]byte
	if got := testing.AllocsPerRun(100, func() {
		frame, err := marshalSSU2I2NPTo(ssuFrame[:], message)
		if err != nil {
			t.Fatal(err)
		}
		managerHotPathFrame = frame
	}); got != 0 {
		t.Fatalf("SSU2 caller-buffer frame allocations = %v, want 0", got)
	}

	fragmented := message
	fragmented.Payload = make([]byte, ssu2.MaxIPv4PacketLen-ssu2.ShortHeaderLen-ssu2.PacketTagLen-3-i2np.TransportHeaderLen+1)
	var fragmentFrame [ssu2.MaxIPv4PacketLen]byte
	if got := testing.AllocsPerRun(100, func() {
		fragments := 0
		if err := forEachSSU2I2NPFragment(fragmentFrame[:], fragmented, ssu2.MaxIPv4PacketLen, func([]byte, bool) error {
			fragments++
			return nil
		}); err != nil {
			t.Fatal(err)
		} else if fragments != 2 {
			t.Fatalf("SSU2 fragment count = %d, want 2", fragments)
		}
	}); got != 0 {
		t.Fatalf("SSU2 caller-buffer fragment allocations = %v, want 0", got)
	}

	manager := &NTCP2Manager{replaySeen: make(map[[32]byte]struct{}, ntcp2ReplayEntries)}
	var ephemeral [32]byte
	if got := testing.AllocsPerRun(100, func() {
		ephemeral[0]++
		if manager.replayedRequest(ephemeral[:]) {
			t.Fatal("fresh replay admission rejected")
		}
	}); got != 0 {
		t.Fatalf("NTCP2 replay admission allocations = %v, want 0 after manager initialization", got)
	}
}

func TestSSU2LiveVectorReadAuthDispatchWriteAllocations(t *testing.T) {
	aliceConn := newSSU2LoopbackConn(t)
	bobConn := newSSU2LoopbackConn(t)
	alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
	bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
	aliceDB := netdb.NewDatabase(alice.Hash(), 16)
	bobDB := netdb.NewDatabase(bob.Hash(), 16)
	now := uint64(time.Now().UnixMilli())
	if err := aliceDB.AdmitRouterInfo(bob.Snapshot(), false, now); err != nil {
		t.Fatal(err)
	}
	if err := bobDB.AdmitRouterInfo(alice.Snapshot(), false, now); err != nil {
		t.Fatal(err)
	}
	aliceMetrics, bobMetrics := observability.NewRegistry(), observability.NewRegistry()
	aliceManager, err := NewSSU2Manager(SSU2ManagerConfig{
		Database: aliceDB, StaticPrivate: aliceStatic, IntroKey: aliceIntro,
		IdleTimeout: time.Minute, HandshakeTimeout: 500 * time.Millisecond, Metrics: aliceMetrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	bobManager, err := NewSSU2Manager(SSU2ManagerConfig{
		Database: bobDB, StaticPrivate: bobStatic, IntroKey: bobIntro,
		IdleTimeout: time.Minute, HandshakeTimeout: 500 * time.Millisecond, Metrics: bobMetrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var delivered atomic.Uint64
	startSSU2LiveManager(t, ctx, aliceManager, aliceConn, alice, nil)
	startSSU2LiveManager(t, ctx, bobManager, bobConn, bob, func(i2np.Message, uint64, bool) error {
		delivered.Add(1)
		return nil
	})
	t.Cleanup(func() {
		cancel()
		closeSSU2LiveManager(t, aliceManager)
		closeSSU2LiveManager(t, bobManager)
	})

	message := ssu2LiveMessage(900)
	for range 16 {
		message.Header.ID++
		if err = aliceManager.Send(ctx, bob.Hash(), message); err != nil {
			t.Fatal(err)
		}
	}
	waitForSSU2Live(t, 5*time.Second, func() bool {
		aliceManager.mu.RLock()
		session := aliceManager.sessionsByPeer[bob.Hash()]
		peerTests := len(aliceManager.peerTests)
		aliceManager.mu.RUnlock()
		if session == nil || peerTests != 0 || delivered.Load() < 16 {
			return false
		}
		session.sendMu.Lock()
		pending := len(session.sent)
		session.sendMu.Unlock()
		return pending == 0
	}, "warm live vector/auth/dispatch/write path")

	var sendErr error
	before := delivered.Load()
	allocations := testing.AllocsPerRun(64, func() {
		message.Header.ID++
		sendErr = aliceManager.Send(ctx, bob.Hash(), message)
	})
	if sendErr != nil {
		t.Fatal(sendErr)
	}
	waitForSSU2Live(t, 5*time.Second, func() bool {
		return delivered.Load() >= before+65
	}, "measured live vector/auth/dispatch/write delivery")
	if allocations != 0 {
		t.Fatalf("live SSU2 vector read/auth/dispatch/write allocations = %v, want 0 after warmup", allocations)
	}
	for name, snapshot := range map[string]observability.SSU2Snapshot{
		"alice": aliceMetrics.Snapshot().SSU2,
		"bob":   bobMetrics.Snapshot().SSU2,
	} {
		if snapshot.ReceivedDatagrams != snapshot.EnqueuedDatagrams+snapshot.ReceiveQueueDrops ||
			snapshot.EnqueuedDatagrams != snapshot.ProcessedDatagrams+snapshot.IngressQueueDepth ||
			snapshot.SendEnqueuedDatagrams != snapshot.SentDatagrams+snapshot.SendFailedDatagrams+snapshot.SendQueueDrops+snapshot.EgressQueueDepth {
			t.Fatalf("%s SSU2 conservation failed after live allocation run: %+v", name, snapshot)
		}
	}
}
