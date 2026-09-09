package router

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	dataplanessu2 "gosuda.org/ivnp/dataplane/internal/transport/ssu2"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/observability"
)

func TestSSU2I2NPOversizedPayloadFragments(t *testing.T) {
	message := managerHotPathMessage()
	message.Payload = make([]byte, dataplanessu2.MaxIPv4PacketLen-dataplanessu2.ShortHeaderLen-dataplanessu2.PacketTagLen-3-foundation.I2NPTransportHeaderLen+1)
	var fragmentFrame [dataplanessu2.MaxIPv4PacketLen]byte
	fragments := 0
	if err := forEachSSU2I2NPFragment(fragmentFrame[:], message, dataplanessu2.MaxIPv4PacketLen, func([]byte, bool) error {
		fragments++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if fragments != 2 {
		t.Fatalf("SSU2 fragment count = %d, want 2", fragments)
	}
}

func TestSSU2LiveVectorReadAuthDispatchWriteDelivery(t *testing.T) {
	aliceConn := newSSU2LoopbackConn(t)
	bobConn := newSSU2LoopbackConn(t)
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
	aliceMetrics, bobMetrics := observability.NewRegistry(), observability.NewRegistry()
	aliceManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2,
		Peers: aliceDB, StaticPrivate: aliceStatic, IntroKey: aliceIntro,
		IdleTimeout: time.Minute, HandshakeTimeout: 2 * time.Second, Metrics: aliceMetrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	bobManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2,
		Peers: bobDB, StaticPrivate: bobStatic, IntroKey: bobIntro,
		IdleTimeout: time.Minute, HandshakeTimeout: 2 * time.Second, Metrics: bobMetrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var delivered atomic.Uint64
	startSSU2LiveManager(t, ctx, aliceManager, aliceConn, alice, nil)
	startSSU2LiveManager(t, ctx, bobManager, bobConn, bob, func(foundation.I2NPMessage, uint64, bool) error {
		delivered.Add(1)
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
	message := ssu2LiveMessage(900)
	for range 16 {
		message.Header.ID++
		if err = aliceManager.Send(ctx, bob.Hash(), message); err != nil {
			t.Fatal(err)
		}
	}
	waitForSSU2Live(t, 30*time.Second, func() bool {
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
	}, "initial live vector/auth/dispatch/write delivery")

	before := delivered.Load()
	const messages = 64
	for range messages {
		message.Header.ID++
		if err := aliceManager.Send(ctx, bob.Hash(), message); err != nil {
			t.Fatal(err)
		}
	}
	waitForSSU2Live(t, 30*time.Second, func() bool {
		return delivered.Load() >= before+messages
	}, "live vector/auth/dispatch/write delivery")
	for name, snapshot := range map[string]observability.SSU2Snapshot{
		"alice": aliceMetrics.Snapshot().SSU2,
		"bob":   bobMetrics.Snapshot().SSU2,
	} {
		if snapshot.ReceivedDatagrams != snapshot.EnqueuedDatagrams+snapshot.ReceiveQueueDrops ||
			snapshot.EnqueuedDatagrams != snapshot.ProcessedDatagrams+snapshot.IngressQueueDepth ||
			snapshot.SendEnqueuedDatagrams != snapshot.SentDatagrams+snapshot.SendFailedDatagrams+snapshot.SendQueueDrops+snapshot.EgressQueueDepth {
			t.Fatalf("%s SSU2 conservation failed after live delivery: %+v", name, snapshot)
		}
	}
}
