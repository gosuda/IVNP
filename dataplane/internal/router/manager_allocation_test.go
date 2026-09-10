package router

import (
	"context"
	"fmt"
	"sync"
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

func TestSSU2DeliversExpectedMessagesIntact(t *testing.T) {
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
	const initialMessages = 16
	const messages = 64
	expected := make(map[uint32]string, initialMessages+messages)
	outbound := make([]foundation.I2NPMessage, initialMessages+messages)
	for i := range outbound {
		id := uint32(901 + i)
		payload := fmt.Sprintf("live SSU2 message %d", id)
		expected[id] = payload
		outbound[i] = ssu2LiveMessage(id)
		outbound[i].Payload = []byte(payload)
	}
	var deliveredMu sync.Mutex
	delivered := make(map[uint32]bool, len(expected))
	deliveredCount := func() int {
		deliveredMu.Lock()
		defer deliveredMu.Unlock()
		return len(delivered)
	}
	startSSU2LiveManager(t, ctx, aliceManager, aliceConn, alice, nil)
	startSSU2LiveManager(t, ctx, bobManager, bobConn, bob, func(message foundation.I2NPMessage, _ uint64, _ bool) error {
		want, ok := expected[message.Header.ID]
		if !ok {
			t.Errorf("received unexpected message ID %d", message.Header.ID)
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
		for _, message := range outbound {
			if !delivered[message.Header.ID] {
				t.Errorf("message %d was not delivered intact", message.Header.ID)
			}
		}
	})

	if err = aliceManager.EnsureSession(ctx, bob.Hash()); err != nil {
		t.Fatal(err)
	}
	for _, message := range outbound[:initialMessages] {
		if err = aliceManager.Send(ctx, bob.Hash(), message); err != nil {
			t.Fatal(err)
		}
	}
	waitForSSU2Live(t, 30*time.Second, func() bool {
		aliceManager.mu.RLock()
		session := aliceManager.sessionsByPeer[bob.Hash()]
		peerTests := len(aliceManager.peerTests)
		aliceManager.mu.RUnlock()
		if session == nil || peerTests != 0 || deliveredCount() < initialMessages {
			return false
		}
		session.sendMu.Lock()
		pending := len(session.sent)
		session.sendMu.Unlock()
		return pending == 0
	}, "initial messages and transport acknowledgments")

	for _, message := range outbound[initialMessages:] {
		if err := aliceManager.Send(ctx, bob.Hash(), message); err != nil {
			t.Fatal(err)
		}
	}
	waitForSSU2Live(t, 30*time.Second, func() bool {
		return deliveredCount() == len(expected)
	}, "every expected message delivered intact")
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
