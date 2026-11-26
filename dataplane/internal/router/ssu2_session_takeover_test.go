package router

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	dataplanessu2 "gosuda.org/ivnp/dataplane/internal/transport/ssu2"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/simnet"
)

type ssu2TakeoverPair struct {
	network       *simnet.Network
	aliceConn     *simnet.UDPConn
	bobConn       *simnet.UDPConn
	alice, bob    *transportTestLocal
	aliceManager  *SSU2Manager
	bobManager    *SSU2Manager
	bobDB         *transportTestPeers
	bobStatic     []byte
	bobIntro      []byte
	receivedMu    sync.Mutex
	receivedByBob map[uint32]bool
	victimReceive uint64
	victimOnBob   *ssu2TransportSession
}

// newSSU2TakeoverPair establishes an authenticated Alice to Bob session and
// returns Bob's view of it.
func newSSU2TakeoverPair(t *testing.T) *ssu2TakeoverPair {
	t.Helper()
	p := &ssu2TakeoverPair{receivedByBob: make(map[uint32]bool)}
	p.network = newSSU2SimNetwork(t)
	p.aliceConn = newSSU2SimConn(t, p.network, "alice")
	p.bobConn = newSSU2SimConn(t, p.network, "bob")
	var aliceStatic, aliceIntro []byte
	p.alice, aliceStatic, aliceIntro = newSSU2TestLocal(t, p.aliceConn.LocalAddr().String())
	p.bob, p.bobStatic, p.bobIntro = newSSU2TestLocal(t, p.bobConn.LocalAddr().String())
	aliceDB := newTransportTestPeers()
	p.bobDB = newTransportTestPeers()
	now := uint64(time.Now().UnixMilli())
	if err := aliceDB.AdmitRouterInfo(p.bob.Snapshot(), now); err != nil {
		t.Fatal(err)
	}
	if err := p.bobDB.AdmitRouterInfo(p.alice.Snapshot(), now); err != nil {
		t.Fatal(err)
	}
	p.aliceManager = newSSU2LiveManager(t, aliceDB, aliceStatic, aliceIntro, time.Minute, time.Minute)
	p.bobManager = newSSU2LiveManager(t, p.bobDB, p.bobStatic, p.bobIntro, time.Minute, time.Minute)
	ctx := t.Context()
	startSSU2SimManager(t, ctx, p.aliceManager, p.aliceConn, p.alice, nil)
	startSSU2SimManager(t, ctx, p.bobManager, p.bobConn, p.bob, func(message foundation.I2NPMessage, _ uint64, _ bool) error {
		p.receivedMu.Lock()
		p.receivedByBob[message.Header.ID] = true
		p.receivedMu.Unlock()
		return nil
	})
	t.Cleanup(func() {
		closeSSU2LiveManager(t, p.aliceManager)
		closeSSU2LiveManager(t, p.bobManager)
	})
	if err := p.aliceManager.EnsureSession(ctx, p.bob.Hash()); err != nil {
		t.Fatal(err)
	}
	p.network.Advance(100 * time.Millisecond)
	p.bobManager.mu.RLock()
	p.victimOnBob = p.bobManager.sessionsByPeer[p.alice.Hash()]
	p.bobManager.mu.RUnlock()
	if p.victimOnBob == nil {
		t.Fatal("setup: Bob has no session for Alice")
	}
	p.victimReceive = p.victimOnBob.receiveID
	return p
}

func (p *ssu2TakeoverPair) bobPublic(t *testing.T) []byte {
	t.Helper()
	private, err := ecdh.X25519().NewPrivateKey(p.bobStatic)
	if err != nil {
		t.Fatal(err)
	}
	return private.PublicKey().Bytes()
}

// requireAliceDelivers checks that Bob still holds the original session and
// that a message Alice sends on it reaches Bob's I2NP handler.
func (p *ssu2TakeoverPair) requireAliceDelivers(t *testing.T, id uint32) {
	t.Helper()
	p.bobManager.mu.RLock()
	byPeer := p.bobManager.sessionsByPeer[p.alice.Hash()]
	byID := p.bobManager.sessionsByID[p.victimReceive]
	p.bobManager.mu.RUnlock()
	if byPeer != p.victimOnBob || byID != p.victimOnBob {
		t.Fatalf("Bob's authenticated session for Alice was replaced: byPeer=%p byID=%p want %p", byPeer, byID, p.victimOnBob)
	}
	if err := p.aliceManager.Send(t.Context(), p.bob.Hash(), ssu2LiveMessage(id)); err != nil {
		t.Fatalf("Alice send: %v", err)
	}
	p.network.Advance(100 * time.Millisecond)
	p.receivedMu.Lock()
	delivered := p.receivedByBob[id]
	p.receivedMu.Unlock()
	if !delivered {
		t.Fatalf("message %d from Alice did not reach Bob", id)
	}
}

func ssu2TakeoverRandomID(t *testing.T) uint64 {
	t.Helper()
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	return binary.BigEndian.Uint64(raw[:]) | 1
}

func ssu2TakeoverRequestPayload(t *testing.T) []byte {
	t.Helper()
	var dateTime [4]byte
	binary.BigEndian.PutUint32(dateTime[:], uint32(time.Now().Unix()))
	payload, err := dataplanessu2.MarshalBlock(nil, dataplanessu2.BlockDateTime, dateTime[:])
	if err != nil {
		t.Fatal(err)
	}
	payload, err = dataplanessu2.MarshalBlock(payload, dataplanessu2.BlockPadding, nil)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestSSU2UnauthenticatedSessionRequestKeepsLiveSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newSSU2TakeoverPair(t)
		mallory := newSSU2SimConn(t, p.network, "mallory")
		bobAddr := p.bobConn.LocalAddr()
		bobPub := p.bobPublic(t)
		// The victim's receive ID is visible to any observer of Alice's
		// traffic, because the first header bytes are masked only with Bob's
		// public intro key.
		sourceID := ssu2TakeoverRandomID(t)
		probe, err := dataplanessu2.NewInitiator(bobPub, p.bobIntro, p.victimReceive, sourceID, 2)
		if err != nil {
			t.Fatal(err)
		}
		request, err := probe.BuildSessionRequest(make([]byte, dataplanessu2.MaxIPv4PacketLen), ssu2TakeoverRequestPayload(t), 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = mallory.WriteTo(request, bobAddr); err != nil {
			t.Fatal(err)
		}
		in := make([]byte, 2048)
		n, _, err := mallory.ReadFrom(in)
		if err != nil {
			t.Fatal(err)
		}
		retry, _, err := dataplanessu2.ParseRetry(in[:n], p.bobIntro, 2)
		if err != nil {
			t.Fatalf("parse Retry: %v", err)
		}
		initiator, err := dataplanessu2.NewInitiator(bobPub, p.bobIntro, p.victimReceive, sourceID, 2)
		if err != nil {
			t.Fatal(err)
		}
		request, err = initiator.BuildSessionRequest(make([]byte, dataplanessu2.MaxIPv4PacketLen), ssu2TakeoverRequestPayload(t), 1, retry.Token)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = mallory.WriteTo(request, bobAddr); err != nil {
			t.Fatal(err)
		}
		if n, _, err = mallory.ReadFrom(in); err != nil {
			t.Fatal(err)
		}
		if _, _, err = initiator.ParseSessionCreated(in[:n]); err != nil {
			t.Fatalf("parse SessionCreated: %v", err)
		}

		p.requireAliceDelivers(t, 41)
	})
}

func TestSSU2SessionConfirmedFromOtherPeerCannotTakeOverConnectionID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newSSU2TakeoverPair(t)
		malloryConn := newSSU2SimConn(t, p.network, "mallory")
		mallory, malloryStatic, malloryIntro := newSSU2TestLocal(t, malloryConn.LocalAddr().String())
		malloryDB := newTransportTestPeers()
		if err := malloryDB.AdmitRouterInfo(p.bob.Snapshot(), uint64(time.Now().UnixMilli())); err != nil {
			t.Fatal(err)
		}
		malloryManager := newSSU2LiveManager(t, malloryDB, malloryStatic, malloryIntro, time.Minute, time.Minute)
		startSSU2SimManager(t, t.Context(), malloryManager, malloryConn, mallory, nil)
		t.Cleanup(func() { closeSSU2LiveManager(t, malloryManager) })

		// Mallory completes a full handshake under its own identity while
		// claiming Alice's connection ID.
		address, remote, err := malloryManager.resolveOutbound(p.bob.Hash())
		if err != nil {
			t.Fatal(err)
		}
		malloryManager.mu.Lock()
		pending, err := malloryManager.newOutboundToLocked(p.bob.Hash(), address, remote, p.victimReceive, ssu2TakeoverRandomID(t))
		if err == nil {
			pending.tokenSent = true
		}
		malloryManager.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		malloryManager.sendSessionRequest(pending, 0)
		select {
		case <-pending.ready:
		case <-time.After(5 * time.Second):
			t.Fatal("Mallory handshake did not finish")
		}
		p.network.Advance(100 * time.Millisecond)

		if p.bobManager.HasSession(mallory.Hash()) {
			t.Fatal("Bob installed Mallory's session on Alice's connection ID")
		}
		p.requireAliceDelivers(t, 42)
	})
}

func TestSSU2SessionConfirmedFromSamePeerSupersedesConnectionID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newSSU2TakeoverPair(t)
		// Alice loses her side of the session without telling Bob, then
		// reconnects with the cached NewToken, which reuses Bob's receive ID.
		p.aliceManager.mu.Lock()
		aliceOld := p.aliceManager.sessionsByPeer[p.bob.Hash()]
		p.aliceManager.mu.Unlock()
		if aliceOld == nil {
			t.Fatal("setup: Alice has no session")
		}
		p.aliceManager.removeSession(aliceOld)
		if err := p.aliceManager.EnsureSession(t.Context(), p.bob.Hash()); err != nil {
			t.Fatalf("reconnect: %v", err)
		}
		if err := p.aliceManager.Send(t.Context(), p.bob.Hash(), ssu2LiveMessage(43)); err != nil {
			t.Fatalf("send on reconnected session: %v", err)
		}
		p.network.Advance(100 * time.Millisecond)

		p.bobManager.mu.RLock()
		current := p.bobManager.sessionsByPeer[p.alice.Hash()]
		byID := p.bobManager.sessionsByID[p.victimReceive]
		p.bobManager.mu.RUnlock()
		if current == nil || current == p.victimOnBob {
			t.Fatalf("Bob did not replace Alice's session after an authenticated reconnect: current=%p old=%p", current, p.victimOnBob)
		}
		if current.receiveID != p.victimReceive || byID != current {
			t.Fatalf("reconnect did not reuse the connection ID: receive=%d want %d byID=%p", current.receiveID, p.victimReceive, byID)
		}
		p.receivedMu.Lock()
		delivered := p.receivedByBob[43]
		p.receivedMu.Unlock()
		if !delivered {
			t.Fatal("message on reconnected session did not reach Bob")
		}
	})
}
