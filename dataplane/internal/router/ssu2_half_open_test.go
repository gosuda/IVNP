package router

import (
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	dataplanessu2 "gosuda.org/ivnp/dataplane/internal/transport/ssu2"
	"gosuda.org/ivnp/internal/simnet"
)

// ssu2HalfOpenTarget is the public RouterInfo material an unauthenticated
// initiator needs to open an SSU2 handshake it never confirms.
type ssu2HalfOpenTarget struct {
	addr   net.Addr
	static []byte
	intro  []byte
}

func newSSU2HalfOpenTarget(t *testing.T, conn *simnet.UDPConn, static, intro []byte) ssu2HalfOpenTarget {
	t.Helper()
	private, err := ecdh.X25519().NewPrivateKey(static)
	if err != nil {
		t.Fatal(err)
	}
	return ssu2HalfOpenTarget{addr: conn.LocalAddr(), static: private.PublicKey().Bytes(), intro: intro}
}

func ssu2HalfOpenPayload(t *testing.T) []byte {
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

// openSSU2HalfOpen obtains a Retry token with a token-less SessionRequest,
// sends a tokened SessionRequest from conn, and never sends SessionConfirmed.
// A token-less SessionRequest reaches the responder even when DestinationID
// names a pending entry, where a TokenRequest would be routed to that entry.
// It reports whether the responder answered with SessionCreated, which means
// it now holds a half-open inbound entry.
func openSSU2HalfOpen(t *testing.T, conn *simnet.UDPConn, target ssu2HalfOpenTarget, destinationID, sourceID uint64) bool {
	t.Helper()
	const replyWait = 50 * time.Millisecond
	initiator, err := dataplanessu2.NewInitiator(target.static, target.intro, destinationID, sourceID, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer initiator.ReleaseSensitive()
	request, err := initiator.BuildSessionRequest(make([]byte, dataplanessu2.MaxIPv4PacketLen), ssu2HalfOpenPayload(t), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.WriteTo(request, target.addr); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, dataplanessu2.MaxIPv4PacketLen)
	if err = conn.SetReadDeadline(time.Now().Add(replyWait)); err != nil {
		t.Fatal(err)
	}
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		t.Fatalf("read Retry: %v", err)
	}
	retry, _, err := dataplanessu2.ParseRetry(reply[:n], target.intro, 2)
	if err != nil {
		t.Fatalf("parse Retry: %v", err)
	}
	initiator, err = dataplanessu2.NewInitiator(target.static, target.intro, destinationID, sourceID, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer initiator.ReleaseSensitive()
	request, err = initiator.BuildSessionRequest(make([]byte, dataplanessu2.MaxIPv4PacketLen), ssu2HalfOpenPayload(t), 1, retry.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.WriteTo(request, target.addr); err != nil {
		t.Fatal(err)
	}
	if err = conn.SetReadDeadline(time.Now().Add(replyWait)); err != nil {
		t.Fatal(err)
	}
	n, _, err = conn.ReadFrom(reply)
	if err != nil {
		return false
	}
	_, _, err = initiator.ParseSessionCreated(reply[:n])
	return err == nil
}

func ssu2InboundPendingCount(manager *SSU2Manager) int {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return len(manager.inbound)
}

func ssu2InboundPendingHas(manager *SSU2Manager, destinationID uint64) bool {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.inbound[destinationID] != nil
}

// TestSSU2InboundHalfOpenCappedPerSource reproduces one source opening many
// unconfirmed handshakes with production defaults. Only
// ssu2MaxInboundPendingPerSource may be held, and honest handshakes in both
// directions still complete.
func TestSSU2InboundHalfOpenCappedPerSource(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		// Two sockets on one host share a source address but differ by port.
		mallory := net_.Host("mallory")
		malloryConns := make([]*simnet.UDPConn, 2)
		for i := range malloryConns {
			conn, err := mallory.ListenUDP(netip.AddrPort{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			malloryConns[i] = conn
		}
		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		aliceDB, bobDB := newTransportTestPeers(), newTransportTestPeers()
		now := uint64(time.Now().UnixMilli())
		if err := aliceDB.AdmitRouterInfo(bob.Snapshot(), now); err != nil {
			t.Fatal(err)
		}
		if err := bobDB.AdmitRouterInfo(alice.Snapshot(), now); err != nil {
			t.Fatal(err)
		}
		aliceManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: aliceDB, StaticPrivate: aliceStatic, IntroKey: aliceIntro})
		if err != nil {
			t.Fatal(err)
		}
		bobManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: bobDB, StaticPrivate: bobStatic, IntroKey: bobIntro})
		if err != nil {
			t.Fatal(err)
		}
		ctx := t.Context()
		startSSU2SimManager(t, ctx, aliceManager, aliceConn, alice, nil)
		startSSU2SimManager(t, ctx, bobManager, bobConn, bob, nil)
		t.Cleanup(func() {
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})
		target := newSSU2HalfOpenTarget(t, bobConn, bobStatic, bobIntro)

		accepted := 0
		for i := range 2 * ssu2MaxInboundPendingPerSource {
			if openSSU2HalfOpen(t, malloryConns[i%len(malloryConns)], target, uint64(1000+i), uint64(2000+i)) {
				accepted++
			}
		}
		if accepted != ssu2MaxInboundPendingPerSource {
			t.Fatalf("half-open handshakes accepted from one source = %d, want %d", accepted, ssu2MaxInboundPendingPerSource)
		}
		if got := ssu2InboundPendingCount(bobManager); got != ssu2MaxInboundPendingPerSource {
			t.Fatalf("Bob inbound pending = %d, want %d", got, ssu2MaxInboundPendingPerSource)
		}

		ensureCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := aliceManager.EnsureSession(ensureCtx, bob.Hash()); err != nil {
			t.Fatalf("honest inbound EnsureSession under half-open pressure: %v", err)
		}
	})
}

// TestSSU2InboundHalfOpenPressureLeavesHandshakesWorking fills the whole
// inbound pending table with unconfirmed handshakes. Bob's own outbound
// handshake must not share that budget, and a new honest inbound handshake
// must displace the oldest half-open entry instead of being dropped.
func TestSSU2InboundHalfOpenPressureLeavesHandshakesWorking(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const maxPending = 2
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		carolConn := newSSU2SimConn(t, net_, "carol")
		malloryConns := []*simnet.UDPConn{newSSU2SimConn(t, net_, "mallory-1"), newSSU2SimConn(t, net_, "mallory-2")}
		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		carol, carolStatic, carolIntro := newSSU2TestLocal(t, carolConn.LocalAddr().String())
		aliceDB, bobDB, carolDB := newTransportTestPeers(), newTransportTestPeers(), newTransportTestPeers()
		now := uint64(time.Now().UnixMilli())
		for _, admit := range []struct {
			db   *transportTestPeers
			info *transportTestLocal
		}{{aliceDB, bob}, {bobDB, alice}, {bobDB, carol}, {carolDB, bob}} {
			if err := admit.db.AdmitRouterInfo(admit.info.Snapshot(), now); err != nil {
				t.Fatal(err)
			}
		}
		newManager := func(db *transportTestPeers, static, intro []byte) *SSU2Manager {
			manager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: db, StaticPrivate: static, IntroKey: intro, MaxPending: maxPending})
			if err != nil {
				t.Fatal(err)
			}
			return manager
		}
		aliceManager := newManager(aliceDB, aliceStatic, aliceIntro)
		bobManager := newManager(bobDB, bobStatic, bobIntro)
		carolManager := newManager(carolDB, carolStatic, carolIntro)
		ctx := t.Context()
		startSSU2SimManager(t, ctx, aliceManager, aliceConn, alice, nil)
		startSSU2SimManager(t, ctx, bobManager, bobConn, bob, nil)
		startSSU2SimManager(t, ctx, carolManager, carolConn, carol, nil)
		t.Cleanup(func() {
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
			closeSSU2LiveManager(t, carolManager)
		})
		target := newSSU2HalfOpenTarget(t, bobConn, bobStatic, bobIntro)

		for i, conn := range malloryConns {
			if !openSSU2HalfOpen(t, conn, target, uint64(1000+i), uint64(2000+i)) {
				t.Fatalf("half-open handshake %d was refused below capacity", i)
			}
		}
		if got := ssu2InboundPendingCount(bobManager); got != maxPending {
			t.Fatalf("Bob inbound pending = %d, want %d", got, maxPending)
		}

		ensureCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := bobManager.EnsureSession(ensureCtx, alice.Hash()); err != nil {
			t.Fatalf("outbound EnsureSession with a full inbound table: %v", err)
		}
		if err := carolManager.EnsureSession(ensureCtx, bob.Hash()); err != nil {
			t.Fatalf("honest inbound EnsureSession with a full inbound table: %v", err)
		}
		if ssu2InboundPendingHas(bobManager, 1000) {
			t.Fatal("oldest half-open entry survived eviction")
		}
		if !ssu2InboundPendingHas(bobManager, 1001) {
			t.Fatal("newer half-open entry was evicted instead of the oldest")
		}
	})
}

// TestSSU2InboundHalfOpenExpiresBeforeHandshakeTimeout checks that an entry
// still waiting for SessionConfirmed lives for ssu2InboundHalfOpenTimeout, not
// for the full handshake timeout.
func TestSSU2InboundHalfOpenExpiresBeforeHandshakeTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		bobConn := newSSU2SimConn(t, net_, "bob")
		malloryConn := newSSU2SimConn(t, net_, "mallory")
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		bobManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: newTransportTestPeers(), StaticPrivate: bobStatic, IntroKey: bobIntro})
		if err != nil {
			t.Fatal(err)
		}
		startSSU2SimManager(t, t.Context(), bobManager, bobConn, bob, nil)
		t.Cleanup(func() { closeSSU2LiveManager(t, bobManager) })
		if bobManager.timeout <= ssu2InboundHalfOpenTimeout {
			t.Fatalf("handshake timeout %v does not exceed half-open timeout %v", bobManager.timeout, ssu2InboundHalfOpenTimeout)
		}

		if !openSSU2HalfOpen(t, malloryConn, newSSU2HalfOpenTarget(t, bobConn, bobStatic, bobIntro), 1000, 2000) {
			t.Fatal("half-open handshake was refused")
		}
		net_.Advance(ssu2InboundHalfOpenTimeout + time.Second)
		if got := ssu2InboundPendingCount(bobManager); got != 0 {
			t.Fatalf("Bob inbound pending after half-open timeout = %d, want 0", got)
		}
	})
}

// TestSSU2InboundReplacementCountsAgainstSourceCap checks that a SessionRequest
// reusing another endpoint's pending DestinationID is admitted only when its
// own source is under the per-source cap.
func TestSSU2InboundReplacementCountsAgainstSourceCap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		bobConn := newSSU2SimConn(t, net_, "bob")
		malloryConn := newSSU2SimConn(t, net_, "mallory")
		otherConn := newSSU2SimConn(t, net_, "other")
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		bobManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: newTransportTestPeers(), StaticPrivate: bobStatic, IntroKey: bobIntro})
		if err != nil {
			t.Fatal(err)
		}
		startSSU2SimManager(t, t.Context(), bobManager, bobConn, bob, nil)
		t.Cleanup(func() { closeSSU2LiveManager(t, bobManager) })
		target := newSSU2HalfOpenTarget(t, bobConn, bobStatic, bobIntro)

		const otherDestination = 9000
		if !openSSU2HalfOpen(t, otherConn, target, otherDestination, 9001) {
			t.Fatal("other source half-open handshake was refused")
		}
		for i := range ssu2MaxInboundPendingPerSource {
			if !openSSU2HalfOpen(t, malloryConn, target, uint64(1000+i), uint64(2000+i)) {
				t.Fatalf("half-open handshake %d was refused below the source cap", i)
			}
		}
		if openSSU2HalfOpen(t, malloryConn, target, otherDestination, 9002) {
			t.Fatal("replacement of another endpoint's DestinationID bypassed the source cap")
		}
		if got := ssu2InboundPendingCount(bobManager); got != ssu2MaxInboundPendingPerSource+1 {
			t.Fatalf("Bob inbound pending = %d, want %d", got, ssu2MaxInboundPendingPerSource+1)
		}
		bobManager.mu.RLock()
		owner := bobManager.inbound[otherDestination]
		bobManager.mu.RUnlock()
		if owner == nil || owner.sendID != 9001 {
			t.Fatal("over-cap replacement displaced the other endpoint's pending handshake")
		}
	})
}

func TestSSU2InboundSourceKeyGroupsIPv6By64(t *testing.T) {
	key := func(s string) netip.Prefix {
		t.Helper()
		prefix, ok := ssu2InboundSourceKey(net.UDPAddrFromAddrPort(netip.MustParseAddrPort(s)))
		if !ok {
			t.Fatalf("no source key for %s", s)
		}
		return prefix
	}
	if key("[2001:db8:1:2::1]:1000") != key("[2001:db8:1:2:ffff::9]:2000") {
		t.Fatal("addresses in one IPv6 /64 have different source keys")
	}
	if key("[2001:db8:1:2::1]:1000") == key("[2001:db8:1:3::1]:1000") {
		t.Fatal("addresses in different IPv6 /64s share a source key")
	}
	if key("192.0.2.1:1000") != key("[::ffff:192.0.2.1]:2000") {
		t.Fatal("IPv4-mapped IPv6 address has a different source key from IPv4")
	}
	if key("192.0.2.1:1000") == key("192.0.2.2:1000") {
		t.Fatal("different IPv4 addresses share a source key")
	}
}
