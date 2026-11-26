package router

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	dataplanessu2 "gosuda.org/ivnp/dataplane/internal/transport/ssu2"
	"gosuda.org/ivnp/internal/simnet"
)

// ssu2WriteRecorder records every destination the wrapped socket writes to.
type ssu2WriteRecorder struct {
	UDPSocket
	mu           sync.Mutex
	destinations []netip.AddrPort
}

func (c *ssu2WriteRecorder) record(addr netip.AddrPort) {
	c.mu.Lock()
	c.destinations = append(c.destinations, netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()))
	c.mu.Unlock()
}

func (c *ssu2WriteRecorder) WriteTo(b []byte, addr net.Addr) (int, error) {
	if endpoint, ok := addrPortKey(addr); ok {
		c.record(endpoint)
	}
	return c.UDPSocket.WriteTo(b, addr)
}

func (c *ssu2WriteRecorder) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	c.record(addr.AddrPort())
	return c.UDPSocket.WriteToUDP(b, addr)
}

func (c *ssu2WriteRecorder) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	c.record(addr)
	return c.UDPSocket.WriteToUDPAddrPort(b, addr)
}

func (c *ssu2WriteRecorder) writesTo(endpoint netip.AddrPort) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for _, destination := range c.destinations {
		if destination == endpoint {
			count++
		}
	}
	return count
}

type ssu2RelayIntroFixture struct {
	network        *simnet.Network
	mallory        *transportTestLocal
	charlie        *transportTestLocal
	malloryIntro   []byte
	malloryManager *SSU2Manager
	charlieManager *SSU2Manager
	charlieWrites  *ssu2WriteRecorder
	victimConn     *simnet.UDPConn
	victim         netip.AddrPort
}

// newSSU2RelayIntroFixture connects Mallory to Charlie. Mallory is an
// authenticated SSU2 peer of Charlie but not, unless granted, its introducer.
func newSSU2RelayIntroFixture(t *testing.T, charlieMaxPending int) *ssu2RelayIntroFixture {
	return newSSU2RelayIntroFixtureWithPolicy(t, charlieMaxPending, false)
}

func newSSU2RelayIntroFixtureWithPolicy(t *testing.T, charlieMaxPending int, requirePublic bool) *ssu2RelayIntroFixture {
	t.Helper()
	f := &ssu2RelayIntroFixture{network: newSSU2SimNetwork(t)}
	malloryConn := newSSU2SimConn(t, f.network, "mallory")
	charlieConn := newSSU2SimConn(t, f.network, "charlie")
	f.victimConn = newSSU2SimConn(t, f.network, "victim")
	victim, err := netip.ParseAddrPort(f.victimConn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	f.victim = victim
	var malloryStatic, charlieStatic, charlieIntro []byte
	f.mallory, malloryStatic, f.malloryIntro = newSSU2TestLocal(t, malloryConn.LocalAddr().String())
	f.charlie, charlieStatic, charlieIntro = newSSU2TestLocal(t, charlieConn.LocalAddr().String())
	malloryDB, charlieDB := newTransportTestPeers(), newTransportTestPeers()
	now := uint64(time.Now().UnixMilli())
	if err = malloryDB.AdmitRouterInfo(f.charlie.Snapshot(), now); err != nil {
		t.Fatal(err)
	}
	if err = charlieDB.AdmitRouterInfo(f.mallory.Snapshot(), now); err != nil {
		t.Fatal(err)
	}
	f.malloryManager = newSSU2LiveManager(t, malloryDB, malloryStatic, f.malloryIntro, time.Minute, time.Minute)
	f.charlieManager, err = NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: charlieDB, StaticPrivate: charlieStatic, IntroKey: charlieIntro,
		TokenLifetime: time.Minute, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, MaxPending: charlieMaxPending,
		RequirePublicPeerAddresses: requirePublic})
	if err != nil {
		t.Fatal(err)
	}
	f.charlieWrites = &ssu2WriteRecorder{UDPSocket: charlieConn}
	ctx := t.Context()
	startSSU2SimManager(t, ctx, f.malloryManager, malloryConn, f.mallory, nil)
	startSSU2SimManager(t, ctx, f.charlieManager, f.charlieWrites, f.charlie, nil)
	t.Cleanup(func() {
		closeSSU2LiveManager(t, f.malloryManager)
		closeSSU2LiveManager(t, f.charlieManager)
	})
	if err = f.malloryManager.EnsureSession(ctx, f.charlie.Hash()); err != nil {
		t.Fatal(err)
	}
	f.network.Advance(100 * time.Millisecond)
	return f
}

// grantRelayTag makes Charlie request a relay tag from Mallory, so Mallory
// becomes one of Charlie's introducers, and returns the granted tag.
func (f *ssu2RelayIntroFixture) grantRelayTag(t *testing.T) uint32 {
	t.Helper()
	if err := f.charlieManager.RequestRelayTag(t.Context(), f.mallory.Hash()); err != nil {
		t.Fatal(err)
	}
	f.network.Advance(100 * time.Millisecond)
	f.charlieManager.mu.RLock()
	lease, granted := f.charlieManager.advertisedRelays[f.mallory.Hash()]
	f.charlieManager.mu.RUnlock()
	if !granted || lease.tag == 0 {
		t.Fatal("setup: Charlie holds no relay tag from Mallory")
	}
	return lease.tag
}

// sendIntro makes Mallory forward a RelayIntro to Charlie that names Mallory
// as Alice and asks Charlie to hole-punch endpoint.
func (f *ssu2RelayIntroFixture) sendIntro(t *testing.T, nonce, tag uint32, endpoint netip.AddrPort) []byte {
	t.Helper()
	malloryHash, charlieHash := f.mallory.Hash(), f.charlie.Hash()
	request := dataplanessu2.RelayRequest{Nonce: nonce, RelayTag: tag, Timestamp: uint32(time.Now().Unix()), Endpoint: endpoint}
	input, err := dataplanessu2.RelayRequestSignatureInput(nil, malloryHash[:], charlieHash[:], request)
	if err != nil {
		t.Fatal(err)
	}
	request.Signature = f.mallory.Sign(input)
	block, err := dataplanessu2.MarshalRelayIntroBlock(nil, dataplanessu2.RelayIntro{AliceHash: [32]byte(malloryHash), Request: request})
	if err != nil {
		t.Fatal(err)
	}
	f.resend(t, block)
	return block
}

func (f *ssu2RelayIntroFixture) resend(t *testing.T, block []byte) {
	t.Helper()
	f.malloryManager.mu.RLock()
	session := f.malloryManager.sessionsByPeer[f.charlie.Hash()]
	f.malloryManager.mu.RUnlock()
	if session == nil {
		t.Fatal("setup: Mallory has no session to Charlie")
	}
	if err := f.malloryManager.sendSessionData(session, block, false); err != nil {
		t.Fatal(err)
	}
	f.network.Advance(100 * time.Millisecond)
}

// victimHolePunches drains the victim socket and returns how many HolePunch
// packets keyed to Mallory's intro key it received.
func (f *ssu2RelayIntroFixture) victimHolePunches(t *testing.T) int {
	t.Helper()
	count := 0
	buf := make([]byte, 2048)
	for {
		if err := f.victimConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := f.victimConn.ReadFrom(buf)
		if err != nil {
			return count
		}
		if header, _, parseErr := dataplanessu2.ParseHolePunch(buf[:n], f.malloryIntro, 2); parseErr == nil && header.Type == dataplanessu2.HolePunch {
			count++
		}
	}
}

func TestSSU2RelayIntroRequiresGrantedRelayTag(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newSSU2RelayIntroFixture(t, 0)
		f.sendIntro(t, 0x41414141, 0xdeadbeef, f.victim)
		if got := f.victimHolePunches(t); got != 0 {
			t.Fatalf("Charlie hole-punched %d times for a peer that is not its introducer", got)
		}

		tag := f.grantRelayTag(t)
		f.sendIntro(t, 0x42424242, tag^1, f.victim)
		if got := f.victimHolePunches(t); got != 0 {
			t.Fatalf("Charlie hole-punched %d times for a relay tag it was not granted", got)
		}

		f.sendIntro(t, 0x43434343, tag, f.victim)
		if got := f.victimHolePunches(t); got != 1 {
			t.Fatalf("Charlie hole-punched %d times for its introducer's granted tag, want 1", got)
		}
	})
}

func TestSSU2RelayIntroDropsReplayedNonce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newSSU2RelayIntroFixture(t, 0)
		tag := f.grantRelayTag(t)
		block := f.sendIntro(t, 0x51515151, tag, f.victim)
		if got := f.victimHolePunches(t); got != 1 {
			t.Fatalf("first RelayIntro produced %d hole punches, want 1", got)
		}
		f.resend(t, block)
		f.resend(t, block)
		if got := f.victimHolePunches(t); got != 0 {
			t.Fatalf("replayed RelayIntro produced %d more hole punches, want 0", got)
		}
	})
}

func TestSSU2RelayIntroRateLimitsEachIntroducer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const budget = 2
		f := newSSU2RelayIntroFixture(t, budget)
		tag := f.grantRelayTag(t)
		for i := range budget + 3 {
			f.sendIntro(t, 0x61616100+uint32(i), tag, f.victim)
		}
		if got := f.victimHolePunches(t); got != budget {
			t.Fatalf("introducer burst produced %d hole punches, want the budget of %d", got, budget)
		}
	})
}

func TestSSU2RelayIntroRejectsNonUnicastEndpoint(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newSSU2RelayIntroFixture(t, 0)
		tag := f.grantRelayTag(t)
		for i, endpoint := range []netip.AddrPort{
			netip.MustParseAddrPort("224.0.0.1:9"),
			netip.MustParseAddrPort("239.255.255.250:1900"),
			netip.MustParseAddrPort("255.255.255.255:9"),
			netip.MustParseAddrPort("[ff02::1]:9"),
		} {
			f.sendIntro(t, 0x71717100+uint32(i), tag, endpoint)
			if got := f.charlieWrites.writesTo(endpoint); got != 0 {
				t.Fatalf("Charlie sent %d packets to non-unicast endpoint %s", got, endpoint)
			}
		}
	})
}

func TestSSU2RelayIntroPublicPolicyRejectsNonPublicEndpoint(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newSSU2RelayIntroFixtureWithPolicy(t, 0, true)
		tag := f.grantRelayTag(t)
		for i, endpoint := range []netip.AddrPort{
			netip.MustParseAddrPort("127.0.0.1:9"),
			netip.MustParseAddrPort("10.0.0.5:9"),
			netip.MustParseAddrPort("192.168.1.1:9"),
			netip.MustParseAddrPort("100.64.0.1:9"),
			netip.MustParseAddrPort("169.254.1.1:9"),
			netip.MustParseAddrPort("[::1]:9"),
			netip.MustParseAddrPort("[fd00::1]:9"),
		} {
			f.sendIntro(t, 0x81818100+uint32(i), tag, endpoint)
			if got := f.charlieWrites.writesTo(endpoint); got != 0 {
				t.Fatalf("public-policy Charlie sent %d packets to non-public endpoint %s", got, endpoint)
			}
		}
		f.sendIntro(t, 0x82828282, tag, f.victim)
		if got := f.victimHolePunches(t); got != 1 {
			t.Fatalf("public-policy Charlie hole-punched %d times for routable simnet endpoint, want 1", got)
		}
	})
}
