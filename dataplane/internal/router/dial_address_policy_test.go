package router

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

var nonPublicDialHosts = []string{
	"10.0.0.5",
	"172.16.0.1",
	"192.168.1.1",
	"127.0.0.1",
	"100.64.0.1",
	"100.127.255.254",
	"169.254.1.1",
	"0.0.0.0",
	"0.1.2.3",
	"224.0.0.1",
	"255.255.255.255",
	"::",
	"::1",
	"fd00::1",
	"fc00::1",
	"fe80::1",
	"ff02::1",
	"::ffff:10.0.0.5",
	"::ffff:127.0.0.1",
}

var (
	errTestDialMustNotBeAttempted = errors.New("dial must not be attempted")
	hostnameDialHosts             = []string{"internal.example", "localhost"}
)

func TestPublicDialAddressClassification(t *testing.T) {
	for _, host := range nonPublicDialHosts {
		if publicDialAddress(netip.MustParseAddr(host)) {
			t.Errorf("publicDialAddress(%s) = true, want false", host)
		}
	}
	if publicDialAddress(netip.MustParseAddr("fe80::1%eth0")) {
		t.Error("publicDialAddress accepted a zoned address")
	}
	for _, host := range []string{"192.0.2.1", "8.8.8.8", "100.63.255.255", "100.128.0.1", "2001:db8::1", "2a00:1450::1", "::ffff:8.8.8.8"} {
		if !publicDialAddress(netip.MustParseAddr(host)) {
			t.Errorf("publicDialAddress(%s) = false, want true", host)
		}
	}
}

func TestNTCP2PublicPeerAddressesRefuseNonPublicHostsBeforeDial(t *testing.T) {
	_, static, iv := newNTCP2TestLocal(t, "127.0.0.1:1")
	for _, host := range append(append([]string(nil), nonPublicDialHosts...), hostnameDialHosts...) {
		t.Run(host, func(t *testing.T) {
			owner, _, _ := newNTCP2TestLocal(t, net.JoinHostPort(host, "9"))
			info := owner.Snapshot()
			peers := newTransportTestPeers()
			if err := peers.AdmitRouterInfo(info, uint64(time.Now().UnixMilli())); err != nil {
				t.Fatal(err)
			}
			var admissions atomic.Int32
			manager, err := NewNTCP2Manager(NTCP2ManagerConfig{
				NetworkID: 2, Peers: peers, StaticPrivate: static, StaticIV: iv, RequirePublicPeerAddresses: true,
				AdmitPeer: func(context.Context, PeerAdmission) error {
					admissions.Add(1)
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			var dials atomic.Int32
			manager.ctx, manager.cancel = context.WithCancel(context.Background())
			manager.started = true
			manager.bindings = TransportBindings{Clock: WallClock{}, DialStream: func(context.Context, Endpoint) (net.Conn, error) {
				dials.Add(1)
				return nil, errTestDialMustNotBeAttempted
			}}
			t.Cleanup(manager.cancel)
			if err := manager.openOutbound(t.Context(), info.Hash()); !errors.Is(err, ErrNTCP2Peer) {
				t.Fatalf("openOutbound error = %v, want %v", err, ErrNTCP2Peer)
			}
			if dials.Load() != 0 || admissions.Load() != 0 {
				t.Fatalf("non-public host reached dial=%d admission=%d", dials.Load(), admissions.Load())
			}
			if manager.PeerReachable(info) {
				t.Fatal("PeerReachable reported a non-public NTCP2 host as dialable")
			}
		})
	}
}

func TestNTCP2PublicPeerAddressesSkipNonPublicForPublicAddress(t *testing.T) {
	owner, _, _ := newNTCP2TestLocalWithEndpoints(t, "10.0.0.5:9", "[fd00::1]:9", "192.0.2.1:23456")
	selected, err := selectNTCP2AddressForNetwork(owner.Snapshot(), ntcp2AddressAny, dialPublicAddresses)
	if err != nil {
		t.Fatal(err)
	}
	if selected.host != "192.0.2.1" || selected.port != 23456 {
		t.Fatalf("selected %s:%d, want 192.0.2.1:23456", selected.host, selected.port)
	}
}

func TestNTCP2LocalPeerAddressesAllowPrivateButNotHostnames(t *testing.T) {
	_, static, iv := newNTCP2TestLocal(t, "127.0.0.1:1")
	manager, err := NewNTCP2Manager(NTCP2ManagerConfig{NetworkID: 2, StaticPrivate: static, StaticIV: iv})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"127.0.0.1", "10.0.0.5", "fd00::1"} {
		owner, _, _ := newNTCP2TestLocal(t, net.JoinHostPort(host, "9"))
		if !manager.PeerReachable(owner.Snapshot()) {
			t.Errorf("local-address policy rejected %s", host)
		}
	}
	for _, host := range hostnameDialHosts {
		owner, _, _ := newNTCP2TestLocal(t, net.JoinHostPort(host, "9"))
		if manager.PeerReachable(owner.Snapshot()) {
			t.Errorf("NTCP2 accepted hostname %q instead of an IP literal", host)
		}
	}
}

func TestSSU2PublicPeerAddressesRefuseNonPublicHostsBeforeDial(t *testing.T) {
	for _, host := range nonPublicDialHosts {
		t.Run(host, func(t *testing.T) {
			owner, _, _ := newSSU2TestLocal(t, net.JoinHostPort(host, "9"))
			info := owner.Snapshot()
			peers := newTransportTestPeers()
			if err := peers.AdmitRouterInfo(info, uint64(time.Now().UnixMilli())); err != nil {
				t.Fatal(err)
			}
			var admissions atomic.Int32
			manager, err := NewSSU2Manager(SSU2ManagerConfig{
				NetworkID: 2, Peers: peers, StaticPrivate: bytes32(1), IntroKey: bytes32(2), RequirePublicPeerAddresses: true,
				AdmitPeer: func(context.Context, PeerAdmission) error {
					admissions.Add(1)
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			manager.ctx, manager.cancel = context.WithCancel(context.Background())
			manager.bindings = TransportBindings{Clock: WallClock{}}
			t.Cleanup(manager.cancel)
			if _, _, err := manager.resolveOutbound(info.Hash()); !errors.Is(err, ErrSSU2Peer) {
				t.Fatalf("resolveOutbound error = %v, want %v", err, ErrSSU2Peer)
			}
			if admissions.Load() != 0 {
				t.Fatal("non-public SSU2 host reached peer admission")
			}
			if manager.InspectPeer(info, uint64(time.Now().Unix())).Direct {
				t.Fatal("InspectPeer reported a non-public SSU2 host as directly reachable")
			}
		})
	}
}

func TestSSU2PublicPeerAddressesRefuseNonPublicIntroducedEndpoint(t *testing.T) {
	manager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, StaticPrivate: bytes32(1), IntroKey: bytes32(2), RequirePublicPeerAddresses: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range nonPublicDialHosts {
		endpoint := netip.AddrPortFrom(netip.MustParseAddr(host), 9)
		manager.mu.Lock()
		pending, err := manager.newIntroducedOutboundLocked(foundation.Hash{3}, ssu2PeerAddress{}, endpoint, 1, 2)
		manager.mu.Unlock()
		if pending != nil || !errors.Is(err, ErrSSU2Introduction) {
			t.Fatalf("introduced endpoint %s: pending=%v err=%v, want %v", endpoint, pending != nil, err, ErrSSU2Introduction)
		}
	}
}

func TestSSU2LocalPeerAddressesAllowPrivate(t *testing.T) {
	owner, _, _ := newSSU2TestLocal(t, "10.0.0.5:9")
	manager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, StaticPrivate: bytes32(1), IntroKey: bytes32(2)})
	if err != nil {
		t.Fatal(err)
	}
	if !manager.InspectPeer(owner.Snapshot(), uint64(time.Now().Unix())).Direct {
		t.Fatal("local-address policy rejected a private SSU2 host")
	}
}
