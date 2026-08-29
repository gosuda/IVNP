//go:build integration

package router

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/netdb"
)

const (
	stableSSU2RouterHash = "mIyKvlqkIKXM9Gts7hp1PGI62kA01S-h8wWwxdOq47Q="
	stableSSU2Endpoint   = "23.128.248.46:7777"
)

type stableSSU2Reply struct {
	source  foundation.Hash
	message i2np.Message
}

// TestStableRouterSSU2Interop pins the public StormyCloud router used by the
// live transport check. Its current signed RouterInfo must be supplied because
// RouterInfos expire and cannot be committed as a durable fixture.
func TestStableRouterSSU2Interop(t *testing.T) {
	if os.Getenv("IVNP_STABLE_SSU2_INTEGRATION") != "1" {
		t.Skip("set IVNP_STABLE_SSU2_INTEGRATION=1 to run the live stable-router check")
	}
	path := os.Getenv("IVNP_STABLE_SSU2_ROUTER_INFO")
	if path == "" {
		t.Fatal("IVNP_STABLE_SSU2_ROUTER_INFO must name the current signed RouterInfo")
	}

	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read stable SSU2 RouterInfo: %v", err)
	}
	peer, err := netdb.ParseRouterInfo(wire)
	if err != nil {
		t.Fatalf("parse stable SSU2 RouterInfo: %v", err)
	}
	valid, err := peer.Verify()
	if err != nil || !valid {
		t.Fatalf("verify stable SSU2 RouterInfo: valid=%t err=%v", valid, err)
	}
	expectedHash := decodeStableSSU2Hash(t)
	actualHash := peer.Hash()
	if actualHash != expectedHash {
		t.Fatalf("stable SSU2 RouterInfo hash = %s, want %s", foundation.EncodeI2PBase64(actualHash[:]), stableSSU2RouterHash)
	}
	address, err := selectSSU2AddressForNetwork(peer, false)
	if err != nil {
		t.Fatalf("select stable router SSU2 address: %v", err)
	}
	if endpoint := netip.AddrPortFrom(netip.MustParseAddr(address.host), address.port); endpoint != netip.MustParseAddrPort(stableSSU2Endpoint) {
		t.Fatalf("stable router SSU2 endpoint = %s, want %s", endpoint, stableSSU2Endpoint)
	}
	if !netdb.IsFloodfill(peer) {
		t.Fatal("pinned stable SSU2 router is not a floodfill")
	}

	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	local, staticPrivate, introKey := newSSU2TestLocal(t, connection.LocalAddr().String())
	database := netdb.NewDatabase(local.Hash(), 16)
	if err = database.AdmitRouterInfo(peer, false, uint64(time.Now().UnixMilli())); err != nil {
		_ = connection.Close()
		t.Fatalf("admit current stable SSU2 RouterInfo: %v", err)
	}
	manager, err := NewSSU2Manager(SSU2ManagerConfig{
		Database: database, StaticPrivate: staticPrivate, IntroKey: introKey,
		HandshakeTimeout: 30 * time.Second, IdleTimeout: time.Minute,
	})
	if err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	received := make(chan stableSSU2Reply, 4)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	if err = manager.Start(ctx, TransportBindings{
		SSU2: connection, LocalInfo: local, Clock: WallClock{},
		HandleI2NPContext: func(_ context.Context, source foundation.Hash, message i2np.Message, _ uint64, _ bool) error {
			select {
			case received <- stableSSU2Reply{source: source, message: message}:
			default:
			}
			return nil
		},
	}); err != nil {
		cancel()
		_ = connection.Close()
		t.Fatalf("start stable-router SSU2 client: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = manager.Close()
		if waitErr := manager.Wait(); waitErr != nil {
			t.Errorf("wait for stable-router SSU2 client: %v", waitErr)
		}
	})

	lookup := make([]byte, 67)
	localHash := local.Hash()
	copy(lookup[:32], expectedHash[:])
	copy(lookup[32:64], localHash[:])
	if _, err = i2np.ParseDatabaseLookup(lookup); err != nil {
		t.Fatalf("build stable-router DatabaseLookup: %v", err)
	}
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.DatabaseLookup, ID: 1, Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())},
		Payload: lookup,
	}
	if err = manager.Send(ctx, expectedHash, message); err != nil {
		t.Fatalf("send exact-hash DatabaseLookup over SSU2: %v", err)
	}
	requireStableSSU2OutboundSession(t, manager, expectedHash)
	requireStableSSU2RoundTrip(t, received, expectedHash)
	if !waitForSSU2SentPackets(manager, expectedHash, 10*time.Second) {
		t.Fatal("stable router did not acknowledge the reliable SSU2 lookup")
	}
}

func decodeStableSSU2Hash(t *testing.T) foundation.Hash {
	t.Helper()
	raw, err := foundation.DecodeI2PBase64([]byte(stableSSU2RouterHash))
	if err != nil || len(raw) != foundation.HashLength {
		t.Fatalf("decode pinned stable router hash: length=%d err=%v", len(raw), err)
	}
	var hash foundation.Hash
	copy(hash[:], raw)
	return hash
}

func requireStableSSU2OutboundSession(t *testing.T, manager *SSU2Manager, peer foundation.Hash) {
	t.Helper()
	manager.mu.RLock()
	session := manager.sessionsByPeer[peer]
	manager.mu.RUnlock()
	if session == nil {
		t.Fatal("exact-hash outbound send did not install an SSU2 session")
	}
	endpoint, ok := addrPortKey(session.remoteAddr())
	if !ok || endpoint != netip.MustParseAddrPort(stableSSU2Endpoint) {
		t.Fatalf("outbound SSU2 session endpoint = %s, %t; want %s", endpoint, ok, stableSSU2Endpoint)
	}
}

func requireStableSSU2RoundTrip(t *testing.T, received <-chan stableSSU2Reply, peer foundation.Hash) {
	t.Helper()
	select {
	case reply := <-received:
		if reply.source != peer {
			t.Fatalf("stable-router reply source = %s, want %s", reply.source, peer)
		}
		if reply.message.Header.Type != i2np.DatabaseStore {
			t.Fatalf("stable-router reply type = %d, want DatabaseStore", reply.message.Header.Type)
		}
		store, err := i2np.ParseDatabaseStore(reply.message.Payload)
		if err != nil {
			t.Fatalf("parse stable-router DatabaseStore: %v", err)
		}
		if store.Type != i2np.StoreRouterInfo || store.Key != peer {
			t.Fatalf("stable-router reply = type %d key %s; want RouterInfo for %s", store.Type, store.Key, peer)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("stable router did not return an authenticated I2NP DatabaseStore")
	}
}
