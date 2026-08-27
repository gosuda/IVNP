package tunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/netdb"
)

func TestNetDBOutboundBuildSourceRanksDistinctVerifiedPeers(t *testing.T) {
	left := verifiedX25519Router(t, 1)
	right := verifiedX25519Router(t, 2)
	table := netdb.NewTable(foundation.Hash{}, 8)
	table.StoreVerified(left, false, 1)
	table.StoreVerified(right, false, 1)
	profiles := NewPeerProfiles(PeerProfilesConfig{Window: 4})
	profiles.RecordSuccess(right.Hash(), 5)
	nextTunnel := uint32(80)
	source, err := NewNetDBOutboundBuildSource(NetDBOutboundBuildSourceConfig{
		Table: table, Profiles: profiles, ReplyRouter: foundation.Hash{9}, ReplyTunnelID: 10,
		Hops: 2, CandidateLimit: 4, Lifetime: 100,
		CircuitID: func() uint32 { return 70 },
		TunnelID:  func() uint32 { nextTunnel++; return nextTunnel },
		Target:    func(uint64) foundation.Hash { return foundation.Hash{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	build, err := source.NextOutbound(context.Background(), 500)
	if err != nil {
		t.Fatal(err)
	}
	if build.CircuitID != 70 || build.ExpiresAt != 600 || len(build.Hops) != 2 {
		t.Fatalf("build = %#v", build)
	}
	if build.Hops[0].Router != right.Hash() || build.Hops[0].Router == build.Hops[1].Router || build.Hops[0].ReceiveTunnelID != 81 || build.Hops[1].ReceiveTunnelID != 82 {
		t.Fatalf("selected hops = %#v", build.Hops)
	}
	if build.Hops[0].StaticKey[0] != 2 || build.Hops[1].StaticKey[0] != 1 {
		t.Fatalf("static keys = %x, %x", build.Hops[0].StaticKey, build.Hops[1].StaticKey)
	}
}

func TestNetDBBuildSourceRejectsReseedFreshButTransportStalePeer(t *testing.T) {
	info := verifiedX25519Router(t, 1)
	table := netdb.NewTable(foundation.Hash{}, 8)
	table.StoreVerified(info, false, 1)
	source, err := NewNetDBInboundBuildSource(NetDBInboundBuildSourceConfig{
		Table: table, Profiles: NewPeerProfiles(PeerProfilesConfig{}), LocalRouter: foundation.Hash{8},
		Hops: 1, Lifetime: uint64((10 * time.Minute) / time.Millisecond),
		CircuitID: func() uint32 { return 70 }, TunnelID: func() uint32 { return 80 },
	})
	if err != nil {
		t.Fatal(err)
	}
	now := uint64((91 * time.Minute) / time.Millisecond)
	if _, err = source.NextInbound(context.Background(), now, 0); !errors.Is(err, ErrNoEligiblePeers) {
		t.Fatalf("stale reseed peer selection error = %v, want %v", err, ErrNoEligiblePeers)
	}
}

func TestNetDBBuildSourceExcludesTransportIneligiblePeer(t *testing.T) {
	unusable := verifiedX25519Router(t, 1)
	usable := verifiedX25519Router(t, 2)
	table := netdb.NewTable(foundation.Hash{}, 8)
	table.StoreVerified(unusable, false, 1)
	table.StoreVerified(usable, false, 1)
	source, err := NewNetDBInboundBuildSource(NetDBInboundBuildSourceConfig{
		Table: table, Profiles: NewPeerProfiles(PeerProfilesConfig{}), LocalRouter: foundation.Hash{8},
		Hops: 1, CandidateLimit: 8, Lifetime: 100,
		CircuitID: func() uint32 { return 70 }, TunnelID: func() uint32 { return 80 },
		Eligible: func(peer foundation.Hash) bool { return peer == usable.Hash() },
	})
	if err != nil {
		t.Fatal(err)
	}
	build, err := source.NextInbound(context.Background(), 500, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(build.Hops) != 1 || build.Hops[0].Router != usable.Hash() {
		t.Fatalf("transport-filtered build = %#v", build)
	}
}

func TestNetDBBuildSourceRequiresAdjacentTransportCompatibility(t *testing.T) {
	first := verifiedX25519RouterTransport(t, 1, "NTCP2", "192.0.2.1", "", "")
	incompatible := verifiedX25519RouterTransport(t, 2, "SSU2", "2001:db8::1", "", "")
	compatible := verifiedX25519RouterTransport(t, 3, "NTCP2", "198.51.100.1", "", "")
	table := netdb.NewTable(foundation.Hash{}, 8)
	table.StoreVerified(first, false, 1)
	table.StoreVerified(incompatible, false, 1)
	table.StoreVerified(compatible, false, 1)
	profiles := NewPeerProfiles(PeerProfilesConfig{Window: 4})
	profiles.RecordSuccess(first.Hash(), 1)
	profiles.RecordSuccess(first.Hash(), 2)
	profiles.RecordSuccess(incompatible.Hash(), 1)
	nextTunnel := uint32(80)
	source, err := NewNetDBOutboundBuildSource(NetDBOutboundBuildSourceConfig{
		Table: table, Profiles: profiles, ReplyRouter: foundation.Hash{9}, ReplyTunnelID: 10,
		Hops: 2, CandidateLimit: 3, Lifetime: 100,
		CircuitID: func() uint32 { return 70 },
		TunnelID:  func() uint32 { nextTunnel++; return nextTunnel },
	})
	if err != nil {
		t.Fatal(err)
	}
	build, err := source.NextOutbound(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(build.Hops) != 2 || build.Hops[0].Router != first.Hash() || build.Hops[1].Router != compatible.Hash() {
		t.Fatalf("transport-compatible path = %#v", build.Hops)
	}
}

func TestNetDBBuildSourceExcludesPeersRejectingTunnelParticipation(t *testing.T) {
	table := netdb.NewTable(foundation.Hash{}, 8)
	for marker, capability := range []string{"H", "U", "K", "E", "G"} {
		table.StoreVerified(verifiedX25519RouterTransport(t, byte(marker+1), "NTCP2", "192.0.2.1", "", capability), false, 1)
	}
	healthy := verifiedX25519RouterTransport(t, 9, "NTCP2", "198.51.100.1", "", "OR")
	table.StoreVerified(healthy, false, 1)
	source, err := NewNetDBInboundBuildSource(NetDBInboundBuildSourceConfig{
		Table: table, Profiles: NewPeerProfiles(PeerProfilesConfig{}), LocalRouter: foundation.Hash{8},
		Hops: 1, CandidateLimit: 8, Lifetime: 100,
		CircuitID: func() uint32 { return 70 }, TunnelID: func() uint32 { return 80 },
	})
	if err != nil {
		t.Fatal(err)
	}
	build, err := source.NextInbound(context.Background(), 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(build.Hops) != 1 || build.Hops[0].Router != healthy.Hash() {
		t.Fatalf("tunnel-capable path = %#v", build.Hops)
	}
}

func verifiedX25519Router(t *testing.T, marker byte) netdb.RouterInfo {
	t.Helper()
	return verifiedX25519RouterTransport(t, marker, "NTCP2", "192.0.2.1", "", "")
}

func verifiedX25519RouterTransport(t *testing.T, marker byte, style, host, addressCaps, routerCaps string) netdb.RouterInfo {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = marker
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	identity := make([]byte, foundation.IdentityBaseLength+foundation.CertificateHeader+4)
	identity[0] = marker
	copy(identity[foundation.IdentityBaseLength-32:foundation.IdentityBaseLength], public)
	identity[foundation.IdentityBaseLength] = byte(foundation.CertificateKey)
	binary.BigEndian.PutUint16(identity[foundation.IdentityBaseLength+1:], 4)
	binary.BigEndian.PutUint16(identity[foundation.IdentityBaseLength+3:], uint16(foundation.SigningEdDSASHA512Ed25519))
	binary.BigEndian.PutUint16(identity[foundation.IdentityBaseLength+5:], uint16(foundation.CryptoX25519))

	addressEntries := make([]foundation.MappingEntry, 0, 3)
	if addressCaps != "" {
		addressEntries = append(addressEntries, foundation.MappingEntry{Key: []byte("caps"), Value: []byte(addressCaps)})
	}
	if host != "" {
		addressEntries = append(addressEntries, foundation.MappingEntry{Key: []byte("host"), Value: []byte(host)})
	}
	addressEntries = append(addressEntries, foundation.MappingEntry{Key: []byte("port"), Value: []byte("12345")})
	addressMappingLen, err := foundation.MappingEncodedLen(addressEntries)
	if err != nil {
		t.Fatal(err)
	}
	routerEntries := make([]foundation.MappingEntry, 0, 1)
	if routerCaps != "" {
		routerEntries = append(routerEntries, foundation.MappingEntry{Key: []byte("caps"), Value: []byte(routerCaps)})
	}
	routerMappingLen, err := foundation.MappingEncodedLen(routerEntries)
	if err != nil {
		t.Fatal(err)
	}
	addressLen := 1 + 8 + 1 + len(style) + addressMappingLen
	unsigned := make([]byte, len(identity)+8+1+addressLen+1+routerMappingLen)
	copy(unsigned, identity)
	offset := len(identity)
	binary.BigEndian.PutUint64(unsigned[offset:], 1)
	offset += 8
	unsigned[offset] = 1
	offset++
	unsigned[offset] = 10
	offset++
	offset += 8
	unsigned[offset] = byte(len(style))
	offset++
	copy(unsigned[offset:], style)
	offset += len(style)
	if _, err = foundation.MarshalMappingTo(unsigned[offset:], addressEntries); err != nil {
		t.Fatal(err)
	}
	offset += addressMappingLen
	offset++ // peer count
	if _, err = foundation.MarshalMappingTo(unsigned[offset:], routerEntries); err != nil {
		t.Fatal(err)
	}

	signature := ed25519.Sign(private, unsigned)
	info, err := netdb.ParseRouterInfo(append(unsigned, signature...))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestNetDBBuildSourcesLimitClosestCandidatesBeforeProfileRanking(t *testing.T) {
	table := netdb.NewTable(foundation.Hash{}, 8)
	for marker := byte(1); marker <= 3; marker++ {
		table.StoreVerified(verifiedX25519Router(t, marker), false, 1)
	}
	target := foundation.Hash{}
	all := table.ClosestInto(make([]netdb.RouterRef, table.Len()), target)
	outside := all[2].Hash
	profiles := NewPeerProfiles(PeerProfilesConfig{Window: 4})
	profiles.RecordSuccess(outside, 1)
	nextTunnel := uint32(100)
	outbound, err := NewNetDBOutboundBuildSource(NetDBOutboundBuildSourceConfig{
		Table: table, Profiles: profiles, ReplyRouter: foundation.Hash{9}, ReplyTunnelID: 10,
		Hops: 1, CandidateLimit: 2, Lifetime: 100,
		CircuitID: func() uint32 { return 70 },
		TunnelID:  func() uint32 { nextTunnel++; return nextTunnel },
		Target:    func(uint64) foundation.Hash { return target },
	})
	if err != nil {
		t.Fatal(err)
	}
	outboundBuild, err := outbound.NextOutbound(context.Background(), 500)
	if err != nil {
		t.Fatal(err)
	}
	if outboundBuild.Hops[0].Router == outside {
		t.Fatalf("outbound selected high-profile peer outside candidate limit: %#v", outboundBuild.Hops)
	}
	inbound, err := NewNetDBInboundBuildSource(NetDBInboundBuildSourceConfig{
		Table: table, Profiles: profiles, LocalRouter: foundation.Hash{8},
		Hops: 1, CandidateLimit: 2, Lifetime: 100,
		CircuitID: func() uint32 { return 71 },
		TunnelID:  func() uint32 { nextTunnel++; return nextTunnel },
		Target:    func(uint64) foundation.Hash { return target },
	})
	if err != nil {
		t.Fatal(err)
	}
	inboundBuild, err := inbound.NextInbound(context.Background(), 500, 0)
	if err != nil {
		t.Fatal(err)
	}
	if inboundBuild.Hops[0].Router == outside {
		t.Fatalf("inbound selected high-profile peer outside candidate limit: %#v", inboundBuild.Hops)
	}
}
