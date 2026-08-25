package tunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/network_database"
	"testing"
	"time"
)

func TestNetDBOutboundBuildSourceRanksDistinctVerifiedPeers(t *testing.T) {
	left := verifiedX25519Router(t, 1)
	right := verifiedX25519Router(t, 2)
	table := netdb.NewTable(ivnp.Hash{}, 8)
	table.StoreVerified(left, false, 1)
	table.StoreVerified(right, false, 1)
	profiles := NewPeerProfiles(PeerProfilesConfig{Window: 4})
	profiles.RecordSuccess(right.Hash(), 5)
	nextTunnel := uint32(80)
	source, err := NewNetDBOutboundBuildSource(NetDBOutboundBuildSourceConfig{
		Table: table, Profiles: profiles, ReplyRouter: ivnp.Hash{9}, ReplyTunnelID: 10,
		Hops: 2, CandidateLimit: 4, Lifetime: 100,
		CircuitID: func() uint32 { return 70 },
		TunnelID:  func() uint32 { nextTunnel++; return nextTunnel },
		Target:    func(uint64) ivnp.Hash { return ivnp.Hash{} },
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
	table := netdb.NewTable(ivnp.Hash{}, 8)
	table.StoreVerified(info, false, 1)
	source, err := NewNetDBInboundBuildSource(NetDBInboundBuildSourceConfig{
		Table: table, Profiles: NewPeerProfiles(PeerProfilesConfig{}), LocalRouter: ivnp.Hash{8},
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
	table := netdb.NewTable(ivnp.Hash{}, 8)
	table.StoreVerified(unusable, false, 1)
	table.StoreVerified(usable, false, 1)
	source, err := NewNetDBInboundBuildSource(NetDBInboundBuildSourceConfig{
		Table: table, Profiles: NewPeerProfiles(PeerProfilesConfig{}), LocalRouter: ivnp.Hash{8},
		Hops: 1, CandidateLimit: 8, Lifetime: 100,
		CircuitID: func() uint32 { return 70 }, TunnelID: func() uint32 { return 80 },
		Eligible: func(peer ivnp.Hash) bool { return peer == usable.Hash() },
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

func verifiedX25519Router(t *testing.T, marker byte) netdb.RouterInfo {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = marker
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	identity := make([]byte, ivnp.IdentityBaseLength+ivnp.CertificateHeader+4)
	identity[0] = marker
	copy(identity[ivnp.IdentityBaseLength-32:ivnp.IdentityBaseLength], public)
	identity[ivnp.IdentityBaseLength] = byte(ivnp.CertificateKey)
	binary.BigEndian.PutUint16(identity[ivnp.IdentityBaseLength+1:], 4)
	binary.BigEndian.PutUint16(identity[ivnp.IdentityBaseLength+3:], uint16(ivnp.SigningEdDSASHA512Ed25519))
	binary.BigEndian.PutUint16(identity[ivnp.IdentityBaseLength+5:], uint16(ivnp.CryptoX25519))
	unsigned := make([]byte, len(identity)+8+1+1+2)
	copy(unsigned, identity)
	binary.BigEndian.PutUint64(unsigned[len(identity):], 1)
	// The final address count, peer count, and empty mapping are already zero.
	signature := ed25519.Sign(private, unsigned)
	info, err := netdb.ParseRouterInfo(append(unsigned, signature...))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestNetDBBuildSourcesLimitClosestCandidatesBeforeProfileRanking(t *testing.T) {
	table := netdb.NewTable(ivnp.Hash{}, 8)
	for marker := byte(1); marker <= 3; marker++ {
		table.StoreVerified(verifiedX25519Router(t, marker), false, 1)
	}
	target := ivnp.Hash{}
	all := table.ClosestInto(make([]netdb.RouterRef, table.Len()), target)
	outside := all[2].Hash
	profiles := NewPeerProfiles(PeerProfilesConfig{Window: 4})
	profiles.RecordSuccess(outside, 1)
	nextTunnel := uint32(100)
	outbound, err := NewNetDBOutboundBuildSource(NetDBOutboundBuildSourceConfig{
		Table: table, Profiles: profiles, ReplyRouter: ivnp.Hash{9}, ReplyTunnelID: 10,
		Hops: 1, CandidateLimit: 2, Lifetime: 100,
		CircuitID: func() uint32 { return 70 },
		TunnelID:  func() uint32 { nextTunnel++; return nextTunnel },
		Target:    func(uint64) ivnp.Hash { return target },
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
		Table: table, Profiles: profiles, LocalRouter: ivnp.Hash{8},
		Hops: 1, CandidateLimit: 2, Lifetime: 100,
		CircuitID: func() uint32 { return 71 },
		TunnelID:  func() uint32 { nextTunnel++; return nextTunnel },
		Target:    func(uint64) ivnp.Hash { return target },
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

func TestNetDBBuildSourcePrefersConfiguredVerifiedBootstrapPeers(t *testing.T) {
	table := netdb.NewTable(ivnp.Hash{}, 8)
	ordinary := verifiedX25519Router(t, 1)
	preferred := verifiedX25519Router(t, 2)
	table.StoreVerified(ordinary, false, 1)
	table.StoreVerified(preferred, false, 1)
	source, err := NewNetDBInboundBuildSource(NetDBInboundBuildSourceConfig{
		Table: table, Profiles: NewPeerProfiles(PeerProfilesConfig{}), LocalRouter: ivnp.Hash{8},
		Hops: 1, PreferredPeers: []ivnp.Hash{preferred.Hash()}, CandidateLimit: 2, Lifetime: 100,
		CircuitID: func() uint32 { return 70 }, TunnelID: func() uint32 { return 80 },
	})
	if err != nil {
		t.Fatal(err)
	}
	build, err := source.NextInbound(context.Background(), 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(build.Hops) != 1 || build.Hops[0].Router != preferred.Hash() {
		t.Fatalf("selected hops = %#v, want configured bootstrap peer", build.Hops)
	}
}

func TestNetDBOutboundBuildSourceUsesNextPreferredPeerForInboundReplyGateway(t *testing.T) {
	table := netdb.NewTable(ivnp.Hash{}, 8)
	first := verifiedX25519Router(t, 1)
	second := verifiedX25519Router(t, 2)
	table.StoreVerified(first, false, 1)
	table.StoreVerified(second, false, 1)
	nextTunnel := uint32(80)
	source, err := NewNetDBOutboundBuildSource(NetDBOutboundBuildSourceConfig{
		Table: table, Profiles: NewPeerProfiles(PeerProfilesConfig{}), LocalRouter: ivnp.Hash{8},
		Hops: 1, PreferredPeers: []ivnp.Hash{first.Hash(), second.Hash()}, CandidateLimit: 2, Lifetime: 100,
		CircuitID: func() uint32 { return 70 }, TunnelID: func() uint32 { nextTunnel++; return nextTunnel },
	})
	if err != nil {
		t.Fatal(err)
	}
	build, err := source.NextOutboundForReply(context.Background(), 50, ReplyRoute{Gateway: first.Hash(), TunnelID: 90})
	if err != nil {
		t.Fatal(err)
	}
	if len(build.Hops) != 1 || build.Hops[0].Router != second.Hash() {
		t.Fatalf("selected hops = %#v, want second configured peer", build.Hops)
	}
}

func TestNetDBBuildSourcesProbePreferredPeersAfterProfileQuarantine(t *testing.T) {
	table := netdb.NewTable(ivnp.Hash{}, 8)
	first := verifiedX25519Router(t, 1)
	second := verifiedX25519Router(t, 2)
	ordinary := verifiedX25519Router(t, 3)
	table.StoreVerified(first, false, 1)
	table.StoreVerified(second, false, 1)
	table.StoreVerified(ordinary, false, 1)
	profiles := NewPeerProfiles(PeerProfilesConfig{Window: 4})
	profiles.Record(first.Hash(), Observation{Kind: BuildObservation})
	profiles.Record(second.Hash(), Observation{Kind: BuildObservation})
	preferred := []ivnp.Hash{first.Hash(), second.Hash()}
	nextTunnel := uint32(80)
	inbound, err := NewNetDBInboundBuildSource(NetDBInboundBuildSourceConfig{
		Table: table, Profiles: profiles, LocalRouter: ivnp.Hash{8},
		Hops: 1, PreferredPeers: preferred, CandidateLimit: 3, Lifetime: 100,
		CircuitID: func() uint32 { return 70 }, TunnelID: func() uint32 { nextTunnel++; return nextTunnel },
	})
	if err != nil {
		t.Fatal(err)
	}
	inboundBuild, err := inbound.NextInbound(context.Background(), 50, 0)
	if err != nil || len(inboundBuild.Hops) != 1 || inboundBuild.Hops[0].Router != first.Hash() {
		t.Fatalf("inbound recovery build = %#v, %v", inboundBuild, err)
	}
	inboundBuild, err = inbound.NextInbound(context.Background(), 51, 0)
	if err != nil || len(inboundBuild.Hops) != 1 || inboundBuild.Hops[0].Router != ordinary.Hash() {
		t.Fatalf("inbound quarantined fallback build = %#v, %v", inboundBuild, err)
	}
	outbound, err := NewNetDBOutboundBuildSource(NetDBOutboundBuildSourceConfig{
		Table: table, Profiles: profiles, LocalRouter: ivnp.Hash{8},
		Hops: 1, PreferredPeers: preferred, CandidateLimit: 3, Lifetime: 100,
		CircuitID: func() uint32 { return 71 }, TunnelID: func() uint32 { nextTunnel++; return nextTunnel },
	})
	if err != nil {
		t.Fatal(err)
	}
	outboundBuild, err := outbound.NextOutboundForReply(context.Background(), 50, ReplyRoute{Gateway: first.Hash(), TunnelID: 90})
	if err != nil || len(outboundBuild.Hops) != 1 || outboundBuild.Hops[0].Router != second.Hash() {
		t.Fatalf("outbound recovery build = %#v, %v", outboundBuild, err)
	}
	outboundBuild, err = outbound.NextOutboundForReply(context.Background(), 51, ReplyRoute{Gateway: first.Hash(), TunnelID: 90})
	if err != nil || len(outboundBuild.Hops) != 1 || outboundBuild.Hops[0].Router != ordinary.Hash() {
		t.Fatalf("outbound quarantined fallback build = %#v, %v", outboundBuild, err)
	}
}

func TestNetDBBuildSourceRetainsPreferredPeerOutsideRoutingKBucket(t *testing.T) {
	local := ivnp.Hash{8}
	table := netdb.NewTable(local, 5)
	preferred := verifiedX25519Router(t, 1)
	table.StoreVerified(preferred, false, 1)
	source, err := NewNetDBInboundBuildSource(NetDBInboundBuildSourceConfig{
		Table: table, Profiles: NewPeerProfiles(PeerProfilesConfig{}), LocalRouter: local,
		Hops: 1, PreferredPeers: []ivnp.Hash{preferred.Hash()}, CandidateLimit: 2, Lifetime: 100,
		CircuitID: func() uint32 { return 70 }, TunnelID: func() uint32 { return 80 },
	})
	if err != nil {
		t.Fatal(err)
	}
	for seed := byte(2); seed != 0; seed++ {
		table.StoreVerified(verifiedX25519Router(t, seed), false, 2)
	}
	if _, ok := table.Get(preferred.Hash()); !ok {
		t.Fatal("independent RouterInfo store discarded preferred peer")
	}
	build, err := source.NextInbound(context.Background(), 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(build.Hops) != 1 || build.Hops[0].Router != preferred.Hash() {
		t.Fatalf("selected hops = %#v, want retained preferred peer", build.Hops)
	}
}
