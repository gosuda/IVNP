package overlay

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

func testHost(t *testing.T, topology Topology) *Host {
	t.Helper()
	host, err := NewHost(HostConfig{Topology: topology})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { host.Close() })
	return host
}

func nativeFabric() FabricConfig {
	return FabricConfig{
		Kind:          ContextNativeI2P,
		IdentityRef:   "native-router",
		StateDir:      "state-native",
		Participation: ParticipationWarm,
	}
}

func ivnpFabric() FabricConfig {
	return FabricConfig{
		Kind:        ContextIVNP,
		Descriptor:  testDescriptor(),
		IdentityRef: "ivnp-router",
		StateDir:    "state-ivnp",
	}
}

func TestHostContextIsolation(t *testing.T) {
	host := testHost(t, TopologyPublicDualStack)
	ctx := context.Background()
	native, err := host.OpenFabric(ctx, nativeFabric())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.OpenFabric(ctx, nativeFabric()); err == nil {
		t.Fatal("second native context admitted")
	}
	fast, err := host.OpenFabric(ctx, ivnpFabric())
	if err != nil {
		t.Fatal(err)
	}
	shared := ivnpFabric()
	shared.IdentityRef = "native-router"
	shared.StateDir = "state-ivnp-2"
	if _, err := host.OpenFabric(ctx, shared); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("identity reuse admitted: %v", err)
	}
	fabric, netID, router, id := fast.Identity()
	if fabric != PublicFastFabricID || netID != 77 || id == 0 || router == (RouterID{}) {
		t.Fatalf("context identity: %v %v %v", fabric, netID, id)
	}
	if _, err := fast.NativePublic(); !errors.Is(err, CodeContextScopeMismatch) {
		t.Fatalf("native boundary on ivnp context: %v", err)
	}
	fabric2, netID2, _, _ := native.Identity()
	if netID2 != WireNetworkIDPublicI2P {
		t.Fatalf("native netid %v", netID2)
	}
	_ = fabric2
}

func TestTopologyPlacement(t *testing.T) {
	ctx := context.Background()
	host := testHost(t, TopologyIsolated)
	if _, err := host.OpenFabric(ctx, nativeFabric()); !errors.Is(err, CodeContextScopeMismatch) {
		t.Fatalf("native context in isolated topology: %v", err)
	}
	host2 := testHost(t, TopologyNativeI2P)
	if _, err := host2.OpenFabric(ctx, ivnpFabric()); !errors.Is(err, CodeContextScopeMismatch) {
		t.Fatalf("ivnp context in native topology: %v", err)
	}
}

func TestDescriptorValidation(t *testing.T) {
	d := testDescriptor()
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []WireNetworkID{0, 2, 15, 255} {
		d.NetworkID = bad
		if err := d.Validate(); err == nil {
			t.Fatalf("netid %d admitted", bad)
		}
	}
	d = testDescriptor()
	d.Production = true
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	d.NetworkID = IllustrativeNetworkID
	if err := d.Validate(); err == nil {
		t.Fatal("production descriptor on illustrative netid admitted")
	}
	d.NetworkID = 77
	d.Reviewed = false
	if err := d.Validate(); err == nil {
		t.Fatal("unreviewed production descriptor admitted")
	}
}

func openRealm(t *testing.T, host *Host, cfg RealmConfig) *Realm {
	t.Helper()
	r, err := host.OpenRealm(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRealmAdmissionRules(t *testing.T) {
	ctx := context.Background()
	host := testHost(t, TopologyPublicDualStack)
	native, _ := host.OpenFabric(ctx, nativeFabric())
	fast, _ := host.OpenFabric(ctx, ivnpFabric())
	bound := []ContextID{native.id, fast.id}

	base := RealmConfig{
		ID:          PublicFastRealmID,
		Contexts:    bound,
		Admission:   AdmissionOpen,
		Discovery:   DiscoveryHedged,
		Privacy:     PrivacyExplicitDirect,
		Routing:     RoutingOpportunistic,
		Publication: PublicationLS2,
		Prefix:      PrefixPolicy{Mode: PrefixBestEffort, IPv4Prefix: 24, IPv6Prefix: 48, MaxPerPrefix: 4},
	}
	if _, err := host.OpenRealm(base); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("open admission without acknowledgement: %v", err)
	}
	base.AcknowledgeOpen = true
	r := openRealm(t, host, base)
	if r.Assurance() != SybilUnboundedOpen {
		t.Fatal("open realm must report unbounded sybil assurance")
	}

	cred := base
	cred.ID = RealmID{9}
	cred.Admission = AdmissionCredential
	if _, err := host.OpenRealm(cred); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("credential realm without providers: %v", err)
	}

	confined := base
	confined.ID = RealmID{10}
	confined.Privacy = PrivacyPrivateConfined
	confined.Routing = RoutingOverlayRouted
	confined.Discovery = DiscoveryPublicPrimary
	if _, err := host.OpenRealm(confined); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("private_confined with public discovery: %v", err)
	}
}

// stubTransport is a test TransportProvider that returns a pipe channel with a
// fixed binding.
type stubTransport struct {
	carrier string
	caps    TransportCapabilities
	binding ChannelScope
	key     [32]byte
	delay   time.Duration
	err     error
}

func (s *stubTransport) Carrier() string                     { return s.carrier }
func (s *stubTransport) Capabilities() TransportCapabilities { return s.caps }

func (s *stubTransport) Setup(ctx context.Context, c RouteCandidate, scope ChannelScope, admission *AdmissionRequest) (Channel, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	binding := s.binding
	if binding == (ChannelScope{}) {
		binding = scope
	}
	return &stubChannel{binding: binding, key: s.key}, nil
}

type stubChannel struct {
	binding ChannelScope
	key     [32]byte
}

func (c *stubChannel) Binding() (ChannelScope, [32]byte) { return c.binding, c.key }
func (c *stubChannel) Read([]byte) (int, error)          { return 0, nil }
func (c *stubChannel) Write(b []byte) (int, error)       { return len(b), nil }
func (c *stubChannel) Close() error                      { return nil }
func (c *stubChannel) LocalAddr() net.Addr               { return nil }
func (c *stubChannel) RemoteAddr() net.Addr              { return nil }
func (c *stubChannel) SetDeadline(time.Time) error       { return nil }
func (c *stubChannel) SetReadDeadline(time.Time) error   { return nil }
func (c *stubChannel) SetWriteDeadline(time.Time) error  { return nil }

type stubSessions struct{}

func (stubSessions) Open(ctx context.Context, channel Channel, target ServiceTarget) (Session, error) {
	return stubSession{}, nil
}

type stubSession struct{}

func (stubSession) Protocol() EndpointProtocol      { return EndpointProtocolIVNPStream }
func (stubSession) Resume() (ResumeContract, error) { return ResumeContract{}, nil }
func (stubSession) Close() error                    { return nil }

// signedLS2 builds a real signed LS2 payload for resolver tests.
func signedLS2(t *testing.T, dest *foundation.LocalDestination, options []foundation.MappingEntry) []byte {
	t.Helper()
	pub := uint32(time.Now().Unix())
	return signedLS2At(t, dest, options, pub, 600, pub+600)
}

// signedLS2At builds a signed LS2 with explicit header and lease lifetimes so
// tests can separate record freshness from usable-lease freshness.
func signedLS2At(t *testing.T, dest *foundation.LocalDestination, options []foundation.MappingEntry, pub uint32, headerExpires uint16, leaseEnd uint32) []byte {
	t.Helper()
	identity, err := dest.Identity()
	if err != nil {
		t.Fatal(err)
	}
	mappingLen, err := foundation.MappingEncodedLen(options)
	if err != nil {
		t.Fatal(err)
	}
	var buf []byte
	buf = append(buf, identity.Bytes()...)
	buf = binary.BigEndian.AppendUint32(buf, pub)
	buf = binary.BigEndian.AppendUint16(buf, headerExpires)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	mapping := make([]byte, mappingLen)
	if _, err := foundation.MarshalMappingTo(mapping, options); err != nil {
		t.Fatal(err)
	}
	buf = append(buf, mapping...)
	buf = append(buf, 1)
	buf = binary.BigEndian.AppendUint16(buf, uint16(foundation.CryptoX25519))
	buf = binary.BigEndian.AppendUint16(buf, 32)
	buf = append(buf, make([]byte, 32)...)
	buf = append(buf, 1)
	lease := make([]byte, 40)
	gateway := foundation.Hash{9}
	copy(lease, gateway[:])
	binary.BigEndian.PutUint32(lease[32:], 77)
	binary.BigEndian.PutUint32(lease[36:], leaseEnd)
	buf = append(buf, lease...)
	signed := append([]byte{byte(foundation.I2NPStoreLeaseSet2)}, buf...)
	sig, err := dest.Sign(signed)
	if err != nil {
		t.Fatal(err)
	}
	return append(buf, sig...)
}

// signedRI builds a real signed RouterInfo payload for resolver tests:
// identity || published(ms) || no addresses || no peers || options || sig.
func signedRI(t *testing.T, dest *foundation.LocalDestination, publishedMillis uint64, options []foundation.MappingEntry) []byte {
	t.Helper()
	identity, err := dest.Identity()
	if err != nil {
		t.Fatal(err)
	}
	mappingLen, err := foundation.MappingEncodedLen(options)
	if err != nil {
		t.Fatal(err)
	}
	var buf []byte
	buf = append(buf, identity.Bytes()...)
	buf = binary.BigEndian.AppendUint64(buf, publishedMillis)
	buf = append(buf, 0) // address count
	buf = append(buf, 0) // peer count
	mapping := make([]byte, mappingLen)
	if _, err := foundation.MarshalMappingTo(mapping, options); err != nil {
		t.Fatal(err)
	}
	buf = append(buf, mapping...)
	sig, err := dest.Sign(buf)
	if err != nil {
		t.Fatal(err)
	}
	return append(buf, sig...)
}
