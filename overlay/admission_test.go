package overlay

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

// stubSigner is a non-exportable signing handle for tests.
type stubSigner [32]byte

func (s stubSigner) Public() [32]byte { return [32]byte(s) }
func (s stubSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(ed25519.NewKeyFromSeed(s[:]), msg), nil
}

type stubIdentity struct {
	proof     IdentityProof
	signer    Signer
	issuerKey ed25519.PrivateKey
	err       error
}

func (s *stubIdentity) LocalIdentity(ctx context.Context, realm RealmID) (IdentityProof, Signer, error) {
	if s.err != nil {
		return IdentityProof{}, nil, s.err
	}
	proof := s.proof
	proof.Realm = realm
	if s.issuerKey != nil {
		proof.Credential = signTestCredential(s.issuerKey, proof)
	}
	return proof, s.signer, nil
}

type stubTrust struct {
	state TrustState
	err   error
}

func (s *stubTrust) Trust(ctx context.Context, realm RealmID) (TrustState, error) {
	if s.err != nil {
		return TrustState{}, s.err
	}
	return s.state, nil
}

// Test credential documents bind membership claims to an issuer signature.
// The wire shape is a test fixture: realm || member || slot || issuer ||
// notAfter || channelKey, followed by the issuer's ed25519 signature.
var (
	testCAKey    = testIssuerKey(0xca)
	testRogueKey = testIssuerKey(0x99)
)

func testIssuerKey(b byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b
	}
	return ed25519.NewKeyFromSeed(seed)
}

func testCredentialClaims(p IdentityProof) []byte {
	out := make([]byte, 0, 128)
	out = append(out, p.Realm[:]...)
	out = append(out, p.Member[:]...)
	out = binary.BigEndian.AppendUint64(out, p.Slot)
	out = binary.BigEndian.AppendUint16(out, uint16(len(p.Issuer)))
	out = append(out, p.Issuer...)
	out = binary.BigEndian.AppendUint64(out, uint64(p.NotAfter))
	return append(out, p.ChannelKey[:]...)
}

func signTestCredential(key ed25519.PrivateKey, p IdentityProof) []byte {
	claims := testCredentialClaims(p)
	return append(claims, ed25519.Sign(key, claims)...)
}

// stubVerifier is the test CredentialVerifier: it parses the document, then
// checks the issuer signature under the registered issuer key. Only the
// document's claims are returned — nothing outside it is consulted.
type stubVerifier struct {
	keys map[string]ed25519.PublicKey
	err  error
}

func (v *stubVerifier) VerifyCredential(ctx context.Context, realm RealmID, credential []byte) (IdentityProof, error) {
	if v.err != nil {
		return IdentityProof{}, v.err
	}
	claims, err := parseTestCredential(credential, v.keys)
	if err != nil {
		return IdentityProof{}, err
	}
	claims.Credential = credential
	return claims, nil
}

var (
	errCredentialTruncated = errors.New("credential truncated")
	errCredentialMalformed = errors.New("credential malformed")
	errUnknownIssuerKey    = errors.New("unknown issuer key")
	errCredentialSignature = errors.New("credential signature invalid")
)

func parseTestCredential(credential []byte, keys map[string]ed25519.PublicKey) (IdentityProof, error) {
	var p IdentityProof
	body := len(credential) - ed25519.SignatureSize
	if body < 32+32+8+2+8+32 {
		return p, errCredentialTruncated
	}
	claims, sig := credential[:body], credential[body:]
	copy(p.Realm[:], claims[:32])
	copy(p.Member[:], claims[32:64])
	p.Slot = binary.BigEndian.Uint64(claims[64:72])
	n := int(binary.BigEndian.Uint16(claims[72:74]))
	if len(claims) != 74+n+8+32 {
		return p, errCredentialMalformed
	}
	p.Issuer = string(claims[74 : 74+n])
	p.NotAfter = int64(binary.BigEndian.Uint64(claims[74+n : 82+n]))
	copy(p.ChannelKey[:], claims[82+n:114+n])
	key, ok := keys[p.Issuer]
	if !ok {
		return p, errUnknownIssuerKey
	}
	if !ed25519.Verify(key, claims, sig) {
		return p, errCredentialSignature
	}
	return p, nil
}

type stubLease struct {
	key        []byte
	epoch      uint64
	released   atomic.Int32
	releasedCh chan struct{}
	releaseOne sync.Once
}

func newStubLease(key []byte, epoch uint64) *stubLease {
	return &stubLease{key: key, epoch: epoch, releasedCh: make(chan struct{})}
}

func (l *stubLease) Key() []byte   { return l.key }
func (l *stubLease) Epoch() uint64 { return l.epoch }
func (l *stubLease) Release() error {
	l.released.Add(1)
	l.releaseOne.Do(func() { close(l.releasedCh) })
	return nil
}

type stubSecrets struct {
	lease *stubLease
	err   error
}

func (s *stubSecrets) Lease(ctx context.Context, realm RealmID, purpose KeyPurpose) (SecretLease, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.lease, nil
}

type stubEnroll struct {
	proof IdentityProof
	err   error
}

func (s *stubEnroll) Enroll(ctx context.Context, realm RealmID, op EnrollmentOp) (IdentityProof, error) {
	if s.err != nil {
		return IdentityProof{}, s.err
	}
	return s.proof, nil
}

type stubAuthorizer struct {
	allow bool
	calls atomic.Int32
}

func (s *stubAuthorizer) Authorize(ctx context.Context, peer PeerRef, op string) (bool, error) {
	s.calls.Add(1)
	return s.allow, nil
}

// memberChannel is a Channel carrying peer credential evidence.
type memberChannel struct {
	stubChannel
	proof    IdentityProof
	hasProof bool
}

func (c *memberChannel) PeerMembership() (IdentityProof, bool) {
	return c.proof, c.hasProof
}

// credTransport captures the admission request and returns a membership
// channel bound to the requested scope.
type credTransport struct {
	carrier   string
	key       [32]byte
	proof     IdentityProof
	hasProof  bool
	plain     bool // return a channel that exchanged no credential material
	onSetup   func()
	admission *AdmissionRequest
}

func (s *credTransport) Carrier() string { return s.carrier }
func (s *credTransport) Capabilities() TransportCapabilities {
	return TransportCapabilities{Exporter: true, DirectBinding: true}
}
func (s *credTransport) Setup(ctx context.Context, c RouteCandidate, scope ChannelScope, admission *AdmissionRequest) (Channel, error) {
	s.admission = admission
	if s.onSetup != nil {
		s.onSetup()
	}
	if s.plain {
		return &stubChannel{binding: scope, key: s.key}, nil
	}
	return &memberChannel{stubChannel: stubChannel{binding: scope, key: s.key}, proof: s.proof, hasProof: s.hasProof}, nil
}

// isolatedHost builds an isolated host with one private IVNP context.
func isolatedHost(t *testing.T) (*Host, *NetworkContext) {
	t.Helper()
	host := testHost(t, TopologyIsolated)
	fast, err := host.OpenFabric(context.Background(), FabricConfig{
		Kind: ContextIVNP, Descriptor: privateDescriptor(),
		IdentityRef: "ivnp-router", StateDir: "state-ivnp",
	})
	if err != nil {
		t.Fatal(err)
	}
	return host, fast
}

// openAdmissionRealm opens a local-only private-confined realm under the
// given admission mode; providers must be registered first.
func openAdmissionRealm(t *testing.T, host *Host, fast *NetworkContext, id RealmID, admission AdmissionMode) *Realm {
	t.Helper()
	realm, err := host.OpenRealm(RealmConfig{
		ID: id, Contexts: []ContextID{fast.id},
		Admission: admission, AcknowledgeOpen: admission == AdmissionOpen,
		Discovery: DiscoveryLocalOnly, Privacy: PrivacyPrivateConfined,
		Routing: RoutingOverlayDirect, Publication: PublicationNone,
		Prefix: PrefixPolicy{Mode: PrefixDisabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	return realm
}

var testChannelKey = [32]byte{0xaa}

// seedDirectCandidate installs one local direct candidate for the realm.
func seedDirectCandidate(t *testing.T, nctx *NetworkContext, realm RealmID, endpoint EndpointID) {
	t.Helper()
	contact := Endpoint{Transport: "mem", Address: netip.MustParseAddrPort("192.0.2.7:4433")}
	err := nctx.InsertCandidate(foundation.Hash(endpoint), RouteCandidate{
		Endpoint: endpoint, Fabric: privateDescriptor().ID, NetworkID: 88,
		Realm: realm, Class: RouteDirect, Carrier: "mem",
		ContactKey: testChannelKey, Contact: &contact,
		NotAfter: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func confinedService(t *testing.T, realm *Realm) *Service {
	t.Helper()
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyPrivateConfined,
		Routing: RoutingOverlayDirect, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func confinedPolicy() DialPolicy {
	policy := testPolicy(privateDescriptor().ID)
	policy.RouteClasses = []RouteClass{RouteDirect}
	policy.Privacy = PrivacyPrivateConfined
	return policy
}

func registerCredentialProviders(t *testing.T, host *Host, trust TrustState) {
	t.Helper()
	future := time.Now().Add(time.Hour).Unix()
	local := IdentityProof{
		Member: MemberID{2}, Slot: 2, Issuer: "ca", NotAfter: future,
		ChannelKey: [32]byte{9},
	}
	if err := host.RegisterProvider(&stubIdentity{
		proof:     local,
		signer:    stubSigner{1},
		issuerKey: testCAKey,
	}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(&stubTrust{state: trust}); err != nil {
		t.Fatal(err)
	}
	// The verifier knows both issuer keys so that a correctly-signed "rogue"
	// credential still fails the trust-side issuer check, distinct from a
	// signature failure.
	if err := host.RegisterProvider(&stubVerifier{keys: map[string]ed25519.PublicKey{
		"ca":    testCAKey.Public().(ed25519.PublicKey),
		"rogue": testRogueKey.Public().(ed25519.PublicKey),
	}}); err != nil {
		t.Fatal(err)
	}
}

// TestCredentialAdmissionPresentsMaterial: a credential realm passes the
// verified local proof to the transport and verifies the peer's presented
// credential against the trust snapshot before the channel activates. Only
// the document's verified claims are consulted: deliberately wrong hint
// fields on the presented proof must not affect admission.
func TestCredentialAdmissionPresentsMaterial(t *testing.T) {
	host, fast := isolatedHost(t)
	future := time.Now().Add(time.Hour).Unix()
	registerCredentialProviders(t, host, TrustState{
		Generation: 1, Issuers: []string{"ca"}, MaxActiveSlots: 8, NotAfter: future,
	})
	realm := openAdmissionRealm(t, host, fast, RealmID{5}, AdmissionCredential)
	endpoint := EndpointID{0x42}
	seedDirectCandidate(t, fast, realm.realmID(), endpoint)
	claims := IdentityProof{
		Realm: realm.realmID(), Member: MemberID{1}, Slot: 1,
		Issuer: "ca", NotAfter: future, ChannelKey: testChannelKey,
	}
	proof := IdentityProof{
		Realm: RealmID{0xee}, Member: MemberID{0xee}, Issuer: "nobody",
		ChannelKey: [32]byte{0xee}, // hints contradict the signed document
		Credential: signTestCredential(testCAKey, claims),
	}
	transport := &credTransport{
		carrier: "mem", key: testChannelKey, hasProof: true, proof: proof,
	}
	if err := host.RegisterProvider(transport); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	svc := confinedService(t, realm)
	conn, err := svc.Dial(context.Background(),
		ServiceTarget{Endpoint: EndpointRef{ID: endpoint}, Port: 47001}, confinedPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if transport.admission == nil || transport.admission.Credential == nil || transport.admission.Signer == nil {
		t.Fatalf("setup received no admission material: %+v", transport.admission)
	}
	if transport.admission.Realm != realm.realmID() {
		t.Fatalf("admission realm %v", transport.admission.Realm)
	}
	if len(transport.admission.Credential.Credential) == 0 {
		t.Fatal("local admission material carries no credential document")
	}
}

// TestCredentialRealmRequiresVerifier: credential admission cannot open
// without a registered verifier — without one there is no fail-closed path.
func TestCredentialRealmRequiresVerifier(t *testing.T) {
	host, fast := isolatedHost(t)
	future := time.Now().Add(time.Hour).Unix()
	if err := host.RegisterProvider(&stubIdentity{
		proof:  IdentityProof{Member: MemberID{2}, Issuer: "ca", NotAfter: future},
		signer: stubSigner{1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(&stubTrust{state: TrustState{
		Issuers: []string{"ca"}, NotAfter: future,
	}}); err != nil {
		t.Fatal(err)
	}
	_, err := host.OpenRealm(RealmConfig{
		ID: RealmID{14}, Contexts: []ContextID{fast.id},
		Admission: AdmissionCredential,
		Discovery: DiscoveryLocalOnly, Privacy: PrivacyPrivateConfined,
		Routing: RoutingOverlayDirect, Publication: PublicationNone,
		Prefix: PrefixPolicy{Mode: PrefixDisabled},
	})
	if !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("credential realm without verifier: %v", err)
	}
}

// TestCredentialAdmissionDenials: each membership violation fails the dial
// closed; no provider flag substitutes for evidence. The peer's presented
// hint fields are never consulted — every signed case presents a document
// whose verified claims are checked against the realm and trust snapshot.
func TestCredentialAdmissionDenials(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	cases := []struct {
		name       string
		trust      TrustState
		claims     IdentityProof // signed into the presented document
		signer     ed25519.PrivateKey
		doc        []byte // overrides the signed document when set
		noEvidence bool   // present a channel carrying no credential material
		plain      bool
		want       error
	}{
		{
			name:  "foreign realm credential",
			trust: TrustState{Issuers: []string{"ca"}, MaxActiveSlots: 8, NotAfter: future},
			claims: IdentityProof{
				Realm: RealmID{9}, Member: MemberID{1}, Slot: 1,
				Issuer: "ca", NotAfter: future, ChannelKey: testChannelKey,
			},
			want: CodeRealmMismatch,
		},
		{
			name:  "expired credential",
			trust: TrustState{Issuers: []string{"ca"}, MaxActiveSlots: 8, NotAfter: future},
			claims: IdentityProof{
				Member: MemberID{1}, Slot: 1, Issuer: "ca",
				NotAfter: time.Now().Add(-time.Hour).Unix(), ChannelKey: testChannelKey,
			},
			want: CodeCredentialExpired,
		},
		{
			name:  "revoked member",
			trust: TrustState{Issuers: []string{"ca"}, Revoked: []MemberID{{1}}, MaxActiveSlots: 8, NotAfter: future},
			claims: IdentityProof{
				Member: MemberID{1}, Slot: 1, Issuer: "ca",
				NotAfter: future, ChannelKey: testChannelKey,
			},
			want: CodeMembershipDenied,
		},
		{
			name:  "untrusted issuer with valid signature",
			trust: TrustState{Issuers: []string{"ca"}, MaxActiveSlots: 8, NotAfter: future},
			claims: IdentityProof{
				Member: MemberID{1}, Slot: 1, Issuer: "rogue",
				NotAfter: future, ChannelKey: testChannelKey,
			},
			signer: testRogueKey,
			want:   CodeMembershipDenied,
		},
		{
			name:  "forged signature under claimed issuer",
			trust: TrustState{Issuers: []string{"ca"}, MaxActiveSlots: 8, NotAfter: future},
			claims: IdentityProof{
				Member: MemberID{1}, Slot: 1, Issuer: "ca",
				NotAfter: future, ChannelKey: testChannelKey,
			},
			signer: testRogueKey,
			want:   CodeMembershipDenied,
		},
		{
			name:  "malformed document",
			trust: TrustState{Issuers: []string{"ca"}, MaxActiveSlots: 8, NotAfter: future},
			doc:   []byte("not a credential"),
			want:  CodeMembershipDenied,
		},
		{
			name:  "empty issuer trust list",
			trust: TrustState{MaxActiveSlots: 8, NotAfter: future},
			claims: IdentityProof{
				Member: MemberID{1}, Slot: 1, Issuer: "ca",
				NotAfter: future, ChannelKey: testChannelKey,
			},
			want: CodeMembershipDenied,
		},
		{
			name:  "slot bound exceeded",
			trust: TrustState{Issuers: []string{"ca"}, MaxActiveSlots: 1, NotAfter: future},
			claims: IdentityProof{
				Member: MemberID{1}, Slot: 1, Issuer: "ca",
				NotAfter: future, ChannelKey: testChannelKey,
			},
			want: CodeMembershipDenied,
		},
		{
			name:  "credential does not bind the proven channel key",
			trust: TrustState{Issuers: []string{"ca"}, MaxActiveSlots: 8, NotAfter: future},
			claims: IdentityProof{
				Member: MemberID{1}, Slot: 1, Issuer: "ca",
				NotAfter: future, ChannelKey: [32]byte{0xbb},
			},
			want: CodeMembershipDenied,
		},
		{
			name:       "no evidence presented",
			trust:      TrustState{Issuers: []string{"ca"}, MaxActiveSlots: 8, NotAfter: future},
			noEvidence: true,
			want:       CodeMembershipDenied,
		},
		{
			name:  "carrier exchanged nothing",
			trust: TrustState{Issuers: []string{"ca"}, MaxActiveSlots: 8, NotAfter: future},
			plain: true,
			want:  CodeMembershipDenied,
		},
		{
			name:  "stale trust snapshot",
			trust: TrustState{Issuers: []string{"ca"}, MaxActiveSlots: 8, NotAfter: time.Now().Add(-time.Minute).Unix()},
			claims: IdentityProof{
				Member: MemberID{1}, Slot: 1, Issuer: "ca",
				NotAfter: future, ChannelKey: testChannelKey,
			},
			want: CodeTrustStale,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, fast := isolatedHost(t)
			registerCredentialProviders(t, host, tc.trust)
			realm := openAdmissionRealm(t, host, fast, RealmID{5}, AdmissionCredential)
			endpoint := EndpointID{0x43}
			seedDirectCandidate(t, fast, realm.realmID(), endpoint)
			claims := tc.claims
			if claims.Realm == (RealmID{}) {
				claims.Realm = realm.realmID()
			}
			signer := tc.signer
			if signer == nil {
				signer = testCAKey
			}
			doc := tc.doc
			if doc == nil {
				doc = signTestCredential(signer, claims)
			}
			if err := host.RegisterProvider(&credTransport{
				carrier: "mem", key: testChannelKey,
				proof:    IdentityProof{Credential: doc},
				hasProof: !tc.noEvidence, plain: tc.plain,
			}); err != nil {
				t.Fatal(err)
			}
			if err := host.RegisterProvider(stubSessions{}); err != nil {
				t.Fatal(err)
			}
			svc := confinedService(t, realm)
			_, err := svc.Dial(context.Background(),
				ServiceTarget{Endpoint: EndpointRef{ID: endpoint}, Port: 47001}, confinedPolicy())
			if !errors.Is(err, tc.want) {
				t.Fatalf("dial error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestCredentialDigestBinding: a resolved candidate that advertises a
// credential digest accepts only the document that hashes to it.
func TestCredentialDigestBinding(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	claims := func(realm RealmID) IdentityProof {
		return IdentityProof{
			Realm: realm, Member: MemberID{1}, Slot: 1, Issuer: "ca",
			NotAfter: future, ChannelKey: testChannelKey,
		}
	}
	seed := func(t *testing.T, fast *NetworkContext, realm RealmID, digest *[32]byte) {
		t.Helper()
		contact := Endpoint{Transport: "mem", Address: netip.MustParseAddrPort("192.0.2.7:4433")}
		err := fast.InsertCandidate(foundation.Hash(EndpointID{0x47}), RouteCandidate{
			Endpoint: EndpointID{0x47}, Fabric: privateDescriptor().ID, NetworkID: 88,
			Realm: realm, Class: RouteDirect, Carrier: "mem",
			ContactKey: testChannelKey, Contact: &contact, CredentialDigest: digest,
			NotAfter: time.Now().Add(time.Hour).Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	dial := func(t *testing.T, digest *[32]byte, doc []byte) error {
		t.Helper()
		host, fast := isolatedHost(t)
		registerCredentialProviders(t, host, TrustState{
			Issuers: []string{"ca"}, MaxActiveSlots: 8, NotAfter: future,
		})
		realm := openAdmissionRealm(t, host, fast, RealmID{5}, AdmissionCredential)
		seed(t, fast, realm.realmID(), digest)
		if err := host.RegisterProvider(&credTransport{
			carrier: "mem", key: testChannelKey, hasProof: true,
			proof: IdentityProof{Credential: doc},
		}); err != nil {
			t.Fatal(err)
		}
		if err := host.RegisterProvider(stubSessions{}); err != nil {
			t.Fatal(err)
		}
		svc := confinedService(t, realm)
		conn, err := svc.Dial(context.Background(),
			ServiceTarget{Endpoint: EndpointRef{ID: EndpointID{0x47}}, Port: 47001}, confinedPolicy())
		if err == nil {
			conn.Close()
		}
		return err
	}

	doc := signTestCredential(testCAKey, claims(RealmID{5}))
	right := sha256.Sum256(doc)
	wrong := sha256.Sum256([]byte("another document"))
	if err := dial(t, &wrong, doc); !errors.Is(err, CodeMembershipDenied) {
		t.Fatalf("digest mismatch admitted: %v", err)
	}
	if err := dial(t, &right, doc); err != nil {
		t.Fatalf("digest-bound credential rejected: %v", err)
	}
}

// TestPSKAdmissionLeasesAndReleases: psk admission leases a purpose-scoped key
// for setup and the lease is released once every attempt finishes.
func TestPSKAdmissionLeasesAndReleases(t *testing.T) {
	host, fast := isolatedHost(t)
	lease := newStubLease([]byte("network-key-material"), 3)
	if err := host.RegisterProvider(&stubSecrets{lease: lease}); err != nil {
		t.Fatal(err)
	}
	realm := openAdmissionRealm(t, host, fast, RealmID{5}, AdmissionPSK)
	endpoint := EndpointID{0x44}
	seedDirectCandidate(t, fast, realm.realmID(), endpoint)
	transport := &credTransport{carrier: "mem", key: testChannelKey}
	if err := host.RegisterProvider(transport); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	svc := confinedService(t, realm)
	conn, err := svc.Dial(context.Background(),
		ServiceTarget{Endpoint: EndpointRef{ID: endpoint}, Port: 47001}, confinedPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if transport.admission == nil || len(transport.admission.NetworkKey) == 0 || transport.admission.Epoch != 3 {
		t.Fatalf("psk admission material: %+v", transport.admission)
	}
	select {
	case <-lease.releasedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("admission lease never released")
	}
}

// TestAuthorizationDeniesOpenRealm: the policy decision point can only deny;
// a denial rejects an otherwise admissible open-realm channel.
func TestAuthorizationDeniesOpenRealm(t *testing.T) {
	host, fast := isolatedHost(t)
	if err := host.RegisterProvider(&stubAuthorizer{allow: false}); err != nil {
		t.Fatal(err)
	}
	realm := openAdmissionRealm(t, host, fast, RealmID{6}, AdmissionOpen)
	endpoint := EndpointID{0x45}
	seedDirectCandidate(t, fast, realm.realmID(), endpoint)
	if err := host.RegisterProvider(&credTransport{carrier: "mem", key: testChannelKey}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	svc := confinedService(t, realm)
	_, err := svc.Dial(context.Background(),
		ServiceTarget{Endpoint: EndpointRef{ID: endpoint}, Port: 47001}, confinedPolicy())
	if !errors.Is(err, CodeMembershipDenied) {
		t.Fatalf("denied dial: %v", err)
	}
}

// resumableSession reports a negotiated contract with its fence.
type resumableSession struct{ fence uint64 }

func (s *resumableSession) Protocol() EndpointProtocol { return EndpointProtocolIVNPStream }
func (s *resumableSession) Resume() (ResumeContract, error) {
	return ResumeContract{Supported: true, FenceToken: s.fence}, nil
}
func (s *resumableSession) Close() error { return nil }

// resumableSessions resumes under the contract with a strictly newer fence.
type resumableSessions struct {
	resumeCalls atomic.Int32
	stale       bool
}

func (s *resumableSessions) Open(ctx context.Context, channel Channel, target ServiceTarget) (Session, error) {
	return &resumableSession{fence: 7}, nil
}

func (s *resumableSessions) Resume(ctx context.Context, channel Channel, target ServiceTarget, contract ResumeContract) (Session, error) {
	s.resumeCalls.Add(1)
	fence := contract.FenceToken + 1
	if s.stale {
		fence = contract.FenceToken
	}
	return &resumableSession{fence: fence}, nil
}

// openOnlySessions opens contract-bearing sessions but cannot resume them.
type openOnlySessions struct{}

func (openOnlySessions) Open(ctx context.Context, channel Channel, target ServiceTarget) (Session, error) {
	return &resumableSession{fence: 7}, nil
}

func dialForResume(t *testing.T, sessions SessionProvider) (*Service, *flakyChannel, ServiceTarget) {
	t.Helper()
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dest.ReleaseSensitive)
	presence := testPresence()
	entries, err := presence.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, entries), Provenance: ProvenancePublicNative},
	}}
	host, realm, _, _ := dualHost(t, &stubFabric{native: netdb})
	flaky := &flakyChannel{stubChannel: stubChannel{key: presence.ContactKey}}
	if err := host.RegisterProvider(&chanTransport{carrier: "tls13", ch: flaky}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(sessions); err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, flaky, ServiceTarget{
		Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)},
		Port:     47001,
	}
}

func resumePolicy() DialPolicy {
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.Failover = FailoverNegotiatedResume
	return policy
}

func losePathAfterWrite(t *testing.T, conn *Connection, flaky *flakyChannel) {
	t.Helper()
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	flaky.fail.Store(true)
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected path failure")
	}
	if conn.FailoverStatus() != ConnPathLost {
		t.Fatalf("state %v", conn.FailoverStatus())
	}
}

// TestReconnectNegotiatedResume: a proven contract is reconciled through the
// resumable provider and the successor session must advance the fence.
func TestReconnectNegotiatedResume(t *testing.T) {
	sessions := &resumableSessions{}
	svc, flaky, target := dialForResume(t, sessions)
	conn, err := svc.Dial(context.Background(), target, resumePolicy())
	if err != nil {
		t.Fatal(err)
	}
	losePathAfterWrite(t, conn, flaky)
	next, err := conn.Reconnect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if next == conn {
		t.Fatal("resume returned the failed connection")
	}
	if sessions.resumeCalls.Load() != 1 {
		t.Fatalf("resume calls %d", sessions.resumeCalls.Load())
	}
	contract, err := next.Session.Resume()
	if err != nil || contract.FenceToken != 8 {
		t.Fatalf("successor fence %+v %v", contract, err)
	}
}

// TestReconnectStaleFenceRejected: a resumed session whose fence did not
// advance is a state mismatch, never a committed resume.
func TestReconnectStaleFenceRejected(t *testing.T) {
	sessions := &resumableSessions{stale: true}
	svc, flaky, target := dialForResume(t, sessions)
	conn, err := svc.Dial(context.Background(), target, resumePolicy())
	if err != nil {
		t.Fatal(err)
	}
	losePathAfterWrite(t, conn, flaky)
	if _, err := conn.Reconnect(context.Background()); !errors.Is(err, CodeResumeStateMismatch) {
		t.Fatalf("stale fence: %v", err)
	}
}

// TestReconnectNoResumableProvider: a negotiated contract cannot be executed
// by a provider that only opens fresh sessions.
func TestReconnectNoResumableProvider(t *testing.T) {
	svc, flaky, target := dialForResume(t, openOnlySessions{})
	conn, err := svc.Dial(context.Background(), target, resumePolicy())
	if err != nil {
		t.Fatal(err)
	}
	losePathAfterWrite(t, conn, flaky)
	if _, err := conn.Reconnect(context.Background()); !errors.Is(err, CodeResumeNotSupported) {
		t.Fatalf("non-resumable provider: %v", err)
	}
}

// TestOrderSetupsIVNPFirst: native candidates always hedge behind IVNP setups.
func TestOrderSetupsIVNPFirst(t *testing.T) {
	in := []RouteCandidate{
		{Class: RouteNativeI2P, Carrier: "i2p-tunnel"},
		{Class: RouteDirect, Carrier: "tls13"},
		{Class: RouteRouted, Carrier: "routed"},
		{Class: RouteNativeI2P, Carrier: "i2p-tunnel-2"},
	}
	out := orderSetups(in)
	if out[0].Class == RouteNativeI2P || out[1].Class == RouteNativeI2P {
		t.Fatalf("native not hedged: %+v", out)
	}
	if out[2].Class != RouteNativeI2P || out[3].Class != RouteNativeI2P {
		t.Fatalf("native candidates lost: %+v", out)
	}
}

// TestDialPrefersIVNPBeforeNativeHedge: the IVNP setup launches first; the
// native setup only runs as the delayed hedge.
func TestDialPrefersIVNPBeforeNativeHedge(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	presence := testPresence()
	entries, err := presence.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, entries), Provenance: ProvenancePublicNative},
	}}
	host, realm, _, _ := dualHost(t, &stubFabric{native: netdb})
	nativeEntered := make(chan struct{}, 1)
	if err := host.RegisterProvider(&gatedTransport{
		carrier: "i2p-tunnel", entered: nativeEntered, ch: newTrackedChannel(), speculative: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(&stubTransport{
		carrier: "tls13", caps: TransportCapabilities{DirectBinding: true},
		key: presence.ContactKey,
	}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.HedgeDelay = 500 * time.Millisecond
	conn, err := svc.Dial(context.Background(),
		ServiceTarget{Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)}, Port: 47001},
		policy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-nativeEntered:
		t.Fatal("native setup launched before the hedge delay expired")
	case <-time.After(100 * time.Millisecond):
	}
}

// TestStalePolicyGenRejected: a setup completing under a superseded policy
// generation cannot activate a route.
func TestStalePolicyGenRejected(t *testing.T) {
	host, fast := isolatedHost(t)
	realm := openAdmissionRealm(t, host, fast, RealmID{7}, AdmissionOpen)
	endpoint := EndpointID{0x46}
	seedDirectCandidate(t, fast, realm.realmID(), endpoint)
	realm.mu.Lock()
	cfg := realm.cfg
	realm.mu.Unlock()
	transport := &credTransport{
		carrier: "mem", key: testChannelKey,
		onSetup: func() {
			// Replace the policy while this setup is in flight; the
			// completion must be rejected as stale.
			for i := 0; i < 50; i++ {
				if err := realm.ApplyPolicy(context.Background(), cfg, realm.PolicyGen()); err == nil {
					return
				}
			}
		},
	}
	if err := host.RegisterProvider(transport); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	svc := confinedService(t, realm)
	_, err := svc.Dial(context.Background(),
		ServiceTarget{Endpoint: EndpointRef{ID: endpoint}, Port: 47001}, confinedPolicy())
	if !errors.Is(err, CodeRevisionConflict) {
		t.Fatalf("stale generation dial: %v", err)
	}
}

// TestCandidateRealmMismatch: candidates carrying a foreign realm are dropped
// at admission.
func TestCandidateRealmMismatch(t *testing.T) {
	_, realm, _, _ := dualHost(t, nil)
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	contact := Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("9.9.9.9:4433")}
	in := []RouteCandidate{
		{Endpoint: EndpointID{5}, Fabric: PublicFastFabricID, NetworkID: 77, Realm: RealmID{0xff},
			Class: RouteDirect, ContactKey: testChannelKey, Contact: &contact, NotAfter: time.Now().Add(time.Hour).Unix()},
	}
	out, err := realm.admitCandidates(context.Background(),
		ServiceTarget{Endpoint: EndpointRef{ID: EndpointID{5}}}, eff, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("foreign realm admitted: %+v", out)
	}
}

// TestPresencePortScope: a presence authorizes contacts only for the port it
// was published under; a different service port yields no direct candidate.
func TestPresencePortScope(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	presence := testPresence() // Port 47001
	entries, err := presence.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, entries), Provenance: ProvenancePublicNative},
	}}
	_, realm, _, _ := dualHost(t, &stubFabric{native: netdb})
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	found, err := realm.resolveCandidates(context.Background(),
		ServiceTarget{Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)}, Port: 47002},
		eff)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range found {
		if c.Class == RouteDirect {
			t.Fatalf("presence authorized a different port: %+v", c)
		}
	}
}

// TestStrictPrefixInsufficientDiversity: strict mode fails resolution when
// candidates concentrate beyond the bound; best-effort proceeds capped.
func TestStrictPrefixInsufficientDiversity(t *testing.T) {
	_, realm, _, _ := dualHost(t, nil)
	realm.mu.Lock()
	realm.cfg.Prefix = PrefixPolicy{Mode: PrefixStrict, IPv4Prefix: 24, IPv6Prefix: 48, MaxPerPrefix: 1}
	realm.mu.Unlock()
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	a := Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("9.9.9.1:4433")}
	b := Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("9.9.9.2:4433")}
	mk := func(ep Endpoint) RouteCandidate {
		return RouteCandidate{Endpoint: EndpointID{4}, Fabric: PublicFastFabricID, NetworkID: 77,
			Realm: realm.realmID(), Class: RouteDirect, ContactKey: testChannelKey, Contact: &ep,
			NotAfter: time.Now().Add(time.Hour).Unix()}
	}
	target := ServiceTarget{Endpoint: EndpointRef{ID: EndpointID{4}}}
	if _, err := realm.admitCandidates(context.Background(), target, eff, []RouteCandidate{mk(a), mk(b)}); !errors.Is(err, CodeInsufficientDiversity) {
		t.Fatalf("strict concentration: %v", err)
	}
	realm.mu.Lock()
	realm.cfg.Prefix.Mode = PrefixBestEffort
	realm.mu.Unlock()
	out, err := realm.admitCandidates(context.Background(), target, eff, []RouteCandidate{mk(a), mk(b)})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("best-effort kept %d", len(out))
	}
}

// countingNetDB records lookup counts for discovery-mode tests.
type countingNetDB struct {
	inner *stubNetDB
	calls atomic.Int32
}

func (s *countingNetDB) LookupRouter(ctx context.Context, h foundation.Hash) (RouterRecord, error) {
	s.calls.Add(1)
	return s.inner.LookupRouter(ctx, h)
}
func (s *countingNetDB) LookupDestination(ctx context.Context, h foundation.Hash) (DestinationRecord, error) {
	s.calls.Add(1)
	return s.inner.LookupDestination(ctx, h)
}
func (s *countingNetDB) PublishOwnedRouter(ctx context.Context, r RouterRecord) (PublicationObservation, error) {
	return s.inner.PublishOwnedRouter(ctx, r)
}
func (s *countingNetDB) PublishOwnedDestination(ctx context.Context, r DestinationRecord) (PublicationObservation, error) {
	return s.inner.PublishOwnedDestination(ctx, r)
}

// TestLocalOnlyNoPublicLookup: local_only resolution must never reach the
// native netDB even when a native context is bound.
func TestLocalOnlyNoPublicLookup(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	netdb := &countingNetDB{inner: &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, nil), Provenance: ProvenancePublicNative},
	}}}
	host := testHost(t, TopologyPublicDualStack)
	if err := host.RegisterProvider(&stubFabric{native: netdb, local: map[foundation.Hash]RouteCandidate{}}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	native, err := host.OpenFabric(ctx, nativeFabric())
	if err != nil {
		t.Fatal(err)
	}
	fast, err := host.OpenFabric(ctx, ivnpFabric())
	if err != nil {
		t.Fatal(err)
	}
	realm, err := host.OpenRealm(RealmConfig{
		ID: PublicFastRealmID, Contexts: []ContextID{native.id, fast.id},
		Admission: AdmissionOpen, AcknowledgeOpen: true, AcknowledgeExposure: true,
		Discovery: DiscoveryLocalOnly, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Publication: PublicationNone,
		Prefix: PrefixPolicy{Mode: PrefixDisabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := PeerRef{
		Realm:   realm.realmID(),
		Locator: Locator{Kind: LocatorDestinationHash, Hash: dest.Hash()},
	}
	if _, err := realm.ResolvePeer(ctx, ref); err == nil {
		t.Fatal("expected local resolution failure")
	}
	if netdb.calls.Load() != 0 {
		t.Fatalf("local_only issued %d public lookups", netdb.calls.Load())
	}
}

// TestPublicFallbackLocalFirst: public_fallback consults bounded local
// discovery before the public path.
func TestPublicFallbackLocalFirst(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	var mu sync.Mutex
	var order []string
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, nil), Provenance: ProvenancePublicNative},
	}}
	host := testHost(t, TopologyPublicDualStack)
	if err := host.RegisterProvider(&orderFabric{
		local: &orderRuntime{order: &order, mu: &mu},
		netdb: &orderNetDB{inner: netdb, order: &order, mu: &mu},
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	native, err := host.OpenFabric(ctx, nativeFabric())
	if err != nil {
		t.Fatal(err)
	}
	fast, err := host.OpenFabric(ctx, ivnpFabric())
	if err != nil {
		t.Fatal(err)
	}
	realm, err := host.OpenRealm(RealmConfig{
		ID: PublicFastRealmID, Contexts: []ContextID{fast.id, native.id},
		Admission: AdmissionOpen, AcknowledgeOpen: true, AcknowledgeExposure: true,
		Discovery: DiscoveryPublicFallback, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Publication: PublicationNone,
		Prefix: PrefixPolicy{Mode: PrefixDisabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := PeerRef{
		Realm:   realm.realmID(),
		Locator: Locator{Kind: LocatorDestinationHash, Hash: dest.Hash()},
	}
	peer, err := realm.ResolvePeer(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if !peer.RecordVerified {
		t.Fatal("public record not verified")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "local" || order[1] != "public" {
		t.Fatalf("fallback order %v", order)
	}
}

// orderRuntime records that the local lookup ran.
type orderRuntime struct {
	order *[]string
	mu    *sync.Mutex
}

func (r *orderRuntime) RouterID() RouterID { return RouterID{2} }
func (r *orderRuntime) LookupPeer(ctx context.Context, ref PeerRef) ([]RouteCandidate, error) {
	r.mu.Lock()
	*r.order = append(*r.order, "local")
	r.mu.Unlock()
	return nil, CodeUnreachable.Wrap("no local candidate")
}
func (r *orderRuntime) NetDB() (PublicNetDBBackend, error) {
	return nil, CodeUnsupportedCapability.Wrap("no netdb")
}
func (r *orderRuntime) Ready(ctx context.Context) (Connectivity, error) {
	return Connectivity{Connected: true}, nil
}
func (r *orderRuntime) Close() error { return nil }

// orderNetDB records the public lookup in the shared order log.
type orderNetDB struct {
	inner *stubNetDB
	order *[]string
	mu    *sync.Mutex
}

func (s *orderNetDB) LookupRouter(ctx context.Context, h foundation.Hash) (RouterRecord, error) {
	return s.inner.LookupRouter(ctx, h)
}
func (s *orderNetDB) LookupDestination(ctx context.Context, h foundation.Hash) (DestinationRecord, error) {
	s.mu.Lock()
	*s.order = append(*s.order, "public")
	s.mu.Unlock()
	return s.inner.LookupDestination(ctx, h)
}
func (s *orderNetDB) PublishOwnedRouter(ctx context.Context, r RouterRecord) (PublicationObservation, error) {
	return s.inner.PublishOwnedRouter(ctx, r)
}
func (s *orderNetDB) PublishOwnedDestination(ctx context.Context, r DestinationRecord) (PublicationObservation, error) {
	return s.inner.PublishOwnedDestination(ctx, r)
}

// orderFabric returns the order-recording local runtime and the order netdb.
type orderFabric struct {
	local *orderRuntime
	netdb *orderNetDB
}

func (f *orderFabric) OpenContext(ctx context.Context, cfg FabricConfig) (ContextRuntime, error) {
	if cfg.Kind == ContextNativeI2P {
		return &orderNativeRuntime{netdb: f.netdb}, nil
	}
	return f.local, nil
}

type orderNativeRuntime struct{ netdb *orderNetDB }

func (r *orderNativeRuntime) RouterID() RouterID { return RouterID{3} }
func (r *orderNativeRuntime) LookupPeer(ctx context.Context, ref PeerRef) ([]RouteCandidate, error) {
	return nil, CodeUnreachable.Wrap("native context does not resolve peers locally")
}
func (r *orderNativeRuntime) NetDB() (PublicNetDBBackend, error) { return r.netdb, nil }
func (r *orderNativeRuntime) Ready(ctx context.Context) (Connectivity, error) {
	return Connectivity{Connected: true, PublicLookup: true}, nil
}
func (r *orderNativeRuntime) Close() error { return nil }

// TestApplyPolicyConcurrentWithResolve exercises policy replacement against
// live resolution under the race detector.
func TestApplyPolicyConcurrentWithResolve(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, nil), Provenance: ProvenancePublicNative},
	}}
	_, realm, _, _ := dualHost(t, &stubFabric{native: netdb, local: map[foundation.Hash]RouteCandidate{}})
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	target := ServiceTarget{Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)}}
	realm.mu.Lock()
	base := realm.cfg
	realm.mu.Unlock()
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = realm.resolveCandidates(context.Background(), target, eff)
				_ = realm.Status(context.Background())
				_ = realm.realmID()
			}
		}()
	}
	for i := 0; i < 100; i++ {
		_ = realm.ApplyPolicy(context.Background(), base, realm.PolicyGen())
	}
	close(stop)
	readers.Wait()
}

// TestExtensionOnlyPreservesOptions: the budget filter must not mutate the
// caller's option set; the driver receives exactly base + signed extras.
// Caller-supplied extension keys are rejected — extension material enters the
// record only through the verified path.
func TestExtensionOnlyPreservesOptions(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	driver := &captureDriver{obs: PublicationObservation{Accepted: true}}
	_, realm, _, _ := dualHost(t, &stubFabric{driver: driver})
	extra, err := testPresence().MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	if err := realm.host.RegisterProvider(testSigningBinding()); err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingOpportunistic,
		Protocols:    []EndpointProtocol{EndpointProtocolIVNPStream},
		DualPresence: true, Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	base := []foundation.MappingEntry{
		{Key: []byte("unrelated"), Value: []byte("v")},
		{Key: []byte("x-ov.custom"), Value: []byte("k")},
	}
	if _, err := svc.Publish(context.Background(), base); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("unverified extension key in base admitted: %v", err)
	}
	base = base[:1]
	if _, err := svc.Publish(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	if len(driver.options) != len(base)+len(extra) {
		t.Fatalf("driver received %d options, want %d", len(driver.options), len(base)+len(extra))
	}
	for i, e := range base {
		if string(driver.options[i].Key) != string(e.Key) {
			t.Fatalf("option %d corrupted: %q", i, driver.options[i].Key)
		}
	}
}

// stubBinding returns precomputed presence entries regardless of the passed
// presence — a provider that substitutes its own projection. It exists to
// prove the core rejects output that does not carry the reserved position.
type stubBinding struct{ entries []foundation.MappingEntry }

func (s *stubBinding) SignPresence(ctx context.Context, presence DualPresence, destination []byte) ([]foundation.MappingEntry, error) {
	return append([]foundation.MappingEntry(nil), s.entries...), nil
}

// signingBinding is an honest EndpointBindingProvider: it fills the
// owner-side fields the core leaves unset (fabric, contact key, expiry,
// capabilities, endpoints) and marshals the passed presence verbatim, so the
// signed projection always carries the core's reserved position.
type signingBinding struct {
	fabric     FabricDescriptor
	contactKey [32]byte
	notAfter   int64
	caps       []string
	endpoints  []Endpoint
}

func (s *signingBinding) SignPresence(ctx context.Context, presence DualPresence, destination []byte) ([]foundation.MappingEntry, error) {
	if presence.FabricID == (FabricID{}) {
		presence.FabricID = s.fabric.ID
		presence.NetworkID = s.fabric.NetworkID
	}
	if presence.ContactKey == ([32]byte{}) {
		presence.ContactKey = s.contactKey
	}
	if presence.NotAfter == 0 {
		presence.NotAfter = s.notAfter
	}
	if len(presence.Capabilities) == 0 {
		presence.Capabilities = s.caps
	}
	if len(presence.Endpoints) == 0 {
		presence.Endpoints = s.endpoints
	}
	return presence.MarshalEntries()
}

func testSigningBinding() *signingBinding {
	return &signingBinding{
		fabric:     testDescriptor(),
		contactKey: [32]byte{7, 7, 7},
		notAfter:   time.Now().Add(time.Hour).Unix(),
		caps:       []string{CapDirect, CapStreamV1},
		endpoints: []Endpoint{
			{Transport: "tls13", Address: netip.MustParseAddrPort("9.9.9.9:9443")},
		},
	}
}

// TestFabricListenerOwnership: a listener address belongs to exactly one
// context, both within one config and across contexts.
func TestFabricListenerOwnership(t *testing.T) {
	cfg := ivnpFabric()
	cfg.Listeners = []string{"0.0.0.0:7777", "0.0.0.0:7777"}
	if err := cfg.Validate(); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("duplicate listener in one config: %v", err)
	}
	host := testHost(t, TopologyPublicDualStack)
	ctx := context.Background()
	first := ivnpFabric()
	first.Listeners = []string{"0.0.0.0:7777"}
	if _, err := host.OpenFabric(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := testDescriptor()
	second.ID = FabricID{0x33}
	dup := FabricConfig{
		Kind: ContextIVNP, Descriptor: second,
		IdentityRef: "ivnp-2", StateDir: "state-ivnp-2",
		Listeners: []string{"0.0.0.0:7777"},
	}
	if _, err := host.OpenFabric(ctx, dup); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("shared listener admitted: %v", err)
	}
}

// TestSameFabricDedup: two contexts cannot pin the same fabric descriptor.
func TestSameFabricDedup(t *testing.T) {
	host := testHost(t, TopologyPublicDualStack)
	ctx := context.Background()
	if _, err := host.OpenFabric(ctx, ivnpFabric()); err != nil {
		t.Fatal(err)
	}
	dup := ivnpFabric()
	dup.IdentityRef = "ivnp-2"
	dup.StateDir = "state-ivnp-2"
	if _, err := host.OpenFabric(ctx, dup); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("same fabric admitted twice: %v", err)
	}
}

// TestDualStackRealmOneOfEach: a dual-stack realm binds at most one context
// of each kind.
func TestDualStackRealmOneOfEach(t *testing.T) {
	host := testHost(t, TopologyPublicDualStack)
	ctx := context.Background()
	fast1, err := host.OpenFabric(ctx, ivnpFabric())
	if err != nil {
		t.Fatal(err)
	}
	alt := testDescriptor()
	alt.ID = FabricID{0x34}
	fast2, err := host.OpenFabric(ctx, FabricConfig{
		Kind: ContextIVNP, Descriptor: alt,
		IdentityRef: "ivnp-2", StateDir: "state-ivnp-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.OpenRealm(RealmConfig{
		ID: RealmID{11}, Contexts: []ContextID{fast1.id, fast2.id},
		Admission: AdmissionOpen, AcknowledgeOpen: true,
		Discovery: DiscoveryLocalOnly, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOverlayDirect, Publication: PublicationNone,
		Prefix: PrefixPolicy{Mode: PrefixDisabled},
	}); !errors.Is(err, CodeContextScopeMismatch) {
		t.Fatalf("two ivnp contexts bound: %v", err)
	}
}

// TestRealmPublicationConstrainsService: a realm that forbids public
// projections rejects an LS2-publishing service.
func TestRealmPublicationConstrainsService(t *testing.T) {
	_, realm, _, _ := dualHost(t, nil)
	realm.mu.Lock()
	realm.cfg.Publication = PublicationNone
	realm.mu.Unlock()
	_, err := realm.OpenService(ServiceSpec{
		Destination: make([]byte, 4), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingOpportunistic,
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if !errors.Is(err, CodePrivacyPolicyConflict) {
		t.Fatalf("publication against realm policy: %v", err)
	}
}

// TestDualPresenceRequiresIVNPBinding: a realm without a bound IVNP context
// cannot open a dual-presence service.
func TestDualPresenceRequiresIVNPBinding(t *testing.T) {
	host := testHost(t, TopologyPublicDualStack)
	ctx := context.Background()
	native, err := host.OpenFabric(ctx, nativeFabric())
	if err != nil {
		t.Fatal(err)
	}
	realm, err := host.OpenRealm(RealmConfig{
		ID: RealmID{12}, Contexts: []ContextID{native.id},
		Admission: AdmissionOpen, AcknowledgeOpen: true, AcknowledgeExposure: true,
		Discovery: DiscoveryPublicPrimary, Privacy: PrivacyExplicitDirect,
		Routing: RoutingNativeI2P, Publication: PublicationLS2,
		Prefix: PrefixPolicy{Mode: PrefixDisabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = realm.OpenService(ServiceSpec{
		Destination: make([]byte, 4), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingNativeI2P,
		Protocols:    []EndpointProtocol{EndpointProtocolIVNPStream},
		DualPresence: true, Port: 47001,
	})
	if !errors.Is(err, CodeContextScopeMismatch) {
		t.Fatalf("dual presence without ivnp context: %v", err)
	}
}

// TestLocalRuntimeBoundedAndHonest: the built-in table respects the
// descriptor's MaxPeers and reports no connectivity while empty.
func TestLocalRuntimeBoundedAndHonest(t *testing.T) {
	d := privateDescriptor()
	d.MaxPeers = 1
	rt := newLocalRuntime(FabricConfig{
		Kind: ContextIVNP, Descriptor: d,
		IdentityRef: "ivnp-router", StateDir: "state-ivnp",
	})
	conn, err := rt.Ready(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if conn.Connected {
		t.Fatal("empty local table claims connectivity")
	}
	c := RouteCandidate{Endpoint: EndpointID{1}, Fabric: d.ID, Realm: RealmID{5}, Class: RouteDirect}
	if err := rt.InsertCandidate(foundation.Hash{1}, c); err != nil {
		t.Fatal(err)
	}
	if err := rt.InsertCandidate(foundation.Hash{2}, c); err == nil {
		t.Fatal("table accepted a candidate beyond MaxPeers")
	}
	conn, err = rt.Ready(context.Background())
	if err != nil || !conn.Connected || conn.Peers != 1 {
		t.Fatalf("readiness %+v %v", conn, err)
	}
}

// TestReadinessAxes: realm status computes each axis from its own evidence.
func TestReadinessAxes(t *testing.T) {
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{}}
	_, realm, _, _ := dualHost(t, &stubFabric{native: netdb})
	status := realm.Status(context.Background())
	if !status.LocalConnectivity || !status.PublicLookup {
		t.Fatalf("connectivity axes: %+v", status)
	}
	if !status.FallbackReady {
		t.Fatalf("fallback axis: %+v", status)
	}
	if !status.MembershipFresh {
		t.Fatalf("open realm membership: %+v", status)
	}
	if !status.PublicationCurrent || !status.RoutePolicySatisfied {
		t.Fatalf("policy axes: %+v", status)
	}
	if status.ServiceAccepting {
		t.Fatalf("no listener but accepting: %+v", status)
	}
}

// TestRealmWatchEvents: the realm-filtered watcher forwards only this realm's
// events and closes with the realm.
func TestRealmWatchEvents(t *testing.T) {
	_, realm, _, _ := dualHost(t, nil)
	other, err := realm.host.OpenRealm(RealmConfig{
		ID: RealmID{13}, Contexts: realmContextIDs(realm),
		Admission: AdmissionOpen, AcknowledgeOpen: true, AcknowledgeExposure: true,
		Discovery: DiscoveryHedged, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Publication: PublicationNone,
		Prefix: PrefixPolicy{Mode: PrefixDisabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	mine := realm.WatchEvents()
	theirs := other.WatchEvents()
	realm.setDiscovery(context.Background(), DiscoveryDegraded)
	select {
	case ev := <-mine:
		if ev.Kind != EventHostDegraded || ev.Realm != realm.realmID() {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("realm watcher missed its event")
	}
	select {
	case ev := <-theirs:
		t.Fatalf("foreign realm event leaked: %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}
	if err := realm.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, open := <-mine:
			if !open {
				return
			}
		case <-deadline:
			t.Fatal("realm watcher never closed")
		}
	}
}

func realmContextIDs(r *Realm) []ContextID {
	var ids []ContextID
	for _, nctx := range r.boundContexts() {
		ids = append(ids, nctx.id)
	}
	return ids
}

// TestHostCapabilities: registered provider roles are reported honestly.
func TestHostCapabilities(t *testing.T) {
	host := testHost(t, TopologyIsolated)
	caps := host.Capabilities()
	if caps.Identity || caps.Sessions || len(caps.Transports) != 0 {
		t.Fatalf("empty host reports capabilities: %+v", caps)
	}
	if err := host.RegisterProvider(&stubIdentity{proof: IdentityProof{}, signer: stubSigner{}}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(&stubTransport{carrier: "mem"}); err != nil {
		t.Fatal(err)
	}
	caps = host.Capabilities()
	if !caps.Identity || !caps.Sessions || len(caps.Transports) != 1 || caps.Transports[0] != "mem" {
		t.Fatalf("capabilities %+v", caps)
	}
}

// TestRealmEnroll: enrollment returns a realm-scoped proof; foreign-realm
// proofs are rejected.
func TestRealmEnroll(t *testing.T) {
	_, realm, _, _ := dualHost(t, nil)
	if _, err := realm.Enroll(context.Background(), EnrollIssue); !errors.Is(err, CodeUnsupportedCapability) {
		t.Fatalf("enroll without provider: %v", err)
	}
	if err := realm.host.RegisterProvider(&stubEnroll{proof: IdentityProof{Realm: realm.realmID(), Member: MemberID{1}}}); err != nil {
		t.Fatal(err)
	}
	proof, err := realm.Enroll(context.Background(), EnrollIssue)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Member != (MemberID{1}) {
		t.Fatalf("enrollment proof %+v", proof)
	}
	if err := realm.host.RegisterProvider(&stubEnroll{proof: IdentityProof{Realm: RealmID{9}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := realm.Enroll(context.Background(), EnrollIssue); !errors.Is(err, CodeRealmMismatch) {
		t.Fatalf("foreign enrollment: %v", err)
	}
	if _, err := realm.Enroll(context.Background(), EnrollmentOp(99)); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("unknown op: %v", err)
	}
}

// TestFallbackNotReady: a fallback-mode realm whose native path cannot serve
// lookups reports fallback_not_ready rather than a generic failure.
func TestFallbackNotReady(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	host := testHost(t, TopologyPublicDualStack)
	if err := host.RegisterProvider(&stubFabric{local: map[foundation.Hash]RouteCandidate{}}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	native, err := host.OpenFabric(ctx, nativeFabric())
	if err != nil {
		t.Fatal(err)
	}
	fast, err := host.OpenFabric(ctx, ivnpFabric())
	if err != nil {
		t.Fatal(err)
	}
	realm, err := host.OpenRealm(RealmConfig{
		ID: PublicFastRealmID, Contexts: []ContextID{fast.id, native.id},
		Admission: AdmissionOpen, AcknowledgeOpen: true, AcknowledgeExposure: true,
		Discovery: DiscoveryPublicFallback, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Publication: PublicationNone,
		Prefix: PrefixPolicy{Mode: PrefixDisabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	_, err = realm.resolveCandidates(ctx,
		ServiceTarget{Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)}}, eff)
	if !errors.Is(err, CodeFallbackNotReady) {
		t.Fatalf("fallback without native path: %v", err)
	}
}

// TestRouteInfoFallbackReady: the committed route reports endpoint-level
// fallback readiness from live native evidence.
func TestRouteInfoFallbackReady(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	presence := testPresence()
	entries, err := presence.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, entries), Provenance: ProvenancePublicNative},
	}}
	host, realm, _, _ := dualHost(t, &stubFabric{native: netdb})
	if err := host.RegisterProvider(&stubTransport{
		carrier: "tls13", caps: TransportCapabilities{DirectBinding: true},
		key: presence.ContactKey,
	}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := svc.Dial(context.Background(),
		ServiceTarget{Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)}, Port: 47001},
		testPolicy(PublicFastFabricID, NativeI2PFabricID))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	info := conn.RouteInfo()
	if !info.FallbackReady {
		t.Fatal("native path up but fallback not reported ready")
	}
	if info.Context == 0 {
		t.Fatal("route info lacks context id")
	}
}
