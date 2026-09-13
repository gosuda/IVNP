package overlay

import (
	"context"
	"net"

	"gosuda.org/ivnp/foundation"
)

// Provider contracts. A plugin's self-reported flag is never sufficient proof
// of a property; the core verifies evidence and applies minimum policy. All
// calls take caller deadlines and return bounded results.

// Signer is a non-exportable signing handle over a bound key.
type Signer interface {
	// Public returns the handle's public key bytes.
	Public() [32]byte
	// Sign produces a signature over msg without exporting private material.
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

// IdentityProof is provider-supplied membership evidence. The core validates
// realm/audience, issuer constraints, validity, revocation, and the live proof
// of the bound key; a returned flag cannot manufacture admission.
//
// For a local identity (IdentityProvider.LocalIdentity) every field is the
// member evidence a transport presents. For a peer's presented evidence
// (MembershipChannel.PeerMembership) only Credential is authoritative: the
// remaining fields are the carrier's parse hints, and the core admits solely
// on the claims a CredentialVerifier extracts from the document.
type IdentityProof struct {
	Realm      RealmID
	Member     MemberID
	Slot       uint64
	Issuer     string
	NotAfter   int64
	ChannelKey [32]byte
	// Credential is the serialized issuer-signed document (X.509, SVID, or a
	// reviewed signed membership format).
	Credential []byte
}

// CredentialVerifier authenticates an issuer-signed membership document and
// returns the claims it attests. The core applies realm, channel-key binding,
// expiry, issuer, revocation, and slot policy to the verified claims; fields a
// peer merely presented are never consulted. Credential-mode realms cannot be
// opened without a registered verifier.
type CredentialVerifier interface {
	// VerifyCredential checks the document's issuer signature and structure
	// and returns the attested claims. Any error denies admission.
	VerifyCredential(ctx context.Context, realm RealmID, credential []byte) (IdentityProof, error)
}

// IdentityProvider supplies the local workload/device credential and signing
// handle.
type IdentityProvider interface {
	LocalIdentity(ctx context.Context, realm RealmID) (IdentityProof, Signer, error)
}

// TrustState is a versioned trust snapshot.
type TrustState struct {
	Generation uint64
	Issuers    []string
	// Revoked lists members denied at this generation.
	Revoked []MemberID
	// MaxActiveSlots bounds simultaneous member incarnations per issuer slot.
	MaxActiveSlots int
	// NotAfter bounds the snapshot's freshness as a Unix timestamp; zero
	// means the snapshot does not expire on its own.
	NotAfter int64
}

// TrustProvider supplies issuer constraints, revocation, and limits.
type TrustProvider interface {
	Trust(ctx context.Context, realm RealmID) (TrustState, error)
}

// KeyPurpose separates secret leases by use. Never reuse one lease across
// purposes.
type KeyPurpose uint8

const (
	KeyPurposeNetworkAdmission KeyPurpose = iota + 1
	KeyPurposeLeaseSetDecryption
	KeyPurposeSession
	KeyPurposeEnrollment
)

// SecretLease is a purpose-scoped key lease; Release wipes the material.
type SecretLease interface {
	Key() []byte
	// Epoch identifies the key epoch the lease belongs to; PSK proofs bind it.
	Epoch() uint64
	Release() error
}

// SecretProvider obtains purpose-scoped key leases.
type SecretProvider interface {
	Lease(ctx context.Context, realm RealmID, purpose KeyPurpose) (SecretLease, error)
}

// BootstrapProvider supplies bounded candidate references and signed bootstrap
// hints. It cannot decide admission or assert directory completeness.
type BootstrapProvider interface {
	Candidates(ctx context.Context, realm RealmID, limit int) ([]PeerRef, error)
}

// RouterRecord is an unverified native RouterInfo plus retrieval provenance.
// Raw bytes cross the local verifier before becoming usable evidence.
type RouterRecord struct {
	Raw        []byte
	Provenance Provenance
	FetchedAt  int64
}

// DestinationRecord is an unverified native LeaseSet family record.
type DestinationRecord struct {
	Raw        []byte
	Provenance Provenance
	FetchedAt  int64
	// Encrypted marks an Encrypted LS2 requiring local access material.
	Encrypted bool
}

// PublicationObservation reports a store attempt. Acknowledgements and
// read-back are observations, not durable-storage receipts or a quorum.
type PublicationObservation struct {
	Accepted   bool
	ReadBack   bool
	ObservedAt int64
	// RecordHash is the lookup key the record was stored under, when the
	// driver observed it. For encrypted records this is the blinded hash;
	// Refresh binds read-back to it.
	RecordHash foundation.Hash
	// ContentHash, when non-zero, is SHA-256 of the exact record bytes the
	// driver stored. Refresh requires read-back bytes to hash to it, so an
	// older signed version of the same record cannot masquerade as the
	// stored projection. A driver that assembles the record knows the bytes;
	// it should report the hash.
	ContentHash foundation.Hash
}

// PublicNetDBBackend is the narrow native I2P lookup/publication boundary. It
// exists only on a netId=2 context.
type PublicNetDBBackend interface {
	LookupRouter(ctx context.Context, hash foundation.Hash) (RouterRecord, error)
	LookupDestination(ctx context.Context, hash foundation.Hash) (DestinationRecord, error)
	PublishOwnedRouter(ctx context.Context, record RouterRecord) (PublicationObservation, error)
	PublishOwnedDestination(ctx context.Context, record DestinationRecord) (PublicationObservation, error)
}

// ChannelScope is the full authenticated binding required before an
// AdmittedPeer exists.
type ChannelScope struct {
	Fabric    FabricID
	NetworkID WireNetworkID
	Realm     RealmID
	Endpoint  EndpointID
	// Port is the logical service selector bound with the channel.
	Port uint16
	// Selector is the negotiated endpoint-protocol selector (I2CP-style)
	// bound with the channel; zero means the target pinned none.
	Selector  uint8
	Protocol  EndpointProtocol
	Class     RouteClass
	Exposure  PrivacyClass
	PolicyGen uint64
}

// Channel is an authenticated setup result. Its binding must equal the scope
// the core requested; a plugin-returned trusted flag is not evidence.
type Channel interface {
	net.Conn
	// Binding returns the verified channel scope and the peer's proven
	// contact key.
	Binding() (ChannelScope, [32]byte)
}

// MembershipChannel is a Channel whose carrier exchanged credential material
// during setup. Credential-mode realms require it: the core verifies the
// peer's evidence locally rather than trusting a flag.
type MembershipChannel interface {
	Channel
	// PeerMembership returns the credential evidence the peer presented
	// during authenticated setup; ok is false when the carrier did not
	// exchange credential material. Only proof.Credential is authoritative —
	// a CredentialVerifier attests the claims the document binds.
	PeerMembership() (proof IdentityProof, ok bool)
}

// AdmissionRequest carries the verified local admission material a transport
// must present during channel setup. It is nil for open realms. For PSK
// modes NetworkKey is a leased key that must not be retained past Setup; for
// credential modes Credential and Signer are the local member evidence and
// signing handle, and the peer's evidence is verified by the core through
// MembershipChannel after setup.
type AdmissionRequest struct {
	Realm      RealmID
	Credential *IdentityProof
	Signer     Signer
	NetworkKey []byte
	Epoch      uint64
}

// TransportProvider implements secure channel setup with bounded I/O.
type TransportProvider interface {
	// Carrier names the provider/carrier implementation; candidates select by it.
	Carrier() string
	// Capabilities reports exporter, identity, and message-semantics support.
	Capabilities() TransportCapabilities
	// Setup establishes one bounded channel attempt. admission is nil for
	// open realms; otherwise the transport presents Credential/Signer or
	// proves NetworkKey under the channel's own authentication, and fails
	// the attempt if the peer cannot complete the matching proof.
	Setup(ctx context.Context, candidate RouteCandidate, scope ChannelScope, admission *AdmissionRequest) (Channel, error)
}

// TransportCapabilities gates carrier selection; a missing exporter or
// identity capability makes a provider ineligible rather than adapted.
type TransportCapabilities struct {
	// Exporter reports an RFC 8446 exporter or a reviewed equivalent.
	Exporter      bool
	DirectBinding bool
	RoutedBinding bool
	Speculative   bool
}

// AuditEvent is a security event without secret material or packet payloads.
type AuditEvent struct {
	Kind     string
	Realm    RealmID
	Endpoint EndpointID
	At       int64
}

// AuditSink receives security events under configured delivery semantics.
type AuditSink interface {
	Emit(ctx context.Context, event AuditEvent) error
}

// AuthorizationProvider is an optional policy decision point. It cannot
// weaken mandatory cryptographic, trust, or freshness checks.
type AuthorizationProvider interface {
	Authorize(ctx context.Context, peer PeerRef, operation string) (bool, error)
}

// PublicationDriverSource is a ContextRuntime that can publish owned records
// under its native key. Only the bound netId=2 context's runtime is consulted,
// so an IVNP context can never overwrite the owned public key.
type PublicationDriverSource interface {
	// PublicationDriver returns the owned-record publisher bound to
	// endpoint — the service whose Destination the endpoint identifies — or
	// nil when this runtime cannot publish for it. A runtime serving many
	// destinations must not guess the record key.
	PublicationDriver(endpoint EndpointRef) PublicationDriver
}

// ContextRuntime drives one fabric's discovery and routing state. A
// FabricProvider opens it; the core owns lifecycle.
type ContextRuntime interface {
	// RouterID is the context-scoped routing principal.
	RouterID() RouterID
	// LookupPeer resolves a typed identity within this context's discovery.
	LookupPeer(ctx context.Context, ref PeerRef) ([]RouteCandidate, error)
	// NetDB returns the native public backend; valid only on ContextNativeI2P.
	NetDB() (PublicNetDBBackend, error)
	// Ready reports the context's own connectivity evidence.
	Ready(ctx context.Context) (Connectivity, error)
	Close() error
}

// Connectivity is one context's independent readiness evidence.
type Connectivity struct {
	Connected    bool
	PublicLookup bool
	// Peers is the count of independently attested usable peers.
	Peers int
}

// FabricProvider opens scoped contexts. It cannot merge stores, accept another
// network's records, or change netId based on a peer.
type FabricProvider interface {
	OpenContext(ctx context.Context, cfg FabricConfig) (ContextRuntime, error)
}

// EndpointBindingProvider creates owner-authorized presence. It never infers
// endpoint ownership from a RouterInfo or lease gateway. A projection's
// authority is the verified native record that carries it; the core
// re-verifies every signed projection itself.
type EndpointBindingProvider interface {
	// SignPresence produces an x-ivnp.* entry set for the owned destination.
	// The returned entries must all carry the x-ivnp. prefix — the core
	// rejects anything else — and must parse back through ParseDualPresence
	// against a bound fabric.
	SignPresence(ctx context.Context, presence DualPresence, destination []byte) ([]foundation.MappingEntry, error)
}

// RouteProvider produces bounded candidates and prepares carrier paths. It
// cannot downgrade policy, manufacture measurements, or issue unmanaged
// public lookups.
type RouteProvider interface {
	Candidates(ctx context.Context, target ServiceTarget, realm RealmID, limit int) ([]RouteCandidate, error)
}

// Session is an endpoint-protocol association over an admitted channel.
type Session interface {
	// Protocol is the negotiated endpoint protocol.
	Protocol() EndpointProtocol
	// Resume reports a proven negotiated-resumption contract, when present.
	Resume() (ResumeContract, error)
	Close() error
}

// ResumeContract is an explicitly negotiated resumption capability; a new CID
// or ordinary reconnect is not one.
type ResumeContract struct {
	Supported bool
	// FenceToken orders resume attempts across owners.
	FenceToken uint64
}

// SessionProvider binds an endpoint protocol to an admitted channel.
type SessionProvider interface {
	Open(ctx context.Context, channel Channel, target ServiceTarget) (Session, error)
}

// ResumableSessionProvider is a SessionProvider that can continue a
// previously negotiated session lineage on a new channel. Resume reconciles
// replay/offset state and fencing under the contract; the returned session's
// negotiated contract must carry a strictly newer FenceToken. A session
// opened by ordinary Open is never reported as resumed.
type ResumableSessionProvider interface {
	SessionProvider
	Resume(ctx context.Context, channel Channel, target ServiceTarget, contract ResumeContract) (Session, error)
}

// EnrollmentOp selects the credential lifecycle operation.
type EnrollmentOp uint8

const (
	// EnrollIssue requests initial credential issuance.
	EnrollIssue EnrollmentOp = iota + 1
	// EnrollRenew requests renewal of an existing credential.
	EnrollRenew
	// EnrollReplace requests replacement (re-key) of a credential.
	EnrollReplace
)

// Valid reports whether op is a defined enrollment operation.
func (o EnrollmentOp) Valid() bool {
	return o >= EnrollIssue && o <= EnrollReplace
}

// EnrollmentProvider requests issue/renew/replace operations from a
// corporate CA or issuer. Enrollment tokens are audience-scoped and never
// carry data-plane keys.
type EnrollmentProvider interface {
	Enroll(ctx context.Context, realm RealmID, op EnrollmentOp) (IdentityProof, error)
}
