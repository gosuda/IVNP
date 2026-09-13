package overlay

import (
	"gosuda.org/ivnp/foundation"
)

// LocatorKind selects the single typed native locator a PeerRef carries.
type LocatorKind uint8

const (
	// LocatorRouterHash names a public router by its native hash.
	LocatorRouterHash LocatorKind = iota + 1
	// LocatorDestinationHash names an endpoint by its conventional
	// destination hash.
	LocatorDestinationHash
	// LocatorDestination carries the full canonical Destination; it must hash
	// to Hash.
	LocatorDestination
	// LocatorEncrypted names a blinded record whose decryption requires the
	// referenced local access material.
	LocatorEncrypted
)

// Locator is exactly one typed native reference. H(RealmID || MemberID) is a
// local index key only and is never a valid public netDB storage key.
type Locator struct {
	Kind        LocatorKind
	Hash        foundation.Hash
	Destination []byte
	Encrypted   *EncryptedLookupRef
}

// Validate enforces the single-locator invariant and internal consistency.
func (l Locator) Validate() error {
	switch l.Kind {
	case LocatorRouterHash, LocatorDestinationHash:
		if l.Hash == (foundation.Hash{}) || l.Destination != nil || l.Encrypted != nil {
			return CodeInvalidConfig.Wrap("hash locator carries no extra fields")
		}
	case LocatorDestination:
		if l.Encrypted != nil {
			return CodeInvalidConfig.Wrap("destination locator carries no encrypted ref")
		}
		id, err := EndpointIDFromDestination(l.Destination)
		if err != nil {
			return err
		}
		if foundation.Hash(id) != l.Hash {
			return CodeIdentityMismatch.Wrap("destination does not match locator hash")
		}
	case LocatorEncrypted:
		if l.Encrypted == nil || l.Encrypted.KeyRef == "" {
			return CodeLookupCapabilityRequired.Wrap("encrypted locator requires a local key reference")
		}
		if l.Encrypted.BlindedHash == (foundation.Hash{}) {
			return CodeLookupCapabilityRequired.Wrap("encrypted locator requires the blinded lookup key")
		}
		if l.Destination != nil {
			return CodeInvalidConfig.Wrap("encrypted locator carries no destination bytes")
		}
	default:
		return CodeInvalidConfig.Wrap("unknown locator kind")
	}
	return nil
}

// PeerRef identifies a realm-scoped principal at one typed native locator.
// Member is the expected slot where known; open realms self-certify it.
type PeerRef struct {
	Realm     RealmID
	Member    MemberID
	HasMember bool
	Locator   Locator
}

func (r PeerRef) Validate() error {
	if r.Realm == (RealmID{}) {
		return CodeInvalidConfig.Wrap("peer ref requires a realm")
	}
	return r.Locator.Validate()
}

// RouteCandidate is a scoped route reference. It carries evidence and
// provenance; admission remains an independent gate.
type RouteCandidate struct {
	Endpoint  EndpointID
	Fabric    FabricID
	NetworkID WireNetworkID
	Realm     RealmID
	Class     RouteClass
	// Carrier identifies the actual provider/carrier implementation.
	Carrier string
	// ContactKey is the owner-authorized endpoint contact key to prove.
	// Admission requires it for every non-native class — without a pinned
	// key there is no endpoint key binding to verify. Native candidates
	// carry none: destination authentication is inherent to the tunnel.
	ContactKey [32]byte
	// CredentialDigest, when non-nil, binds the credential the peer must
	// present: admission requires the presented document to hash to it.
	CredentialDigest *[32]byte
	// RouterHint resolves only within the candidate's own fabric.
	RouterHint *RouterID
	// Contact is the direct dial address for Class == RouteDirect.
	Contact     *Endpoint
	Incarnation uint64
	Sequence    uint64
	// NotAfter bounds the candidate's freshness; zero means the provider
	// asserts no expiry, which admission accepts only for sources outside a
	// signed record — record-derived candidates always carry the record's
	// verified bound.
	NotAfter int64
	// Provenance records which plane supplied this candidate.
	Provenance Provenance
	// Exposure reports the route's observed address-exposure class.
	Exposure PrivacyClass
}

// locatorEndpoint is the endpoint identity a locator names, or the zero
// value when it carries none: an encrypted locator's blinded key is not the
// endpoint and must never be compared against one.
func locatorEndpoint(l Locator) EndpointID {
	switch l.Kind {
	case LocatorRouterHash, LocatorDestinationHash, LocatorDestination:
		return EndpointID(l.Hash)
	}
	return EndpointID{}
}

// Provenance distinguishes independently maintained retrieval paths.
type Provenance uint8

const (
	// ProvenanceLocal came from the scoped IVNP-local cache or peer exchange.
	ProvenanceLocal Provenance = iota + 1
	// ProvenancePublicNative came from the native public netDB path; it is the
	// evidence that survives IVNP-local eclipse.
	ProvenancePublicNative
)
