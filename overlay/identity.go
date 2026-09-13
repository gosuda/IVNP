package overlay

import (
	"crypto/sha256"
	"encoding/base32"
	"net"
	"strconv"
	"strings"

	"gosuda.org/ivnp/foundation"
)

// EndpointID is the global endpoint identity: SHA-256 over the exact canonical
// serialized I2P Destination. Network numbers, RouterIDs, and locators are not
// components of this identity.
type EndpointID [32]byte

// FabricID is the full routing-domain discriminator pinned by a FabricDescriptor.
type FabricID [32]byte

// RealmID scopes membership and service authorization; it is not a group secret.
type RealmID [32]byte

// RealmIDFor derives a stable realm identity from a name. Two deployments
// using the same realm name share a RealmID without coordinating.
func RealmIDFor(name string) RealmID {
	return RealmID(sha256.Sum256([]byte("ivnp-realm/" + name)))
}

// MemberID is a RealmID-scoped member principal. Its assurance depends on the
// realm's admission mode; in open realms it is self-certifying.
type MemberID [32]byte

// RouterID is a FabricID-scoped routing principal (native RouterIdentity hash).
// It is never an endpoint identity.
type RouterID [32]byte

// WireNetworkID is the native wire discriminator: 2 for public I2P, 16..254
// for IVNP fabrics. It is not a secret or an admission credential.
type WireNetworkID uint8

// ContextID selects a concrete NetworkContext instance for ownership and
// accounting. It is a local handle, never a globally trusted identity.
type ContextID uint64

const (
	WireNetworkIDPublicI2P WireNetworkID = 2
	WireNetworkIDIVNPMin   WireNetworkID = 16
	WireNetworkIDIVNPMax   WireNetworkID = 254
)

func sha256Sum(text string) [32]byte { return sha256.Sum256([]byte(text)) }

// Canonical identifiers from the v3 architecture. The fixed inputs carry no
// secret and do not authenticate members.
var (
	PublicFastFabricID = FabricID(sha256Sum("ivnp-public-fast-fabric/v1"))
	PublicFastRealmID  = RealmID(sha256Sum("ivnp-public-fast-realm/v1"))
	// PublicI2PRealmID is the version-2 compatibility realm; its value is pinned
	// and must not be rekeyed by document revisions.
	PublicI2PRealmID = RealmID(sha256Sum("overlay-public-i2p/v2"))
	// NativeI2PFabricID is the fixed routing-domain identity of public I2P.
	NativeI2PFabricID = FabricID(sha256Sum("i2p-public-native/v1"))
)

// EndpointIDFromDestination validates canonical serialized Destination bytes
// (the binary wire form, not the base64 text) and derives the endpoint
// identity: SHA-256 over the exact input.
func EndpointIDFromDestination(canonical []byte) (EndpointID, error) {
	identity, n, err := foundation.ParseIdentity(canonical)
	if err != nil {
		return EndpointID{}, err
	}
	if n != len(canonical) {
		return EndpointID{}, foundation.ErrInvalidIdentity
	}
	return EndpointID(identity.Hash()), nil
}

// String returns the ivnp:// identity form: a 52-character lowercase unpadded
// base32 encoding of the endpoint hash. It denotes identity only; it is not a
// registered URI scheme and carries no lookup capability.
func (id EndpointID) String() string {
	return "ivnp://" + endpointText(id)
}

func endpointText(id EndpointID) string {
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id[:]))
}

// ParseEndpointID accepts the ivnp:// form or a bare 52-character
// b32 endpoint hash and returns the decoded identity.
func ParseEndpointID(text string) (EndpointID, error) {
	s := strings.TrimPrefix(text, "ivnp://")
	if len(s) != 52 {
		return EndpointID{}, CodeIdentityMismatch.Wrap("endpoint id must be 52 base32 characters")
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(s))
	if err != nil || len(decoded) != 32 {
		return EndpointID{}, CodeIdentityMismatch.Wrap("endpoint id is not canonical base32")
	}
	var id EndpointID
	copy(id[:], decoded)
	if endpointText(id) != s {
		return EndpointID{}, CodeIdentityMismatch.Wrap("endpoint id is not lowercase canonical")
	}
	return id, nil
}

// Addr identifies an overlay endpoint and port as a net.Addr.
type Addr struct {
	Endpoint EndpointID
	Port     uint16
}

var _ net.Addr = Addr{}

func (a Addr) Network() string { return "ivnp" }

func (a Addr) String() string {
	if a.Port == 0 {
		return a.Endpoint.String()
	}
	return a.Endpoint.String() + ":" + strconv.Itoa(int(a.Port))
}

// EncryptedLookupRef carries the local access material needed to locate and
// decrypt an Encrypted LS2. KeyRef names a secret-store entry; raw decryption
// keys never appear in a serializable reference.
type EncryptedLookupRef struct {
	// BlindedHash is the current blinded lookup key; daily reblinding means it
	// may be stale relative to the owner's published record.
	BlindedHash foundation.Hash
	// KeyRef is an opaque local reference to the client's authorization secret.
	KeyRef string
}

// EndpointRef names one endpoint independent of fabric, netId, and host router.
// Destination, when present, must hash to ID.
type EndpointRef struct {
	ID          EndpointID
	Destination []byte
	Encrypted   *EncryptedLookupRef
}

// Validate checks internal consistency; a ref without encrypted-lookup material
// cannot resolve an encrypted-only record.
func (r EndpointRef) Validate() error {
	if r.ID == (EndpointID{}) {
		return CodeIdentityMismatch.Wrap("empty endpoint id")
	}
	if r.Encrypted != nil {
		if r.Encrypted.KeyRef == "" {
			return CodeLookupCapabilityRequired.Wrap("encrypted endpoint requires a local key reference")
		}
		if r.Encrypted.BlindedHash == (foundation.Hash{}) {
			return CodeLookupCapabilityRequired.Wrap("encrypted endpoint requires the blinded lookup key")
		}
	}
	if r.Destination == nil {
		return nil
	}
	id, err := EndpointIDFromDestination(r.Destination)
	if err != nil {
		return err
	}
	if id != r.ID {
		return CodeIdentityMismatch.Wrap("destination bytes do not match endpoint id")
	}
	return nil
}

// ServiceTarget selects an application under an endpoint. Changing the network
// path does not change this selector.
type ServiceTarget struct {
	Endpoint EndpointRef
	// Protocol is the negotiated endpoint protocol selector (I2CP-style).
	Protocol uint8
	// Port is the logical service port at the destination.
	Port uint16
}
