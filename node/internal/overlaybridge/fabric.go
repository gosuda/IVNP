package overlaybridge

import (
	"cmp"
	"context"
	"sync"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/overlay"
)

// fabricRuntime is one IVNP fabric's scoped context: a bounded static
// membership table plus the carrier's listener evidence. It never claims
// public reachability and never accepts a candidate outside its own
// descriptor.
type fabricRuntime struct {
	carrier *fabricCarrier
	router  overlay.RouterID
	mu      sync.Mutex
	peers   map[foundation.Hash]overlay.RouteCandidate
	closed  bool
}

func (r *fabricRuntime) RouterID() overlay.RouterID { return r.router }

// LookupPeer resolves a typed locator against the configured membership
// table. The realm stamp is applied here, never at configuration time, so a
// candidate cannot escape its realm.
func (r *fabricRuntime) LookupPeer(ctx context.Context, ref overlay.PeerRef) ([]overlay.RouteCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	key := ref.Locator.Hash
	if ref.Locator.Kind == overlay.LocatorEncrypted && ref.Locator.Encrypted != nil {
		key = ref.Locator.Encrypted.BlindedHash
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, overlay.CodeClosed.Wrap("fabric context closed")
	}
	candidate, ok := r.peers[key]
	if !ok {
		return nil, overlay.CodeUnreachable.Wrap("no fabric member for locator")
	}
	candidate.Realm = ref.Realm
	candidate.Provenance = overlay.ProvenanceLocal
	return []overlay.RouteCandidate{candidate}, nil
}

// insertPeer adds a configured member. Destination, when present, is parsed
// for its endpoint identity and Ed25519 signing key and is authoritative over
// the explicit fields.
func (r *fabricRuntime) insertPeer(peer StaticPeer) error {
	contact, err := overlay.ParseEndpoint(peer.Contact)
	if err != nil {
		return err
	}
	carrier := cmp.Or(contact.Transport, carrierTransportToken)
	if carrier == "ntcp2" || carrier == "ssu2" || carrier == "i2p" {
		return overlay.CodeInvalidConfig.Wrap("peer contact transport cannot be a native transport")
	}
	var endpoint overlay.EndpointID
	var key [32]byte
	if len(peer.Destination) > 0 {
		identity, n, err := foundation.ParseIdentity(peer.Destination)
		if err != nil || n != len(peer.Destination) {
			return overlay.CodeInvalidConfig.Wrap("peer destination does not parse canonically")
		}
		if carrier == carrierTransportToken && identity.SigningKeyType() != foundation.SigningEdDSASHA512Ed25519 {
			// ivnp-tls contact keys are verified as standard Ed25519; a
			// RedDSA destination could never complete the pinned handshake.
			return overlay.CodeInvalidConfig.Wrap("peer destination requires an Ed25519 signing key")
		}
		inline, _ := identity.SigningKeyParts()
		if len(inline) < 32 {
			return overlay.CodeInvalidConfig.Wrap("peer destination carries no inline signing key")
		}
		copy(key[:], inline[:32])
		endpoint, err = overlay.EndpointIDFromDestination(peer.Destination)
		if err != nil {
			return err
		}
	} else {
		if peer.EndpointID == (overlay.EndpointID{}) || peer.ContactKey == ([32]byte{}) {
			return overlay.CodeInvalidConfig.Wrap("static peer requires destination or endpoint id plus contact key")
		}
		endpoint, key = peer.EndpointID, peer.ContactKey
	}
	bound := r.carrier.maxPeers
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.peers[foundation.Hash(endpoint)]; !exists && len(r.peers) >= bound {
		return overlay.CodeInvalidConfig.Wrap("fabric membership table is at its descriptor bound")
	}
	r.peers[foundation.Hash(endpoint)] = overlay.RouteCandidate{
		Endpoint: endpoint, Fabric: r.carrier.fabric, NetworkID: r.carrier.netID,
		Class: overlay.RouteDirect, Carrier: carrier,
		ContactKey: key, Contact: &contact,
		Provenance: overlay.ProvenanceLocal, Exposure: overlay.PrivacyExplicitDirect,
	}
	return nil
}

func (r *fabricRuntime) NetDB() (overlay.PublicNetDBBackend, error) {
	return nil, overlay.CodeUnsupportedCapability.Wrap("ivnp fabric carries no public netdb backend")
}

// Ready reports listener liveness and the configured membership count. A
// configured member is not proven reachable; connectivity claims only that
// the fabric is locally operational.
func (r *fabricRuntime) Ready(ctx context.Context) (overlay.Connectivity, error) {
	if err := ctx.Err(); err != nil {
		return overlay.Connectivity{}, err
	}
	r.mu.Lock()
	peers := len(r.peers)
	closed := r.closed
	r.mu.Unlock()
	return overlay.Connectivity{
		Connected: !closed && r.carrier.live() && peers > 0, Peers: peers,
	}, nil
}

func (r *fabricRuntime) Close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return r.carrier.close()
}

// staticSecrets serves purpose-scoped PSK leases from configuration. Each
// lease hands out an owned copy; Release wipes it.
type staticSecrets struct {
	mu   sync.Mutex
	keys map[overlay.RealmID][]byte
}

func (s *staticSecrets) Lease(ctx context.Context, realm overlay.RealmID, purpose overlay.KeyPurpose) (overlay.SecretLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if purpose != overlay.KeyPurposeNetworkAdmission {
		return nil, overlay.CodeUnsupportedCapability.Wrap("static secrets serve network admission only")
	}
	s.mu.Lock()
	key, ok := s.keys[realm]
	s.mu.Unlock()
	if !ok {
		return nil, overlay.CodeMembershipDenied.Wrap("no configured key for realm")
	}
	return &staticLease{key: append([]byte(nil), key...)}, nil
}

type staticLease struct {
	key []byte
}

func (l *staticLease) Key() []byte   { return l.key }
func (l *staticLease) Epoch() uint64 { return 1 }
func (l *staticLease) Release() error {
	clear(l.key)
	return nil
}

// wipe clears every stored realm key; called when the owning mux closes.
func (s *staticSecrets) wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range s.keys {
		clear(key)
	}
}

// seedBootstrap returns configured member references for realm discovery.
// Hints carry configured provenance; they cannot decide admission.
type seedBootstrap struct {
	fabrics *carrierMux
}

func (s *seedBootstrap) Candidates(ctx context.Context, realm overlay.RealmID, limit int) ([]overlay.PeerRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	refs := s.fabrics.bootstrapRefs(realm, limit)
	if len(refs) == 0 {
		return nil, overlay.CodeUnreachable.Wrap("no configured bootstrap members")
	}
	return refs, nil
}

var _ overlay.SecretProvider = (*staticSecrets)(nil)
var _ overlay.BootstrapProvider = (*seedBootstrap)(nil)
