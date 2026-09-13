package overlaybridge

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/overlay"
)

// nativeContext adapts the running controller to the overlay's native
// (netId=2) context contract. Peer evidence comes only from the verified
// netDB table and bounded lookups; nothing here manufactures connectivity.
type nativeContext struct {
	controller *controlplane.Controller
}

func (c *nativeContext) RouterID() overlay.RouterID {
	return overlay.RouterID(c.controller.Hash())
}

// LookupPeer resolves a router-hash locator to a native route candidate.
// Destination locators resolve through the public netDB path instead — the
// realm's lookupPublic owns that flow.
func (c *nativeContext) LookupPeer(ctx context.Context, ref overlay.PeerRef) ([]overlay.RouteCandidate, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	if ref.Locator.Kind != overlay.LocatorRouterHash {
		return nil, overlay.CodeUnsupportedCapability.Wrap("native context resolves router-hash locators only")
	}
	raw, err := c.controller.LookupRouterRecord(ctx, ref.Locator.Hash)
	if err != nil {
		return nil, err
	}
	info, err := foundation.NetworkDatabaseParseRouterInfo(raw)
	if err != nil {
		return nil, err
	}
	if info.Hash() != ref.Locator.Hash {
		return nil, overlay.CodeIdentityMismatch.Wrap("netdb record does not match the locator")
	}
	hint := overlay.RouterID(ref.Locator.Hash)
	return []overlay.RouteCandidate{{
		Endpoint: overlay.EndpointID(ref.Locator.Hash), Fabric: overlay.NativeI2PFabricID,
		NetworkID: overlay.WireNetworkIDPublicI2P, Realm: ref.Realm,
		Class: overlay.RouteNativeI2P, Carrier: "i2p-tunnel",
		RouterHint: &hint, Provenance: overlay.ProvenancePublicNative,
		Exposure: overlay.PrivacyI2PCompatible,
	}}, nil
}

func (c *nativeContext) NetDB() (overlay.PublicNetDBBackend, error) {
	return &publicBackend{controller: c.controller}, nil
}

// PublicationDriver returns the owned-record publisher bound to endpoint —
// the destination the endpoint identifies. The controller still rejects a
// hash it does not own, so the driver can never publish under a foreign key.
func (c *nativeContext) PublicationDriver(endpoint overlay.EndpointRef) overlay.PublicationDriver {
	return &nativePublicationDriver{controller: c.controller, endpoint: endpoint}
}

// nativePublicationDriver binds one service endpoint to the controller's
// owned LeaseSet2 publisher. Store installs the verified extension entries as
// the record's mapping options and publishes; ReadBack returns the stored
// record through the controller's verified lookup path.
type nativePublicationDriver struct {
	controller *controlplane.Controller
	endpoint   overlay.EndpointRef
}

func (d *nativePublicationDriver) Store(ctx context.Context, options []foundation.MappingEntry) (overlay.PublicationObservation, error) {
	raw, confirmed, err := d.controller.PublishOwnedDestinationOptions(ctx, foundation.Hash(d.endpoint.ID), options)
	if err != nil {
		return overlay.PublicationObservation{}, err
	}
	return overlay.PublicationObservation{
		Accepted: true, ReadBack: confirmed, ObservedAt: time.Now().Unix(),
		RecordHash: foundation.Hash(d.endpoint.ID), ContentHash: sha256.Sum256(raw),
	}, nil
}

func (d *nativePublicationDriver) ReadBack(ctx context.Context) (overlay.DestinationRecord, error) {
	raw, encrypted, err := d.controller.LookupDestinationRecord(ctx, foundation.Hash(d.endpoint.ID))
	if err != nil {
		return overlay.DestinationRecord{}, err
	}
	return overlay.DestinationRecord{
		Raw: raw, Provenance: overlay.ProvenancePublicNative,
		FetchedAt: time.Now().Unix(), Encrypted: encrypted,
	}, nil
}

// presenceRecordTTL bounds a presence projection to roughly the enclosing
// record's lease lifetime: a native LS2 never outlives its leases, so the
// projection promises no more reachability than the record that carries it.
const presenceRecordTTL = 600

// bridgeBinding is the embedded EndpointBindingProvider: it fills the
// owner-side presence fields from the fabric's actual contact endpoints and
// the destination's verified Ed25519 key, then marshals the projection the
// core re-verifies. It never invents reachability — an endpoint without a
// public contact is published without the direct capability.
type bridgeBinding struct {
	bridge     *Bridge
	controller *controlplane.Controller
}

func (p *bridgeBinding) SignPresence(ctx context.Context, presence overlay.DualPresence, destination []byte) ([]foundation.MappingEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	identity, n, err := foundation.ParseIdentity(destination)
	if err != nil || n != len(destination) {
		return nil, overlay.CodeInvalidConfig.Wrap("presence destination does not parse canonically")
	}
	if identity.SigningKeyType() != foundation.SigningEdDSASHA512Ed25519 {
		return nil, overlay.CodeInvalidConfig.Wrap("ivnp-tls presence requires an Ed25519 destination")
	}
	inline, _ := identity.SigningKeyParts()
	if len(inline) < 32 {
		return nil, overlay.CodeInvalidConfig.Wrap("presence destination carries no inline signing key")
	}
	copy(presence.ContactKey[:], inline[:32])
	endpoint, err := overlay.EndpointIDFromDestination(destination)
	if err != nil {
		return nil, err
	}
	fabricID, carrier, endpoints := p.bridge.mux.presenceContact(endpoint, p.bridge.realmFabrics)
	if carrier == nil {
		return nil, overlay.CodeUnsupportedCapability.Wrap("no bound ivnp fabric carries the endpoint's contact key")
	}
	presence.FabricID = fabricID
	presence.NetworkID = carrier.netID
	if p.controller != nil {
		hint := overlay.RouterID(p.controller.Hash())
		presence.RouterHint = &hint
	}
	presence.NotAfter = time.Now().Unix() + presenceRecordTTL
	presence.Endpoints = endpoints
	if len(endpoints) > 0 {
		presence.Capabilities = []string{overlay.CapDirect}
	}
	return presence.MarshalEntries()
}

// Ready reports transport liveness and the verified peer count; it never
// claims a lookup will succeed.
func (c *nativeContext) Ready(ctx context.Context) (overlay.Connectivity, error) {
	if err := ctx.Err(); err != nil {
		return overlay.Connectivity{}, err
	}
	running, peers, err := c.controller.OverlayConnectivity()
	if err != nil {
		return overlay.Connectivity{}, err
	}
	return overlay.Connectivity{Connected: running && peers > 0, PublicLookup: running, Peers: peers}, nil
}

// Close is a no-op: the controller owns the native runtime's lifetime.
func (c *nativeContext) Close() error { return nil }

// publicBackend is the narrow public netDB boundary: lookups reuse the
// controller's verified store and bounded request path, and publication only
// ever republishes records the node itself owns.
type publicBackend struct {
	controller *controlplane.Controller
}

func (b *publicBackend) LookupRouter(ctx context.Context, hash foundation.Hash) (overlay.RouterRecord, error) {
	raw, err := b.controller.LookupRouterRecord(ctx, hash)
	if err != nil {
		return overlay.RouterRecord{}, err
	}
	return overlay.RouterRecord{
		Raw: raw, Provenance: overlay.ProvenancePublicNative, FetchedAt: time.Now().Unix(),
	}, nil
}

func (b *publicBackend) LookupDestination(ctx context.Context, hash foundation.Hash) (overlay.DestinationRecord, error) {
	raw, encrypted, err := b.controller.LookupDestinationRecord(ctx, hash)
	if err != nil {
		return overlay.DestinationRecord{}, err
	}
	return overlay.DestinationRecord{
		Raw: raw, Provenance: overlay.ProvenancePublicNative,
		FetchedAt: time.Now().Unix(), Encrypted: encrypted,
	}, nil
}

// PublishOwnedRouter republishes the node's current RouterInfo. A record
// naming a different router hash is rejected inside the controller — the
// bridge can never store foreign records under the local key.
func (b *publicBackend) PublishOwnedRouter(ctx context.Context, record overlay.RouterRecord) (overlay.PublicationObservation, error) {
	info, err := foundation.NetworkDatabaseParseRouterInfo(record.Raw)
	if err != nil {
		return overlay.PublicationObservation{}, err
	}
	confirmed, err := b.controller.PublishOwnedRouter(ctx, info.Hash())
	if err != nil {
		return overlay.PublicationObservation{}, err
	}
	return overlay.PublicationObservation{
		Accepted: true, ReadBack: confirmed, ObservedAt: time.Now().Unix(),
		RecordHash: info.Hash(), ContentHash: sha256.Sum256(record.Raw),
	}, nil
}

func (b *publicBackend) PublishOwnedDestination(ctx context.Context, record overlay.DestinationRecord) (overlay.PublicationObservation, error) {
	if record.Encrypted {
		return overlay.PublicationObservation{}, overlay.CodeUnsupportedCapability.Wrap("encrypted lease set publication is not wired")
	}
	set, err := foundation.NetworkDatabaseParseLeaseSet2(record.Raw)
	if err != nil {
		return overlay.PublicationObservation{}, err
	}
	valid, err := set.Verify()
	if err != nil || !valid {
		return overlay.PublicationObservation{}, overlay.CodeEndpointBindingInvalid.Wrap("refusing to publish a record with an invalid signature")
	}
	confirmed, err := b.controller.PublishOwnedDestination(ctx, set.Hash())
	if err != nil {
		return overlay.PublicationObservation{}, err
	}
	return overlay.PublicationObservation{
		Accepted: true, ReadBack: confirmed, ObservedAt: time.Now().Unix(),
		RecordHash: set.Hash(), ContentHash: sha256.Sum256(record.Raw),
	}, nil
}

// bridgeFabricProvider opens context runtimes: the native context adapts the
// controller and each IVNP fabric gets its own seeded runtime.
type bridgeFabricProvider struct {
	controller *controlplane.Controller
	mux        *carrierMux
	mu         sync.Mutex
	opened     map[overlay.FabricID]*fabricRuntime
}

func (p *bridgeFabricProvider) OpenContext(ctx context.Context, cfg overlay.FabricConfig) (overlay.ContextRuntime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.Kind == overlay.ContextNativeI2P {
		if p.controller == nil {
			return nil, overlay.CodeInvalidConfig.Wrap("native context requires a running controller")
		}
		return &nativeContext{controller: p.controller}, nil
	}
	carrier, err := p.mux.openFabric(cfg)
	if err != nil {
		return nil, err
	}
	runtime := &fabricRuntime{
		carrier: carrier, peers: make(map[foundation.Hash]overlay.RouteCandidate),
		router: overlay.RouterID(sha256.Sum256([]byte("ivnp-fabric/" + cfg.IdentityRef))),
	}
	carrier.table = runtime
	p.mu.Lock()
	if p.opened == nil {
		p.opened = make(map[overlay.FabricID]*fabricRuntime)
	}
	p.opened[cfg.Descriptor.ID] = runtime
	p.mu.Unlock()
	return runtime, nil
}

var _ overlay.ContextRuntime = (*nativeContext)(nil)
var _ overlay.PublicationDriverSource = (*nativeContext)(nil)
var _ overlay.PublicationDriver = (*nativePublicationDriver)(nil)
var _ overlay.EndpointBindingProvider = (*bridgeBinding)(nil)
var _ overlay.ContextRuntime = (*fabricRuntime)(nil)
var _ overlay.PublicNetDBBackend = (*publicBackend)(nil)
var _ overlay.FabricProvider = (*bridgeFabricProvider)(nil)
