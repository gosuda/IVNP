// Package overlaybridge adapts the embedded router to the overlay provider
// contracts: the native control plane becomes the netId=2 context and each
// configured IVNP fabric gets its own transport carrier, peer table, and
// listeners. The adapters supply evidence; admission, freshness, and policy
// remain the overlay core's gates.
package overlaybridge

import (
	"context"
	"errors"
	"sync"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/overlay"
)

// StaticPeer is one configured fabric member: a typed contact address plus the
// endpoint's authorized contact key. Static membership is the embedded
// deployment's directory; it never substitutes for admission.
type StaticPeer struct {
	// Destination is the peer's canonical serialized Destination. When
	// present it derives EndpointID and ContactKey (Ed25519 signing public
	// key) and is authoritative over the explicit fields.
	Destination []byte
	EndpointID  overlay.EndpointID
	// ContactKey is the peer's proven transport key: for IVNP-TLS it is the
	// endpoint's Ed25519 signing public key.
	ContactKey [32]byte
	// Contact is the direct dial address, e.g. "ivnp-tls@203.0.113.10:47001".
	Contact string
}

// FabricSpec describes one IVNP fabric context the node owns.
type FabricSpec struct {
	// Name is the local handle destinations reference in
	// DestinationConfig.Networks.
	Name        string
	Descriptor  overlay.FabricDescriptor
	IdentityRef string
	StateDir    string
	// Listeners are owned TCP bind addresses ("ip:port") serving ivnp-tls.
	Listeners []string
	// Advertise lists operator-declared public contact endpoints
	// ("ivnp-tls@ip:port") the fabric's presence projection may carry —
	// required when listeners bind unspecified or translated addresses.
	Advertise []string
	// Peers is the fabric's static membership directory.
	Peers []StaticPeer
}

// RealmSpec is the node's single realm configuration over opened contexts.
type RealmSpec struct {
	ID        overlay.RealmID
	Admission overlay.AdmissionMode
	Discovery overlay.DiscoveryMode
	Privacy   overlay.PrivacyClass
	Routing   overlay.DataRouting
	// Publication bounds what services may publish; PublicationNone keeps the
	// realm purely local.
	Publication overlay.PublicationMode
	Prefix      overlay.PrefixPolicy
	// Fabrics names which opened fabrics join the realm; empty binds every
	// configured fabric. The native context is bound only by IncludeNative.
	Fabrics []string
	// IncludeNative binds the netId=2 context into the realm.
	IncludeNative bool
	// PSK is the realm's admission key for psk modes; the bridge never
	// retains the caller's slice.
	PSK                 []byte
	AcknowledgeOpen     bool
	AcknowledgeExposure bool
}

// Spec is the node-level overlay composition: fabrics plus one realm.
type Spec struct {
	// Native wires the running controller as the netId=2 context. False keeps
	// the host isolated.
	Native   bool
	NativeID string
	// NativeName is the configured network handle for the native context (e.g. "i2p", "main", "public").
	NativeName          string
	NativeParticipation overlay.PublicParticipation
	NativeStateDir      string
	Fabrics             []FabricSpec
	Realm               RealmSpec
	// Audit is an optional security event sink.
	Audit overlay.AuditSink
	// Transports registers custom TransportProviders with the overlay host.
	Transports []overlay.TransportProvider
	// Providers registers custom overlay providers (e.g. CredentialVerifier,
	// IdentityProvider, TrustProvider, etc.) with the overlay host.
	Providers []any
}

// Bridge owns the composed overlay host: contexts, providers, realm, and the
// per-fabric carriers. Close joins every owned listener before the host.
type Bridge struct {
	host      *overlay.Host
	realm     *overlay.Realm
	mux       *carrierMux
	contexts  map[string]overlay.ContextID
	fabricIDs map[string]overlay.FabricID
	// realmFabrics bounds which fabric listeners route inbound channels to
	// this realm's services.
	realmFabrics map[overlay.FabricID]struct{}
	realmNative  bool
	mu           sync.Mutex
	closed       bool
}

// Realm returns the composed realm.
func (b *Bridge) Realm() *overlay.Realm {
	if b == nil {
		return nil
	}
	return b.realm
}

// Host returns the composed overlay host for direct domain access.
func (b *Bridge) Host() *overlay.Host {
	if b == nil {
		return nil
	}
	return b.host
}

// RealmFabrics returns the realm's bound fabric identities, native included
// when bound — the full set a dial policy may select from.
func (b *Bridge) RealmFabrics() []overlay.FabricID {
	if b == nil {
		return nil
	}
	out := make([]overlay.FabricID, 0, len(b.realmFabrics)+1)
	if b.realmNative {
		out = append(out, overlay.NativeI2PFabricID)
	}
	for id := range b.realmFabrics {
		out = append(out, id)
	}
	return out
}

// FabricID resolves a configured fabric name to its descriptor identity.
func (b *Bridge) FabricID(name string) (overlay.FabricID, bool) {
	id, ok := b.fabricIDs[name]
	return id, ok
}

// Open composes the host, opens the configured contexts, and opens the realm.
// ctx bounds construction only; the bridge runs until Close.
func Open(ctx context.Context, spec Spec, controller *controlplane.Controller) (*Bridge, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if spec.Realm.ID == (overlay.RealmID{}) {
		return nil, overlay.CodeInvalidConfig.Wrap("overlay spec requires a realm id")
	}
	topology, err := specTopology(spec)
	if err != nil {
		return nil, err
	}
	secrets := &staticSecrets{keys: make(map[overlay.RealmID][]byte)}
	if len(spec.Realm.PSK) > 0 {
		secrets.keys[spec.Realm.ID] = append([]byte(nil), spec.Realm.PSK...)
	}
	mux := &carrierMux{
		secrets:  secrets,
		fabrics:  make(map[overlay.FabricID]*fabricCarrier),
		services: make(map[routeKey]*serviceQueue),
		bySvc:    make(map[*overlay.Service]map[routeKey]struct{}),
	}
	host, err := overlay.NewHost(overlay.HostConfig{Topology: topology, Audit: spec.Audit})
	if err != nil {
		return nil, err
	}
	b := &Bridge{
		host: host, mux: mux, contexts: make(map[string]overlay.ContextID),
		fabricIDs: make(map[string]overlay.FabricID), realmFabrics: make(map[overlay.FabricID]struct{}),
	}
	if err := b.open(ctx, spec, controller, secrets); err != nil {
		_ = b.Close()
		return nil, err
	}
	return b, nil
}

func (b *Bridge) open(ctx context.Context, spec Spec, controller *controlplane.Controller, secrets *staticSecrets) error {
	if spec.Native && controller == nil {
		return overlay.CodeInvalidConfig.Wrap("native context requires a running controller")
	}
	if err := validateFabricSpecs(spec); err != nil {
		return err
	}
	provider := &bridgeFabricProvider{controller: controller, mux: b.mux}
	if err := b.host.RegisterProvider(provider); err != nil {
		return err
	}
	if err := b.host.RegisterProvider(b.mux); err != nil {
		return err
	}
	if err := b.host.RegisterProvider(&bridgeBinding{bridge: b, controller: controller}); err != nil {
		return err
	}
	if err := b.host.RegisterProvider(streamSessions{}); err != nil {
		return err
	}
	if len(secrets.keys) > 0 {
		if err := b.host.RegisterProvider(secrets); err != nil {
			return err
		}
	}
	if err := b.host.RegisterProvider(&seedBootstrap{fabrics: b.mux}); err != nil {
		return err
	}
	for _, t := range spec.Transports {
		if err := b.host.RegisterProvider(t); err != nil {
			return err
		}
	}
	for _, p := range spec.Providers {
		if err := b.host.RegisterProvider(p); err != nil {
			return err
		}
	}
	bound := make([]overlay.ContextID, 0, len(spec.Fabrics)+1)
	if spec.Native {
		nctx, err := b.host.OpenFabric(ctx, overlay.FabricConfig{
			Kind: overlay.ContextNativeI2P, IdentityRef: spec.NativeID,
			StateDir: spec.NativeStateDir, Participation: spec.NativeParticipation,
		})
		if err != nil {
			return err
		}
		_, _, _, nativeCtxID := nctx.Identity()
		nativeName := "i2p"
		if spec.NativeName != "" {
			nativeName = spec.NativeName
		}
		b.contexts[nativeName] = nativeCtxID
		b.contexts["i2p"] = nativeCtxID
		if spec.Realm.IncludeNative {
			bound = append(bound, nativeCtxID)
			b.realmNative = true
		}
	}
	for i := range spec.Fabrics {
		fabric := spec.Fabrics[i]
		nctx, err := b.host.OpenFabric(ctx, overlay.FabricConfig{
			Kind: overlay.ContextIVNP, Descriptor: fabric.Descriptor,
			IdentityRef: fabric.IdentityRef, StateDir: fabric.StateDir,
			Listeners: append([]string(nil), fabric.Listeners...),
		})
		if err != nil {
			return err
		}
		fabricID, _, _, ctxID := nctx.Identity()
		runtime := provider.opened[fabricID]
		if runtime == nil {
			return errFabricNotOpened
		}
		for _, advertise := range fabric.Advertise {
			endpoint, err := overlay.ParseEndpoint(advertise)
			if err != nil {
				return overlay.CodeInvalidConfig.Wrap("fabric " + fabric.Name + " advertise endpoint")
			}
			runtime.carrier.advertise = append(runtime.carrier.advertise, endpoint)
		}
		for _, peer := range fabric.Peers {
			if err := runtime.insertPeer(peer); err != nil {
				return err
			}
		}
		b.contexts[fabric.Name] = ctxID
		b.fabricIDs[fabric.Name] = fabricID
		if len(spec.Realm.Fabrics) == 0 || contains(spec.Realm.Fabrics, fabric.Name) {
			bound = append(bound, ctxID)
			b.realmFabrics[fabricID] = struct{}{}
		}
	}
	realm, err := b.host.OpenRealm(overlay.RealmConfig{
		ID: spec.Realm.ID, Contexts: bound,
		Admission: spec.Realm.Admission, Discovery: spec.Realm.Discovery,
		Privacy: spec.Realm.Privacy, Routing: spec.Realm.Routing,
		Publication: spec.Realm.Publication, Prefix: spec.Realm.Prefix,
		AcknowledgeOpen: spec.Realm.AcknowledgeOpen, AcknowledgeExposure: spec.Realm.AcknowledgeExposure,
	})
	if err != nil {
		return err
	}
	b.realm = realm
	return nil
}

// validateFabricSpecs rejects configurations the core cannot express: unknown
// realm fabric references, duplicate names, and duplicate network numbers.
// The wire still separates same-netId fabrics, but a duplicated number is
// always operator error.
func validateFabricSpecs(spec Spec) error {
	names := make(map[string]struct{}, len(spec.Fabrics))
	networks := make(map[overlay.WireNetworkID]string, len(spec.Fabrics))
	for _, fabric := range spec.Fabrics {
		if fabric.Name == "" {
			return overlay.CodeInvalidConfig.Wrap("fabric requires a name")
		}
		if _, dup := names[fabric.Name]; dup {
			return overlay.CodeInvalidConfig.Wrap("duplicate fabric name")
		}
		names[fabric.Name] = struct{}{}
		if owner, dup := networks[fabric.Descriptor.NetworkID]; dup {
			return overlay.CodeInvalidConfig.Wrap("fabrics " + owner + " and " + fabric.Name + " share a network id")
		}
		networks[fabric.Descriptor.NetworkID] = fabric.Name
	}
	for _, name := range spec.Realm.Fabrics {
		if _, ok := names[name]; !ok {
			return overlay.CodeInvalidConfig.Wrap("realm binds unknown fabric " + name)
		}
	}
	if spec.Realm.IncludeNative && !spec.Native {
		return overlay.CodeInvalidConfig.Wrap("realm binds the native context but none is configured")
	}
	return nil
}

func specTopology(spec Spec) (overlay.Topology, error) {
	if len(spec.Fabrics) == 0 && !spec.Native {
		return 0, overlay.CodeInvalidConfig.Wrap("overlay spec requires at least one network")
	}
	switch {
	case spec.Native && len(spec.Fabrics) > 0:
		return overlay.TopologyPublicDualStack, nil
	case spec.Native:
		return overlay.TopologyNativeI2P, nil
	default:
		return overlay.TopologyIsolated, nil
	}
}

// RegisterServiceKey makes an owned destination's signing key available as the
// service's TLS contact key so inbound channels can prove it. The bridge does
// not retain the destination.
func (b *Bridge) RegisterServiceKey(svc *overlay.Service, destination *foundation.LocalDestination) error {
	return b.mux.registerServiceKey(svc, destination)
}

// OpenService opens a realm service and wires its inbound routing. destination
// may be nil for an outbound-only service; when non-nil its identity must
// equal the spec's declared destination and its signing key backs the
// service's TLS contact key.
func (b *Bridge) OpenService(spec overlay.ServiceSpec, destination *foundation.LocalDestination) (*overlay.Service, error) {
	if destination != nil {
		declared, err := overlay.EndpointIDFromDestination(spec.Destination)
		if err != nil {
			return nil, err
		}
		if destination.IdentityHash() != foundation.Hash(declared) {
			return nil, overlay.CodeIdentityMismatch.Wrap("service destination does not match the supplied identity")
		}
	}
	svc, err := b.realm.OpenService(spec)
	if err != nil {
		return nil, err
	}
	if err := b.mux.trackService(svc, b.realmFabrics); err != nil {
		_ = svc.Close()
		return nil, err
	}
	if destination != nil {
		if err := b.mux.registerServiceKey(svc, destination); err != nil {
			_ = svc.Close()
			b.mux.untrackService(svc)
			return nil, err
		}
	}
	go func() {
		<-svc.Done()
		b.mux.untrackService(svc)
	}()
	return svc, nil
}

// Close releases the host and every owned fabric listener.
func (b *Bridge) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	b.mu.Unlock()
	return errors.Join(b.mux.close(), b.host.Close())
}

// RegisterProvider registers a custom provider or transport with the overlay host.
func (b *Bridge) RegisterProvider(p any) error {
	if b == nil || b.host == nil {
		return errBridgeDown
	}
	return b.host.RegisterProvider(p)
}

func contains(list []string, name string) bool {
	for _, item := range list {
		if item == name {
			return true
		}
	}
	return false
}

var errBridgeDown = errors.New("overlaybridge: closed")

var errFabricNotOpened = errors.New("overlaybridge: fabric provider did not open the requested context")
