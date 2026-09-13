package overlay

import (
	"time"
)

// effectivePolicy is the dial-time intersection of realm, service, and caller
// constraints. Every field is a hard filter; a caller preference never widens
// what the realm or service declared.
type effectivePolicy struct {
	privacy   PrivacyClass
	classes   map[RouteClass]struct{}
	fabrics   map[FabricID]struct{}
	protocols map[EndpointProtocol]struct{}
	// protocol is the preferred endpoint protocol; the channel binding
	// declares it for the first attempt per candidate, and every allowed
	// protocol is attempted in preference order until one commits.
	protocol       EndpointProtocol
	publicFabrics  map[FabricID]struct{}
	discoveryHedge time.Duration
	// gen is the realm policy generation this intersection was computed
	// under. Setup scopes are stamped with it so a completion is stale the
	// moment ApplyPolicy advances the generation, even when the stamp would
	// otherwise be fresh: eligibility decided under a superseded policy is
	// not evidence under the current one.
	gen uint64
}

func (e *effectivePolicy) allowsFabric(id FabricID) bool {
	_, ok := e.fabrics[id]
	return ok
}

func (e *effectivePolicy) allowsClass(class RouteClass) bool {
	_, ok := e.classes[class]
	return ok
}

func (e *effectivePolicy) allowsProtocol(p EndpointProtocol) bool {
	_, ok := e.protocols[p]
	return ok
}

// privacyRestrictiveness orders exposure classes; a participant may tighten a
// realm's privacy but never relax it.
func privacyRestrictiveness(p PrivacyClass) int {
	switch p {
	case PrivacyPrivateConfined:
		return 3
	case PrivacyI2PCompatible:
		return 2
	default:
		return 1
	}
}

// mergePrivacy folds participant constraints into the strictest applicable
// class. private_confined and i2p_compatible are disjoint requirements: a
// confined participant forbids public carriage while an i2p_compatible
// participant requires the public native path, so the pair is impossible.
func mergePrivacy(classes ...PrivacyClass) (PrivacyClass, error) {
	var confined, i2p bool
	for _, c := range classes {
		switch c {
		case PrivacyPrivateConfined:
			confined = true
		case PrivacyI2PCompatible:
			i2p = true
		}
	}
	if confined && i2p {
		return 0, CodePrivacyPolicyConflict.Wrap("private_confined and i2p_compatible cannot both apply")
	}
	if confined {
		return PrivacyPrivateConfined, nil
	}
	if i2p {
		return PrivacyI2PCompatible, nil
	}
	return PrivacyExplicitDirect, nil
}

func routingClasses(d DataRouting) map[RouteClass]struct{} {
	switch d {
	case RoutingNativeI2P:
		return map[RouteClass]struct{}{RouteNativeI2P: {}}
	case RoutingOverlayDirect:
		return map[RouteClass]struct{}{RouteDirect: {}}
	case RoutingOverlayRouted:
		return map[RouteClass]struct{}{RouteRouted: {}}
	default:
		return map[RouteClass]struct{}{RouteNativeI2P: {}, RouteDirect: {}, RouteRouted: {}}
	}
}

func classSetValid(classes []RouteClass) bool {
	for _, c := range classes {
		if c < RouteNativeI2P || c > RouteRouted {
			return false
		}
	}
	return true
}

func setOfRouteClasses(in []RouteClass) map[RouteClass]struct{} {
	out := make(map[RouteClass]struct{}, len(in))
	for _, c := range in {
		out[c] = struct{}{}
	}
	return out
}

func setOfProtocols(in []EndpointProtocol) map[EndpointProtocol]struct{} {
	out := make(map[EndpointProtocol]struct{}, len(in))
	for _, p := range in {
		out[p] = struct{}{}
	}
	return out
}

func setOfFabrics(in []FabricID) map[FabricID]struct{} {
	out := make(map[FabricID]struct{}, len(in))
	for _, f := range in {
		out[f] = struct{}{}
	}
	return out
}

func intersectRouteClasses(dst map[RouteClass]struct{}, other map[RouteClass]struct{}) {
	for c := range dst {
		if _, ok := other[c]; !ok {
			delete(dst, c)
		}
	}
}

func intersectProtocols(dst map[EndpointProtocol]struct{}, other map[EndpointProtocol]struct{}) {
	for p := range dst {
		if _, ok := other[p]; !ok {
			delete(dst, p)
		}
	}
}

// publicFabrics returns the fabrics that may never carry confined application
// data: native public I2P plus every bound context whose descriptor is marked
// public.
func (r *Realm) publicFabrics() map[FabricID]struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return publicFabricSet(r.bound)
}

func publicFabricSet(bound []*NetworkContext) map[FabricID]struct{} {
	out := map[FabricID]struct{}{NativeI2PFabricID: {}}
	for _, nctx := range bound {
		if nctx.kind == ContextNativeI2P || nctx.cfg.Descriptor.Public {
			out[nctx.fabric.ID] = struct{}{}
		}
	}
	return out
}

// policySnapshot reads the realm configuration, bound contexts, and policy
// generation under one lock. A dial-time intersection must never tear across
// a policy replacement: a privacy class from generation N combined with a
// routing mode from N+1 admits routes no generation permits.
func (r *Realm) policySnapshot() (cfg RealmConfig, bound []*NetworkContext, gen uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg, append([]*NetworkContext(nil), r.bound...), r.policyGen.Load()
}

// effectiveDialPolicy validates the caller policy and computes the dial-time
// constraint intersection. Impossible intersections fail before resolution.
func (r *Realm) effectiveDialPolicy(spec ServiceSpec, p DialPolicy) (*effectivePolicy, error) {
	if !p.Privacy.valid() || !p.Fallback.valid() || !p.Failover.valid() {
		return nil, CodeInvalidConfig.Wrap("dial policy carries an unknown enum value")
	}
	if len(p.RouteClasses) == 0 || len(p.EndpointProtocols) == 0 || len(p.Fabrics) == 0 {
		return nil, CodeInvalidConfig.Wrap("dial policy requires a non-empty allowed set")
	}
	if !classSetValid(p.RouteClasses) || !validProtocols(p.EndpointProtocols) {
		return nil, CodeInvalidConfig.Wrap("dial policy carries an unknown enum value")
	}
	cfg, bound, gen := r.policySnapshot()
	privacy, err := mergePrivacy(cfg.Privacy, spec.Privacy, p.Privacy)
	if err != nil {
		return nil, err
	}
	classes := routingClasses(cfg.Routing)
	intersectRouteClasses(classes, routingClasses(spec.Routing))
	intersectRouteClasses(classes, setOfRouteClasses(p.RouteClasses))
	if privacy == PrivacyI2PCompatible {
		intersectRouteClasses(classes, map[RouteClass]struct{}{RouteNativeI2P: {}})
	}
	if len(classes) == 0 {
		return nil, CodeMinimumSecurityUnsatisfied.Wrap("no route class satisfies every participant")
	}
	protocols := setOfProtocols(spec.Protocols)
	intersectProtocols(protocols, setOfProtocols(p.EndpointProtocols))
	switch p.Fallback {
	case ProtocolIVNPOnly:
		intersectProtocols(protocols, map[EndpointProtocol]struct{}{EndpointProtocolIVNPStream: {}})
	case ProtocolLegacyOnly:
		intersectProtocols(protocols, map[EndpointProtocol]struct{}{EndpointProtocolLegacyStream: {}})
	}
	if len(protocols) == 0 {
		return nil, CodeMinimumSecurityUnsatisfied.Wrap("no endpoint protocol satisfies every participant")
	}
	declared := EndpointProtocolLegacyStream
	if _, ok := protocols[EndpointProtocolIVNPStream]; ok && p.Fallback != ProtocolLegacyOnly {
		declared = EndpointProtocolIVNPStream
	}
	fabrics := setOfFabrics(p.Fabrics)
	public := publicFabricSet(bound)
	if privacy == PrivacyPrivateConfined {
		for f := range fabrics {
			if _, open := public[f]; open {
				delete(fabrics, f)
			}
		}
		if len(fabrics) == 0 {
			return nil, CodePrivacyPolicyConflict.Wrap("private_confined leaves only public fabrics")
		}
	}
	return &effectivePolicy{
		privacy: privacy, classes: classes, fabrics: fabrics,
		protocols: protocols, protocol: declared, publicFabrics: public,
		discoveryHedge: p.DiscoveryHedgeDelay, gen: gen,
	}, nil
}

func (r *Realm) privacyClass() PrivacyClass {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg.Privacy
}

func (r *Realm) routingMode() DataRouting {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg.Routing
}
