package overlay

import (
	"context"

	"gosuda.org/ivnp/foundation"
)

// Public-resolution concurrency budgets from the attack-response rules: two
// simultaneous public resolutions per realm, eight host-wide, and at most
// eight query attempts per resolution.
const (
	maxRealmPublicQueries = 2
	maxHostPublicQueries  = 8
	maxQueryAttempts      = 8
)

// DiscoveryState is the realm's attack-response position for public
// resolution. States are evidence-driven: a public record alone is not
// recovery, and a failed local answer escalates to the public path.
type DiscoveryState uint8

const (
	DiscoveryHealthy DiscoveryState = iota + 1
	DiscoveryLocalSuspect
	DiscoveryPublicResolving
	DiscoveryContactRevalidated
	DiscoveryDegraded
	DiscoveryIsolated
	// DiscoveryReconnecting marks setup attempts running under a revalidated
	// contact.
	DiscoveryReconnecting
)

func (s DiscoveryState) valid() bool {
	return s >= DiscoveryHealthy && s <= DiscoveryReconnecting
}

// sflightKey deduplicates concurrent resolutions by realm-implicit scope,
// identity, service port, locator material, access-policy generation, and
// privacy class. Port and blinded key must participate: candidate filtering
// and the lookup key itself depend on them, so a joiner under a different
// scope must never inherit the leader's result.
type sflightKey struct {
	endpoint EndpointID
	port     uint16
	blinded  foundation.Hash
	gen      uint64
	privacy  PrivacyClass
}

type sflightCall struct {
	done chan struct{}
	res  []RouteCandidate
	err  error
}

// acquirePublic takes one realm token and one host token for a public netDB
// query. Exhaustion fails fast with lookup_budget_exceeded rather than
// queueing unbounded work.
func (r *Realm) acquirePublic() (func(), error) {
	select {
	case r.publicSem <- struct{}{}:
	default:
		return nil, CodeLookupBudgetExceeded.Wrap("realm public-resolution budget exhausted")
	}
	select {
	case r.host.publicSem <- struct{}{}:
	default:
		<-r.publicSem
		return nil, CodeLookupBudgetExceeded.Wrap("host public-resolution budget exhausted")
	}
	return func() {
		<-r.publicSem
		<-r.host.publicSem
	}, nil
}

// setDiscovery records an attack-response transition and audits the change.
// Degraded and isolated positions are host-visible lifecycle events.
func (r *Realm) setDiscovery(ctx context.Context, to DiscoveryState) {
	r.discMu.Lock()
	if r.discovery == to {
		r.discMu.Unlock()
		return
	}
	r.discovery = to
	r.discMu.Unlock()
	realm := r.realmID()
	r.host.emit(ctx, AuditEvent{Kind: "discovery_state", Realm: realm})
	if to == DiscoveryDegraded || to == DiscoveryIsolated {
		r.host.broadcast(HostEvent{Kind: EventHostDegraded, Realm: realm})
	}
}

// DiscoveryState reports the realm's current attack-response position.
func (r *Realm) DiscoveryState() DiscoveryState {
	r.discMu.Lock()
	defer r.discMu.Unlock()
	return r.discovery
}
