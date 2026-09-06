package router

import (
	"errors"
	"sync"
	"sync/atomic"

	"gosuda.org/ivnp/cryptography"
	dataplanetunnel "gosuda.org/ivnp/dataplane/internal/tunnel"
	"gosuda.org/ivnp/foundation"
)

var (
	ErrPreparedRouteMissing = errors.New("router: prepared route unavailable")
	ErrRoutePreparationBusy = errors.New("router: route preparation capacity exhausted")
	ErrRouteGeneration      = errors.New("router: route policy generation changed")
)

// PreparedRoute is a control-plane validated snapshot. InstallRoute copies its
// byte slices; callers retain ownership of the supplied snapshot.
type PreparedRoute struct {
	Owner          foundation.Hash
	Remote         foundation.Hash
	Generation     uint64
	KeyType        foundation.CryptoKeyType
	KeyData        []byte
	LegacyKey      cryptography.ElGamalPublicKey
	Legacy         bool
	Gateway        foundation.Hash
	TunnelID       uint32
	Circuit        dataplanetunnel.CircuitToken
	Expires        uint64
	LocalLeaseSet  []byte
	LocalLeaseSet2 bool
}

type preparedRouteEntry struct {
	route   PreparedRoute
	active  sync.WaitGroup
	used    uint64
	wiping  atomic.Bool
	drained chan struct{}
}

func (r *preparedRouteEntry) retire() {
	r.active.Wait()
	if !r.wiping.Swap(true) {
		clear(r.route.KeyData)
		clear(r.route.LegacyKey[:])
		clear(r.route.LocalLeaseSet)
		close(r.drained)
		return
	}
	<-r.drained
}

// InstallRoute rejects stale preparation, including preparation racing policy
// replacement. Evicted snapshots are wiped only after their final active send.
func (s *PreparedRouteSender) InstallRoute(route PreparedRoute) error {
	if route.Owner != s.owner || route.Remote == (foundation.Hash{}) || route.Expires <= s.now() || route.Circuit == (dataplanetunnel.CircuitToken{}) || route.TunnelID == 0 {
		return ErrDataPlaneConfig
	}
	if !route.Legacy {
		if route.KeyType != foundation.CryptoX25519 && route.KeyType != foundation.CryptoMLKEM768X25519 && route.KeyType != foundation.CryptoMLKEM1024X25519 {
			return ErrUnsupportedEncryption
		}
		length, ok := route.KeyType.PublicKeyLen()
		if !ok || len(route.KeyData) != length {
			return ErrUnsupportedEncryption
		}
	}
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		return ErrDataPlaneConfig
	}
	s.routesMu.Lock()
	if route.Generation != s.generation {
		s.routesMu.Unlock()
		return ErrRouteGeneration
	}
	// Detached snapshots retain keys until their admitted writes finish.
	if len(s.routes)+len(s.retiring) >= 2*s.routeCapacity {
		s.routesMu.Unlock()
		return ErrRoutePreparationBusy
	}
	previous := s.routes[route.Remote]
	if previous == nil && len(s.routes) >= s.routeCapacity {
		for _, candidate := range s.routes {
			if previous == nil || candidate.used < previous.used {
				previous = candidate
			}
		}
		delete(s.routes, previous.route.Remote)
	}
	if previous != nil {
		s.retiring[previous] = struct{}{}
	}
	route.KeyData = append([]byte(nil), route.KeyData...)
	route.LocalLeaseSet = append([]byte(nil), route.LocalLeaseSet...)
	s.routeClock++
	s.routes[route.Remote] = &preparedRouteEntry{route: route, used: s.routeClock, drained: make(chan struct{})}
	s.routesMu.Unlock()
	if previous != nil {
		s.retireRouteEntry(previous)
	}
	return nil
}

// InvalidateRoutes advances policy generation before waiting for active uses.
// New sends cannot acquire retired routes while an old tunnel write drains.
func (s *PreparedRouteSender) InvalidateRoutes(generation uint64) {
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		return
	}
	s.routesMu.Lock()
	if generation > s.generation {
		s.generation = generation
		for remote, route := range s.routes {
			s.retiring[route] = struct{}{}
			delete(s.routes, remote)
		}
	}
	previous := make([]*preparedRouteEntry, 0, len(s.retiring))
	for route := range s.retiring {
		if route.route.Generation < generation {
			previous = append(previous, route)
		}
	}
	s.routesMu.Unlock()
	for _, route := range previous {
		s.retireRouteEntry(route)
	}
}

func (s *PreparedRouteSender) acquireRoute(remote foundation.Hash) (*preparedRouteEntry, error) {
	s.routesMu.Lock()
	defer s.routesMu.Unlock()
	route := s.routes[remote]
	if route == nil || route.route.Expires <= s.now() {
		return nil, ErrPreparedRouteMissing
	}
	s.routeClock++
	route.used = s.routeClock
	route.active.Add(1)
	return route, nil
}

// RetireRoute removes a failed execution plan without retrying its payload.
func (s *PreparedRouteSender) RetireRoute(remote foundation.Hash) {
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		return
	}
	s.routesMu.Lock()
	if previous := s.routes[remote]; previous != nil {
		delete(s.routes, remote)
		s.retiring[previous] = struct{}{}
	}
	previous := make([]*preparedRouteEntry, 0, len(s.retiring))
	for route := range s.retiring {
		if route.route.Remote == remote {
			previous = append(previous, route)
		}
	}
	s.routesMu.Unlock()
	for _, route := range previous {
		s.retireRouteEntry(route)
	}
}

func (s *PreparedRouteSender) HasRoute(remote foundation.Hash, generation uint64) bool {
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		return false
	}
	s.routesMu.Lock()
	defer s.routesMu.Unlock()
	route := s.routes[remote]
	return route != nil && route.route.Generation == generation && route.route.Expires > s.now()
}

func (s *PreparedRouteSender) retireRouteEntry(route *preparedRouteEntry) {
	route.retire()
	s.routesMu.Lock()
	delete(s.retiring, route)
	s.routesMu.Unlock()
}
