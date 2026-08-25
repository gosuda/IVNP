package router

import (
	"context"
	"errors"
	"sync"

	"gosuda.org/ivnp/networking/internal/network_database"
)

var ErrPublicationMaintenanceConfig = errors.New("router: invalid publication maintenance configuration")

// RouterInfoRefresher is satisfied by LocalRouterInfo. Keeping this interface
// narrow ensures scheduled refreshes use its existing signing and netdb
// admission path rather than reproducing either operation.
type RouterInfoRefresher interface {
	Publish(context.Context) error
}

// LeaseSetRefresher is satisfied by netdb.LeaseSetPublisher. Its Maintain
// method owns lease replacement, signing, and retry scheduling.
type LeaseSetRefresher interface {
	Maintain(context.Context) (int, error)
}

// PublicationMaintenanceConfig supplies independently scheduled local
// RouterInfo and LeaseSet refresh hooks. LeaseSet maintenance is called every
// tick because its publisher already owns its precise renewal deadline.
type PublicationMaintenanceConfig struct {
	RouterInfo        RouterInfoRefresher
	NetworkRouterInfo netdb.ConfirmedPublisher
	LeaseSet          LeaseSetRefresher
	Now               func() uint64
	RouterInfoRefresh uint64
}

// PublicationMaintenanceResult describes work performed by one maintenance
// tick. Publication sends are floodfill sends, not signatures.
type PublicationMaintenanceResult struct {
	RouterInfoRefreshed    bool
	RouterInfoPublications int
	LeaseSetPublications   int
}

// PublicationMaintenance is driven by the router's existing maintenance loop.
// Each call joins its bounded publication work before returning.
type PublicationMaintenance struct {
	routerInfo        RouterInfoRefresher
	networkRouterInfo netdb.ConfirmedPublisher
	leaseSet          LeaseSetRefresher
	now               func() uint64
	refresh           uint64

	mu             sync.Mutex
	nextRouterInfo uint64
}

func NewPublicationMaintenance(config PublicationMaintenanceConfig) (*PublicationMaintenance, error) {
	newPublicationMaintenanceRejected := config.Now == nil || (config.RouterInfo == nil && config.NetworkRouterInfo == nil && config.LeaseSet == nil)
	if !newPublicationMaintenanceRejected {
		newPublicationMaintenanceRejected = (config.RouterInfo != nil && config.RouterInfoRefresh == 0)
	}
	if newPublicationMaintenanceRejected {
		return nil, ErrPublicationMaintenanceConfig
	}
	return &PublicationMaintenance{
		routerInfo: config.RouterInfo, networkRouterInfo: config.NetworkRouterInfo, leaseSet: config.LeaseSet,
		now: config.Now, refresh: config.RouterInfoRefresh,
	}, nil
}

// Maintain refreshes each enabled publisher when due. RouterInfo publication
// remains in LocalRouterInfo, and LeaseSet publication remains in its netdb
// publisher, so this hook does not duplicate admission or signing paths.
func (m *PublicationMaintenance) Maintain(ctx context.Context) (PublicationMaintenanceResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return PublicationMaintenanceResult{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	result := PublicationMaintenanceResult{}
	var firstErr error
	if m.routerInfo != nil {
		now := m.now()
		if m.nextRouterInfo == 0 || now >= m.nextRouterInfo {
			if err := m.routerInfo.Publish(ctx); err != nil {
				firstErr = err
			} else {
				result.RouterInfoRefreshed = true
				m.nextRouterInfo = saturatingMillisAdd(now, m.refresh)
			}
		}
	}
	type publicationResult struct {
		leaseSet bool
		sent     int
		err      error
	}
	publishers := 0
	results := make(chan publicationResult, 2)
	if m.networkRouterInfo != nil {
		publishers++
		go func() {
			sent, err := m.networkRouterInfo.Maintain(ctx)
			results <- publicationResult{sent: sent, err: err}
		}()
	}
	if m.leaseSet != nil {
		publishers++
		go func() {
			sent, err := m.leaseSet.Maintain(ctx)
			results <- publicationResult{leaseSet: true, sent: sent, err: err}
		}()
	}
	for range publishers {
		published := <-results
		if published.leaseSet {
			result.LeaseSetPublications = published.sent
		} else {
			result.RouterInfoPublications = published.sent
		}
		if firstErr == nil && published.err != nil {
			firstErr = published.err
		}
	}
	return result, firstErr
}

func saturatingMillisAdd(value, increment uint64) uint64 {
	if ^uint64(0)-value < increment {
		return ^uint64(0)
	}
	return value + increment
}
