package noderuntime

import (
	"context"
	"errors"

	"gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/controlplane/internal/router"
	"gosuda.org/ivnp/foundation"
)

type ownedLeaseSetPublisher interface {
	netdb.ConfirmedPublisher
	Confirmed() bool
	Close()
}

type destinationPublisher struct {
	publisher ownedLeaseSetPublisher
	sender    *router.StreamingTunnelSender
}

func (p *destinationPublisher) Maintain(ctx context.Context) (int, error) {
	count, err := p.publisher.Maintain(ctx)
	return count, errors.Join(err, p.sender.RefreshLocalLeaseSet())
}

func (p *destinationPublisher) HandleDeliveryStatus(status foundation.I2NPDeliveryStatusMessage) bool {
	return p.publisher.HandleDeliveryStatus(status)
}

func (p *destinationPublisher) Close() { p.publisher.Close() }

func (p *destinationPublisher) Confirmed() bool { return p.publisher.Confirmed() }
