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
	Publish(context.Context) (int, error)
	SetOptions([]foundation.MappingEntry) error
}

type destinationPublisher struct {
	publisher ownedLeaseSetPublisher
	sender    *router.StreamingTunnelSender
}

func (p *destinationPublisher) Maintain(ctx context.Context) (int, error) {
	count, err := p.publisher.Maintain(ctx)
	return count, errors.Join(err, p.sender.RefreshLocalLeaseSet())
}

// PublishWithOptions installs the record's mapping entries — extension
// contracts such as x-ov.* / x-ivnp.* — then publishes immediately. A nil or
// empty set restores the canonical empty mapping. Encrypted destinations
// carry no options: the signed inner record is not wired for extensions, so
// SetOptions rejects them.
func (p *destinationPublisher) PublishWithOptions(ctx context.Context, entries []foundation.MappingEntry) error {
	if p == nil || p.publisher == nil {
		return netdb.ErrLeaseSetPublisherConfig
	}
	if err := p.publisher.SetOptions(entries); err != nil {
		return err
	}
	_, err := p.publisher.Publish(ctx)
	return errors.Join(err, p.sender.RefreshLocalLeaseSet())
}

func (p *destinationPublisher) HandleDeliveryStatus(status foundation.I2NPDeliveryStatusMessage) bool {
	return p.publisher.HandleDeliveryStatus(status)
}

func (p *destinationPublisher) Close() { p.publisher.Close() }

func (p *destinationPublisher) Confirmed() bool { return p.publisher.Confirmed() }
