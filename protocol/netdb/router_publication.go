package netdb

import (
	"context"
	"errors"
	"log/slog"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/protocol/i2np"
)

var ErrRouterInfoPublisherConfig = errors.New("netdb: invalid RouterInfo publisher configuration")

// RouterInfoSource is intentionally tiny so router.LocalRouterInfo remains the
// only signing and local-admission boundary while NetDB observes immutable
// snapshots for network confirmation.
type RouterInfoSource interface {
	Hash() ivnp.Hash
	Snapshot() RouterInfo
}

type RouterInfoPublisherConfig struct {
	Local            RouterInfoSource
	Database         *Database
	Sender           LeaseSetPublishSender
	ReplyPath        ReplyPathSource
	Registry         *PublicationTokenRegistry
	Now              func() uint64
	Random           func() uint32
	PreferredTargets []ivnp.Hash
	Logger           *slog.Logger
}

type RouterInfoPublisher struct {
	local     RouterInfoSource
	confirmed *confirmedPublication
	last      []byte
}

func NewRouterInfoPublisher(config RouterInfoPublisherConfig) (*RouterInfoPublisher, error) {
	if config.Local == nil || config.Database == nil || config.Sender == nil || config.ReplyPath == nil || config.Now == nil || config.Random == nil {
		return nil, ErrRouterInfoPublisherConfig
	}
	return &RouterInfoPublisher{local: config.Local, confirmed: newConfirmedPublication(config.Database, config.Sender, config.ReplyPath, config.Registry, config.Now, config.Random, config.Local.Hash(), i2np.StoreRouterInfo, config.PreferredTargets, config.Logger)}, nil
}

// Maintain snapshots a pre-signed RouterInfo generation and sends/advances the
// confirmed K-way floodfill publication state.
func (p *RouterInfoPublisher) Maintain(ctx context.Context) (int, error) {
	info := p.local.Snapshot()
	if len(info.Bytes()) == 0 {
		return 0, nil
	}
	raw := info.Bytes()
	if string(p.last) != string(raw) {
		compressed, err := CompressRouterInfo(raw)
		if err != nil {
			return 0, err
		}
		p.last = append(p.last[:0], raw...)
		p.confirmed.replace(compressed)
	}
	return p.confirmed.maintain(ctx, false)
}

// Publish forces another confirmed-publication scheduling pass for the current
// immutable signed generation; it never signs or mutates LocalRouterInfo.
func (p *RouterInfoPublisher) Publish(ctx context.Context) (int, error) {
	info := p.local.Snapshot()
	if len(info.Bytes()) == 0 {
		return 0, nil
	}
	raw := info.Bytes()
	if string(p.last) != string(raw) {
		compressed, err := CompressRouterInfo(raw)
		if err != nil {
			return 0, err
		}
		p.last = append(p.last[:0], raw...)
		p.confirmed.replace(compressed)
	}
	return p.confirmed.maintain(ctx, true)
}
func (p *RouterInfoPublisher) HandleDeliveryStatus(status i2np.DeliveryStatusMessage) bool {
	return p.confirmed.handle(status)
}
