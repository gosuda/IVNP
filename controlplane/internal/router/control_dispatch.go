package router

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

type ControlSinks struct {
	DatabaseLookup      func(foundation.I2NPDatabaseLookupMessage) error
	DatabaseSearchReply func(context.Context, foundation.I2NPDatabaseSearchReplyMessage) error
	// Expected lookup replies must be classified before admission and completion.
	DatabaseStoreExpected    func(foundation.I2NPDatabaseStoreMessage) bool
	DatabaseStoreCompleted   func(context.Context, foundation.I2NPDatabaseStoreMessage)
	DatabaseStoreFlood       func(dataplane.RouterI2NPSource, foundation.I2NPDatabaseStoreMessage) error
	DatabaseStoreReply       func(context.Context, foundation.Hash, uint32, foundation.I2NPDeliveryStatusMessage) error
	DeliveryStatus           func(foundation.I2NPDeliveryStatusMessage) error
	TunnelBuild              func(context.Context, dataplane.RouterI2NPSource, foundation.I2NPBuildRecords, foundation.I2NPMessage) error
	OutboundTunnelBuildReply func(foundation.I2NPMessage) error
	TunnelTest               func(foundation.I2NPDeliveryStatusMessage) error
}

type ControlDispatcherConfig struct {
	QueueLimits dataplane.RouterControlQueueLimits
	// HandlerTimeout bounds each execution; zero selects 30 seconds.
	HandlerTimeout time.Duration
}

type ControlDispatcher struct {
	database       *controlplanenetdb.Database
	sinks          ControlSinks
	queue          *dataplane.RouterControlQueue
	handlerTimeout time.Duration
}

func NewControlDispatcher(database *controlplanenetdb.Database, sinks ControlSinks, config ControlDispatcherConfig) (*ControlDispatcher, error) {
	if config.HandlerTimeout < 0 {
		return nil, errors.New("router: negative control handler timeout")
	}
	if config.HandlerTimeout == 0 {
		config.HandlerTimeout = 30 * time.Second
	}
	dispatcher := &ControlDispatcher{database: database, sinks: sinks, handlerTimeout: config.HandlerTimeout}
	queue, err := dataplane.RouterNewControlQueue(dispatcher, config.QueueLimits)
	if err != nil {
		return nil, err
	}
	dispatcher.queue = queue
	return dispatcher, nil
}

func (d *ControlDispatcher) Enqueue(incoming dataplane.RouterControlMessage) error {
	if incoming.Message.Header.Type == foundation.I2NPDatabaseStore && d.sinks.DatabaseStoreExpected != nil {
		store, err := foundation.I2NPParseDatabaseStore(incoming.Message.Payload)
		if err != nil {
			return err
		}
		// A queued reply may outlive the request that made its contents private.
		incoming.PrivateStore = incoming.PrivateStore || d.sinks.DatabaseStoreExpected(store)
	}
	return d.queue.Enqueue(incoming)
}

func (d *ControlDispatcher) Start(ctx context.Context) error    { return d.queue.Start(ctx) }
func (d *ControlDispatcher) Close() error                       { return d.queue.Close() }
func (d *ControlDispatcher) WaitIdle(ctx context.Context) error { return d.queue.WaitIdle(ctx) }
func (d *ControlDispatcher) Barrier(ctx context.Context) error  { return d.queue.Barrier(ctx) }

func (d *ControlDispatcher) Accepts(message foundation.I2NPMessage) bool {
	switch message.Header.Type {
	case foundation.I2NPDatabaseStore:
		return d.database != nil && len(message.Payload) >= 37 && (binary.BigEndian.Uint32(message.Payload[33:37]) == 0 || d.sinks.DatabaseStoreReply != nil)
	case foundation.I2NPDatabaseLookup:
		return d.sinks.DatabaseLookup != nil
	case foundation.I2NPDatabaseSearchReply:
		return d.sinks.DatabaseSearchReply != nil
	case foundation.I2NPDeliveryStatus:
		return d.sinks.DeliveryStatus != nil
	case foundation.I2NPOutboundTunnelBuildReply:
		return d.sinks.OutboundTunnelBuildReply != nil
	case foundation.I2NPTunnelBuild, foundation.I2NPTunnelBuildReply, foundation.I2NPVariableTunnelBuild, foundation.I2NPVariableTunnelBuildReply, foundation.I2NPShortTunnelBuild:
		return d.sinks.TunnelBuild != nil
	case foundation.I2NPTunnelTest:
		return d.sinks.TunnelTest != nil
	default:
		return false
	}
}

func (d *ControlDispatcher) HandleControl(ctx context.Context, incoming dataplane.RouterControlMessage) error {
	ctx, cancel := context.WithTimeout(ctx, d.handlerTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	message := incoming.Message
	if !d.Accepts(message) {
		return dataplane.RouterErrUnhandledI2NP
	}
	switch message.Header.Type {
	case foundation.I2NPDatabaseStore:
		store, err := foundation.I2NPParseDatabaseStore(message.Payload)
		if err != nil {
			return err
		}
		private := incoming.PrivateStore || d.sinks.DatabaseStoreExpected != nil && d.sinks.DatabaseStoreExpected(store)
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := d.database.HandleDatabaseStoreAsPublished(store, incoming.FromFloodfill, incoming.NowMillis, !private); err != nil {
			return err
		}
		if d.sinks.DatabaseStoreCompleted != nil {
			d.sinks.DatabaseStoreCompleted(ctx, store)
		}
		if store.ReplyToken == 0 {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		var floodErr error
		if d.sinks.DatabaseStoreFlood != nil {
			floodErr = d.sinks.DatabaseStoreFlood(incoming.Source, store)
		}
		replyErr := d.sinks.DatabaseStoreReply(ctx, store.ReplyGateway, store.ReplyTunnelID, foundation.I2NPDeliveryStatusMessage{MessageID: store.ReplyToken, Timestamp: incoming.NowMillis})
		return errors.Join(floodErr, replyErr)
	case foundation.I2NPDatabaseLookup:
		lookup, err := foundation.I2NPParseDatabaseLookup(message.Payload)
		if err != nil {
			return err
		}
		return d.sinks.DatabaseLookup(lookup)
	case foundation.I2NPDatabaseSearchReply:
		reply, err := foundation.I2NPParseDatabaseSearchReply(message.Payload)
		if err != nil {
			return err
		}
		return d.sinks.DatabaseSearchReply(ctx, reply)
	case foundation.I2NPDeliveryStatus:
		status, err := foundation.I2NPParseDeliveryStatus(message.Payload)
		if err != nil {
			return err
		}
		return d.sinks.DeliveryStatus(status)
	case foundation.I2NPOutboundTunnelBuildReply:
		if _, err := foundation.I2NPParseBuildRecords(message.Header.Type, message.Payload); err != nil {
			return err
		}
		return d.sinks.OutboundTunnelBuildReply(message)
	case foundation.I2NPTunnelBuild, foundation.I2NPTunnelBuildReply, foundation.I2NPVariableTunnelBuild, foundation.I2NPVariableTunnelBuildReply, foundation.I2NPShortTunnelBuild:
		records, err := foundation.I2NPParseBuildRecords(message.Header.Type, message.Payload)
		if err != nil {
			return err
		}
		return d.sinks.TunnelBuild(ctx, incoming.Source, records, message)
	case foundation.I2NPTunnelTest:
		status, err := foundation.I2NPParseTunnelTest(message.Payload)
		if err != nil {
			return err
		}
		return d.sinks.TunnelTest(status)
	}
	return dataplane.RouterErrUnhandledI2NP
}
