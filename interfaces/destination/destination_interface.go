package destination

import (
	"context"
	"gosuda.org/ivnp/foundation"
	"net"
	"sync"
)

// DestinationResolver resolves an ASCII I2P name or validates a literal full
// Destination. Implementations return a canonical full Destination encoding.
type DestinationResolver interface {
	ResolveDestination(context.Context, string) (string, error)
}

// LeaseSetPolicy is the protocol-neutral publication policy used by local
// client APIs. Authentication material is consumed during destination creation
// and must never be returned in a status response.
type LeaseSetPolicy struct {
	Encrypted  bool
	Secret     []byte
	DHClients  [][32]byte
	PSKClients [][32]byte
	// CryptoTypes is an ordered preference list. The daemon rejects values it
	// cannot publish rather than silently changing the requested policy.
	CryptoTypes []uint16
}

// DestinationSpec describes one transient local Destination. The controller
// takes its own sensitive clone; callers retain and must release Local.
type DestinationSpec struct {
	Local  *foundation.LocalDestination
	Policy LeaseSetPolicy
}

// DestinationRoute identifies one I2CP protocol and local port. ToPort zero is
// a wildcard for the protocol.
type DestinationRoute struct {
	Protocol uint8
	ToPort   uint16
}

// Delivery is one authenticated payload routed to a local destination.
// Implementations which retain Payload must copy it before returning.
type Delivery struct {
	From, To         foundation.Hash
	FromPort, ToPort uint16
	Protocol         uint8
	Payload          []byte
}

type ReceivedMessage struct {
	Delivery Delivery
	release  func(int)
	size     int
	once     sync.Once
}

func (m *ReceivedMessage) Release() {
	if m == nil {
		return
	}
	m.once.Do(func() {
		clear(m.Delivery.Payload)
		m.Delivery.Payload = nil
		if m.release != nil {
			m.release(m.size)
		}
	})
}

// NewReceivedMessage transfers payload ownership to a releasable message.
// release is invoked exactly once with the retained payload size.
func NewReceivedMessage(delivery Delivery, release func(int)) *ReceivedMessage {
	return &ReceivedMessage{Delivery: delivery, release: release, size: len(delivery.Payload)}
}

// ByteBudget is the neutral non-blocking accounting boundary used by queued
// destination message routes.
type ByteBudget interface {
	TryReserve(int) bool
	Release(int)
}

// MessageSubscription is a bounded destination-message route.
type MessageSubscription interface {
	Receive(context.Context) (*ReceivedMessage, error)
	Close() error
}

// DestinationEndpoint is the narrow client-facing view of one daemon-owned,
// destination-isolated graph.
type DestinationEndpoint interface {
	Hash() foundation.Hash
	B32() string
	Destination() []byte
	DialI2P(context.Context, string) (net.Conn, error)
	ListenI2P(context.Context, string) (net.Listener, error)
	SendMessage(context.Context, Delivery) error
	MarshalDatagramV1To([]byte, []byte) (int, error)
	Subscribe(DestinationRoute, int) (MessageSubscription, error)
	Close() error
}

// SourcePortDestinationEndpoint is implemented by destination runtimes that
// support selecting the local virtual port of an outbound Streaming connection.
// It is optional so neutral test and external implementations remain compatible.
type SourcePortDestinationEndpoint interface {
	DialI2PFromPort(context.Context, string, uint16) (net.Conn, error)
}

// BoundedDestinationEndpoint installs a route whose retained payloads are
// charged to both a per-route limit and the supplied aggregate budget.
type BoundedDestinationEndpoint interface {
	SubscribeBounded(DestinationRoute, int, int64, ByteBudget) (MessageSubscription, error)
}

// ReadyDestinationEndpoint blocks until owner-bound inbound and outbound
// tunnels are usable and the current LeaseSet publication is confirmed.
type ReadyDestinationEndpoint interface {
	WaitReady(context.Context) error
}

// DestinationController is implemented by the daemon and consumed by local
// protocols such as SAM. The protocol package never owns pools or imports the
// daemon. DestroyDestination is the authoritative teardown boundary.
type DestinationController interface {
	CreateDestination(context.Context, DestinationSpec) (DestinationEndpoint, error)
	DestroyDestination(context.Context, DestinationEndpoint) error
}
