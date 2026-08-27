package destination

import (
	"context"
	"net"
	"sync"

	"gosuda.org/ivnp/foundation"
)

// DestinationResolver resolves human-readable I2P hostnames (like example.i2p) or parses full Base64 destinations.
type DestinationResolver interface {
	ResolveDestination(context.Context, string) (string, error)
}

// LeaseSetPolicy defines publication and encryption options for local destinations.
type LeaseSetPolicy struct {
	Encrypted  bool
	Secret     []byte
	DHClients  [][32]byte
	PSKClients [][32]byte
	// CryptoTypes specifies preferred encryption key types in order of priority.
	CryptoTypes []uint16
}

// DestinationSpec holds configuration and keys for creating a local destination.
// The destination controller creates an internal copy of the key material.
type DestinationSpec struct {
	Local  *foundation.LocalDestination
	Policy LeaseSetPolicy
}

// DestinationRoute matches an I2CP protocol and local port. Port 0 acts as a wildcard.
type DestinationRoute struct {
	Protocol uint8
	ToPort   uint16
}

// Delivery represents an authenticated incoming I2CP message payload.
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

// NewReceivedMessage creates a message with a cleanup hook invoked on release.
func NewReceivedMessage(delivery Delivery, release func(int)) *ReceivedMessage {
	return &ReceivedMessage{Delivery: delivery, release: release, size: len(delivery.Payload)}
}

// ByteBudget tracks memory or bandwidth consumption without blocking.
type ByteBudget interface {
	TryReserve(int) bool
	Release(int)
}

// MessageSubscription is a stream of incoming messages matching a route.
type MessageSubscription interface {
	Receive(context.Context) (*ReceivedMessage, error)
	Close() error
}

// DestinationEndpoint provides network operations (dial, listen, send, subscribe) for a local destination.
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

// SourcePortDestinationEndpoint is an optional interface for endpoints that allow selecting the local virtual port.
type SourcePortDestinationEndpoint interface {
	DialI2PFromPort(context.Context, string, uint16) (net.Conn, error)
}

// BoundedDestinationEndpoint supports subscriptions bounded by both per-route queue limits and a shared byte budget.
type BoundedDestinationEndpoint interface {
	SubscribeBounded(DestinationRoute, int, int64, ByteBudget) (MessageSubscription, error)
}

// ReadyDestinationEndpoint blocks until the destination has active tunnels and published LeaseSets.
type ReadyDestinationEndpoint interface {
	WaitReady(context.Context) error
}

// DestinationController manages the lifecycle of local destinations for client protocols like SAM.
type DestinationController interface {
	CreateDestination(context.Context, DestinationSpec) (DestinationEndpoint, error)
	DestroyDestination(context.Context, DestinationEndpoint) error
}
