package router

import (
	"context"
	"errors"
	"net"
	"time"

	"gosuda.org/ivnp/foundation"
)

var ErrStarted = errors.New("router: already started")

type TransportLocalInfo interface {
	Hash() foundation.Hash
	Snapshot() foundation.NetworkDatabaseRouterInfo
}

// Clock centralizes wall-clock conversion for protocol timestamps.
type Clock interface {
	Now() time.Time
}

// WallClock is the standard wall-clock implementation.
type WallClock struct{}

func (WallClock) Now() time.Time { return time.Now() }

// TransportStatus is reported by a TransportManager. Transport-specific state
// belongs to the manager rather than the Router.
type TransportStatus struct {
	Running bool
	Error   error
}

// TransportBindings are the resources a Router gives its transport manager.
// The manager owns session handling; it must not expose native connections as
// purported I2P streams. SSU2 ownership transfers only after Start succeeds.
type TransportBindings struct {
	NTCP2          net.Listener
	SSU2           *net.UDPConn
	LocalInfo      TransportLocalInfo
	HandleI2NP     func(foundation.I2NPMessage, uint64, bool) error
	HandleI2NPFrom func(foundation.Hash, foundation.I2NPMessage, uint64, bool) error
	// HandleI2NPContext is the bounded SSU2 dispatch contract. Implementations
	// must return when ctx is canceled and must not retain message.Payload.
	HandleI2NPContext func(context.Context, foundation.Hash, foundation.I2NPMessage, uint64, bool) error
	Clock             Clock
}

// TransportManager owns peer and session lifecycle around the router-bound
// transport sockets.
type TransportManager interface {
	Start(context.Context, TransportBindings) error
	Close() error
	Wait() error
	Send(context.Context, foundation.Hash, foundation.I2NPMessage) error
	Status() TransportStatus
}
