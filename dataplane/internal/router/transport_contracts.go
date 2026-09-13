package router

import (
	"context"
	"errors"
	"net"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/ingress"
)

var (
	ErrStarted    = errors.New("router: already started")
	ErrPeerDenied = errors.New("router: peer denied by admission policy")
)

// PeerTransport identifies the transport protocol carrying a peer session.
type PeerTransport uint8

const (
	PeerTransportNTCP2 PeerTransport = iota + 1
	PeerTransportSSU2
)

func (t PeerTransport) String() string {
	switch t {
	case PeerTransportNTCP2:
		return "NTCP2"
	case PeerTransportSSU2:
		return "SSU2"
	default:
		return "unknown"
	}
}

// PeerAdmission presents one authenticated transport peer for policy approval.
// RouterInfo is the signature-verified, netId-matched peer record — for
// inbound peers it was received in the handshake and bound to the session
// static key; for outbound peers it is the record being dialed. RouterInfo is
// a view over transport-owned bytes and must not be retained after the
// callback returns.
type PeerAdmission struct {
	Peer       foundation.Hash
	RouterInfo foundation.NetworkDatabaseRouterInfo
	Transport  PeerTransport
	Inbound    bool
	RemoteAddr net.Addr
}

// PeerAdmissionFunc approves a verified transport peer before its session is
// installed. A non-nil error denies the session. The callback runs
// synchronously on transport setup paths, so it must be fast and bounded;
// ctx carries the handshake or dial deadline.
type PeerAdmissionFunc func(context.Context, PeerAdmission) error

// runPeerAdmission invokes fn with panic containment: a panicking callback is
// reported through reporter and treated as denial. Every denial — callback
// error or panic — carries ErrPeerDenied so classification and callers can
// recognize policy rejections uniformly.
func runPeerAdmission(ctx context.Context, fn PeerAdmissionFunc, reporter ingress.Reporter, boundary ingress.Boundary, request PeerAdmission) (err error) {
	if fn == nil {
		return nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errors.Join(ingress.Report(recovered, reporter, boundary, request.RemoteAddr), ErrPeerDenied)
		}
	}()
	if err = fn(ctx, request); err != nil {
		err = errors.Join(err, ErrPeerDenied)
	}
	return err
}

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
