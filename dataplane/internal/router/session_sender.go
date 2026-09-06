package router

import (
	"context"
	"errors"
	"net/netip"

	dataplanentcp2 "gosuda.org/ivnp/dataplane/internal/transport/ntcp2"
	"gosuda.org/ivnp/foundation"
)

var ErrSessionUnavailable = errors.New("router: authenticated session unavailable")

// SessionSender borrows one authenticated session and consumes Payload before
// returning. Send honors cancellation while waiting for serialization or I/O;
// it never retries, resolves, or dials. The manager retains session ownership.
type SessionSender interface {
	Send(context.Context, foundation.I2NPMessage) error
}

type SessionProvider interface {
	PreparedSession(foundation.Hash) (SessionSender, error)
}

// TransportPeerSource supplies verified setup inputs and owns admission policy.
// Implementations must not retain packet payloads or execute bulk delivery.
type TransportPeerSource interface {
	RouterInfo(foundation.Hash) (foundation.NetworkDatabaseRouterInfo, bool)
	DialRouterInfo(foundation.Hash, uint64) (foundation.NetworkDatabaseRouterInfo, error)
	AdmitRouterInfo(foundation.NetworkDatabaseRouterInfo, uint64) error
	PeerAtEndpoint(netip.AddrPort) (foundation.Hash, bool)
}

type ntcp2SessionSender struct {
	manager *NTCP2Manager
	peer    foundation.Hash
	session *dataplanentcp2.Session
}

func (m *NTCP2Manager) PreparedSession(peer foundation.Hash) (SessionSender, error) {
	session := m.session(peer)
	if session == nil || m.contextErr() != nil {
		return nil, ErrSessionUnavailable
	}
	return ntcp2SessionSender{manager: m, peer: peer, session: session}, nil
}

func (s ntcp2SessionSender) Send(ctx context.Context, message foundation.I2NPMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ctx.Done() == nil {
		return s.sendBulk(ctx, message)
	}
	retired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		// A partial TCP frame consumes the cipher nonce. Retire exactly this
		// session, never a replacement installed for the same peer.
		_ = s.session.Close()
		close(retired)
	})
	err := s.sendBulk(ctx, message)
	if !stop() {
		<-retired
		return errors.Join(ctx.Err(), err)
	}
	return err
}

func (s ntcp2SessionSender) sendBulk(ctx context.Context, message foundation.I2NPMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.manager.contextErr() != nil || s.manager.session(s.peer) != s.session {
		return ErrSessionUnavailable
	}
	return s.manager.writeI2NP(s.session, message)
}

type ssu2SessionSender struct {
	manager *SSU2Manager
	session *ssu2TransportSession
}

func (m *SSU2Manager) PreparedSession(peer foundation.Hash) (SessionSender, error) {
	session := m.sessionForSend(peer)
	if session == nil {
		return nil, ErrSessionUnavailable
	}
	return ssu2SessionSender{manager: m, session: session}, nil
}

func (m *SSU2Manager) sessionForSend(peer foundation.Hash) *ssu2TransportSession {
	m.mu.RLock()
	session := m.sessionsByPeer[peer]
	active := m.runningLocked() && session != nil && !session.idle(m.nowLocked(), m.idleTimeout)
	m.mu.RUnlock()
	if !active {
		return nil
	}
	return session
}

func (s ssu2SessionSender) Send(ctx context.Context, message foundation.I2NPMessage) error {
	return s.send(ctx, message, true)
}

func (s ssu2SessionSender) send(ctx context.Context, message foundation.I2NPMessage, interruptible bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(message.Payload) > foundation.I2NPI2PDMaxPayload {
		return foundation.I2NPErrPayloadTooLarge
	}
	if !s.manager.sessionActive(s.session) || s.manager.contextErr() != nil {
		return ErrSessionUnavailable
	}
	if interruptible {
		if err := s.session.frameMu.LockContext(ctx); err != nil {
			return err
		}
	} else {
		s.session.frameMu.Lock()
	}
	defer s.session.frameMu.Unlock()
	return forEachSSU2I2NPFragment(s.session.frame[:], message, ssu2SessionPacketSize(s.session), func(payload []byte, _ bool) error {
		return s.manager.sendSessionDataContext(ctx, s.session, payload, ssu2SessionDataOptions{
			reliable: true, congestionControlled: true, waitEgress: true, interruptible: interruptible,
		})
	})
}
