package noderuntime

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

const (
	replyRouterInfoPayloadCapacity = 128
	replyRouterInfoSeedCapacity    = 1024
	replyRouterInfoSeedLifetime    = uint64(5 * time.Minute / time.Millisecond)
)

type replyRouterInfoPayload struct {
	wire []byte
	used uint64
}

type replyRouterInfoSeedKey struct {
	endpoint foundation.Hash
	snapshot foundation.Hash
	session  dataplane.RouterSessionSender
}

type replyRouterInfoSeed struct {
	done chan struct{}
	sent uint64
}

type replyRouterInfoSeeds struct {
	mu        sync.Mutex
	sequence  uint64
	payloads  map[foundation.Hash]replyRouterInfoPayload
	seeds     map[replyRouterInfoSeedKey]*replyRouterInfoSeed
	nextSweep uint64
	closed    bool
}

type replyRouterInfoSessionPreparer interface {
	PrepareSession(context.Context, foundation.Hash) (dataplane.RouterSessionSender, error)
}

// close releases cached handles and wakes waiters. Transport owners drain active
// sends separately; their borrowed payloads must remain intact until completion.
func (s *replyRouterInfoSeeds) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, entry := range s.seeds {
		if entry.done != nil {
			close(entry.done)
			entry.done = nil
		}
	}
	s.seeds = nil
	s.payloads = nil
}

func (s *replyRouterInfoSeeds) expire(now uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if now < s.nextSweep {
		return nil
	}
	for key, entry := range s.seeds {
		if entry.done == nil && (now < entry.sent || now-entry.sent >= replyRouterInfoSeedLifetime) {
			delete(s.seeds, key)
		}
	}
	s.nextSweep = now + 60_000
	return nil
}

func (s *replyRouterInfoSeeds) seed(ctx context.Context, database *netdb.Database, sender dataplane.TunnelSender, now func() uint64, endpoint, replyRouter foundation.Hash) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.expire(now()); err != nil {
			return err
		}
		var session dataplane.RouterSessionSender
		if preparer, ok := sender.(replyRouterInfoSessionPreparer); ok {
			var err error
			session, err = preparer.PrepareSession(ctx, endpoint)
			if err != nil {
				return err
			}
		}
		ref, ok := database.Routers().Get(replyRouter)
		if !ok {
			return fmt.Errorf("daemon: reply-gateway RouterInfo unavailable")
		}
		if err := netdb.RouterInfoFresh(ref.Info, now()); err != nil {
			return err
		}
		snapshot, payload, err := s.payload(ref.Info)
		if err != nil {
			return err
		}
		// Native handles contain the exact manager and session pointers. Unknown
		// handle representations cannot safely promise session-scoped suppression.
		if session == nil || !reflect.ValueOf(session).Comparable() {
			return sendReplyRouterInfo(ctx, sender, session, endpoint, payload, now)
		}
		key := replyRouterInfoSeedKey{endpoint: endpoint, snapshot: snapshot, session: session}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return net.ErrClosed
		}
		current := now()
		entry := s.seeds[key]
		if entry != nil && entry.done != nil {
			done := entry.done
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-done:
				continue // Reacquire the current snapshot and transport session.
			}
		}
		if entry != nil && current >= entry.sent && current-entry.sent < replyRouterInfoSeedLifetime {
			s.mu.Unlock()
			return ctx.Err()
		}
		if s.seeds == nil {
			s.seeds = make(map[replyRouterInfoSeedKey]*replyRouterInfoSeed)
		}
		if entry == nil && len(s.seeds) >= replyRouterInfoSeedCapacity {
			var oldestKey replyRouterInfoSeedKey
			var oldest *replyRouterInfoSeed
			for candidate, value := range s.seeds {
				if value.done == nil && (oldest == nil || value.sent < oldest.sent) {
					oldestKey, oldest = candidate, value
				}
			}
			if oldest == nil {
				s.mu.Unlock()
				return sendReplyRouterInfo(ctx, sender, session, endpoint, payload, now)
			}
			delete(s.seeds, oldestKey)
		}
		entry = &replyRouterInfoSeed{done: make(chan struct{})}
		s.seeds[key] = entry
		s.mu.Unlock()

		err = sendReplyRouterInfo(ctx, sender, session, endpoint, payload, now)
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return err
		}
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			delete(s.seeds, key)
		} else {
			entry.sent = now()
		}
		close(entry.done)
		entry.done = nil
		s.mu.Unlock()
		return err
	}
}

func (s *replyRouterInfoSeeds) payload(info foundation.NetworkDatabaseRouterInfo) (foundation.Hash, []byte, error) {
	snapshot := foundation.Sum(info.Bytes())
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return snapshot, nil, net.ErrClosed
	}
	s.sequence++
	if payload, ok := s.payloads[snapshot]; ok {
		payload.used = s.sequence
		s.payloads[snapshot] = payload
		return snapshot, payload.wire, nil
	}
	// Table admission verifies signatures; the cache only owns the encoding.
	compressed, err := foundation.NetworkDatabaseCompressRouterInfo(info.Bytes())
	if err != nil {
		return snapshot, nil, err
	}
	payload, err := foundation.NetworkDatabaseMarshalDatabaseStore(info.Hash(), foundation.I2NPStoreRouterInfo, compressed, 0, foundation.Hash{}, 0)
	if err != nil {
		return snapshot, nil, err
	}
	if s.payloads == nil {
		s.payloads = make(map[foundation.Hash]replyRouterInfoPayload)
	}
	if len(s.payloads) >= replyRouterInfoPayloadCapacity {
		var oldest foundation.Hash
		used := s.sequence
		for key, value := range s.payloads {
			if value.used < used {
				oldest, used = key, value.used
			}
		}
		delete(s.payloads, oldest)
	}
	s.payloads[snapshot] = replyRouterInfoPayload{wire: payload, used: s.sequence}
	return snapshot, payload, nil
}

func sendReplyRouterInfo(ctx context.Context, sender dataplane.TunnelSender, session dataplane.RouterSessionSender, endpoint foundation.Hash, payload []byte, now func() uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	messageID, err := randomMessageID()
	if err != nil {
		return err
	}
	message := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: messageID, Expiration: now() + 60_000},
		Payload: payload,
	}
	if session != nil {
		err = session.Send(ctx, message)
	} else {
		// Only prepared sessions guarantee synchronous consumption of borrowed payloads.
		message.Payload = bytes.Clone(payload)
		err = sender.Send(ctx, endpoint, message)
	}
	if err == nil {
		err = ctx.Err()
	}
	return err
}
