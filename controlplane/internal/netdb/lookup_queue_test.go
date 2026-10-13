package netdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

func newAdmissionResponder(t *testing.T) (*LookupResponder, *Database) {
	t.Helper()
	local := foundation.Hash{90}
	database := NewDatabase(local, DefaultBucketCapacity)
	responder, err := NewLookupResponder(LookupResponderConfig{
		Database: database, Sender: &lookupReplyCapture{ready: make(chan struct{}, 1)},
		Local: local, Now: func() uint64 { return 100 }, Random: func() uint32 { return 7 },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := responder.Close(); err != nil {
			t.Error(err)
		}
	})
	return responder, database
}

func TestLookupResponderRejectsUnverifiedReturnRoutes(t *testing.T) {
	r, database := newAdmissionResponder(t)
	peer, stranger, key := foundation.Hash{1}, foundation.Hash{2}, foundation.Hash{3}
	source := LookupSource{Peer: peer, Direct: true}
	base := foundation.I2NPDatabaseLookupMessage{Key: key, From: peer, Flags: uint8(RouterInfoLookup << 2)}
	for _, tc := range []struct {
		name   string
		source LookupSource
		lookup foundation.I2NPDatabaseLookupMessage
	}{
		{"spoofed direct return", source, foundation.I2NPDatabaseLookupMessage{Key: key, From: stranger}},
		{"anonymous direct return", LookupSource{}, base},
		{"zero return hash", source, foundation.I2NPDatabaseLookupMessage{Key: key}},
		{"direct reply with tunnel ID", source, foundation.I2NPDatabaseLookupMessage{Key: key, From: peer, ReplyTunnelID: 9}},
		{"tunnel reply missing ID", source, foundation.I2NPDatabaseLookupMessage{Key: key, From: stranger, Flags: 1}},
		{"unverified tunnel gateway", source, foundation.I2NPDatabaseLookupMessage{Key: key, From: stranger, Flags: 1, ReplyTunnelID: 9}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := r.Enqueue(tc.source, tc.lookup); !errors.Is(err, ErrLookupResponderReplyRoute) {
				t.Fatalf("Enqueue() = %v, want invalid route", err)
			}
		})
	}
	if err := r.Enqueue(source, base); err != nil {
		t.Fatalf("authenticated direct lookup: %v", err)
	}
	gateway := routerWithSeed(55)
	database.Routers().StoreVerified(gateway, false, 100)
	tunneled := foundation.I2NPDatabaseLookupMessage{
		Key: key, From: gateway.Hash(), Flags: 1 | uint8(RouterInfoLookup << 2), ReplyTunnelID: 9,
	}
	if err := r.Enqueue(LookupSource{}, tunneled); err != nil {
		t.Fatalf("verified anonymous tunnel lookup: %v", err)
	}
	if err := r.Enqueue(source, tunneled); err != nil {
		t.Fatalf("verified gateway differing from authenticated peer: %v", err)
	}
	if r.queue.reserved != 3 {
		t.Fatalf("reserved = %d, want only 3 accepted routes", r.queue.reserved)
	}
}

func TestLookupResponderSourceLimitIncludesExecutingWork(t *testing.T) {
	r, _ := newAdmissionResponder(t)
	peer := foundation.Hash{1}
	source := LookupSource{Peer: peer, Direct: true}
	lookup := foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{9}, From: peer}
	if err := r.Enqueue(source, lookup); err != nil {
		t.Fatal(err)
	}
	active, ok := r.nextJob(context.Background())
	if !ok || active.source != peer {
		t.Fatalf("active = %#v / %t, want peer", active, ok)
	}
	for i := 1; i < lookupResponderSourceQueue; i++ {
		lookup.Key = foundation.Hash{byte(i + 1)}
		if err := r.Enqueue(source, lookup); err != nil {
			t.Fatalf("admission %d: %v", i, err)
		}
	}
	if err := r.Enqueue(source, lookup); !errors.Is(err, ErrLookupResponderSourceFull) {
		t.Fatalf("in-flight source limit = %v", err)
	}
	clearLookupJob(&active)
	r.completeJob(peer, nil)
	if err := r.Enqueue(source, lookup); err != nil {
		t.Fatalf("slot not returned on completion: %v", err)
	}
}

func TestLookupResponderRoundRobinAndGlobalLimit(t *testing.T) {
	r, _ := newAdmissionResponder(t)
	for p := 1; p <= lookupResponderQueue/lookupResponderSourceQueue; p++ {
		peer := foundation.Hash{byte(p)}
		for i := range lookupResponderSourceQueue {
			lookup := foundation.I2NPDatabaseLookupMessage{
				Key: foundation.Hash{byte(p), byte(i + 1)}, From: peer,
			}
			if err := r.Enqueue(LookupSource{Peer: peer, Direct: true}, lookup); err != nil {
				t.Fatalf("peer %d job %d: %v", p, i, err)
			}
		}
	}
	overflow := foundation.Hash{100}
	if err := r.Enqueue(LookupSource{Peer: overflow, Direct: true},
		foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{10}, From: overflow}); !errors.Is(err, ErrLookupResponderFull) {
		t.Fatalf("global reservation limit = %v", err)
	}
	first, ok := r.nextJob(context.Background())
	if !ok || first.source != (foundation.Hash{1}) {
		t.Fatalf("first source = %x, valid = %t", first.source, ok)
	}
	clearLookupJob(&first)
	r.completeJob(first.source, nil)
	next, ok := r.nextJob(context.Background())
	if !ok || next.source != (foundation.Hash{2}) {
		t.Fatalf("next source = %x, valid = %t; expected round-robin", next.source, ok)
	}
	clearLookupJob(&next)
	r.completeJob(next.source, nil)
	if err := r.Enqueue(LookupSource{Peer: overflow, Direct: true},
		foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{10}, From: overflow}); err != nil {
		t.Fatalf("global reservation not released after completion: %v", err)
	}
}

func TestLookupResponderAnonymousSourcesShareBudget(t *testing.T) {
	r, database := newAdmissionResponder(t)
	gateway := routerWithSeed(56)
	database.Routers().StoreVerified(gateway, false, 100)
	lookup := foundation.I2NPDatabaseLookupMessage{
		From: gateway.Hash(), Flags: 1, ReplyTunnelID: 99,
	}
	for i := range lookupResponderSourceQueue {
		lookup.Key = foundation.Hash{byte(i + 1)}
		if err := r.Enqueue(LookupSource{Peer: foundation.Hash{byte(i + 1)}}, lookup); err != nil {
			t.Fatalf("anonymous lookup %d: %v", i, err)
		}
	}
	lookup.Key = foundation.Hash{99}
	if err := r.Enqueue(LookupSource{}, lookup); !errors.Is(err, ErrLookupResponderSourceFull) {
		t.Fatalf("anonymous source limit = %v", err)
	}
}

type heldLookupReplySender struct {
	entered chan struct{}
	release chan struct{}
}

func (s *heldLookupReplySender) SendNetDBReply(ctx context.Context, _ foundation.Hash, _ uint32, _ foundation.I2NPMessage) error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestLookupResponderSourceReservationHeldThroughSend(t *testing.T) {
	local, peer, other := foundation.Hash{90}, foundation.Hash{1}, foundation.Hash{2}
	sender := &heldLookupReplySender{entered: make(chan struct{}, 1), release: make(chan struct{})}
	responder, err := NewLookupResponder(LookupResponderConfig{
		Database: NewDatabase(local, DefaultBucketCapacity), Sender: sender,
		Local: local, Now: func() uint64 { return 100 }, Random: func() uint32 { return 7 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := responder.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := responder.Close(); err != nil {
			t.Error(err)
		}
	})
	defer close(sender.release)
	source := LookupSource{Peer: peer, Direct: true}
	lookup := foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{10}, From: peer}
	if err := responder.Enqueue(source, lookup); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sender.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not begin reply send")
	}
	for i := 1; i < lookupResponderSourceQueue; i++ {
		lookup.Key = foundation.Hash{byte(i + 10)}
		if err := responder.Enqueue(source, lookup); err != nil {
			t.Fatalf("queued work %d = %v", i, err)
		}
	}
	if err := responder.Enqueue(source, lookup); !errors.Is(err, ErrLookupResponderSourceFull) {
		t.Fatalf("executing sender failed to retain reservation: %v", err)
	}
	if err := responder.Enqueue(LookupSource{Peer: other, Direct: true},
		foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{90}, From: other}); err != nil {
		t.Fatalf("independent source was starved: %v", err)
	}
}
