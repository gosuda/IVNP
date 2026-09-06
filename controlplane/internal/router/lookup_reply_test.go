package router

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

type encryptedLookupReplyCapture struct {
	mu      sync.Mutex
	message foundation.I2NPMessage
	ready   chan struct{}
}

func (capture *encryptedLookupReplyCapture) SendNetDBReply(_ context.Context, _ foundation.Hash, _ uint32, message foundation.I2NPMessage) error {
	capture.mu.Lock()
	capture.message = foundation.I2NPMessage{Header: message.Header, Payload: append([]byte(nil), message.Payload...)}
	capture.mu.Unlock()
	select {
	case capture.ready <- struct{}{}:
	default:
	}
	return nil
}

func TestLookupResponderEncryptsECIESReplyEndToEnd(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	local, from, key := foundation.Hash{1}, foundation.Hash{2}, foundation.Hash{3}
	var replyKey [32]byte
	var replyTag [8]byte
	for index := range replyKey {
		replyKey[index] = byte(index + 1)
	}
	for index := range replyTag {
		replyTag[index] = byte(index + 33)
	}

	wireLookup := make([]byte, 32+32+1+2+32+1+8)
	copy(wireLookup[:32], key[:])
	copy(wireLookup[32:64], from[:])
	wireLookup[64] = uint8(controlplanenetdb.RouterInfoLookup<<2) | 1<<4
	binary.BigEndian.PutUint16(wireLookup[65:67], 0)
	copy(wireLookup[67:99], replyKey[:])
	wireLookup[99] = 1
	copy(wireLookup[100:], replyTag[:])
	lookup, err := foundation.I2NPParseDatabaseLookup(wireLookup)
	if err != nil {
		t.Fatal(err)
	}

	capture := &encryptedLookupReplyCapture{ready: make(chan struct{}, 1)}
	responder, err := controlplanenetdb.NewLookupResponder(controlplanenetdb.LookupResponderConfig{
		Database: controlplanenetdb.NewDatabase(local, controlplanenetdb.DefaultBucketCapacity),
		Sender:   capture,
		Local:    local,
		Now:      func() uint64 { return now },
		Random:   func() uint32 { return 7 },
		Wrapper:  dataplane.GarlicDatabaseLookupReplyWrapper{MessageID: func() uint32 { return 8 }},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = responder.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = responder.Enqueue(lookup); err != nil {
		t.Fatal(err)
	}
	select {
	case <-capture.ready:
	case <-time.After(time.Second):
		t.Fatal("encrypted lookup reply was not sent")
	}
	if err = responder.Close(); err != nil {
		t.Fatal(err)
	}

	capture.mu.Lock()
	outer := capture.message
	capture.mu.Unlock()
	if outer.Header.Type != foundation.I2NPGarlic {
		t.Fatalf("encrypted response type = %d, want Garlic", outer.Header.Type)
	}
	registry := dataplane.GarlicNewReplyKeyRegistry(1)
	if err = registry.RegisterGarlicReplyKey(dataplane.GarlicReplyKey{
		Key: replyKey, Tag: replyTag, ExpiresAt: now + 60_000,
	}); err != nil {
		t.Fatal(err)
	}
	var search foundation.I2NPDatabaseSearchReplyMessage
	service, queue := newControlServiceForTest(t, nil, ControlSinks{DatabaseSearchReply: func(_ context.Context, reply foundation.I2NPDatabaseSearchReplyMessage) error {
		search = reply
		return nil
	}})
	receiver, err := dataplane.RouterNewGarlicReceiver(dataplane.RouterGarlicReceiverConfig{
		Service: service, ReplyKeys: registry, Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	service.SetGarlicSink(receiver.HandleGarlicFrom)
	if err = service.HandleI2NP(outer, now, false); err != nil {
		t.Fatal(err)
	}
	if registry.Len() != 0 {
		t.Fatal("authenticated lookup reply tag was not consumed")
	}
	if err := queue.WaitIdle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if search.Key != key || search.From != local {
		t.Fatalf("decrypted search reply = %#v", search)
	}
}

func TestLookupResponderRejectsIncompleteEncryptedMetadataAtIngress(t *testing.T) {
	local := foundation.Hash{1}
	capture := &encryptedLookupReplyCapture{ready: make(chan struct{}, 1)}
	responder, err := controlplanenetdb.NewLookupResponder(controlplanenetdb.LookupResponderConfig{
		Database: controlplanenetdb.NewDatabase(local, controlplanenetdb.DefaultBucketCapacity),
		Sender:   capture,
		Local:    local,
		Now:      func() uint64 { return 1_700_000_000_000 },
		Random:   func() uint32 { return 1 },
		Wrapper:  dataplane.GarlicDatabaseLookupReplyWrapper{MessageID: func() uint32 { return 2 }},
	})
	if err != nil {
		t.Fatal(err)
	}
	lookup := foundation.I2NPDatabaseLookupMessage{
		Key: foundation.Hash{3}, From: foundation.Hash{2}, Flags: 1 << 4, ReplyKey: make([]byte, 32), ReplyTagLen: 8,
	}
	if err = responder.Enqueue(lookup); !errors.Is(err, dataplane.GarlicErrLookupReply) {
		t.Fatalf("Enqueue() = %v, want ErrLookupReply", err)
	}
	if err = responder.Close(); err != nil {
		t.Fatal(err)
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.message.Header.Type != 0 {
		t.Fatalf("invalid encrypted lookup was enqueued: %#v", capture.message)
	}
}
