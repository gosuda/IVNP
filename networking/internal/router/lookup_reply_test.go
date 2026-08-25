package router

import (
	"context"
	"encoding/binary"
	"errors"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/garlic"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/network_database"
	"gosuda.org/ivnp/networking/internal/tunnel"
	"sync"
	"testing"
	"time"
)

type encryptedLookupReplyCapture struct {
	mu      sync.Mutex
	message i2np.Message
	ready   chan struct{}
}

func (capture *encryptedLookupReplyCapture) SendNetDBReply(_ context.Context, _ foundation.Hash, _ uint32, message i2np.Message) error {
	capture.mu.Lock()
	capture.message = i2np.Message{Header: message.Header, Payload: append([]byte(nil), message.Payload...)}
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
	wireLookup[64] = uint8(networkdatabase.RouterInfoLookup<<2) | 1<<4
	binary.BigEndian.PutUint16(wireLookup[65:67], 0)
	copy(wireLookup[67:99], replyKey[:])
	wireLookup[99] = 1
	copy(wireLookup[100:], replyTag[:])
	lookup, err := i2np.ParseDatabaseLookup(wireLookup)
	if err != nil {
		t.Fatal(err)
	}

	capture := &encryptedLookupReplyCapture{ready: make(chan struct{}, 1)}
	responder, err := networkdatabase.NewLookupResponder(networkdatabase.LookupResponderConfig{
		Database: networkdatabase.NewDatabase(local, networkdatabase.DefaultBucketCapacity),
		Sender:   capture,
		Local:    local,
		Now:      func() uint64 { return now },
		Random:   func() uint32 { return 7 },
		Wrapper:  garlic.DatabaseLookupReplyWrapper{MessageID: func() uint32 { return 8 }},
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
	if outer.Header.Type != i2np.Garlic {
		t.Fatalf("encrypted response type = %d, want Garlic", outer.Header.Type)
	}
	registry := garlic.NewReplyKeyRegistry(1)
	if err = registry.RegisterGarlicReplyKey(tunnel.GarlicReplyKey{
		Key: replyKey, Tag: replyTag, ExpiresAt: now + 60_000,
	}); err != nil {
		t.Fatal(err)
	}
	var search i2np.DatabaseSearchReplyMessage
	service := NewWithSinks(nil, Sinks{DatabaseSearchReply: func(reply i2np.DatabaseSearchReplyMessage) error {
		search = reply
		return nil
	}})
	receiver, err := NewGarlicReceiver(GarlicReceiverConfig{
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
	if search.Key != key || search.From != local {
		t.Fatalf("decrypted search reply = %#v", search)
	}
}

func TestLookupResponderRejectsIncompleteEncryptedMetadataAtIngress(t *testing.T) {
	local := foundation.Hash{1}
	capture := &encryptedLookupReplyCapture{ready: make(chan struct{}, 1)}
	responder, err := networkdatabase.NewLookupResponder(networkdatabase.LookupResponderConfig{
		Database: networkdatabase.NewDatabase(local, networkdatabase.DefaultBucketCapacity),
		Sender:   capture,
		Local:    local,
		Now:      func() uint64 { return 1_700_000_000_000 },
		Random:   func() uint32 { return 1 },
		Wrapper:  garlic.DatabaseLookupReplyWrapper{MessageID: func() uint32 { return 2 }},
	})
	if err != nil {
		t.Fatal(err)
	}
	lookup := i2np.DatabaseLookupMessage{
		From: foundation.Hash{2}, Flags: 1 << 4, ReplyKey: make([]byte, 32), ReplyTagLen: 8,
	}
	if err = responder.Enqueue(lookup); !errors.Is(err, garlic.ErrLookupReply) {
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
