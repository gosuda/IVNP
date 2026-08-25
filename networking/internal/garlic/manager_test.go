package garlic

import (
	"bytes"
	"errors"
	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/foundation"
	"testing"
)

type countingReader struct{ next byte }

func (r *countingReader) Read(dst []byte) (int, error) {
	for i := range dst {
		dst[i] = r.next
		r.next++
	}
	return len(dst), nil
}

func TestSessionManagerNewThenExistingAndOneUseInboundTag(t *testing.T) {
	public, private, err := cryptography.GenerateElGamalKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	peer := foundation.Hash{1}
	sender := NewSessionManager(SessionManagerConfig{
		TagsPerMessage: 1,
		Random:         &countingReader{},
	})
	receiver := NewSessionManager(SessionManagerConfig{})

	first, err := sender.Encrypt(make([]byte, 1024), peer, public, []byte("first"), 100)
	if err != nil {
		t.Fatal(err)
	}
	failureReceiver := NewSessionManager(SessionManagerConfig{})
	if _, _, _, err := failureReceiver.Receive(make([]byte, len(first)), first, private, 100); err != nil {
		t.Fatal(err)
	}
	got, delivered, isNew, err := receiver.Receive(make([]byte, len(first)), first, private, 100)
	if err != nil || !isNew || !bytes.Equal(got, []byte("first")) || len(delivered) != 32 {
		t.Fatalf("new receive = payload %q, delivered %d, new %t, err %v", got, len(delivered), isNew, err)
	}
	if confirmed := sender.ConfirmOutboundTags(peer, 100); confirmed != 1 {
		t.Fatalf("confirmed tags = %d, want 1", confirmed)
	}

	second, err := sender.Encrypt(make([]byte, 256), peer, public, []byte("second"), 101)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) >= cryptography.ElGamalCiphertextSize {
		t.Fatalf("second packet length = %d, want legacy existing-session packet", len(second))
	}
	got, delivered, isNew, err = receiver.Receive(make([]byte, len(second)), second, private, 101)
	if err != nil || isNew || !bytes.Equal(got, []byte("second")) || len(delivered) != 32 {
		t.Fatalf("existing receive = payload %q, delivered %d, new %t, err %v", got, len(delivered), isNew, err)
	}
	tampered := append([]byte(nil), second...)
	tampered[len(tampered)-1] ^= 1
	if _, _, _, err := failureReceiver.Receive(make([]byte, len(tampered)), tampered, private, 101); err == nil {
		t.Fatal("accepted tampered existing-session packet")
	}
	if _, _, _, err := failureReceiver.Receive(make([]byte, len(second)), second, private, 101); err == nil {
		t.Fatal("reinstated tag after existing-session decryption failure")
	}
	if _, _, _, err := receiver.Receive(make([]byte, len(second)), second, private, 101); err == nil {
		t.Fatal("accepted packet after its inbound tag was consumed")
	}
}

func TestSessionManagerFailedExistingSealRetainsTag(t *testing.T) {
	public, private, err := cryptography.GenerateElGamalKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	peer := foundation.Hash{2}
	sender := NewSessionManager(SessionManagerConfig{TagsPerMessage: 1, Random: &countingReader{}})
	receiver := NewSessionManager(SessionManagerConfig{})
	first, err := sender.Encrypt(make([]byte, 1024), peer, public, []byte("first"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := receiver.Receive(make([]byte, len(first)), first, private, 1); err != nil {
		t.Fatal(err)
	}
	if confirmed := sender.ConfirmOutboundTags(peer, 1); confirmed != 1 {
		t.Fatalf("confirmed tags = %d, want 1", confirmed)
	}
	if _, err := sender.Encrypt(make([]byte, 32), peer, public, []byte("second"), 2); err == nil {
		t.Fatal("accepted short caller output buffer")
	}
	second, err := sender.Encrypt(make([]byte, 256), peer, public, []byte("second"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) >= cryptography.ElGamalCiphertextSize {
		t.Fatal("failed existing-session seal consumed the selected outbound tag")
	}
	got, _, isNew, err := receiver.Receive(make([]byte, len(second)), second, private, 2)
	if err != nil || isNew || !bytes.Equal(got, []byte("second")) {
		t.Fatalf("retained tag receive = %q, new %t, err %v", got, isNew, err)
	}
}

func TestSessionManagerDefersOutboundTagsUntilConfirmed(t *testing.T) {
	public, _, err := cryptography.GenerateElGamalKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	peer := foundation.Hash{9}
	manager := NewSessionManager(SessionManagerConfig{
		MaxTagsPerPeer: 2,
		TagsPerMessage: 1,
		Random:         &countingReader{},
	})
	if _, err := manager.Encrypt(make([]byte, 1024), peer, public, []byte("first"), 1); err != nil {
		t.Fatal(err)
	}
	second, err := manager.Encrypt(make([]byte, 1024), peer, public, []byte("second"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) < cryptography.ElGamalCiphertextSize {
		t.Fatal("used an unconfirmed outbound tag")
	}
	if confirmed := manager.ConfirmOutboundTags(peer, 2); confirmed != 2 {
		t.Fatalf("confirmed tags = %d, want 2", confirmed)
	}
	third, err := manager.Encrypt(make([]byte, 256), peer, public, []byte("third"), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(third) >= cryptography.ElGamalCiphertextSize {
		t.Fatal("did not use a confirmed outbound tag")
	}
	shard := manager.peerShard(peer)
	shard.mu.Lock()
	state := shard.peers[peer]
	got := len(state.confirmed) + len(state.pending)
	shard.mu.Unlock()
	if got > 2 {
		t.Fatalf("outbound tag state = %d, exceeds cap", got)
	}
}

func TestSessionManagerAppliesLegacyReplacementKey(t *testing.T) {
	tag, key := make([]byte, 32), make([]byte, 32)
	tag[0], key[0] = 7, 8
	delivered := make([]byte, 32)
	delivered[0] = 9
	replacement := bytes.Repeat([]byte{10}, 32)
	packet := append(append([]byte(nil), tag...), legacyReplacementPacket(t, tag, key, delivered, replacement, []byte("rekey"))...)
	manager := NewSessionManager(SessionManagerConfig{})
	if !manager.InboundTags().Put(tag, key, 10) {
		t.Fatal("inbound tag setup failed")
	}
	payload, gotTags, isNew, err := manager.Receive(make([]byte, len(packet)-32), packet, cryptography.ElGamalPrivateKey{}, 1)
	if err != nil || isNew || !bytes.Equal(payload, []byte("rekey")) || !bytes.Equal(gotTags, delivered) {
		t.Fatalf("receive = payload %q, tags %x, new %t, err %v", payload, gotTags, isNew, err)
	}
	gotKey, ok := manager.InboundTags().Take(delivered, 1)
	if !ok || !bytes.Equal(gotKey[:], replacement) {
		t.Fatalf("replacement tag key = %x, found %t", gotKey, ok)
	}
}

func TestSessionManagerExpiryCapacityAndClose(t *testing.T) {
	public, private, err := cryptography.GenerateElGamalKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	firstPeer, secondPeer := foundation.Hash{3}, foundation.Hash{4}
	manager := NewSessionManager(SessionManagerConfig{
		MaxPeers:       1,
		MaxTagsPerPeer: 1,
		TagsPerMessage: 1,
		TagLifetime:    5,
		Random:         &countingReader{},
	})

	first, err := manager.Encrypt(make([]byte, 1024), firstPeer, public, []byte("first"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if removed := manager.Expire(106); removed == 0 {
		t.Fatal("expiry did not remove the expired outbound tag")
	}
	if _, err := manager.Encrypt(make([]byte, 1024), firstPeer, public, []byte("renewed"), 106); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Encrypt(make([]byte, 1024), secondPeer, public, []byte("second peer"), 107); err != nil {
		t.Fatal(err)
	}
	// The only first-peer state was evicted by the one-peer cap, so it must
	// create a new session rather than retaining unbounded peer state.
	replaced, err := manager.Encrypt(make([]byte, 1024), firstPeer, public, []byte("replacement"), 108)
	if err != nil || len(replaced) < cryptography.ElGamalCiphertextSize {
		t.Fatalf("capacity replacement = %d bytes, %v", len(replaced), err)
	}
	if _, _, _, err := NewSessionManager(SessionManagerConfig{}).Receive(make([]byte, len(first)), first, private, 100); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Encrypt(make([]byte, 1024), firstPeer, public, []byte("closed"), 107); !errors.Is(err, ErrSessionManagerClosed) {
		t.Fatalf("Encrypt after Close error = %v", err)
	}
	if _, _, _, err := manager.Receive(make([]byte, len(first)), first, private, 107); !errors.Is(err, ErrSessionManagerClosed) {
		t.Fatalf("Receive after Close error = %v", err)
	}
}
