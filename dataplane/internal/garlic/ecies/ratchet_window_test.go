package garlicecies

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func windowRatchetPair(t testing.TB, config RatchetConfig, observer TagObserver) (*RatchetManager, *RatchetManager, foundation.Hash, foundation.Hash, uint64) {
	t.Helper()
	a, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.ReleaseSensitive)
	b, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.ReleaseSensitive)
	aM, err := NewRatchetManager(a, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(aM.ReleaseSensitive)
	var bM *RatchetManager
	if observer == nil {
		bM, err = NewRatchetManager(b, config)
	} else {
		bM, err = NewRatchetManagerWithTagObserver(b, config, observer)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bM.ReleaseSensitive)
	return aM, bM, a.Hash(), b.Hash(), 1_800_000_000_000
}

func windowPackets(t testing.TB, sender *RatchetManager, peer foundation.Hash, count int, now uint64) [][]byte {
	t.Helper()
	packets := make([][]byte, count)
	for index := range packets {
		packet, err := sender.EncryptExisting(make([]byte, 256), peer, clove(strconv.Itoa(index)), RatchetOptions{}, now)
		if err != nil {
			t.Fatalf("encrypt index %d: %v", index, err)
		}
		packets[index] = packet
	}
	return packets
}

func receiveWindowIndex(t testing.TB, receiver *RatchetManager, packet []byte, index int, now uint64) {
	t.Helper()
	got, err := receiver.Receive(make([]byte, 256), nil, packet, now)
	want := clove(strconv.Itoa(index))
	if err != nil || !bytes.Equal(got.Payload, want) {
		t.Fatalf("receive index %d: payload=%x, want %x; error=%v", index, got.Payload, want, err)
	}
}

type windowTagObserver struct {
	live    map[SessionTag]struct{}
	removed map[SessionTag]int
}

func (o *windowTagObserver) TagAdded(tag SessionTag) {
	o.live[tag] = struct{}{}
}

func (o *windowTagObserver) TagRemoved(tag SessionTag) {
	delete(o.live, tag)
	o.removed[tag]++
}

func TestRatchetWindowAdvancesAcrossAlternatingLoss(t *testing.T) {
	for _, lookahead := range []int{32, 512} {
		t.Run("lookahead_"+strconv.Itoa(lookahead), func(t *testing.T) {
			a, b, aPeer, bPeer, now := windowRatchetPair(t, RatchetConfig{TagLookahead: lookahead, MaxInboundTags: 8192}, nil)
			establishRatchet(t, a, b, aPeer, bPeer, now)
			var encrypted, plain, received [256]byte
			for index := range 4 * lookahead {
				payload := clove(strconv.Itoa(index))
				packet, err := a.EncryptExistingWithScratch(encrypted[:], plain[:], bPeer, payload, RatchetOptions{}, now+1)
				if err != nil {
					t.Fatalf("encrypt index %d: %v", index, err)
				}
				if index%2 == 0 {
					continue
				}
				got, err := b.Receive(received[:], nil, packet, now+1)
				if err != nil || !bytes.Equal(got.Payload, payload) {
					t.Fatalf("receive index %d after isolated losses: payload=%x, want %x; error=%v", index, got.Payload, payload, err)
				}
				if tags := b.Stats().InboundTags; tags < lookahead || tags > 2*lookahead {
					t.Fatalf("index %d retained %d tags, want between %d and %d", index, tags, lookahead, 2*lookahead)
				}
			}
		})
	}
}

func TestRatchetWindowRetainsReorderingOnlyWithinHistory(t *testing.T) {
	observer := &windowTagObserver{live: make(map[SessionTag]struct{}), removed: make(map[SessionTag]int)}
	a, b, aPeer, bPeer, now := windowRatchetPair(t, RatchetConfig{TagLookahead: 8, MaxInboundTags: 32}, observer)
	establishRatchet(t, a, b, aPeer, bPeer, now)
	packets := windowPackets(t, a, bPeer, 17, now+1)
	receiveWindowIndex(t, b, packets[7], 7, now+1)
	receiveWindowIndex(t, b, packets[3], 3, now+1)
	if _, err := b.Receive(make([]byte, 256), nil, packets[3], now+1); err == nil {
		t.Fatal("replayed reordered packet was accepted")
	}
	receiveWindowIndex(t, b, packets[8], 8, now+1)
	if !b.OwnsTag(packets[0][:ratchetTagLen]) {
		t.Fatal("index 0 was pruned at the eight-index history boundary")
	}
	receiveWindowIndex(t, b, packets[9], 9, now+1)
	if b.OwnsTag(packets[0][:ratchetTagLen]) {
		t.Fatal("index 0 remains routable outside the eight-index history")
	}
	if _, err := b.Receive(make([]byte, 256), nil, packets[0], now+1); err == nil {
		t.Fatal("pruned index 0 was accepted")
	}
	if removed := observer.removed[SessionTag(packets[0][:ratchetTagLen])]; removed != 1 {
		t.Fatalf("pruned index 0 removal notifications = %d, want 1", removed)
	}
	receiveWindowIndex(t, b, packets[1], 1, now+1)
	receiveWindowIndex(t, b, packets[16], 16, now+1)
	if tags := b.Stats().InboundTags; tags > 16 || len(observer.live) != tags {
		t.Fatalf("retained tags=%d, observer tags=%d, want matching counts at most 16", tags, len(observer.live))
	}
}

func TestRatchetWindowUnknownFutureTagDoesNotAdvance(t *testing.T) {
	a, b, aPeer, bPeer, now := windowRatchetPair(t, RatchetConfig{TagLookahead: 4, MaxInboundTags: 16}, nil)
	establishRatchet(t, a, b, aPeer, bPeer, now)
	packets := windowPackets(t, a, bPeer, 65, now+1)
	before := b.Stats()
	if _, err := b.Receive(make([]byte, 256), nil, packets[64], now+1); err == nil {
		t.Fatal("unknown index 64 was accepted")
	}
	after := b.Stats()
	if after.InboundTags != before.InboundTags || after.ExistingSessions != before.ExistingSessions {
		t.Fatalf("unknown tag changed retained tags or authenticated receives: before=%+v, after=%+v", before, after)
	}
	if b.OwnsTag(packets[4][:ratchetTagLen]) {
		t.Fatal("unknown future packet generated index 4")
	}
	for index := 3; index < 64; index += 4 {
		receiveWindowIndex(t, b, packets[index], index, now+1)
	}
	receiveWindowIndex(t, b, packets[64], 64, now+1)
}

func TestRatchetWindowCorruptTagBurnsWithoutAdvancingOrRenewing(t *testing.T) {
	observer := &windowTagObserver{live: make(map[SessionTag]struct{}), removed: make(map[SessionTag]int)}
	a, b, aPeer, bPeer, now := windowRatchetPair(t, RatchetConfig{TagLookahead: 4, MaxInboundTags: 16, SessionLifetime: 100}, observer)
	establishRatchet(t, a, b, aPeer, bPeer, now)
	packets := windowPackets(t, a, bPeer, 6, now+1)
	receiveWindowIndex(t, b, packets[0], 0, now+1)
	corrupt := bytes.Clone(packets[4])
	corrupt[len(corrupt)-1] ^= 1
	before := b.Stats()
	if _, err := b.Receive(make([]byte, 256), nil, corrupt, now+100); !errors.Is(err, ErrRatchet) {
		t.Fatalf("corrupted known tag error = %v, want ErrRatchet", err)
	}
	after := b.Stats()
	if after.InboundTags != before.InboundTags-1 || after.ExistingSessions != before.ExistingSessions {
		t.Fatalf("corruption must burn exactly one tag without authenticating: before=%+v, after=%+v", before, after)
	}
	if b.OwnsTag(packets[4][:ratchetTagLen]) || b.OwnsTag(packets[5][:ratchetTagLen]) {
		t.Fatal("corruption retained its tag or extended the future window")
	}
	for _, index := range []int{4, 5} {
		if _, err := b.Receive(make([]byte, 256), nil, packets[index], now+100); err == nil {
			t.Fatalf("index %d accepted after corrupted window-edge tag", index)
		}
	}
	if removed := observer.removed[SessionTag(packets[4][:ratchetTagLen])]; removed != 1 {
		t.Fatalf("burned tag removal notifications = %d, want 1", removed)
	}
	if _, err := b.Receive(make([]byte, 256), nil, packets[1], now+102); err == nil {
		t.Fatal("corrupted traffic renewed the receive lifetime")
	}
	if stats := b.Stats(); stats.Sessions != 0 || stats.InboundTags != 0 || len(observer.live) != 0 {
		t.Fatalf("expired session retained state: stats=%+v, observer tags=%d", stats, len(observer.live))
	}
}

func TestRatchetWindowTagBudgetDiscardsOldestHistoryFirst(t *testing.T) {
	a, b, aPeer, bPeer, now := windowRatchetPair(t, RatchetConfig{TagLookahead: 4, MaxInboundTags: 5}, nil)
	establishRatchet(t, a, b, aPeer, bPeer, now)
	packets := windowPackets(t, a, bPeer, 64, now+1)
	receiveWindowIndex(t, b, packets[3], 3, now+1)
	for _, index := range []int{0, 1} {
		if b.OwnsTag(packets[index][:ratchetTagLen]) {
			t.Fatalf("budget retained older history index %d", index)
		}
		if _, err := b.Receive(make([]byte, 256), nil, packets[index], now+1); err == nil {
			t.Fatalf("budget-pruned index %d was accepted", index)
		}
	}
	receiveWindowIndex(t, b, packets[2], 2, now+1)
	for index := 7; index < len(packets); index += 4 {
		receiveWindowIndex(t, b, packets[index], index, now+1)
		if tags := b.Stats().InboundTags; tags < 4 || tags > 5 {
			t.Fatalf("index %d retained %d tags under budget 5, want 4 or 5", index, tags)
		}
	}
}

func TestRatchetWindowAcceptsFinalNonceWithoutWrapping(t *testing.T) {
	a, b, aPeer, bPeer, now := windowRatchetPair(t, RatchetConfig{TagLookahead: 4, MaxInboundTags: 8}, nil)
	establishRatchet(t, a, b, aPeer, bPeer, now)
	var encrypted, plain, received [256]byte
	payload := []byte{ratchetGarlicClove, 0, 2, 0, 0}
	var first, last []byte
	for index := 0; index <= 65535; index++ {
		binary.BigEndian.PutUint16(payload[3:], uint16(index))
		options := RatchetOptions{ACKRequest: index == 65535}
		packet, err := a.EncryptExistingWithScratch(encrypted[:], plain[:], bPeer, payload, options, now+1)
		if err != nil {
			t.Fatalf("encrypt nonce %d: %v", index, err)
		}
		if index == 0 {
			first = bytes.Clone(packet)
		}
		got, err := b.Receive(received[:], nil, packet, now+1)
		if err != nil || !bytes.HasPrefix(got.Payload, payload) {
			t.Fatalf("receive nonce %d: payload=%x, want prefix %x; error=%v", index, got.Payload, payload, err)
		}
		if tags := b.Stats().InboundTags; tags > 8 {
			t.Fatalf("nonce %d retained %d tags, want at most 8", index, tags)
		}
		if index == 65535 {
			last = bytes.Clone(packet)
			if len(got.ACKRequests) != 1 || got.ACKRequests[0] != (ACK{TagSet: 0, Message: 65535}) {
				t.Fatalf("final nonce acknowledgement = %v, want tagset 0 message 65535", got.ACKRequests)
			}
		}
	}
	if _, err := a.EncryptExistingWithScratch(encrypted[:], plain[:], bPeer, payload, RatchetOptions{}, now+1); !errors.Is(err, ErrRatchetTagExhausted) {
		t.Fatalf("send past nonce 65535 = %v, want ErrRatchetTagExhausted", err)
	}
	for _, packet := range [][]byte{first, last} {
		if _, err := b.Receive(received[:], nil, packet, now+1); err == nil {
			t.Fatal("exhausted window accepted a consumed nonce")
		}
	}
	if tags := b.Stats().InboundTags; tags != 0 {
		t.Fatalf("exhausted window retained %d tags, want 0", tags)
	}
}

func TestRatchetWindowOldDHSetExpiresDespiteLateDelivery(t *testing.T) {
	observer := &windowTagObserver{live: make(map[SessionTag]struct{}), removed: make(map[SessionTag]int)}
	a, b, aPeer, bPeer, now := windowRatchetPair(t, RatchetConfig{TagLookahead: 4, MaxInboundTags: 32, SessionLifetime: 600_000}, observer)
	bInboundPeer := establishRatchet(t, a, b, aPeer, bPeer, now)
	old := windowPackets(t, a, bPeer, 2, now+1)
	forward, err := a.EncryptExisting(make([]byte, 256), bPeer, clove("rotate"), RatchetOptions{RequestDH: true}, now+1)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.Receive(make([]byte, 256), nil, forward, now+1); err != nil || !bytes.HasPrefix(got.Payload, clove("rotate")) || !got.DHStep {
		t.Fatalf("forward DH delivery: payload=%x, DHStep=%v, error=%v", got.Payload, got.DHStep, err)
	}
	reverse, err := b.EncryptExisting(make([]byte, 256), bInboundPeer, clove("reverse"), RatchetOptions{}, now+2)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := a.Receive(make([]byte, 256), nil, reverse, now+2); err != nil || !bytes.HasPrefix(got.Payload, clove("reverse")) {
		t.Fatalf("reverse DH delivery: payload=%x, error=%v", got.Payload, err)
	}
	current, err := a.EncryptExisting(make([]byte, 256), bPeer, clove("current"), RatchetOptions{}, now+3)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.Receive(make([]byte, 256), nil, current, now+3); err != nil || !bytes.Equal(got.Payload, clove("current")) {
		t.Fatalf("current DH set delivery: payload=%x, error=%v", got.Payload, err)
	}
	receiveWindowIndex(t, b, old[0], 0, now+previousSetLife)
	if _, err := b.Receive(make([]byte, 256), nil, old[0], now+previousSetLife); err == nil {
		t.Fatal("old DH set accepted a replay")
	}
	if !b.OwnsTag(old[1][:ratchetTagLen]) {
		t.Fatal("old DH set lost its unused tag before its deadline")
	}
	current, err = a.EncryptExisting(make([]byte, 256), bPeer, clove("after old expiry"), RatchetOptions{}, now+previousSetLife+2)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.Receive(make([]byte, 256), nil, current, now+previousSetLife+2); err != nil || !bytes.Equal(got.Payload, clove("after old expiry")) {
		t.Fatalf("current set after old expiry: payload=%x, error=%v", got.Payload, err)
	}
	if b.OwnsTag(old[1][:ratchetTagLen]) {
		t.Fatal("late authenticated delivery renewed the old DH set deadline")
	}
	if _, err := b.Receive(make([]byte, 256), nil, old[1], now+previousSetLife+2); err == nil {
		t.Fatal("expired old DH set accepted an unused tag")
	}
	if removed := observer.removed[SessionTag(old[1][:ratchetTagLen])]; removed != 1 {
		t.Fatalf("expired old tag removal notifications = %d, want 1", removed)
	}
	if stats := b.Stats(); stats.Sessions != 1 || stats.InboundTags > 8 || len(observer.live) != stats.InboundTags {
		t.Fatalf("old DH cleanup damaged current state: stats=%+v, observer tags=%d", stats, len(observer.live))
	}
	b.RetirePeer(bInboundPeer)
	if stats := b.Stats(); stats.Sessions != 0 || stats.InboundTags != 0 || len(observer.live) != 0 {
		t.Fatalf("retired DH session retained tags: stats=%+v, observer tags=%d", stats, len(observer.live))
	}
}

func TestRatchetWindowCollisionDoesNotPartiallyAdvance(t *testing.T) {
	a, b, aPeer, bPeer, now := windowRatchetPair(t, RatchetConfig{TagLookahead: 4, MaxInboundTags: 16}, nil)
	establishRatchet(t, a, b, aPeer, bPeer, now)
	packets := windowPackets(t, a, bPeer, 8, now+1)
	conflict := tagEntry{tag: [ratchetTagLen]byte(packets[6][:ratchetTagLen]), set: new(tagSet)}
	b.mu.Lock()
	b.addInboundTagLocked(conflict)
	b.mu.Unlock()
	if _, err := b.Receive(make([]byte, 256), nil, packets[3], now+1); !errors.Is(err, ErrRatchet) {
		t.Fatalf("colliding future tag = %v, want ErrRatchet", err)
	}
	if b.OwnsTag(packets[3][:ratchetTagLen]) || b.OwnsTag(packets[4][:ratchetTagLen]) || b.OwnsTag(packets[5][:ratchetTagLen]) {
		t.Fatal("failed refill retained the consumed tag or admitted partial future tags")
	}
	b.mu.Lock()
	b.removeInboundTagLocked(conflict.tag)
	b.mu.Unlock()
	receiveWindowIndex(t, b, packets[2], 2, now+1)
	receiveWindowIndex(t, b, packets[4], 4, now+1)
}
