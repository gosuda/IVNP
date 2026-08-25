package ecies

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"gosuda.org/ivnp/crypto/cryptx"
	ivnp "gosuda.org/ivnp/i2p"
	"gosuda.org/ivnp/support/observability"
	"testing"
)

func ratchetPair(t testing.TB) (*RatchetManager, *RatchetManager, ivnp.Hash, ivnp.Hash, uint64) {
	return ratchetPairWithMetrics(t, nil)
}

func ratchetPairWithMetrics(t testing.TB, metrics *observability.Registry) (*RatchetManager, *RatchetManager, ivnp.Hash, ivnp.Hash, uint64) {
	t.Helper()
	a, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	b, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	aM, err := NewRatchetManager(a, RatchetConfig{TagLookahead: 4, Metrics: metrics})
	if err != nil {
		t.Fatal(err)
	}
	bM, err := NewRatchetManager(b, RatchetConfig{TagLookahead: 4, Metrics: metrics})
	if err != nil {
		t.Fatal(err)
	}
	return aM, bM, a.Hash(), b.Hash(), 1_800_000_000_000
}

func clove(data string) []byte {
	return append([]byte{ratchetGarlicClove, 0, byte(len(data))}, []byte(data)...)
}

func establishRatchet(t testing.TB, a, b *RatchetManager, aPeer, bPeer ivnp.Hash, now uint64) ivnp.Hash {
	t.Helper()
	bPub := make([]byte, 32)
	copy(bPub, b.private[:]) // public is derived below; this test must not use private material as a public key.
	// Test peers derive the public key through the destination's X25519 scalar.
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(b.private[:])
	if err != nil {
		t.Fatal(err)
	}
	copy(bPub, priv.PublicKey().Bytes())
	ns, err := a.Encrypt(make([]byte, 2048), bPeer, bPub, 4, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Receive(make([]byte, 2048), make([]byte, 2048), ns, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.NewSession || len(got.Payload) != 0 || len(got.Reply) == 0 {
		t.Fatalf("new session result = %#v", got)
	}
	if _, err = a.Receive(make([]byte, 2048), make([]byte, 1), got.Reply, now); err != nil {
		t.Fatal(err)
	}
	return got.Peer
}
func TestRatchetUnboundNewSessionDeliversWithoutReplyState(t *testing.T) {
	a, b, _, _, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	payload := clove("raw")
	packet, err := a.EncryptUnbound(make([]byte, 2048), ratchetPublic(t, b), 4, payload, now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := b.Receive(make([]byte, 2048), make([]byte, 2048), packet, now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.NewSession || len(result.Reply) != 0 || result.Peer != (ivnp.Hash{}) || string(result.Payload) != string(payload) {
		t.Fatalf("unbound result = %#v", result)
	}
	if stats := b.Stats(); stats.Sessions != 0 || stats.Pending != 0 {
		t.Fatalf("unbound retained session state = %+v", stats)
	}
}

func TestReplyTagUsesJavaSessionReplyTagSetKDF(t *testing.T) {
	var chain [32]byte
	for i := range chain {
		chain[i] = byte(i + 1)
	}
	data := hkdf64(chain[:], nil, "SessionReplyTags")
	set, err := newTagSet(0, chain, data[:32], 1)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := set.nextEntry()
	if err != nil {
		t.Fatal(err)
	}
	if got := deriveReplyTag(chain); got != entry.tag {
		t.Fatalf("reply tag = %x, want Java/i2pd tagset %x", got, entry.tag)
	}
}

func TestRatchetExistingSessionUsesNoiseLittleEndianNonce(t *testing.T) {
	a, b, aPeer, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	establishRatchet(t, a, b, aPeer, bPeer, now)
	first, err := a.EncryptExisting(make([]byte, 256), bPeer, clove("first"), RatchetOptions{}, now+1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 256), nil, first, now+1); err != nil {
		t.Fatal(err)
	}
	second, err := a.EncryptExisting(make([]byte, 256), bPeer, clove("second"), RatchetOptions{}, now+2)
	if err != nil {
		t.Fatal(err)
	}
	var tag [ratchetTagLen]byte
	copy(tag[:], second)
	entry, ok := b.inbound[tag]
	if !ok || entry.n == 0 {
		t.Fatalf("second message tag entry = %#v, found %t", entry, ok)
	}
	var nonce [cryptx.ChaChaNonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], uint64(entry.n))
	plain := make([]byte, len(second)-ratchetTagLen-cryptx.ChaChaTagSize)
	if _, err = cryptx.OpenChaCha20Poly1305To(plain, entry.key[:], nonce[:], second[ratchetTagLen:], second[:ratchetTagLen]); err != nil {
		t.Fatal(err)
	}
}

func TestRatchetProductionEncryptAutomaticallyAdvancesDH(t *testing.T) {
	a, b, aPeer, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	bInboundPeer := establishRatchet(t, a, b, aPeer, bPeer, now)
	public := ratchetPublic(t, b)
	var encrypted, received [256]byte
	for index := uint64(1); index <= automaticDHRatchetMessages; index++ {
		packet, err := a.Encrypt(encrypted[:], bPeer, public, 4, nil, now+index)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = b.Receive(received[:], nil, packet, now+index); err != nil {
			t.Fatal(err)
		}
	}
	forward, err := a.Encrypt(encrypted[:], bPeer, public, 4, clove("forward"), now+automaticDHRatchetMessages+1)
	if err != nil {
		t.Fatal(err)
	}
	result, err := b.Receive(received[:], nil, forward, now+automaticDHRatchetMessages+1)
	if err != nil || !result.DHStep {
		t.Fatalf("automatic forward DH = %#v, %v", result, err)
	}
	repeated, err := a.Encrypt(encrypted[:], bPeer, public, 4, clove("repeated"), now+automaticDHRatchetMessages+2)
	if err != nil {
		t.Fatal(err)
	}
	if result, err = b.Receive(received[:], nil, repeated, now+automaticDHRatchetMessages+2); err != nil || !result.DHStep {
		t.Fatalf("idempotent pending DH = %#v, %v", result, err)
	}
	reverse, err := b.Encrypt(encrypted[:], bInboundPeer, ratchetPublic(t, a), 4, clove("reverse"), now+automaticDHRatchetMessages+3)
	if err != nil {
		t.Fatal(err)
	}
	if result, err = a.Receive(received[:], nil, reverse, now+automaticDHRatchetMessages+3); err != nil || !result.DHStep {
		t.Fatalf("automatic reverse DH = %#v, %v", result, err)
	}
}

func TestRatchetProductionEncryptReplacesExhaustedSession(t *testing.T) {
	a, b, aPeer, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	_ = establishRatchet(t, a, b, aPeer, bPeer, now)
	a.mu.Lock()
	a.sessions[bPeer].outbound.next = 1 << 16
	a.mu.Unlock()
	packet, err := a.Encrypt(make([]byte, 2048), bPeer, ratchetPublic(t, b), 4, clove("replacement"), now+1)
	if err != nil {
		t.Fatal(err)
	}
	result, err := b.Receive(make([]byte, 2048), make([]byte, 2048), packet, now+1)
	if err != nil || !result.NewSession {
		t.Fatalf("replacement new session = %#v, %v", result, err)
	}
}

func ratchetPublic(t testing.TB, manager *RatchetManager) []byte {
	t.Helper()
	private, err := ecdh.X25519().NewPrivateKey(manager.private[:])
	if err != nil {
		t.Fatal(err)
	}
	return private.PublicKey().Bytes()
}

func TestRatchetNewExistingReplayAndAck(t *testing.T) {
	a, b, aPeer, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	bInboundPeer := establishRatchet(t, a, b, aPeer, bPeer, now)
	packet, err := a.EncryptExisting(make([]byte, 256), bPeer, clove("hello"), RatchetOptions{ACKRequest: true}, now+1)
	if err != nil {
		t.Fatal(err)
	}
	result, err := b.Receive(make([]byte, 256), make([]byte, 1), packet, now+1)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Payload[:len(clove("hello"))]) != string(clove("hello")) || len(result.ACKRequests) != 1 {
		t.Fatalf("existing result = %#v", result)
	}
	if _, err := b.Receive(make([]byte, 256), make([]byte, 1), packet, now+1); err == nil {
		t.Fatal("replayed existing was accepted")
	}
	ack, err := b.EncryptExisting(make([]byte, 256), bInboundPeer, nil, RatchetOptions{ACKs: result.ACKRequests}, now+2)
	if err != nil {
		t.Fatal(err)
	}
	ackResult, err := a.Receive(make([]byte, 256), make([]byte, 1), ack, now+2)
	if err != nil {
		t.Fatal(err)
	}
	if len(ackResult.ACKs) != 1 || ackResult.ACKs[0] != result.ACKRequests[0] {
		t.Fatalf("ack result = %#v", ackResult)
	}
}

func TestRatchetDHTransitionAndExpiry(t *testing.T) {
	a, b, aPeer, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	bInboundPeer := establishRatchet(t, a, b, aPeer, bPeer, now)
	forward, err := a.EncryptExisting(make([]byte, 256), bPeer, clove("forward"), RatchetOptions{RequestDH: true}, now+1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 256), make([]byte, 1), forward, now+1); err != nil {
		t.Fatal(err)
	}
	reverse, err := b.EncryptExisting(make([]byte, 256), bInboundPeer, clove("reverse"), RatchetOptions{}, now+2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Receive(make([]byte, 256), make([]byte, 1), reverse, now+2); err != nil {
		t.Fatal(err)
	}
	after, err := a.EncryptExisting(make([]byte, 256), bPeer, clove("after"), RatchetOptions{}, now+3)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.Receive(make([]byte, 256), make([]byte, 1), after, now+3); err != nil || string(got.Payload) != string(clove("after")) {
		t.Fatalf("post-DH = %#v, %v", got, err)
	}
	if _, err = a.EncryptExisting(make([]byte, 256), bPeer, nil, RatchetOptions{}, now+defaultSessionLife+1); !errors.Is(err, ErrRatchetNoSession) {
		t.Fatalf("expired session = %v", err)
	}
}

func TestRatchetRejectsDelayedNextKeyAcrossPreviousTagSet(t *testing.T) {
	a, b, aPeer, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	bInboundPeer := establishRatchet(t, a, b, aPeer, bPeer, now)

	forward, err := a.EncryptExisting(make([]byte, 256), bPeer, clove("forward"), RatchetOptions{RequestDH: true}, now+1)
	if err != nil {
		t.Fatal(err)
	}
	delayed, err := a.EncryptExisting(make([]byte, 256), bPeer, clove("delayed"), RatchetOptions{}, now+2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 256), make([]byte, 1), forward, now+1); err != nil {
		t.Fatal(err)
	}
	reverse, err := b.EncryptExisting(make([]byte, 256), bInboundPeer, clove("reverse"), RatchetOptions{}, now+3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Receive(make([]byte, 256), make([]byte, 1), reverse, now+3); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 256), make([]byte, 1), delayed, now+4); !errors.Is(err, ErrRatchet) {
		t.Fatalf("delayed repeated NextKey = %v", err)
	}
	after, err := a.EncryptExisting(make([]byte, 256), bPeer, clove("after-stale"), RatchetOptions{}, now+5)
	if err != nil {
		t.Fatal(err)
	}
	if got, receiveErr := b.Receive(make([]byte, 256), make([]byte, 1), after, now+5); receiveErr != nil || string(got.Payload) != string(clove("after-stale")) {
		t.Fatalf("session after stale NextKey = %#v, %v", got, receiveErr)
	}
}

func TestRatchetRejectsDelayedReverseNextKeyAcrossPreviousTagSet(t *testing.T) {
	a, b, aPeer, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	bInboundPeer := establishRatchet(t, a, b, aPeer, bPeer, now)
	forward, err := a.EncryptExisting(make([]byte, 256), bPeer, nil, RatchetOptions{RequestDH: true}, now+1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 256), make([]byte, 1), forward, now+1); err != nil {
		t.Fatal(err)
	}

	b.mu.Lock()
	responder := b.sessions[bInboundPeer]
	oldOutbound := *responder.outbound
	localKey, pendingID, secret := responder.localKey, responder.pendingKeyID, responder.dhSecret
	b.mu.Unlock()
	reverse, err := b.EncryptExisting(make([]byte, 256), bInboundPeer, nil, RatchetOptions{}, now+2)
	if err != nil {
		t.Fatal(err)
	}
	used, err := oldOutbound.nextEntry()
	if err != nil {
		t.Fatal(err)
	}
	clear(used.key[:])
	b.mu.Lock()
	responder.outbound = &oldOutbound
	responder.outbound.owner = responder
	responder.localKey, responder.pendingKeyID = localKey, pendingID
	responder.dhSecret = secret
	responder.pendingDH, responder.replyDH = true, true
	b.mu.Unlock()
	delayed, err := b.EncryptExisting(make([]byte, 256), bInboundPeer, nil, RatchetOptions{}, now+3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Receive(make([]byte, 256), make([]byte, 1), reverse, now+2); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Receive(make([]byte, 256), make([]byte, 1), delayed, now+3); !errors.Is(err, ErrRatchet) {
		t.Fatalf("delayed repeated reverse NextKey = %v", err)
	}
}
func TestRatchetNextKeyID32767TerminatesWithoutReuse(t *testing.T) {
	a, b, aPeer, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()

	defer b.ReleaseSensitive()
	bInboundPeer := establishRatchet(t, a, b, aPeer, bPeer, now)

	a.mu.Lock()
	a.sessions[bPeer].localKeyID = 32766
	a.mu.Unlock()
	forward, err := a.EncryptExisting(make([]byte, 256), bPeer, clove("last-key"), RatchetOptions{RequestDH: true}, now+1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 256), make([]byte, 1), forward, now+1); err != nil {
		t.Fatal(err)
	}
	reverse, err := b.EncryptExisting(make([]byte, 256), bInboundPeer, nil, RatchetOptions{}, now+2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Receive(make([]byte, 256), make([]byte, 1), reverse, now+2); err != nil {
		t.Fatal(err)
	}
	if _, err = a.EncryptExisting(make([]byte, 256), bPeer, nil, RatchetOptions{RequestDH: true}, now+3); !errors.Is(err, ErrRatchetNoSession) {
		t.Fatalf("initiator reused terminal key ID: %v", err)
	}
	if _, err = b.EncryptExisting(make([]byte, 256), bInboundPeer, nil, RatchetOptions{}, now+3); !errors.Is(err, ErrRatchetNoSession) {
		t.Fatalf("responder remained live after terminal key ID: %v", err)
	}

	c, d, cPeer, dPeer, later := ratchetPair(t)
	defer c.ReleaseSensitive()
	defer d.ReleaseSensitive()
	_ = establishRatchet(t, c, d, cPeer, dPeer, later)
	c.mu.Lock()
	c.sessions[dPeer].localKeyID = 32767
	c.mu.Unlock()
	if _, err = c.EncryptExisting(make([]byte, 256), dPeer, nil, RatchetOptions{RequestDH: true}, later+1); !errors.Is(err, ErrRatchetTagExhausted) {
		t.Fatalf("request past key ID 32767 = %v", err)
	}
	c.mu.Lock()
	terminated := c.sessions[dPeer].terminated
	c.mu.Unlock()
	if !terminated {
		t.Fatal("key ID exhaustion did not terminate session")
	}
}

func TestRatchetForwardNextKeyCapacityFailureIsAtomic(t *testing.T) {
	a, b, aPeer, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	bInboundPeer := establishRatchet(t, a, b, aPeer, bPeer, now)
	forward, err := a.EncryptExisting(make([]byte, 256), bPeer, nil, RatchetOptions{RequestDH: true}, now+1)
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	session := b.sessions[bInboundPeer]
	inbound := session.inbound
	b.config.MaxInboundTags = len(b.inbound)
	b.mu.Unlock()
	if _, err = b.Receive(make([]byte, 256), make([]byte, 1), forward, now+1); !errors.Is(err, ErrRatchetTagExhausted) {
		t.Fatalf("capacity-saturated forward NextKey = %v", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if session.inbound != inbound || session.haveRemoteForward || !session.terminated {
		t.Fatalf("forward capacity failure partially committed: inboundChanged=%t remoteID=%t terminated=%t", session.inbound != inbound, session.haveRemoteForward, session.terminated)
	}
}

func TestRatchetReverseNextKeyCapacityFailureIsAtomic(t *testing.T) {
	a, b, aPeer, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	bInboundPeer := establishRatchet(t, a, b, aPeer, bPeer, now)
	forward, err := a.EncryptExisting(make([]byte, 256), bPeer, nil, RatchetOptions{RequestDH: true}, now+1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 256), make([]byte, 1), forward, now+1); err != nil {
		t.Fatal(err)
	}
	reverse, err := b.EncryptExisting(make([]byte, 256), bInboundPeer, nil, RatchetOptions{}, now+2)
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	session := a.sessions[bPeer]
	outbound, inbound := session.outbound, session.inbound
	a.config.MaxInboundTags = len(a.inbound)
	a.mu.Unlock()
	if _, err = a.Receive(make([]byte, 256), make([]byte, 1), reverse, now+2); !errors.Is(err, ErrRatchetTagExhausted) {
		t.Fatalf("capacity-saturated reverse NextKey = %v", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if session.outbound != outbound || session.inbound != inbound || session.haveRemoteReverse || !session.terminated {
		t.Fatalf("reverse capacity failure partially committed: outboundChanged=%t inboundChanged=%t remoteID=%t terminated=%t", session.outbound != outbound, session.inbound != inbound, session.haveRemoteReverse, session.terminated)
	}
}

func TestRatchetNextKeyIDsAdvanceIndependentlyByDirection(t *testing.T) {
	a, b, aPeer, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	bInboundPeer := establishRatchet(t, a, b, aPeer, bPeer, now)
	forward, err := a.EncryptExisting(make([]byte, 256), bPeer, nil, RatchetOptions{RequestDH: true}, now+1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 256), make([]byte, 1), forward, now+1); err != nil {
		t.Fatal(err)
	}
	reverse, err := b.EncryptExisting(make([]byte, 256), bInboundPeer, nil, RatchetOptions{}, now+2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Receive(make([]byte, 256), make([]byte, 1), reverse, now+2); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	bSession := b.sessions[bInboundPeer]
	bLocalID, bRemoteID := bSession.localKeyID, bSession.remoteForwardKeyID
	b.mu.Unlock()
	if bLocalID != 0 || bRemoteID != 1 {
		t.Fatalf("responder key directions local=%d remote=%d", bLocalID, bRemoteID)
	}
	secondDirection, err := b.EncryptExisting(make([]byte, 256), bInboundPeer, nil, RatchetOptions{RequestDH: true}, now+3)
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	pendingID := b.sessions[bInboundPeer].pendingKeyID
	b.mu.Unlock()
	if pendingID != 1 {
		t.Fatalf("independent local direction started at key ID %d", pendingID)
	}
	if _, err = a.Receive(make([]byte, 256), make([]byte, 1), secondDirection, now+3); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	aRemoteID := a.sessions[bPeer].remoteForwardKeyID
	a.mu.Unlock()
	if aRemoteID != 1 {
		t.Fatalf("initiator remote direction key ID = %d", aRemoteID)
	}
}

func TestRatchetMetricsRecordAuthenticatedTransitions(t *testing.T) {
	metrics := observability.NewRegistry()
	a, b, aPeer, bPeer, now := ratchetPairWithMetrics(t, metrics)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	bInboundPeer := establishRatchet(t, a, b, aPeer, bPeer, now)
	forward, err := a.EncryptExisting(make([]byte, 256), bPeer, clove("forward"), RatchetOptions{RequestDH: true}, now+1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 256), make([]byte, 1), forward, now+1); err != nil {
		t.Fatal(err)
	}
	reverse, err := b.EncryptExisting(make([]byte, 256), bInboundPeer, clove("reverse"), RatchetOptions{}, now+2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Receive(make([]byte, 256), make([]byte, 1), reverse, now+2); err != nil {
		t.Fatal(err)
	}
	got := metrics.Snapshot().Garlic
	ratchetMetricsRecordAuthenticatedTransitionsRejected := got.NewSessionSent != 1 || got.NewSessionReceived != 2 ||
		got.ExistingSessionSent != 2 || got.ExistingSessionReceived != 2 ||
		got.DHStepsSent != 2
	if !ratchetMetricsRecordAuthenticatedTransitionsRejected {
		ratchetMetricsRecordAuthenticatedTransitionsRejected = got.DHStepsReceived != 2
	}
	if ratchetMetricsRecordAuthenticatedTransitionsRejected {
		t.Fatalf("ratchet metrics = %+v", got)
	}
}

func TestRatchetSteadyStateScratchHasZeroAllocations(t *testing.T) {
	a, b, aPeer, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	_ = establishRatchet(t, a, b, aPeer, bPeer, now)
	payload := []byte{ratchetGarlicClove, 0, 1, 9}
	var encrypted [256]byte
	var plain [256]byte
	var received [256]byte
	var receiveReply [256]byte

	// Warm tag maps, AEAD constructors, and both ratchet directions before the
	// regression measurement.
	for index := uint64(1); index <= 64; index++ {
		packet, err := a.EncryptExistingWithScratch(encrypted[:], plain[:], bPeer, payload, RatchetOptions{}, now+index)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = b.Receive(received[:], receiveReply[:], packet, now+index); err != nil {
			t.Fatal(err)
		}
	}
	var hotErr error
	offset := uint64(65)
	allocations := testing.AllocsPerRun(100, func() {
		packet, err := a.EncryptExistingWithScratch(encrypted[:], plain[:], bPeer, payload, RatchetOptions{}, now+offset)
		if err == nil {
			_, err = b.Receive(received[:], receiveReply[:], packet, now+offset)
		}
		hotErr = err
		offset++
	})
	if hotErr != nil {
		t.Fatal(hotErr)
	}
	if allocations != 0 {
		t.Fatalf("steady-state ratchet relay allocations = %v, want 0", allocations)
	}
}

func BenchmarkRatchetExistingWithScratch(b *testing.B) {
	a, receiver, aPeer, bPeer, now := ratchetPair(b)
	defer a.ReleaseSensitive()
	defer receiver.ReleaseSensitive()
	receiverPeer := establishRatchet(b, a, receiver, aPeer, bPeer, now)
	payload := []byte{ratchetGarlicClove, 0, 1, 9}
	var encrypted, plain, received, reply [256]byte
	for index := uint64(1); index <= 64; index++ {
		packet, err := a.EncryptExistingWithScratch(encrypted[:], plain[:], bPeer, payload, RatchetOptions{}, now+index)
		if err != nil {
			b.Fatal(err)
		}
		if _, err = receiver.Receive(received[:], reply[:], packet, now+index); err != nil {
			b.Fatal(err)
		}
	}
	state := ratchetBenchmarkState{
		sender:       a,
		receiver:     receiver,
		senderPeer:   bPeer,
		receiverPeer: receiverPeer,
		payload:      payload,
		encrypted:    &encrypted,
		plain:        &plain,
		received:     &received,
		reply:        &reply,
		now:          now,
		offset:       65,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		state.step(b)
	}
}

type ratchetBenchmarkState struct {
	sender       *RatchetManager
	receiver     *RatchetManager
	senderPeer   ivnp.Hash
	receiverPeer ivnp.Hash
	payload      []byte
	encrypted    *[256]byte
	plain        *[256]byte
	received     *[256]byte
	reply        *[256]byte
	now          uint64
	offset       uint64
}

func (state *ratchetBenchmarkState) step(b *testing.B) {
	if state.offset%4000 == 0 {
		b.StopTimer()
		state.rekey(b)
		b.StartTimer()
	}
	packet, err := state.sender.EncryptExistingWithScratch(state.encrypted[:], state.plain[:], state.senderPeer, state.payload, RatchetOptions{}, state.now+state.offset)
	if err == nil {
		_, err = state.receiver.Receive(state.received[:], state.reply[:], packet, state.now+state.offset)
	}
	if err != nil {
		b.Fatal(err)
	}
	state.offset++
}

func (state *ratchetBenchmarkState) rekey(b *testing.B) {
	forward, err := state.sender.EncryptExistingWithScratch(state.encrypted[:], state.plain[:], state.senderPeer, nil, RatchetOptions{RequestDH: true}, state.now+state.offset)
	if err == nil {
		_, err = state.receiver.Receive(state.received[:], state.reply[:], forward, state.now+state.offset)
	}
	if err == nil {
		reverse, reverseErr := state.receiver.EncryptExistingWithScratch(state.encrypted[:], state.plain[:], state.receiverPeer, nil, RatchetOptions{}, state.now+state.offset)
		err = reverseErr
		if err == nil {
			_, err = state.sender.Receive(state.received[:], state.reply[:], reverse, state.now+state.offset)
		}
	}
	if err != nil {
		b.Fatal(err)
	}
}

func TestRatchetRejectsNewSessionReplayAndClockSkew(t *testing.T) {
	a, b, _, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	curve := ecdh.X25519()
	private, err := curve.NewPrivateKey(b.private[:])
	if err != nil {
		t.Fatal(err)
	}
	ns, err := a.Encrypt(make([]byte, 2048), bPeer, private.PublicKey().Bytes(), 4, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 2048), make([]byte, 2048), ns, now); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 2048), make([]byte, 2048), ns, now); !errors.Is(err, ErrRatchetReplay) {
		t.Fatalf("new-session replay = %v", err)
	}
	if _, err = b.Receive(make([]byte, 2048), make([]byte, 2048), ns, now+301_000); !errors.Is(err, ErrRatchet) && !errors.Is(err, ErrRatchetReplay) && !errors.Is(err, ErrRatchetExpired) {
		t.Fatalf("expired datetime = %v", err)
	}
}

func TestRatchetRejectsRemovedCryptoType5(t *testing.T) {
	local, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer local.ReleaseSensitive()
	if manager, err := NewRatchetManager(local, RatchetConfig{CryptoTypes: []uint16{5}}); err == nil || manager != nil {
		t.Fatalf("NewRatchetManager(type 5) = %#v, %v", manager, err)
	}
	manager, err := NewRatchetManager(local, RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.ReleaseSensitive()
	if _, err = manager.Encrypt(make([]byte, 4096), ivnp.Sum([]byte("peer")), make([]byte, 32), 5, []byte{1, 2, 3}, 1_700_000_000_000); !errors.Is(err, ErrRatchet) {
		t.Fatalf("Encrypt(type 5) = %v", err)
	}
}
func TestRatchetDefaultReceiverNegotiatesEveryProductionCryptoType(t *testing.T) {
	for _, cryptoType := range []uint16{7, 6, 4} {
		t.Run(string(rune('0'+cryptoType)), func(t *testing.T) {
			a, b, _, bPeer, now := ratchetPair(t)
			defer a.ReleaseSensitive()
			defer b.ReleaseSensitive()
			private, err := ecdh.X25519().NewPrivateKey(b.private[:])
			if err != nil {
				t.Fatal(err)
			}
			ns, err := a.Encrypt(make([]byte, 4096), bPeer, private.PublicKey().Bytes(), cryptoType, clove("hybrid"), now)
			if err != nil {
				t.Fatal(err)
			}
			result, err := b.Receive(make([]byte, 4096), make([]byte, 4096), ns, now)
			if err != nil {
				t.Fatal(err)
			}
			if !result.NewSession || string(result.Payload) != string(clove("hybrid")) || len(result.Reply) == 0 {
				t.Fatalf("crypto type %d result = %#v", cryptoType, result)
			}
			if _, err = a.Receive(make([]byte, 4096), nil, result.Reply, now); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRatchetNewSessionCommitIsAtomicAfterReplyFailure(t *testing.T) {
	a, b, _, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	private, err := ecdh.X25519().NewPrivateKey(b.private[:])
	if err != nil {
		t.Fatal(err)
	}
	ns, err := a.Encrypt(make([]byte, 4096), bPeer, private.PublicKey().Bytes(), 7, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 4096), make([]byte, 1), ns, now); err == nil {
		t.Fatal("short reply buffer accepted")
	}
	if stats := b.Stats(); stats.Sessions != 0 || stats.NewSessions != 0 {
		t.Fatalf("failed transition committed state: %+v", stats)
	}
	if _, err = b.Receive(make([]byte, 4096), make([]byte, 4096), ns, now); err != nil {
		t.Fatalf("retry after terminal failure = %v", err)
	}
}

func TestReleaseSensitiveClearsPendingDHSecret(t *testing.T) {
	manager := &RatchetManager{
		sessions: map[ivnp.Hash]*session{{1}: {dhSecret: [32]byte{1}, pendingDH: true, replyDH: true}},
		inbound:  make(map[[ratchetTagLen]byte]tagEntry),
		pending:  make(map[[ratchetTagLen]byte]pendingInitiator),
		replays:  make(map[[32]byte]uint64),
	}
	retained := manager.sessions[ivnp.Hash{1}]
	manager.ReleaseSensitive()
	if retained.dhSecret != ([32]byte{}) || retained.pendingDH || retained.replyDH {
		t.Fatal("pending DH material survived ReleaseSensitive")
	}
}
