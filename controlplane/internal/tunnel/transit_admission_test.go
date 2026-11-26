package tunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

type transitHarness struct {
	t       *testing.T
	now     uint64
	local   foundation.Hash
	public  []byte
	sender  *buildCaptureSender
	runtime *dataplane.TunnelRuntime
	manager *BuildManager
}

func newTransitHarness(t *testing.T, configure func(*BuildManagerConfig)) *transitHarness {
	t.Helper()
	privateBytes := make([]byte, 32)
	for index := range privateBytes {
		privateBytes[index] = byte(index + 1)
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	h := &transitHarness{t: t, now: 1_700_000_000_000, local: sha256.Sum256([]byte("transit-admission-local")), public: private.PublicKey().Bytes()}
	clock := func() uint64 { return h.now }
	h.sender = new(buildCaptureSender)
	h.runtime = dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: h.sender, Now: clock})
	config := BuildManagerConfig{
		Runtime: h.runtime, Sender: h.sender, ReplyKeys: newBuildReplyRegistry(), LocalRouter: h.local,
		StaticPrivate: privateBytes, Now: clock, MaxPending: 32,
	}
	if configure != nil {
		configure(&config)
	}
	h.manager, err = NewBuildManager(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.manager.Close() })
	return h
}

// build returns a ShortTunnelBuild whose only record is addressed to the
// harness router. minuteOffset shifts the request time from the current minute.
func (h *transitHarness) build(messageID, receiveTunnelID uint32, tag string, minuteOffset int) foundation.I2NPMessage {
	h.t.Helper()
	request := ShortBuildRequest{
		ReceiveTunnelID: receiveTunnelID, NextTunnelID: receiveTunnelID + 1, NextRouter: sha256.Sum256([]byte(tag)),
		RequestMinutes: uint32(int64(h.now/60_000) + int64(minuteOffset)), LifetimeSeconds: shortBuildLifetime, NextMessageID: receiveTunnelID + 2,
	}
	var plaintext [ShortBuildRequestPlainSize]byte
	if err := MarshalShortBuildRequest(plaintext[:], request, nil); err != nil {
		h.t.Fatal(err)
	}
	var record [ShortBuildRecordSize]byte
	if _, err := EncryptShortBuildRequest(record[:], h.local, h.public, plaintext[:]); err != nil {
		h.t.Fatal(err)
	}
	return foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPShortTunnelBuild, ID: messageID}, Payload: append([]byte{1}, record[:]...)}
}

func (h *transitHarness) handle(source foundation.Hash, message foundation.I2NPMessage) error {
	return h.manager.HandleBuildContext(context.Background(), BuildSource{Router: source, Direct: true}, message)
}

// TestTransitReplayTableDoesNotLimitParticipationByPendingCapacity covers M1:
// the creator-side pending capacity must not cap how many transit builds the
// replay table can remember, so one peer cannot lock out every other peer.
func TestTransitReplayTableDoesNotLimitParticipationByPendingCapacity(t *testing.T) {
	h := newTransitHarness(t, nil)
	attacker := foundation.Hash{0xaa}
	for index := range uint32(32) {
		if err := h.handle(attacker, h.build(1000+index, 1000+index*10, fmt.Sprint("attacker-next-", index), 0)); err != nil {
			t.Fatalf("attacker build %d: %v", index, err)
		}
	}
	if err := h.handle(foundation.Hash{0xbb}, h.build(9000, 9000, "honest-next", 0)); err != nil {
		t.Fatalf("honest transit build after 32 builds from another peer: %v", err)
	}
}

// TestTransitReplayCoversRequestTimestampWindow checks that a record stays in
// the replay table for as long as its request timestamp is still accepted.
func TestTransitReplayCoversRequestTimestampWindow(t *testing.T) {
	h := newTransitHarness(t, nil)
	source := foundation.Hash{0xcc}
	message := h.build(100, 100, "future-next", shortBuildFutureSkew/60_000)
	replay := append([]byte(nil), message.Payload...)
	if err := h.handle(source, message); err != nil {
		t.Fatalf("future-dated build within skew: %v", err)
	}
	h.now += 10*60_000 + 1_000
	if circuit, installed := h.runtime.InspectCircuit(100); installed {
		h.runtime.RemoveCircuit(circuit.Token)
	}
	message.Header.ID, message.Payload = 101, replay
	if err := h.handle(source, message); !errors.Is(err, ErrBuildTransit) {
		t.Fatalf("replayed record inside its timestamp window error = %v, want %v", err, ErrBuildTransit)
	}
}

// TestVariableTransitUndecryptableBuildDoesNotHoldReplaySlot checks that a
// VariableTunnelBuild nobody can decrypt does not consume replay capacity.
func TestVariableTransitUndecryptableBuildDoesNotHoldReplaySlot(t *testing.T) {
	h := newTransitHarness(t, nil)
	payload := make([]byte, 1+VariableBuildRecordSize)
	payload[0] = 1
	for index := range uint32(4) {
		payload[1] = byte(index)
		message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPVariableTunnelBuild, ID: 500 + index}, Payload: payload}
		if err := h.handle(foundation.Hash{0xdd}, message); err == nil {
			t.Fatalf("undecryptable variable build %d accepted", index)
		}
	}
	h.manager.mu.Lock()
	records := len(h.manager.transitRecords)
	h.manager.mu.Unlock()
	if records != 0 {
		t.Fatalf("undecryptable variable builds hold %d replay records", records)
	}
}

// TestTransitReplayQuotaIsPerPreviousHop checks that one previous hop can fill
// only its own share of the replay table.
func TestTransitReplayQuotaIsPerPreviousHop(t *testing.T) {
	h := newTransitHarness(t, nil)
	attacker := foundation.Hash{0xaa}
	for index := range uint32(transitReplayPerSource) {
		if err := h.handle(attacker, h.build(1000+index, 10_000+index*10, fmt.Sprint("quota-next-", index), 0)); err != nil {
			t.Fatalf("attacker build %d within quota: %v", index, err)
		}
	}
	if err := h.handle(attacker, h.build(5000, 90_000, "quota-over", 0)); !errors.Is(err, ErrBuildTransit) {
		t.Fatalf("attacker build over per-source quota error = %v, want %v", err, ErrBuildTransit)
	}
	if err := h.handle(foundation.Hash{0xbb}, h.build(6000, 95_000, "quota-honest", 0)); err != nil {
		t.Fatalf("honest build while another peer is at quota: %v", err)
	}
	h.now += shortBuildPastSkew + 2*60_000
	if err := h.handle(attacker, h.build(7000, 99_000, "quota-after-expiry", 0)); err != nil {
		t.Fatalf("attacker build after its records expired: %v", err)
	}
}

// TestTransitParticipatingLimitRejectsAndForwards checks that the separate
// participating-tunnel limit rejects with a reply instead of dropping the
// build, and frees capacity when tunnels expire.
func TestTransitParticipatingLimitRejectsAndForwards(t *testing.T) {
	h := newTransitHarness(t, func(config *BuildManagerConfig) { config.MaxParticipating = 2 })
	for index := range uint32(2) {
		if err := h.handle(foundation.Hash{byte(0x10 + index)}, h.build(100+index, 100+index*10, fmt.Sprint("limit-next-", index), 0)); err != nil {
			t.Fatalf("build %d within participating limit: %v", index, err)
		}
	}
	if err := h.handle(foundation.Hash{0x20}, h.build(200, 200, "limit-over", 0)); !errors.Is(err, ErrBuildRejected) {
		t.Fatalf("build over participating limit error = %v, want %v", err, ErrBuildRejected)
	}
	if _, installed := h.runtime.InspectCircuit(200); installed {
		t.Fatal("build over participating limit installed a circuit")
	}
	sent := h.sender.take()
	if len(sent) == 0 || sent[len(sent)-1].peer != sha256.Sum256([]byte("limit-over")) {
		t.Fatal("build over participating limit was not forwarded to the next hop")
	}
	h.now += uint64(shortBuildLifetime)*1_000 + 1_000
	if err := h.handle(foundation.Hash{0x21}, h.build(300, 300, "limit-after-expiry", 0)); err != nil {
		t.Fatalf("build after participating tunnels expired: %v", err)
	}
}
