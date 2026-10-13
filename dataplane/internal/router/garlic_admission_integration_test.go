package router

import (
	"encoding/binary"
	"errors"
	"testing"

	dataplanegarlic "gosuda.org/ivnp/dataplane/internal/garlic"
	"gosuda.org/ivnp/foundation"
)

func garlicAdmissionMessage(packet []byte, id uint32) foundation.I2NPMessage {
	payload := make([]byte, 4+len(packet))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(packet)))
	copy(payload[4:], packet)
	return foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPGarlic, ID: id},
		Payload: payload,
	}
}

func TestGarlicReceiverUnknownCiphertextBudgetFailsClosed(t *testing.T) {
	f := newRatchetReceiverFixture(t)
	packet := make([]byte, 96)
	f.receiver.preauth.mu.Lock()
	f.receiver.preauth.global.available = 2 * garlicPreauthUnitScale
	f.receiver.preauth.global.last = f.now
	f.receiver.preauth.mu.Unlock()
	if err := f.receiver.HandleGarlic(garlicAdmissionMessage(packet, 1)); !errors.Is(err, ErrGarlicPreauthLimit) {
		t.Fatalf("pre-auth budget below 3 crypto formats: %v", err)
	}
	f.receiver.preauth.mu.Lock()
	f.receiver.preauth.global.available = 3 * garlicPreauthUnitScale
	f.receiver.preauth.mu.Unlock()
	if err := f.receiver.HandleGarlic(garlicAdmissionMessage(packet, 2)); !errors.Is(err, ErrGarlicDestination) {
		t.Fatalf("denied ciphertext should not have entered the replay filter: %v", err)
	}
}

func TestGarlicReceiverRejectsCiphertextReplayAcrossI2NPIDs(t *testing.T) {
	f := newRatchetReceiverFixture(t)
	packet := make([]byte, 96)
	packet[0] = 42
	source := I2NPSource{Peer: foundation.Hash{7}, Direct: true}
	if err := f.receiver.HandleGarlicFrom(source, garlicAdmissionMessage(packet, 1)); !errors.Is(err, ErrGarlicDestination) {
		t.Fatalf("first bad ciphertext: %v", err)
	}
	if err := f.receiver.HandleGarlicFrom(source, garlicAdmissionMessage(packet, 2)); !errors.Is(err, ErrGarlicPreauthReplay) {
		t.Fatalf("repeat with different I2NP ID: %v", err)
	}
}

func TestGarlicReceiverTaggedSessionBypassesExhaustedPreauthBudget(t *testing.T) {
	f := newRatchetReceiverFixture(t)
	f.establish(t)
	f.receiver.preauth.mu.Lock()
	f.receiver.preauth.global.available = 0
	f.receiver.preauth.global.last = f.now
	f.receiver.preauth.mu.Unlock()
	packet, err := f.remote.EncryptExisting(make([]byte, 512), f.localHash, nil, dataplanegarlic.RatchetOptions{}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.receive(packet); err != nil {
		t.Fatalf("authenticated existing session blocked by unrelated pre-auth budget: %v", err)
	}
}

func TestGarlicReceiverPreauthRejectsValidNewSessionBeforeDecrypt(t *testing.T) {
	const now = uint64(1_800_000_000_000)
	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.ReleaseSensitive)
	remote, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remote.ReleaseSensitive)
	localRatchet, err := dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{CryptoTypes: []uint16{4}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(localRatchet.ReleaseSensitive)
	remoteRatchet, err := dataplanegarlic.NewRatchetManager(remote, dataplanegarlic.RatchetConfig{CryptoTypes: []uint16{4}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remoteRatchet.ReleaseSensitive)
	public := local.X25519Public()
	packet, err := remoteRatchet.EncryptUnbound(make([]byte, 2048), public[:], 4, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewGarlicReceiver(GarlicReceiverConfig{
		Service: NewService(Sinks{}),
		ReplyKeys: dataplanegarlic.NewReplyKeyRegistry(1),
		Now: func() uint64 { return now },
		Destinations: map[foundation.Hash]GarlicDestination{local.Hash(): {Ratchet: localRatchet}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(receiver.ReleaseSensitive)
	receiver.preauth.mu.Lock()
	receiver.preauth.global.available = 0
	receiver.preauth.global.last = now
	receiver.preauth.mu.Unlock()
	message := garlicAdmissionMessage(packet, 1)
	if err := receiver.HandleGarlic(message); !errors.Is(err, ErrGarlicPreauthLimit) {
		t.Fatalf("valid New Session admitted without budget: %v", err)
	}
	if got := localRatchet.Stats().NewSessions; got != 0 {
		t.Fatalf("New Session authenticated despite denied budget: %d", got)
	}
	receiver.preauth.mu.Lock()
	receiver.preauth.global.available = garlicPreauthBurstUnits * garlicPreauthUnitScale
	receiver.preauth.mu.Unlock()
	if err := receiver.HandleGarlic(message); err != nil {
		t.Fatalf("valid New Session rejected with restored budget: %v", err)
	}
	if got := localRatchet.Stats().NewSessions; got != 1 {
		t.Fatalf("New Session not authenticated after admission: %d", got)
	}
}
