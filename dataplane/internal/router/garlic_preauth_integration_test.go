package router

import (
	"encoding/binary"
	"errors"
	"testing"

	dataplanegarlic "gosuda.org/ivnp/dataplane/internal/garlic"
	"gosuda.org/ivnp/foundation"
)

func garlicPreauthTestMessage(ciphertext []byte) foundation.I2NPMessage {
	payload := make([]byte, 4+len(ciphertext))
	binary.BigEndian.PutUint32(payload, uint32(len(ciphertext)))
	copy(payload[4:], ciphertext)
	return foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPGarlic}, Payload: payload}
}

func TestGarlicReceiverCachesOnlyUnmatchedCiphertext(t *testing.T) {
	fixture := newRatchetReceiverFixture(t)
	ciphertext := make([]byte, 64)
	ciphertext[0] = 0x42
	ciphertext[31] = 0x7f

	if err := fixture.receive(ciphertext); !errors.Is(err, ErrGarlicDestination) {
		t.Fatalf("unmatched packet = %v, want ErrGarlicDestination", err)
	}
	if err := fixture.receive(ciphertext); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("repeated ciphertext = %v, want ErrDuplicate before crypto", err)
	}
	fixture.now += garlicInvalidCiphertextLifetime
	if err := fixture.receive(ciphertext); !errors.Is(err, ErrGarlicDestination) {
		t.Fatalf("expired ciphertext reservation = %v", err)
	}
}

func TestGarlicReceiverCryptoBudgetRejectsWithoutPoisoningRetry(t *testing.T) {
	now := uint64(1_000_000)
	local, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.ReleaseSensitive)
	remote, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remote.ReleaseSensitive)

	recipient, err := dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(recipient.ReleaseSensitive)
	sender, err := dataplanegarlic.NewRatchetManager(remote, dataplanegarlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.ReleaseSensitive)

	receiver, err := NewGarlicReceiver(GarlicReceiverConfig{
		Service: NewService(Sinks{}), ReplyKeys: dataplanegarlic.NewReplyKeyRegistry(1),
		Now: func() uint64 { return now },
		Destinations: map[foundation.Hash]GarlicDestination{local.Hash(): {Ratchet: recipient}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(receiver.ReleaseSensitive)

	public := local.X25519Public()
	packet, err := sender.EncryptUnbound(make([]byte, 2048), public[:], uint16(foundation.CryptoX25519), nil, now)
	if err != nil {
		t.Fatal(err)
	}
	message := garlicPreauthTestMessage(packet)
	source := I2NPSource{Peer: foundation.Hash{7}, Direct: true}
	for range garlicCryptoSourceWorkLimit {
		if !receiver.preauth.allowWork(source, now) {
			t.Fatal("unable to exhaust work budget")
		}
	}
	if err := receiver.HandleGarlicFrom(source, message); !errors.Is(err, ErrGarlicCryptoBudget) {
		t.Fatalf("work budget rejection = %v, want ErrGarlicCryptoBudget", err)
	}
	now += garlicCryptoWindowMillis
	if err := receiver.HandleGarlicFrom(source, message); err != nil {
		t.Fatalf("valid New Session packet rejected after budget refill: %v", err)
	}
}

func TestGarlicReceiverTaggedSessionBypassesCryptoBudget(t *testing.T) {
	fixture := newRatchetReceiverFixture(t)
	fixture.establish(t)
	for _, peer := range []foundation.Hash{{1}, {2}} {
		source := I2NPSource{Peer: peer, Direct: true}
		for range garlicCryptoSourceWorkLimit {
			if !fixture.receiver.preauth.allowWork(source, fixture.now) {
				t.Fatal("unable to exhaust global work budget")
			}
		}
	}
	packet, err := fixture.remote.EncryptExisting(make([]byte, 512), fixture.localHash, nil, dataplanegarlic.RatchetOptions{}, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if !fixture.local.HasTag(packet) {
		t.Fatal("registered session tag not indexed")
	}
	if err := fixture.receive(packet); err != nil {
		t.Fatalf("registered session blocked by pre-authentication budget: %v", err)
	}
}
