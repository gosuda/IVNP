package garlic

import (
	"bytes"
	"gosuda.org/ivnp/cryptography"
	"testing"
)

func TestNewSessionRoundTripAndTamperRejection(t *testing.T) {
	public, private, err := cryptography.GenerateElGamalKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	delivered := bytes.Repeat([]byte{0x7a}, 32)
	packet, sentKey, err := EncryptNew(make([]byte, 1024), public, []byte("new payload"), delivered)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) <= cryptography.ElGamalCiphertextSize || packet[0] != 0 || packet[257] != 0 {
		t.Fatalf("new-session layout = %d bytes", len(packet))
	}
	payload, tags, receivedKey, err := ReceiveNew(make([]byte, len(packet)-cryptography.ElGamalCiphertextSize), packet, private)
	if err != nil || !bytes.Equal(payload, []byte("new payload")) || !bytes.Equal(tags, delivered) || receivedKey != sentKey {
		t.Fatalf("ReceiveNew() = %q / %x / %x / %v", payload, tags, receivedKey, err)
	}

	badElGamal := append([]byte(nil), packet...)
	badElGamal[0] = 1
	if _, _, _, err := ReceiveNew(make([]byte, len(packet)-cryptography.ElGamalCiphertextSize), badElGamal, private); err == nil {
		t.Fatal("accepted malformed ElGamal prefix")
	}
	badBody := append([]byte(nil), packet...)
	badBody[cryptography.ElGamalCiphertextSize] ^= 1
	if _, _, _, err := ReceiveNew(make([]byte, len(packet)-cryptography.ElGamalCiphertextSize), badBody, private); err == nil {
		t.Fatal("accepted tampered authenticated Garlic body")
	}
}
