package garlic

import (
	"encoding/binary"
	"errors"
	"testing"

	"gosuda.org/ivnp/networking/internal/i2np"
)

func TestCloveSetRoundTrip(t *testing.T) {
	message := i2np.Message{Header: i2np.Header{Type: i2np.DeliveryStatus, ID: 1}, Payload: make([]byte, 12)}
	frame := make([]byte, message.EncodedLen())
	if _, err := message.MarshalTo(frame); err != nil {
		t.Fatal(err)
	}
	cloveLen := 1 + len(frame) + 4 + 8 + 3
	payload := make([]byte, 1+cloveLen+3+4+8)
	payload[0] = 1
	off := 1
	payload[off] = byte(DeliveryLocal)
	off++
	off += copy(payload[off:], frame)
	binary.BigEndian.PutUint32(payload[off:off+4], 9)
	off += 4 + 8
	// Individual and set certificates are NULL.
	off += 3
	// Final clove-set certificate is NULL.
	off += 3
	binary.BigEndian.PutUint32(payload[off:off+4], 10)
	off += 4
	binary.BigEndian.PutUint64(payload[off:off+8], 11)
	set, err := ParseCloveSet(payload)
	if err != nil || set.Count() != 1 || set.MessageID != 10 || set.Expiration != 11 {
		t.Fatalf("ParseCloveSet() = %#v, %v", set, err)
	}
	iterator := set.Cloves()
	clove, ok, err := iterator.Next()
	if err != nil || !ok || clove.ID != 9 || clove.Message.Header.Type != i2np.DeliveryStatus {
		t.Fatalf("clove = %#v, %t, %v", clove, ok, err)
	}
}

func TestDeliveryRejectsReservedFlags(t *testing.T) {
	if _, _, err := ParseDelivery([]byte{1}); !errors.Is(err, ErrDelivery) {
		t.Fatalf("reserved flags = %v", err)
	}
}

func TestDeliveryIgnoresDeprecatedEncryptedFlag(t *testing.T) {
	wire := make([]byte, 1+32)
	wire[0] = 0x80 | byte(DeliveryDestination<<5)
	wire[1] = 0xa5
	delivery, used, err := ParseDelivery(wire)
	if err != nil || used != len(wire) || delivery.Type != DeliveryDestination || delivery.To[0] != 0xa5 {
		t.Fatalf("deprecated encrypted flag parse = %#v, %d, %v", delivery, used, err)
	}
	encoded := make([]byte, delivery.EncodedLen())
	if _, err = delivery.MarshalTo(encoded); err != nil {
		t.Fatal(err)
	}
	if encoded[0] != byte(DeliveryDestination<<5) || encoded[1] != 0xa5 {
		t.Fatalf("delivery serialized deprecated flag: %x", encoded)
	}
}
