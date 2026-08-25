package networkdatabase

import (
	"encoding/binary"
	"errors"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/wire"
	"testing"
)

func TestMetaLeaseSetBoundsAndFlags(t *testing.T) {
	identity := legacyIdentity()
	payload := make([]byte, len(identity)+8+2+1+40+1+40)
	offset := len(identity) + 8
	payload[offset], payload[offset+1] = 0, 0
	offset += 2
	payload[offset] = 1
	offset++
	payload[offset+34] = 1 // LeaseSet entry type, high flag bits are zero.
	set, err := ParseMetaLeaseSet(payload)
	if err != nil || set.LeaseCount() != 1 || set.RevocationCount() != 0 {
		t.Fatalf("ParseMetaLeaseSet() = %#v, %v", set, err)
	}
	iterator := set.Leases()
	lease, ok, err := iterator.Next()
	if err != nil || !ok || lease.Type != 1 {
		t.Fatalf("meta lease = %#v, %t, %v", lease, ok, err)
	}
	payload[offset+32] = 1
	if _, err := ParseMetaLeaseSet(payload); !errors.Is(err, ErrMalformed) {
		t.Fatalf("reserved MetaLease flags = %v", err)
	}
}

func TestEncryptedLeaseSetLengthValidation(t *testing.T) {
	keyLen, _ := foundation.SigningDSASHA1.PublicKeyLen()
	payload := make([]byte, 2+keyLen+4+2+2+2+1+40)
	binary.BigEndian.PutUint16(payload[:2], uint16(foundation.SigningDSASHA1))
	offset := 2 + keyLen + 4 + 2 + 2
	binary.BigEndian.PutUint16(payload[offset:offset+2], 1)
	offset += 2
	payload[offset] = 1
	set, err := ParseEncryptedLeaseSet(payload)
	if err != nil || len(set.EncryptedData) != 1 || len(set.Signature) != 40 {
		t.Fatalf("ParseEncryptedLeaseSet() = %#v, %v", set, err)
	}
	binary.BigEndian.PutUint16(payload[2+keyLen+4+2+2:2+keyLen+4+2+2+2], 2)
	if _, err := ParseEncryptedLeaseSet(payload); !errors.Is(err, wire.ErrShortBuffer) {
		t.Fatalf("truncated encrypted payload = %v", err)
	}
}
