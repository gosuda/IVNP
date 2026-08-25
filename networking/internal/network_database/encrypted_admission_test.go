package netdb

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
	"testing"
)

func TestEncryptedLeaseSetRedDSAAdmission(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := make([]byte, 2+len(public)+4+2+2+2+1)
	binary.BigEndian.PutUint16(unsigned[:2], uint16(ivnp.SigningRedDSASHA512Ed25519))
	copy(unsigned[2:], public)
	offset := 2 + len(public) + 4 + 2 + 2
	binary.BigEndian.PutUint16(unsigned[offset:offset+2], 1)
	unsigned[offset+2] = 7
	signed := append([]byte{byte(i2np.StoreEncryptedLeaseSet)}, unsigned...)
	payload := append(unsigned, ed25519.Sign(private, signed)...)
	set, err := ParseEncryptedLeaseSet(payload)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := set.Verify(); err != nil || !valid {
		t.Fatalf("Verify() = %t, %v", valid, err)
	}
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	store := i2np.DatabaseStoreMessage{Key: set.Hash(), Type: i2np.StoreEncryptedLeaseSet, Data: payload}
	if err := database.HandleDatabaseStore(store, false, 1); err != nil {
		t.Fatal(err)
	}
	if _, ok := database.EncryptedLeaseSet(set.Hash()); !ok {
		t.Fatal("encrypted LeaseSet was not retained")
	}
}
