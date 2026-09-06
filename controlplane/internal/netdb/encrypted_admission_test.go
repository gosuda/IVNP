package netdb

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func TestEncryptedLeaseSetRedDSAAdmission(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := make([]byte, 2+len(public)+4+2+2+2+foundation.NetworkDatabaseMinEncryptedLeaseSetDataBytes)
	binary.BigEndian.PutUint16(unsigned[:2], uint16(foundation.SigningRedDSASHA512Ed25519))
	copy(unsigned[2:], public)
	binary.BigEndian.PutUint32(unsigned[2+len(public):2+len(public)+4], 1)
	binary.BigEndian.PutUint16(unsigned[2+len(public)+4:2+len(public)+6], 600)
	offset := 2 + len(public) + 4 + 2 + 2
	binary.BigEndian.PutUint16(unsigned[offset:offset+2], foundation.NetworkDatabaseMinEncryptedLeaseSetDataBytes)
	unsigned[offset+2] = 7
	signed := append([]byte{byte(foundation.I2NPStoreEncryptedLeaseSet)}, unsigned...)
	payload := append(unsigned, ed25519.Sign(private, signed)...)
	set, err := foundation.NetworkDatabaseParseEncryptedLeaseSet(payload)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := set.Verify(); err != nil || !valid {
		t.Fatalf("Verify() = %t, %v", valid, err)
	}
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	store := foundation.I2NPDatabaseStoreMessage{Key: set.Hash(), Type: foundation.I2NPStoreEncryptedLeaseSet, Data: payload}
	if err := database.HandleDatabaseStore(store, false, 1); err != nil {
		t.Fatal(err)
	}
	if _, ok := database.EncryptedLeaseSet(set.Hash()); !ok {
		t.Fatal("encrypted LeaseSet was not retained")
	}
}
