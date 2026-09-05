package netdb

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

// offlineTestDestination builds a LocalDestination whose long-term signing
// private key is absent and replaced by an authorized transient Ed25519 key.
func offlineTestDestination(t *testing.T, expires uint32) *foundation.LocalDestination {
	t.Helper()
	longTerm, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer longTerm.ReleaseSensitive()
	state := make([]byte, longTerm.PrivateEncodedLen())
	n, err := longTerm.MarshalPrivateTo(state)
	if err != nil {
		t.Fatal(err)
	}
	state = state[:n]
	defer clear(state)
	publicLength := int(binary.BigEndian.Uint16(state[:2]))
	clear(state[2+publicLength : 2+publicLength+ed25519.PrivateKeySize])
	transientPublic, transientFull, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(transientFull)
	transientPrivate := transientFull.Seed()
	defer clear(transientPrivate)
	offline := foundation.OfflineSignature{Expires: expires, Type: foundation.SigningEdDSASHA512Ed25519, PublicKey: transientPublic}
	var content [6 + ed25519.PublicKeySize]byte
	contentLen, err := offline.MarshalSignedContentTo(content[:])
	if err != nil {
		t.Fatal(err)
	}
	offline.Signature, err = longTerm.Sign(content[:contentLen])
	if err != nil {
		t.Fatal(err)
	}
	destination, err := foundation.ImportLocalDestinationOffline(state, offline, transientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return destination
}

func TestLocalLeaseSet2OfflineSignatureSection(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	destination := offlineTestDestination(t, uint32(now/1000)+3600)
	defer destination.ReleaseSensitive()
	local, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	var gateway foundation.Hash
	gateway[0] = 1
	if err = local.ReplaceInboundLeases([]Lease{{Gateway: gateway, TunnelID: 7, EndDate: now + 120_000}}); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, MaxLeaseSetBytes)
	n, err := local.MarshalTo(payload, now, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	set, err := ParseLeaseSet2(payload[:n])
	if err != nil {
		t.Fatal(err)
	}
	if set.Header.Flags&leaseSetOfflineFlag == 0 || !set.Header.Offline.Present() {
		t.Fatalf("offline flag/section missing: flags=%#x", set.Header.Flags)
	}
	if set.Header.Offline.Expires != uint32(now/1000)+3600 {
		t.Fatalf("offline expires = %d", set.Header.Offline.Expires)
	}
	if ok, err := set.Verify(); err != nil || !ok {
		t.Fatalf("verified offline LS2 = %t, %v", ok, err)
	}
}

func TestLocalLeaseSet2OfflineExpiredRefusesPublication(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	destination := offlineTestDestination(t, uint32(now/1000)-1)
	defer destination.ReleaseSensitive()
	local, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	var gateway foundation.Hash
	gateway[0] = 1
	if err = local.ReplaceInboundLeases([]Lease{{Gateway: gateway, TunnelID: 7, EndDate: now + 120_000}}); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, MaxLeaseSetBytes)
	if _, err = local.MarshalTo(payload, now, destination.Sign); !errors.Is(err, ErrLocalLeaseSet2) {
		t.Fatalf("expired offline MarshalTo = %v, want ErrLocalLeaseSet2", err)
	}
}

func TestNewLocalEncryptedLeaseSetRejectsOfflineDestination(t *testing.T) {
	destination := offlineTestDestination(t, uint32(1_000_000_000_000/1000)+3600)
	defer destination.ReleaseSensitive()
	local, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := NewLocalEncryptedLeaseSet(destination, local, EncryptedLeaseSetAuthorization{}, nil)
	if err == nil || encrypted != nil {
		t.Fatalf("offline encrypted LeaseSet = %#v, %v", encrypted, err)
	}
}
