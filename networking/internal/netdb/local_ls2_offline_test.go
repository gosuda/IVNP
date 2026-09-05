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
	transientPrivate := append([]byte(nil), transientFull.Seed()...)
	clear(transientFull)
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
	destination := offlineTestDestination(t, uint32(time.Now().Unix())+3600)
	defer destination.ReleaseSensitive()
	local, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := NewLocalEncryptedLeaseSet(destination, local, EncryptedLeaseSetAuthorization{}, nil)
	if !errors.Is(err, ErrEncryptedLeaseSet) || encrypted != nil {
		t.Fatalf("offline encrypted LeaseSet = %#v, %v, want ErrEncryptedLeaseSet", encrypted, err)
	}
}

func TestLocalLeaseSet2OfflineCapsLeaseExpiry(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	expires := uint32(now/1000) + 60
	destination := offlineTestDestination(t, expires)
	defer destination.ReleaseSensitive()
	local, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	var gateway foundation.Hash
	gateway[0] = 1
	if err = local.ReplaceInboundLeases([]Lease{{Gateway: gateway, TunnelID: 7, EndDate: now + 3_600_000}}); err != nil {
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
	leases := set.Leases()
	lease, ok, err := leases.Next()
	if err != nil || !ok {
		t.Fatalf("lease = %t, %v", ok, err)
	}
	// Remote verifiers stop trusting the transient key at the offline
	// authorization expiry, so no published lease may outlive it.
	if lease.EndDate != expires {
		t.Fatalf("lease end = %d, want capped at offline expiry %d", lease.EndDate, expires)
	}
	if ok, err = set.Verify(); err != nil || !ok {
		t.Fatalf("verify = %t, %v", ok, err)
	}
}

func TestOfflineLeaseSet2VerifyRejectsPastExpiry(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	expires := uint32(now/1000) + 60
	destination := offlineTestDestination(t, expires)
	defer destination.ReleaseSensitive()
	local, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	var gateway foundation.Hash
	gateway[0] = 1
	if err = local.ReplaceInboundLeases([]Lease{{Gateway: gateway, TunnelID: 7, EndDate: now + 30_000}}); err != nil {
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
	if ok, err := set.Verify(); err != nil || !ok {
		t.Fatalf("valid set verify = %t, %v", ok, err)
	}

	t.Run("published past offline expires", func(t *testing.T) {
		bad := set
		bad.Header.Offline.Expires = bad.Header.Published - 1
		if ok, err := bad.Verify(); err != nil || ok {
			t.Fatalf("Verify() = %t, %v, want false", ok, err)
		}
	})

	t.Run("header duration past offline expires", func(t *testing.T) {
		bad := set
		bad.Header.Offline.Expires = bad.Header.Published + uint32(bad.Header.Expires) - 1
		if ok, err := bad.Verify(); err != nil || ok {
			t.Fatalf("Verify() = %t, %v, want false", ok, err)
		}
	})

	t.Run("lease end date past offline expires", func(t *testing.T) {
		leases := set.Leases()
		lease, ok, err := leases.Next()
		if err != nil || !ok {
			t.Fatal("no lease")
		}
		bad := set
		bad.Header.Offline.Expires = lease.EndDate - 1
		if ok, err := bad.Verify(); err != nil || ok {
			t.Fatalf("Verify() = %t, %v, want false", ok, err)
		}
	})

	t.Run("leaseSet2Range rejects lease past offline expires", func(t *testing.T) {
		leases := set.Leases()
		lease, ok, err := leases.Next()
		if err != nil || !ok {
			t.Fatal("no lease")
		}
		bad := set
		bad.Header.Offline.Expires = lease.EndDate - 1
		if _, _, err := leaseSet2Range(bad); !errors.Is(err, ErrMalformed) {
			t.Fatalf("leaseSet2Range() = %v, want ErrMalformed", err)
		}
	})

	t.Run("OfflineExpires returns configured expiry", func(t *testing.T) {
		exp, ok := local.OfflineExpires()
		if !ok || exp != expires {
			t.Fatalf("OfflineExpires() = %d, %t, want %d, true", exp, ok, expires)
		}
	})
}
