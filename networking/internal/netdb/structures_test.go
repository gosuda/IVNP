package netdb

import (
	"encoding/binary"
	"errors"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func legacyIdentity() []byte {
	identity := make([]byte, foundation.IdentityBaseLength+foundation.CertificateHeader)
	identity[384] = byte(foundation.CertificateNull)
	return identity
}

func TestRouterInfoParsesLazyAddresses(t *testing.T) {
	identity := legacyIdentity()
	address := []byte{5, 0, 0, 0, 0, 0, 0, 0, 0, 4, 'N', 'T', 'C', 'P', 0, 0}
	info := make([]byte, len(identity)+8+1+len(address)+1+2+40)
	off := copy(info, identity)
	binary.BigEndian.PutUint64(info[off:off+8], 42)
	off += 8
	info[off] = 1
	off++
	off += copy(info[off:], address)
	info[off] = 0
	off++
	info[off], info[off+1] = 0, 0

	parsed, err := ParseRouterInfo(info)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Published != 42 || parsed.AddressCount() != 1 || parsed.PeerCount() != 0 {
		t.Fatalf("RouterInfo fields = published %d, addresses %d, peers %d", parsed.Published, parsed.AddressCount(), parsed.PeerCount())
	}
	it := parsed.Addresses()
	got, ok, err := it.Next()
	if err != nil || !ok || string(got.TransportStyle) != "NTCP" || got.Cost != 5 {
		t.Fatalf("address = %#v, %t, %v", got, ok, err)
	}
	if _, ok, err := it.Next(); err != nil || ok {
		t.Fatalf("unexpected second address: %t, %v", ok, err)
	}
}

func TestRouterAddressRejectsZeroTransportStyle(t *testing.T) {
	address := make([]byte, 1+8+1+2)
	if _, _, err := ParseRouterAddress(address); !errors.Is(err, ErrMalformed) {
		t.Fatalf("zero style error = %v, want ErrMalformed", err)
	}
}

func TestLeaseSetExactLengthAndLeaseValidation(t *testing.T) {
	identity := legacyIdentity()
	payload := make([]byte, len(identity)+256+128+1+44+40)
	off := copy(payload, identity)
	off += 256 + 128
	payload[off] = 1
	off++
	binary.BigEndian.PutUint32(payload[off+32:off+36], 1)
	set, err := ParseLeaseSet(payload)
	if err != nil || set.LeaseCount() != 1 {
		t.Fatalf("ParseLeaseSet() = %#v, %v", set, err)
	}
	leases := set.Leases()
	lease, ok, err := leases.Next()
	if err != nil || !ok || lease.TunnelID != 1 {
		t.Fatalf("lease = %#v, %t, %v", lease, ok, err)
	}
	payload[off+32], payload[off+33], payload[off+34], payload[off+35] = 0, 0, 0, 0
	if _, err := ParseLeaseSet(payload); !errors.Is(err, ErrMalformed) {
		t.Fatalf("zero lease tunnel ID error = %v", err)
	}
}

func TestLeaseSet2ExactKeyAndLeaseBounds(t *testing.T) {
	identity := legacyIdentity()
	payload := make([]byte, len(identity)+8+2+1+4+32+1+40+40)
	off := copy(payload, identity)
	off += 8                            // published, expires, flags
	payload[off], payload[off+1] = 0, 0 // options mapping
	off += 2
	payload[off] = 1
	off++
	binary.BigEndian.PutUint16(payload[off:off+2], uint16(foundation.CryptoX25519))
	binary.BigEndian.PutUint16(payload[off+2:off+4], 32)
	off += 4 + 32
	payload[off] = 1
	off++
	binary.BigEndian.PutUint32(payload[off+32:off+36], 1)

	set, err := ParseLeaseSet2(payload)
	if err != nil || set.KeyCount() != 1 || set.LeaseCount() != 1 {
		t.Fatalf("ParseLeaseSet2() = %#v, %v", set, err)
	}
	keys := set.Keys()
	key, ok, err := keys.Next()
	if err != nil || !ok || key.Type != foundation.CryptoX25519 || len(key.Data) != 32 {
		t.Fatalf("key = %#v, %t, %v", key, ok, err)
	}
	leases := set.Leases()
	lease, ok, err := leases.Next()
	if err != nil || !ok || lease.TunnelID != 1 {
		t.Fatalf("lease = %#v, %t, %v", lease, ok, err)
	}

	keyLengthOffset := len(identity) + 8 + 2 + 1 + 2
	binary.BigEndian.PutUint16(payload[keyLengthOffset:keyLengthOffset+2], 31)
	if _, err := ParseLeaseSet2(payload); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("mismatched known key length error = %v", err)
	}
}

func TestLeaseSet2SelectsCallerPreferenceIndependentOfAdvertisementOrder(t *testing.T) {
	keys := make([]byte, 3*(4+32))
	binary.BigEndian.PutUint16(keys[:2], uint16(foundation.CryptoX25519))
	binary.BigEndian.PutUint16(keys[2:4], 32)
	binary.BigEndian.PutUint16(keys[36:38], uint16(foundation.CryptoMLKEM768X25519))
	binary.BigEndian.PutUint16(keys[38:40], 32)
	binary.BigEndian.PutUint16(keys[72:74], uint16(foundation.CryptoMLKEM1024X25519))
	binary.BigEndian.PutUint16(keys[74:76], 32)
	set := LeaseSet2{keyCount: 3, keys: keys}
	key, err := set.SelectEncryptionKey(foundation.CryptoMLKEM1024X25519, foundation.CryptoMLKEM768X25519, foundation.CryptoX25519)
	if err != nil || key.Type != foundation.CryptoMLKEM1024X25519 {
		t.Fatalf("selected key = %#v, %v", key, err)
	}
	if _, err := set.SelectEncryptionKey(foundation.CryptoP256); !errors.Is(err, ErrNoSupportedEncryptionKey) {
		t.Fatalf("unsupported selection error = %v", err)
	}
}

func TestLeaseSet2RejectsExcessLeasesBeforeSlicing(t *testing.T) {
	identity := legacyIdentity()
	payload := make([]byte, len(identity)+8+2+1+4+32+1)
	off := len(identity) + 8 + 2
	payload[off] = 1
	off++
	binary.BigEndian.PutUint16(payload[off:off+2], uint16(foundation.CryptoX25519))
	binary.BigEndian.PutUint16(payload[off+2:off+4], 32)
	off += 4 + 32
	payload[off] = MaxLeases + 1
	if _, err := ParseLeaseSet2(payload); !errors.Is(err, ErrTooManyItems) {
		t.Fatalf("excess lease count error = %v, want ErrTooManyItems", err)
	}
}

func BenchmarkParseRouterInfo(b *testing.B) {
	identity := legacyIdentity()
	info := make([]byte, len(identity)+8+1+1+2+40)
	off := len(identity) + 8
	info[off] = 0
	off++
	info[off] = 0
	off++
	info[off], info[off+1] = 0, 0
	b.ReportAllocs()
	for b.Loop() {
		_, _ = ParseRouterInfo(info)
	}
}

var routerInfoSink RouterInfo
var routerInfoErrorSink error

func TestParseRouterInfoHasNoHeapAllocation(t *testing.T) {
	identity := legacyIdentity()
	info := make([]byte, len(identity)+8+1+1+2+40)
	offset := len(identity) + 8
	info[offset] = 0
	offset++
	info[offset] = 0
	offset++
	info[offset], info[offset+1] = 0, 0
	allocs := testing.AllocsPerRun(1_000, func() {
		routerInfoSink, routerInfoErrorSink = ParseRouterInfo(info)
	})
	if routerInfoErrorSink != nil {
		t.Fatal(routerInfoErrorSink)
	}
	if allocs != 0 {
		t.Fatalf("ParseRouterInfo() allocations/run = %f, want 0", allocs)
	}
}

func TestParsersEnforceI2PDNetdbCapsBeforeFieldTraversal(t *testing.T) {
	if _, err := ParseRouterInfo(make([]byte, MaxRouterInfoBytes+1)); !errors.Is(err, ErrStructureTooLarge) {
		t.Fatalf("RouterInfo cap error = %v", err)
	}
	if _, err := ParseLeaseSet(make([]byte, MaxLeaseSetBytes+1)); !errors.Is(err, ErrStructureTooLarge) {
		t.Fatalf("LeaseSet cap error = %v", err)
	}
}
