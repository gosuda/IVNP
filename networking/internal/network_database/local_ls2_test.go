package netdb

import (
	"errors"
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
	"testing"
)

func TestLocalLeaseSet2BuildsVerifiedECIESAdvertisement(t *testing.T) {
	destination, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	local, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	const now = uint64(1_000_000)
	var gateway ivnp.Hash
	gateway[0] = 1
	if err := local.ReplaceInboundLeases([]Lease{{Gateway: gateway, TunnelID: 7, EndDate: now + 120_000}}); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, MaxLeaseSetBytes)
	n, err := local.MarshalTo(payload, now, func(message []byte) ([]byte, error) {
		return destination.Sign(message)
	})
	if err != nil {
		t.Fatal(err)
	}
	set, err := ParseLeaseSet2(payload[:n])
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := set.Verify(); err != nil || !ok {
		t.Fatalf("verified LS2 = %t, %v", ok, err)
	}
	if set.KeyCount() != 3 {
		t.Fatalf("advertised key count = %d, want 3", set.KeyCount())
	}
	key, err := set.SelectEncryptionKey(ivnp.CryptoMLKEM1024X25519, ivnp.CryptoMLKEM768X25519, ivnp.CryptoX25519)
	if err != nil || key.Type != ivnp.CryptoMLKEM1024X25519 {
		t.Fatalf("preferred locally usable key = %+v, %v", key, err)
	}
	leases := set.Leases()
	lease, ok, err := leases.Next()
	if err != nil || !ok || lease.TunnelID != 7 || lease.EndDate != uint32((now+120_000)/1000) {
		t.Fatalf("lease = %+v, %t, %v", lease, ok, err)
	}
}

func TestLocalLeaseSet2UsesLegacyDestinationWithModernEncryptionKey(t *testing.T) {
	destination, err := ivnp.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	local, err := NewLocalLeaseSet2WithTypes(destination, []ivnp.CryptoKeyType{ivnp.CryptoX25519})
	if err != nil {
		t.Fatal(err)
	}
	if local.identity.CryptoKeyType() != ivnp.CryptoElGamal {
		t.Fatalf("Destination crypto type = %d, want ElGamal", local.identity.CryptoKeyType())
	}
	key, err := destination.CryptoPublic(ivnp.CryptoX25519)
	if err != nil || key == ([32]byte{}) {
		t.Fatalf("LS2 X25519 key = %x, %v", key, err)
	}
}

func TestLocalLeaseSet2PreservesConfiguredCryptoTypeOrder(t *testing.T) {
	destination, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	local, err := NewLocalLeaseSet2WithTypes(destination, []ivnp.CryptoKeyType{ivnp.CryptoX25519, ivnp.CryptoMLKEM1024X25519})
	if err != nil {
		t.Fatal(err)
	}
	const now = uint64(1_000_000)
	if err = local.ReplaceInboundLeases([]Lease{{Gateway: ivnp.Hash{1}, TunnelID: 7, EndDate: now + 120_000}}); err != nil {
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
	keys := set.Keys()
	first, ok, err := keys.Next()
	if err != nil || !ok || first.Type != ivnp.CryptoX25519 {
		t.Fatalf("first configured key = %+v, %t, %v", first, ok, err)
	}
	second, ok, err := keys.Next()
	if err != nil || !ok || second.Type != ivnp.CryptoMLKEM1024X25519 {
		t.Fatalf("second configured key = %+v, %t, %v", second, ok, err)
	}
	if _, ok, err = keys.Next(); err != nil || ok {
		t.Fatalf("unexpected configured key tail: %t, %v", ok, err)
	}
}

func TestLeaseSet2RejectsRemovedCryptoType5AtConfigurationAndParsing(t *testing.T) {
	destination, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	if local, err := NewLocalLeaseSet2WithTypes(destination, []ivnp.CryptoKeyType{ivnp.CryptoKeyType(5)}); err == nil || local != nil {
		t.Fatalf("NewLocalLeaseSet2WithTypes(type 5) = %#v, %v", local, err)
	}
	local, err := NewLocalLeaseSet2WithTypes(destination, []ivnp.CryptoKeyType{ivnp.CryptoX25519})
	if err != nil {
		t.Fatal(err)
	}
	const now = uint64(1_000_000)
	if err = local.ReplaceInboundLeases([]Lease{{Gateway: ivnp.Hash{1}, TunnelID: 7, EndDate: now + 120_000}}); err != nil {
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
	if _, err = set.SelectEncryptionKey(ivnp.CryptoKeyType(5)); !errors.Is(err, ErrNoSupportedEncryptionKey) {
		t.Fatalf("SelectEncryptionKey(type 5) = %v", err)
	}
	set.keys[0], set.keys[1] = 0, 5
	if _, err = ParseLeaseSet2(payload[:n]); !errors.Is(err, ErrNoSupportedEncryptionKey) {
		t.Fatalf("ParseLeaseSet2(type 5) = %v", err)
	}
}

func TestLeaseSetPublisherPublishesLocalLeaseSet2(t *testing.T) {
	destination, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	local, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	if err := database.AdmitRouterInfo(publisherFloodfill(t), true, 1); err != nil {
		t.Fatal(err)
	}
	now := uint64(1_000)
	source := &publisherLeaseSource{leases: []Lease{{TunnelID: 9, EndDate: now + 60_000}}}
	sender := &publisherSender{}
	publisher, err := NewLeaseSetPublisher(LeaseSetPublisherConfig{
		Local2: local, Database: database, InboundLeases: source, Sender: sender,
		Sign: destination.Sign, Now: func() uint64 { return now }, Random: func() uint32 { return 1 },
		FloodfillLimit: 1, RepublishBefore: 1_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sent, err := publisher.Publish(t.Context()); err != nil || sent != 1 {
		t.Fatalf("Publish() = %d, %v", sent, err)
	}
	store, err := i2np.ParseDatabaseStore(sender.published[0].message.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if store.Key != destination.Hash() || store.Type != i2np.StoreLeaseSet2 {
		t.Fatalf("store = %#v", store)
	}
	if set, err := ParseLeaseSet2(store.Data); err != nil {
		t.Fatal(err)
	} else if ok, err := set.Verify(); err != nil || !ok {
		t.Fatalf("published LS2 verification = %t, %v", ok, err)
	}
}
