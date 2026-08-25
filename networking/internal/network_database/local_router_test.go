package netdb

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	ivnp "gosuda.org/ivnp/foundation"
	"testing"
)

func TestLocalRouterInfoPublishesVerifiedOwnedAdvertisement(t *testing.T) {
	local, err := ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	var peer ivnp.Hash
	peer[0] = 0xa5
	config := LocalRouterInfoConfig{
		Local: local,
		Contacts: RouterInfoContacts{
			Addresses: []LocalRouterAddress{{
				Cost:           5,
				Expiration:     999,
				TransportStyle: []byte("NTCP2"),
				Options: []ivnp.MappingEntry{
					{Key: []byte("host"), Value: []byte("127.0.0.1")},
					{Key: []byte("port"), Value: []byte("12345")},
					{Key: []byte("s"), Value: []byte("test-static-key")},
				},
			}},
			Peers: []ivnp.Hash{peer},
			Options: []ivnp.MappingEntry{
				{Key: []byte("caps"), Value: []byte("R")},
				{Key: []byte("netId"), Value: []byte("2")},
			},
		},
	}
	owner, err := NewLocalRouterInfo(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := owner.Snapshot(); ok {
		t.Fatal("Snapshot succeeded before Publish")
	}

	info, err := owner.Publish(123456789)
	if err != nil {
		t.Fatal(err)
	}
	if info.Hash() != local.Hash || info.Published != 123456789 || info.PeerCount() != 1 {
		t.Fatalf("published RouterInfo = hash %x published %d peers %d", info.Hash(), info.Published, info.PeerCount())
	}
	if valid, err := info.Verify(); err != nil || !valid {
		t.Fatalf("published RouterInfo signature = %t, %v", valid, err)
	}
	iterator := info.Addresses()
	address, ok, err := iterator.Next()
	if err != nil || !ok {
		t.Fatalf("published address = %#v, %t, %v", address, ok, err)
	}
	if address.Cost != 5 || address.Expiration != 999 || !bytes.Equal(address.TransportStyle, []byte("NTCP2")) {
		t.Fatalf("published address header = %#v", address)
	}
	if got := address.Options.Bytes(); !bytes.Contains(got, []byte("host")) || !bytes.Contains(got, []byte("port")) {
		t.Fatalf("published address options = %x", got)
	}
	if owner.Hash() != local.Hash || owner.Published() != info.Published || owner.Version() != 1 {
		t.Fatalf("owner state = hash %x published %d version %d", owner.Hash(), owner.Published(), owner.Version())
	}

	snapshot, ok := owner.Snapshot()
	if !ok {
		t.Fatal("Snapshot failed after Publish")
	}
	snapshot.Bytes()[0] ^= 0xff
	again, ok := owner.Snapshot()
	if !ok {
		t.Fatal("second Snapshot failed")
	}
	if valid, err := again.Verify(); err != nil || !valid {
		t.Fatalf("retained RouterInfo was mutated through Snapshot: %t, %v", valid, err)
	}
}

func TestLocalRouterInfoSnapshotRejectsCorruptedRetainedBytes(t *testing.T) {
	local, err := ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{Local: local})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Publish(1); err != nil {
		t.Fatal(err)
	}
	owner.raw = []byte{0xff}
	if snapshot, ok := owner.Snapshot(); ok || snapshot.Bytes() != nil {
		t.Fatalf("corrupted snapshot = %#v, %t", snapshot, ok)
	}
}

func TestLocalRouterInfoPublishesModernRouterIdentity(t *testing.T) {
	local, err := ivnp.GenerateLocalRouterAddress()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{Local: local})
	if err != nil {
		t.Fatal(err)
	}
	info, err := owner.Publish(123456789)
	if err != nil {
		t.Fatal(err)
	}
	if info.Hash() != local.Hash || info.Identity.CryptoKeyType() != ivnp.CryptoX25519 {
		t.Fatalf("RouterInfo identity = hash %x type %d", info.Hash(), info.Identity.CryptoKeyType())
	}
	crypto, rest := info.Identity.CryptoKeyParts()
	if len(rest) != 0 || !bytes.Equal(crypto, local.X25519Public[:]) {
		t.Fatal("published RouterInfo omitted the local X25519 public key")
	}
	if valid, err := info.Verify(); err != nil || !valid {
		t.Fatalf("published RouterInfo signature = %t, %v", valid, err)
	}
	message := []byte("modern router signature")
	if !ed25519.Verify(local.SigningPublic, message, owner.Sign(message)) {
		t.Fatal("owner signature does not verify with the RouterIdentity signing key")
	}
}

func TestLocalRouterInfoCopiesContactsAndInvalidatesOldAdvertisement(t *testing.T) {
	local, err := ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	contacts := RouterInfoContacts{
		Addresses: []LocalRouterAddress{{
			TransportStyle: []byte("NTCP2"),
			Options:        []ivnp.MappingEntry{{Key: []byte("host"), Value: []byte("old")}},
		}},
	}
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{Local: local, Contacts: contacts})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = owner.Publish(1); err != nil {
		t.Fatal(err)
	}
	contacts.Addresses[0].TransportStyle[0] = 'X'
	contacts.Addresses[0].Options[0].Value[0] = 'X'

	if err = owner.ReplaceContacts(RouterInfoContacts{Addresses: []LocalRouterAddress{{
		TransportStyle: []byte("SSU2"),
		Options:        []ivnp.MappingEntry{{Key: []byte("host"), Value: []byte("new")}},
	}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := owner.Snapshot(); ok {
		t.Fatal("Snapshot retained obsolete contact advertisement")
	}
	info, err := owner.Publish(2)
	if err != nil {
		t.Fatal(err)
	}
	iterator := info.Addresses()
	address, ok, err := iterator.Next()
	if err != nil || !ok || !bytes.Equal(address.TransportStyle, []byte("SSU2")) {
		t.Fatalf("republished address = %#v, %t, %v", address, ok, err)
	}
	if owner.Version() != 3 {
		t.Fatalf("version = %d, want 3", owner.Version())
	}
}

func TestLocalRouterInfoRejectsInvalidIdentityAndContacts(t *testing.T) {
	local, err := ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	local.SigningPrivate[0] ^= 1
	if _, err := NewLocalRouterInfo(LocalRouterInfoConfig{Local: local}); !errors.Is(err, ErrLocalRouterIdentity) {
		t.Fatalf("invalid signing key error = %v, want ErrLocalRouterIdentity", err)
	}

	local, err = ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalRouterInfo(LocalRouterInfoConfig{
		Local: local,
		Contacts: RouterInfoContacts{Addresses: []LocalRouterAddress{{
			TransportStyle: nil,
		}}},
	}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty style error = %v, want ErrMalformed", err)
	}
	if _, err := NewLocalRouterInfo(LocalRouterInfoConfig{
		Local: local,
		Contacts: RouterInfoContacts{Options: []ivnp.MappingEntry{
			{Key: []byte("z"), Value: nil},
			{Key: []byte("a"), Value: nil},
		}},
	}); !errors.Is(err, ivnp.ErrUnsortedMapping) {
		t.Fatalf("unsorted options error = %v, want ivnp.ErrUnsortedMapping", err)
	}
}
