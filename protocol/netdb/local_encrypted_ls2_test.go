package netdb

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/protocol/i2np"
)

type elsFailReader struct {
	remaining int
	err       error
}

func (r *elsFailReader) Read(dst []byte) (int, error) {
	if r.remaining == 0 {
		return 0, r.err
	}
	n := min(len(dst), r.remaining)
	for index := range n {
		dst[index] = byte(index + 1)
	}
	r.remaining -= n
	if n != len(dst) {
		return n, r.err
	}
	return n, nil
}
func encryptedTestSet(t *testing.T, auth EncryptedLeaseSetAuthorization) (*ivnp.LocalDestination, ivnp.Identity, *LocalEncryptedLeaseSet, uint64) {
	t.Helper()
	destination, err := ivnp.GenerateEncryptedLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := destination.Identity()
	if err != nil {
		t.Fatal(err)
	}
	local, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(1_750_000_000_000)
	if err = local.ReplaceInboundLeases([]Lease{{Gateway: ivnp.Hash{1}, TunnelID: 7, EndDate: now + 3_600_000}}); err != nil {
		t.Fatal(err)
	}
	encrypted, err := NewLocalEncryptedLeaseSet(destination, local, auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(encrypted.ReleaseSensitive)
	return destination, identity, encrypted, now
}

func TestEncryptedLeaseSetRoundTripAndTampering(t *testing.T) {
	destination, identity, encrypted, now := encryptedTestSet(t, EncryptedLeaseSetAuthorization{})
	defer destination.ReleaseSensitive()
	payload := make([]byte, MaxLeaseSetBytes)
	n, err := encrypted.MarshalTo(payload, now)
	if err != nil {
		t.Fatal(err)
	}
	set, err := ParseEncryptedLeaseSet(payload[:n])
	if err != nil {
		t.Fatal(err)
	}
	if set.SigningType != ivnp.SigningRedDSASHA512Ed25519 || set.Flags != 0 {
		t.Fatalf("outer header = %#v", set)
	}
	if ok, err := set.Verify(); err != nil || !ok {
		t.Fatalf("outer signature = %t, %v", ok, err)
	}
	inner, err := DecryptEncryptedLeaseSet(set, identity, nil, ELSClientAuthorization{}, now+1_000)
	if err != nil {
		t.Fatal(err)
	}
	if inner.Hash() != identity.Hash() || inner.Header.Published != set.Published || inner.Header.Expires != set.Expires {
		t.Fatalf("inner/outer mismatch: %#v %#v", inner.Header, set)
	}
	tampered := append([]byte(nil), payload[:n]...)
	tampered[len(tampered)-1] ^= 1
	bad, err := ParseEncryptedLeaseSet(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecryptEncryptedLeaseSet(bad, identity, nil, ELSClientAuthorization{}, now+1_000); err == nil {
		t.Fatal("tampered ELS2 decrypted")
	}
	wrong, err := ivnp.GenerateEncryptedLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.ReleaseSensitive()
	wrongIdentity, _ := wrong.Identity()
	if _, err = DecryptEncryptedLeaseSet(set, wrongIdentity, nil, ELSClientAuthorization{}, now+1_000); err == nil {
		t.Fatal("wrong destination decrypted ELS2")
	}
	if _, err = DecryptEncryptedLeaseSet(set, identity, nil, ELSClientAuthorization{}, now+3_700_000); err == nil {
		t.Fatal("expired ELS2 decrypted")
	}
}

func TestEncryptedLeaseSetClientAuthorization(t *testing.T) {
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var clientPublic [32]byte
	copy(clientPublic[:], client.PublicKey().Bytes())
	destination, identity, encrypted, now := encryptedTestSet(t, EncryptedLeaseSetAuthorization{DHClients: [][32]byte{clientPublic}})
	defer destination.ReleaseSensitive()
	payload := make([]byte, MaxLeaseSetBytes)
	n, err := encrypted.MarshalTo(payload, now)
	if err != nil {
		t.Fatal(err)
	}
	set, err := ParseEncryptedLeaseSet(payload[:n])
	if err != nil {
		t.Fatal(err)
	}
	var clientPrivate [32]byte
	copy(clientPrivate[:], client.Bytes())
	if _, err = DecryptEncryptedLeaseSet(set, identity, nil, ELSClientAuthorization{UseDH: true, DHPrivate: clientPrivate, DHPublic: clientPublic}, now+1); err != nil {
		t.Fatal(err)
	}
	if _, err = DecryptEncryptedLeaseSet(set, identity, nil, ELSClientAuthorization{}, now+1); err == nil {
		t.Fatal("unauthorized DH client decrypted ELS2")
	}

	var psk [32]byte
	if _, err = rand.Read(psk[:]); err != nil {
		t.Fatal(err)
	}
	pskDestination, pskIdentity, pskEncrypted, pskNow := encryptedTestSet(t, EncryptedLeaseSetAuthorization{PSKClients: [][32]byte{psk}})
	defer pskDestination.ReleaseSensitive()
	n, err = pskEncrypted.MarshalTo(payload, pskNow)
	if err != nil {
		t.Fatal(err)
	}
	set, err = ParseEncryptedLeaseSet(payload[:n])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecryptEncryptedLeaseSet(set, pskIdentity, nil, ELSClientAuthorization{UsePSK: true, PSK: psk}, pskNow+1); err != nil {
		t.Fatal(err)
	}
	psk[0] ^= 1
	if _, err = DecryptEncryptedLeaseSet(set, pskIdentity, nil, ELSClientAuthorization{UsePSK: true, PSK: psk}, pskNow+1); err == nil {
		t.Fatal("wrong PSK decrypted ELS2")
	}
}

func TestLocalEncryptedLeaseSetFailureCleanupAndRelease(t *testing.T) {
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var public [32]byte
	copy(public[:], client.PublicKey().Bytes())
	destination, _, encrypted, now := encryptedTestSet(t, EncryptedLeaseSetAuthorization{DHClients: [][32]byte{public}})
	defer destination.ReleaseSensitive()
	encrypted.secret = append(encrypted.secret, []byte("secret")...)
	injected := errors.New("injected ELS randomness failure")
	encrypted.random = &elsFailReader{remaining: 32, err: injected}
	dst := make([]byte, MaxLeaseSetBytes)
	for index := range dst {
		dst[index] = 0xa5
	}
	if _, err = encrypted.MarshalTo(dst, now); !errors.Is(err, injected) {
		t.Fatalf("MarshalTo injected error = %v", err)
	}
	for _, value := range dst {
		if value != 0 {
			t.Fatal("MarshalTo error retained partial output")
		}
	}
	secret := encrypted.secret
	clients := encrypted.dhClients
	encrypted.random = rand.Reader
	short := bytes.Repeat([]byte{0xa5}, 63)
	if _, err = encrypted.MarshalTo(short, now); !errors.Is(err, ivnp.ErrDestinationSmall) {
		t.Fatalf("MarshalTo short outer destination = %v", err)
	}
	for _, value := range short {
		if value != 0 {
			t.Fatal("finishOuter error retained partial signed output")
		}
	}
	encrypted.ReleaseSensitive()
	encrypted.ReleaseSensitive()
	for _, value := range secret {
		if value != 0 {
			t.Fatal("ELS blinding secret remained after release")
		}
	}
	for index := range clients {
		if clients[index] != ([32]byte{}) {
			t.Fatal("ELS DH client remained after release")
		}
	}
	localEncryptedLeaseSetFailureCleanupAndReleaseRejected := !encrypted.released || encrypted.destination != nil || encrypted.inner != nil || encrypted.random != nil || encrypted.secret != nil
	if !localEncryptedLeaseSetFailureCleanupAndReleaseRejected {
		localEncryptedLeaseSetFailureCleanupAndReleaseRejected = encrypted.dhClients != nil
	}
	if localEncryptedLeaseSetFailureCleanupAndReleaseRejected {
		t.Fatal("ELS owner retained references after release")
	}
	if _, err = encrypted.MarshalTo(dst, now); !errors.Is(err, ErrEncryptedLeaseSet) {
		t.Fatalf("MarshalTo after release = %v", err)
	}
}

func TestLeaseSetPublisherCloseReleasesSensitiveOwners(t *testing.T) {
	destination, _, encrypted, now := encryptedTestSet(t, EncryptedLeaseSetAuthorization{})
	defer destination.ReleaseSensitive()
	encrypted.secret = append(encrypted.secret, []byte("publisher-secret")...)
	secret := encrypted.secret
	publisher, err := NewLeaseSetPublisher(LeaseSetPublisherConfig{
		Encrypted: encrypted, Database: NewDatabase(ivnp.Hash{}, DefaultBucketCapacity),
		InboundLeases: InboundLeaseSourceFunc(func(uint64) []Lease { return nil }),
		Sender:        LeaseSetPublishSenderFunc(func(context.Context, RouterRef, i2np.Message) error { return nil }),
		Now:           func() uint64 { return now }, Random: func() uint32 { return 1 }, FloodfillLimit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	publisher.encryptionKey = []byte("legacy-encryption")
	publisher.signingKey = []byte("legacy-signing")
	encryptionKey, signingKey := publisher.encryptionKey, publisher.signingKey
	publisher.Close()
	publisher.Close()
	if !publisher.closed || publisher.encrypted != nil || publisher.encryptionKey != nil || publisher.signingKey != nil || !encrypted.released {
		t.Fatal("publisher retained a sensitive owner after close")
	}
	for _, data := range [][]byte{secret, encryptionKey, signingKey} {
		for _, value := range data {
			if value != 0 {
				t.Fatal("publisher close retained copied key bytes")
			}
		}
	}
}

func TestEncryptedLeaseSetPublisherUsesConfirmedStoreType(t *testing.T) {
	destination, _, encrypted, now := encryptedTestSet(t, EncryptedLeaseSetAuthorization{})
	defer destination.ReleaseSensitive()
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	publisher, err := NewLeaseSetPublisher(LeaseSetPublisherConfig{
		Encrypted: encrypted,
		Database:  database,
		InboundLeases: InboundLeaseSourceFunc(func(uint64) []Lease {
			return []Lease{{Gateway: ivnp.Hash{1}, TunnelID: 7, EndDate: now + 3_600_000}}
		}),
		Sender:         LeaseSetPublishSenderFunc(func(_ context.Context, _ RouterRef, _ i2np.Message) error { return nil }),
		Now:            func() uint64 { return now },
		Random:         func() uint32 { return 1 },
		FloodfillLimit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = publisher.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	hash, err := encrypted.Hash(time.UnixMilli(int64(now)))
	if err != nil {
		t.Fatal(err)
	}
	if stored, ok := database.EncryptedLeaseSet(hash); !ok || stored.SigningType != ivnp.SigningRedDSASHA512Ed25519 {
		t.Fatal("encrypted publication was not stored under blinded key")
	}
}
