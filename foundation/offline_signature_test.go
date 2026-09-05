package foundation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func offlineTestState(t *testing.T, expires uint32) (state []byte, offline OfflineSignature, transientPrivate []byte, longTerm *LocalDestination) {
	t.Helper()
	longTerm, err := GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	state = make([]byte, longTerm.PrivateEncodedLen())
	n, err := longTerm.MarshalPrivateTo(state)
	if err != nil {
		t.Fatal(err)
	}
	state = state[:n]
	publicLength := int(binary.BigEndian.Uint16(state[:2]))
	// The offline destination keeps no long-term signing private key.
	clear(state[2+publicLength : 2+publicLength+ed25519.PrivateKeySize])
	transientPublic, transientFull, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	transientPrivate = transientFull.Seed()
	clear(transientFull)
	offline = OfflineSignature{Expires: expires, Type: SigningEdDSASHA512Ed25519, PublicKey: transientPublic}
	var content [6 + ed25519.PublicKeySize]byte
	contentLen, err := offline.MarshalSignedContentTo(content[:])
	if err != nil {
		t.Fatal(err)
	}
	offline.Signature, err = longTerm.Sign(content[:contentLen])
	if err != nil {
		t.Fatal(err)
	}
	return state, offline, transientPrivate, longTerm
}

func TestImportLocalDestinationOfflineRoundtrip(t *testing.T) {
	expires := uint32(time.Now().Add(time.Hour).Unix())
	state, offline, transientPrivate, longTerm := offlineTestState(t, expires)
	defer longTerm.ReleaseSensitive()
	defer clear(transientPrivate)
	defer clear(state)

	destination, err := ImportLocalDestinationOffline(state, offline, transientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	if destination.Hash() != longTerm.Hash() {
		t.Fatal("offline destination hash differs from long-term destination")
	}
	meta, ok := destination.OfflineSignature()
	if !ok || meta.Expires != offline.Expires || meta.Type != offline.Type {
		t.Fatalf("offline metadata = %+v, %v", meta, ok)
	}
	message := []byte("datagram signing input")
	signature, err := destination.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(offline.PublicKey), message, signature) {
		t.Fatal("Sign did not use the transient signing key")
	}
	longTermSignature := mustSign(t, longTerm, message)
	if string(signature) == string(longTermSignature) {
		t.Fatal("offline destination signed with the long-term key")
	}

	clone, err := destination.Clone()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok = clone.OfflineSignature(); !ok {
		t.Fatal("Clone lost the offline signature")
	}
	clone.ReleaseSensitive()
	if _, err = clone.Sign(message); err == nil {
		t.Fatal("released offline destination still signs")
	}
	if _, ok = clone.OfflineSignature(); ok {
		t.Fatal("released offline signature still reported")
	}
}

func mustSign(t *testing.T, d *LocalDestination, message []byte) []byte {
	t.Helper()
	signature, err := d.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func TestOfflineDestinationRejectsExpiredSigning(t *testing.T) {
	fixed := time.Unix(1_800_000_000, 0)
	original := offlineTimeNow
	offlineTimeNow = func() time.Time { return fixed }
	defer func() { offlineTimeNow = original }()
	expires := uint32(fixed.Add(-time.Hour).Unix())
	state, offline, transientPrivate, longTerm := offlineTestState(t, expires)
	defer longTerm.ReleaseSensitive()
	defer clear(transientPrivate)
	defer clear(state)

	destination, err := ImportLocalDestinationOffline(state, offline, transientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	if _, err = destination.Sign([]byte("stale datagram")); !errors.Is(err, ErrOfflineSignatureExpired) {
		t.Fatalf("Sign() error = %v, want ErrOfflineSignatureExpired", err)
	}

	offlineTimeNow = func() time.Time { return time.Unix(4_294_967_296, 0) }
	if _, err = destination.Sign([]byte("overflow datagram")); !errors.Is(err, ErrOfflineSignatureExpired) {
		t.Fatalf("overflow Sign() error = %v, want ErrOfflineSignatureExpired", err)
	}
}

func TestImportLocalDestinationOfflineRejectsForgery(t *testing.T) {
	expires := uint32(time.Now().Add(time.Hour).Unix())
	state, offline, transientPrivate, longTerm := offlineTestState(t, expires)
	defer longTerm.ReleaseSensitive()
	defer clear(transientPrivate)
	defer clear(state)

	t.Run("bad authorization signature", func(t *testing.T) {
		forged := offline
		forged.Signature = append([]byte(nil), offline.Signature...)
		forged.Signature[0] ^= 0xff
		if _, err := ImportLocalDestinationOffline(state, forged, transientPrivate); err == nil {
			t.Fatal("accepted forged authorization signature")
		}
	})
	t.Run("mismatched transient private", func(t *testing.T) {
		_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		otherSeed := otherPrivate.Seed()
		defer clear(otherPrivate)
		defer clear(otherSeed)
		if _, err = ImportLocalDestinationOffline(state, offline, otherSeed); err == nil {
			t.Fatal("accepted transient private key not matching the authorized public key")
		}
	})
	t.Run("long-term key present", func(t *testing.T) {
		full, err := GenerateLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		defer full.ReleaseSensitive()
		fullState := make([]byte, full.PrivateEncodedLen())
		n, err := full.MarshalPrivateTo(fullState)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ImportLocalDestinationOffline(fullState[:n], offline, transientPrivate); err == nil {
			t.Fatal("accepted offline import over a present long-term signing key")
		}
	})
	t.Run("zero key without offline", func(t *testing.T) {
		if _, err := ImportLocalDestination(state); err == nil {
			t.Fatal("standard import accepted an all-zero signing key")
		}
	})
}

func TestOfflinePrivateSerialization(t *testing.T) {
	expires := uint32(time.Now().Add(time.Hour).Unix())
	state, offline, transientPrivate, longTerm := offlineTestState(t, expires)
	defer longTerm.ReleaseSensitive()
	defer clear(transientPrivate)
	defer clear(state)

	destination, err := ImportLocalDestinationOffline(state, offline, transientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	length := destination.OfflinePrivateEncodedLen()
	if length != 6+len(offline.PublicKey)+len(offline.Signature)+len(transientPrivate) {
		t.Fatalf("offline section length = %d", length)
	}
	section := make([]byte, length)
	n, err := destination.MarshalOfflinePrivateTo(section)
	if err != nil || n != length {
		t.Fatalf("marshal = %d, %v", n, err)
	}
	defer clear(section)
	if binary.BigEndian.Uint32(section[:4]) != expires {
		t.Fatal("offline section expires mismatch")
	}
	if SigningKeyType(binary.BigEndian.Uint16(section[4:6])) != offline.Type {
		t.Fatal("offline section key type mismatch")
	}
	meta, _ := destination.OfflineSignature()
	if string(section[6:6+len(meta.PublicKey)]) != string(meta.PublicKey) {
		t.Fatal("offline section public key mismatch")
	}
}
