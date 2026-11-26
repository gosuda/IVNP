package router

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

func scopeSignedRouterInfoStoreData(t *testing.T, now uint64) ([]byte, foundation.Hash) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var info bytes.Buffer
	crypto := make([]byte, 256)
	if _, err = rand.Read(crypto[:32]); err != nil {
		t.Fatal(err)
	}
	info.Write(crypto)
	signing := make([]byte, 128)
	copy(signing[96:], public)
	info.Write(signing)
	info.Write([]byte{5, 0, 4, 0, 7, 0, 4})
	key := foundation.Sum(info.Bytes())
	info.Write(binary.BigEndian.AppendUint64(nil, now))
	info.Write([]byte{0, 0, 0, 0})
	info.Write(ed25519.Sign(private, info.Bytes()))
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err = writer.Write(info.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes(), key
}

func scopeEncryptedLeaseSet(t *testing.T, now uint64) ([]byte, foundation.Hash) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := make([]byte, 2+len(public)+4+2+2+2+foundation.NetworkDatabaseMinEncryptedLeaseSetDataBytes)
	binary.BigEndian.PutUint16(unsigned[:2], uint16(foundation.SigningRedDSASHA512Ed25519))
	copy(unsigned[2:], public)
	binary.BigEndian.PutUint32(unsigned[2+len(public):2+len(public)+4], uint32(now/1000))
	binary.BigEndian.PutUint16(unsigned[2+len(public)+4:2+len(public)+6], 600)
	offset := 2 + len(public) + 4 + 2 + 2
	binary.BigEndian.PutUint16(unsigned[offset:offset+2], foundation.NetworkDatabaseMinEncryptedLeaseSetDataBytes)
	unsigned[offset+2] = 7
	signed := append([]byte{byte(foundation.I2NPStoreEncryptedLeaseSet)}, unsigned...)
	leaseSet := append(unsigned, ed25519.Sign(private, signed)...)
	parsed, err := foundation.NetworkDatabaseParseEncryptedLeaseSet(leaseSet)
	if err != nil {
		t.Fatal(err)
	}
	return leaseSet, parsed.Hash()
}

func appendScopeLocalClove(dst []byte, id uint32, expiration uint64, payload []byte) []byte {
	body := []byte{0, byte(foundation.I2NPDatabaseStore)}
	body = binary.BigEndian.AppendUint32(body, id)
	body = binary.BigEndian.AppendUint32(body, uint32(expiration/1000))
	body = append(body, payload...)
	dst = append(dst, 11, byte(len(body)>>8), byte(len(body)))
	return append(dst, body...)
}

// A peer holding only a hosted Destination's public encryption key must not
// be able to store router records, publish LeaseSets, or make the hosting
// router reply directly to a router of its choice.
func TestDestinationGarlicCannotDriveRouterNetDB(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	var localRouter foundation.Hash
	localRouter[0] = 9
	database := controlplanenetdb.NewDatabaseForNetwork(localRouter, controlplanenetdb.DefaultBucketCapacity, 2)
	var replies []foundation.Hash
	service, queue := newControlServiceForTest(t, database, ControlSinks{
		DatabaseStoreReply: func(_ context.Context, gateway foundation.Hash, _ uint32, _ foundation.I2NPDeliveryStatusMessage) error {
			replies = append(replies, gateway)
			return nil
		},
	})
	destination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destination.ReleaseSensitive)
	attacker, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(attacker.ReleaseSensitive)
	destinationRatchet, err := dataplane.GarlicNewRatchetManager(destination, dataplane.GarlicRatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destinationRatchet.ReleaseSensitive)
	attackerRatchet, err := dataplane.GarlicNewRatchetManager(attacker, dataplane.GarlicRatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(attackerRatchet.ReleaseSensitive)
	receiver, err := dataplane.RouterNewGarlicReceiver(dataplane.RouterGarlicReceiverConfig{
		Service: service, ReplyKeys: dataplane.GarlicNewReplyKeyRegistry(1), Now: func() uint64 { return now },
		Destinations: map[foundation.Hash]dataplane.RouterGarlicDestination{destination.Hash(): {Ratchet: destinationRatchet}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(receiver.ReleaseSensitive)

	attackerRouter := foundation.Sum([]byte("attacker router"))
	routerInfo, routerKey := scopeSignedRouterInfoStoreData(t, now)
	routerStore, err := foundation.NetworkDatabaseMarshalDatabaseStore(routerKey, foundation.I2NPStoreRouterInfo, routerInfo, 0xdeadbeef, attackerRouter, 0)
	if err != nil {
		t.Fatal(err)
	}
	replyingLeaseSet, replyingKey := scopeEncryptedLeaseSet(t, now)
	replyingStore, err := foundation.NetworkDatabaseMarshalDatabaseStore(replyingKey, foundation.I2NPStoreEncryptedLeaseSet, replyingLeaseSet, 0xfeedface, attackerRouter, 0)
	if err != nil {
		t.Fatal(err)
	}
	bundledLeaseSet, bundledKey := scopeEncryptedLeaseSet(t, now)
	bundledStore, err := foundation.NetworkDatabaseMarshalDatabaseStore(bundledKey, foundation.I2NPStoreEncryptedLeaseSet, bundledLeaseSet, 0, foundation.Hash{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	expires := now + 30_000
	payload := appendScopeLocalClove(nil, 101, expires, routerStore)
	payload = appendScopeLocalClove(payload, 102, expires, replyingStore)
	payload = appendScopeLocalClove(payload, 103, expires, bundledStore)
	public := destination.X25519Public()
	packet, err := attackerRatchet.EncryptUnbound(make([]byte, foundation.I2NPI2PDMaxPayload-4), public[:], uint16(foundation.CryptoX25519), payload, now)
	if err != nil {
		t.Fatal(err)
	}
	wire := binary.BigEndian.AppendUint32(nil, uint32(len(packet)))
	wire = append(wire, packet...)
	_ = receiver.HandleGarlic(foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPGarlic, ID: 1, Expiration: expires}, Payload: wire})
	if err = queue.WaitIdle(t.Context()); err != nil {
		t.Fatal(err)
	}

	if len(replies) != 0 {
		t.Fatalf("destination garlic made the router reply directly to %x", replies)
	}
	if _, stored := database.Routers().Get(routerKey); stored {
		t.Fatal("destination garlic stored a RouterInfo in the router NetDB")
	}
	if _, stored := database.EncryptedLeaseSet(replyingKey); stored {
		t.Fatal("destination garlic stored a reply-requesting LeaseSet")
	}
	if _, stored := database.EncryptedLeaseSet(bundledKey); !stored {
		t.Fatal("bundled LeaseSet was not retained for the reply route")
	}
	if _, _, published := database.StoredPublishedLeaseSet(bundledKey, now); published {
		t.Fatal("bundled LeaseSet from destination garlic was exposed as a floodfill publication")
	}
}
