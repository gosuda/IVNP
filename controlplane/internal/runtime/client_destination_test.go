package noderuntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
)

func TestNeutralDestinationControllerUsesDaemonOwnedIsolatedGraph(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	flood := daemonProductionFloodfill(t, now)
	network := newDaemonMemoryNetwork(flood, func() uint64 { return uint64(time.Now().UnixMilli()) })
	cfg := daemonTestConfig(t)
	cfg.StateDir = filepath.Dir(cfg.StatePath)
	cfg.Tunnel.Enabled = true
	cfg.NTCP2.Enabled = false
	cfg.Tunnel.MaintenanceInterval = time.Hour
	d, err := NewController(cfg, ControllerOptions{Transport: network.transport()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	beforeRuntime := d.clientRuntimeSnapshot()
	beforeDurable := len(d.bundle.DestinationPrivate)
	source, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	public := string(source.Destination())
	controller := clientDestinationController{daemon: d}
	endpoint, err := controller.CreateDestination(context.Background(), destination.DestinationSpec{Local: source, Policy: destination.LeaseSetPolicy{CryptoTypes: []uint16{7, 6, 4}}})
	source.ReleaseSensitive()
	if err != nil {
		t.Fatal(err)
	}
	if string(endpoint.Destination()) != public {
		t.Fatal("controller did not clone supplied destination")
	}
	after := d.clientRuntimeSnapshot()
	if len(after) != len(beforeRuntime)+1 {
		t.Fatalf("runtime count = %d", len(after))
	}
	transient := after[len(after)-1]
	if transient.pool == beforeRuntime[0].pool || transient.pool.Owner() != endpoint.Hash() {
		t.Fatal("transient destination reused another owner pool")
	}
	if len(d.bundle.DestinationPrivate) != beforeDurable {
		t.Fatal("transient destination was persisted")
	}
	if err = controller.DestroyDestination(context.Background(), endpoint); err != nil {
		t.Fatal(err)
	}
	if transient.active() {
		t.Fatal("DestroyDestination left transient graph active")
	}
	if len(d.clientRuntimeSnapshot()) != len(beforeRuntime) {
		t.Fatal("DestroyDestination left transient owner registered")
	}
}
func TestClientDestinationRejectsRemovedCryptoType5(t *testing.T) {
	controller := clientDestinationController{daemon: &Controller{
		destinationFactory: new(destinationRuntimeFactory),
		destinations:       new(dataplane.RouterDestinationManager),
	}}
	endpoint, err := controller.CreateDestination(context.Background(), destination.DestinationSpec{
		Policy: destination.LeaseSetPolicy{CryptoTypes: []uint16{5}},
	})
	if !errors.Is(err, errDestinationCryptoTypes) || endpoint != nil {
		t.Fatalf("CreateDestination(type 5) = %#v, %v", endpoint, err)
	}
}

func TestClientDestinationRejectsOfflineDatagram1(t *testing.T) {
	longTerm, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer longTerm.ReleaseSensitive()
	state := make([]byte, longTerm.PrivateEncodedLen())
	defer clear(state)
	if _, err := longTerm.MarshalPrivateTo(state); err != nil {
		t.Fatal(err)
	}
	publicLength := int(binary.BigEndian.Uint16(state[:2]))
	clear(state[2+publicLength : 2+publicLength+ed25519.PrivateKeySize])
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	seed := private.Seed()
	defer clear(seed)
	offline := foundation.OfflineSignature{
		Expires: uint32(time.Now().Add(time.Hour).Unix()),
		Type:    foundation.SigningEdDSASHA512Ed25519, PublicKey: public,
	}
	var content [6 + ed25519.PublicKeySize]byte
	n, err := offline.MarshalSignedContentTo(content[:])
	if err != nil {
		t.Fatal(err)
	}
	offline.Signature, err = longTerm.Sign(content[:n])
	if err != nil {
		t.Fatal(err)
	}
	local, err := foundation.ImportLocalDestinationOffline(state, offline, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer local.ReleaseSensitive()
	endpoint := &clientDestinationEndpoint{runtime: &destinationRuntime{local: local}}
	var packet [1024]byte
	if n, err := endpoint.MarshalDatagramV1To(packet[:], []byte("hello")); n != 0 || !errors.Is(err, foundation.ErrInvalidIdentity) {
		t.Fatalf("offline Datagram1 = %d, %v; want invalid identity", n, err)
	}
}
