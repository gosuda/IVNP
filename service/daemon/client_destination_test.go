package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	ivnp "gosuda.org/ivnp"
	"gosuda.org/ivnp/network/router"
	"gosuda.org/ivnp/service/clientapi"
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
	d, err := New(cfg, Options{Transport: network.transport()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	beforeRuntime := d.clientRuntimeSnapshot()
	beforeDurable := len(d.bundle.DestinationPrivate)
	source, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	public := string(source.Destination())
	controller := clientDestinationController{daemon: d}
	endpoint, err := controller.CreateDestination(context.Background(), clientapi.DestinationSpec{Local: source, Policy: clientapi.LeaseSetPolicy{CryptoTypes: []uint16{7, 6, 4}}})
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
	controller := clientDestinationController{daemon: &Daemon{
		destinationFactory: new(destinationRuntimeFactory),
		destinations:       new(router.DestinationManager),
	}}
	endpoint, err := controller.CreateDestination(context.Background(), clientapi.DestinationSpec{
		Policy: clientapi.LeaseSetPolicy{CryptoTypes: []uint16{5}},
	})
	if !errors.Is(err, errDestinationCryptoTypes) || endpoint != nil {
		t.Fatalf("CreateDestination(type 5) = %#v, %v", endpoint, err)
	}
}
