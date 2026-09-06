package noderuntime

import (
	"context"
	"testing"
	"time"

	"gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/controlplane/internal/router"
	"gosuda.org/ivnp/foundation"
)

type floodfillDirectReplyRoute struct{ gateway foundation.Hash }

func (r floodfillDirectReplyRoute) DatabaseLookupReplyRoute() (foundation.Hash, uint32, bool) {
	return r.gateway, 0, false
}

func TestConfiguredFloodfillPropagatesStoreAndAnswersLookup(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	dummy := daemonProductionFloodfill(t, now)
	network := newDaemonMemoryNetwork(dummy, func() uint64 { return uint64(time.Now().UnixMilli()) })
	newNode := func(floodfill bool) *Controller {
		cfg := daemonTestConfig(t)
		cfg.Router.Floodfill = floodfill
		cfg.Tunnel.Enabled = false
		cfg.NTCP2.Enabled = false
		cfg.SSU2.Enabled = false
		node, err := NewController(cfg, ControllerOptions{Transport: network.transport()})
		if err != nil {
			t.Fatal(err)
		}
		if err = node.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = node.Close()
			_ = node.Wait()
		})
		return node
	}
	client := newNode(false)
	primary := newNode(true)
	targets := []*Controller{newNode(true), newNode(true), newNode(true)}
	for _, node := range append([]*Controller{primary}, targets...) {
		node.localInfo.SetReachability(router.ReachabilityReachable)
		if err := node.localInfo.Publish(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !foundation.NetworkDatabaseIsFloodfill(node.localInfo.Snapshot()) {
			t.Fatal("reachable configured node did not publish floodfill capability")
		}
	}
	for _, target := range targets {
		info := target.localInfo.Snapshot()
		if err := primary.database.AdmitRouterInfo(info, true, now); err != nil {
			t.Fatal(err)
		}
	}

	destination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	leaseSet, err := netdb.NewLocalLeaseSet2WithTypes(destination, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = leaseSet.ReplaceInboundLeases([]foundation.NetworkDatabaseLease{{
		Gateway: primary.localInfo.Hash(), TunnelID: 77, EndDate: now + uint64((10*time.Minute)/time.Millisecond),
	}}); err != nil {
		t.Fatal(err)
	}
	leaseWire := make([]byte, 64<<10)
	n, err := leaseSet.MarshalTo(leaseWire, now, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	key := destination.Hash()
	storePayload, err := foundation.NetworkDatabaseMarshalDatabaseStore(
		key, foundation.I2NPStoreLeaseSet2, leaseWire[:n], 91, client.localInfo.Hash(), 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	storeMessage := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: 92, Expiration: now + 60_000},
		Payload: storePayload,
	}
	if err = network.route(client.localInfo.Hash(), primary.localInfo.Hash(), storeMessage); err != nil {
		t.Fatal(err)
	}
	waitForFloodfillCondition(t, 2*time.Second, func() bool {
		for _, target := range targets {
			if _, found := target.database.LeaseSet2(key); !found {
				return false
			}
		}
		return true
	}, "propagated LeaseSet2 store")

	lookupPayload, err := netdb.BuildDatabaseLookup(
		key, netdb.LeaseSetLookup,
		floodfillDirectReplyRoute{gateway: client.localInfo.Hash()}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	lookupMessage := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPDatabaseLookup, ID: 93, Expiration: now + 60_000},
		Payload: lookupPayload,
	}
	if err = network.route(client.localInfo.Hash(), targets[0].localInfo.Hash(), lookupMessage); err != nil {
		t.Fatal(err)
	}
	waitForFloodfillCondition(t, 2*time.Second, func() bool {
		_, found := client.database.LeaseSet2(key)
		return found
	}, "LeaseSet2 lookup reply")
}

func waitForFloodfillCondition(t testing.TB, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	ticker := time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for !condition() {
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", description)
		case <-ticker.C:
		}
	}
}
