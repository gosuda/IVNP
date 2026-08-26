package noderuntime

import (
	"context"
	"errors"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking"
)

type floodfillDirectReplyRoute struct{ gateway foundation.Hash }

func (r floodfillDirectReplyRoute) DatabaseLookupReplyRoute() (foundation.Hash, uint32, bool) {
	return r.gateway, 0, false
}

func TestConfiguredFloodfillPropagatesStoreAndAnswersLookup(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	dummy := daemonProductionFloodfill(t, now)
	network := newDaemonMemoryNetwork(dummy, func() uint64 { return uint64(time.Now().UnixMilli()) })
	newNode := func(floodfill bool) *Daemon {
		cfg := daemonTestConfig(t)
		cfg.Router.Floodfill = floodfill
		cfg.Tunnel.Enabled = false
		cfg.NTCP2.Enabled = false
		cfg.SSU2.Enabled = false
		node, err := New(cfg, Options{Transport: network.transport()})
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
	client.service.SetDeliveryStatusSink(func(networking.I2NPDeliveryStatusMessage) error { return nil })
	primary := newNode(true)
	targets := []*Daemon{newNode(true), newNode(true), newNode(true)}
	for _, node := range append([]*Daemon{primary}, targets...) {
		node.localInfo.SetReachability(networking.RouterReachabilityReachable)
		if err := node.localInfo.Publish(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !networking.NetworkDatabaseIsFloodfill(node.localInfo.Snapshot()) {
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
	leaseSet, err := networking.NetworkDatabaseNewLocalLeaseSet2WithTypes(destination, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = leaseSet.ReplaceInboundLeases([]networking.NetworkDatabaseLease{{
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
	storePayload, err := networking.NetworkDatabaseMarshalDatabaseStore(
		key, networking.I2NPStoreLeaseSet2, leaseWire[:n], 91, client.localInfo.Hash(), 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	storeMessage := networking.I2NPMessage{
		Header:  networking.I2NPHeader{Type: networking.I2NPDatabaseStore, ID: 92, Expiration: now + 60_000},
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

	lookupPayload, err := networking.NetworkDatabaseBuildDatabaseLookup(
		key, networking.NetworkDatabaseLeaseSetLookup,
		floodfillDirectReplyRoute{gateway: client.localInfo.Hash()}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	lookupMessage := networking.I2NPMessage{
		Header:  networking.I2NPHeader{Type: networking.I2NPDatabaseLookup, ID: 93, Expiration: now + 60_000},
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

func TestDatabaseLookupResponderIsEnabledOnlyForFloodfillMode(t *testing.T) {
	const now = uint64(1_000)
	payload, err := networking.NetworkDatabaseBuildDatabaseLookup(
		foundation.Hash{1}, networking.NetworkDatabaseLeaseSetLookup,
		floodfillDirectReplyRoute{gateway: foundation.Hash{2}}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	message := networking.I2NPMessage{
		Header:  networking.I2NPHeader{Type: networking.I2NPDatabaseLookup, ID: 1, Expiration: now + 1},
		Payload: payload,
	}
	for _, test := range []struct {
		name      string
		floodfill bool
		want      error
	}{
		{"ordinary router", false, networking.RouterErrUnhandledI2NP},
		{"floodfill router", true, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := daemonTestConfig(t)
			cfg.Router.Floodfill = test.floodfill
			node, newErr := New(cfg, Options{SocketRuntime: new(recordingSockets)})
			if newErr != nil {
				t.Fatal(newErr)
			}
			defer node.Close()
			got := node.service.HandleI2NP(message, now, false)
			if !errors.Is(got, test.want) {
				t.Fatalf("DatabaseLookup error = %v, want %v", got, test.want)
			}
		})
	}
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
