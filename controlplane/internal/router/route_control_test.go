package router

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	controlplanetunnel "gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

func routeControlFixture(t *testing.T, prepare func(context.Context, foundation.Hash) error) (*StreamingTunnelSender, []dataplane.StreamingTunnelDelivery, *controlPlaneTunnelSender) {
	t.Helper()
	const now = uint64(1000)
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	owner := local.Hash
	database := controlplanenetdb.NewDatabase(owner, controlplanenetdb.DefaultBucketCapacity)
	storeControlLegacyLeaseSet(t, database, local, foundation.NetworkDatabaseLease{Gateway: foundation.Hash{6}, TunnelID: 7, EndDate: 90000})
	deliveries := make([]dataplane.StreamingTunnelDelivery, 3)
	for i := range deliveries {
		remote, err := foundation.GenerateLocalAddress()
		if err != nil {
			t.Fatal(err)
		}
		storeControlLegacyLeaseSet(t, database, remote, foundation.NetworkDatabaseLease{Gateway: foundation.Hash{4}, TunnelID: 5, EndDate: 100000})
		deliveries[i] = dataplane.StreamingTunnelDelivery{From: owner, To: remote.Hash, Protocol: 6, Payload: []byte("bulk packet")}
	}
	wire := new(controlPlaneTunnelSender)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: wire, Now: func() uint64 { return now }})
	token, err := runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 1, Owner: owner, FirstHop: foundation.Hash{7}, NextTunnelID: 2, ExpiresAt: 100000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.RemoveCircuit(token) })
	pool := controlplanetunnel.NewOwnedPool(owner, 1)
	if err := pool.Add(controlplanetunnel.Entry{ID: 1, Owner: owner, Circuit: token, Direction: controlplanetunnel.Outbound, Expires: 100000}, now); err != nil {
		t.Fatal(err)
	}
	requests, err := controlplanenetdb.NewRequestManager(database, dataPlaneRequestSender{}, dataPlaneReplyRoute{}, controlplanenetdb.RequestManagerConfig{Capacity: 4, TimeoutMillis: 60000, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := requests.Close(); err != nil {
			t.Error(err)
		}
	})
	sender, err := NewStreamingTunnelSender(StreamingTunnelSenderConfig{
		Owner: owner, Database: database, Requests: requests, Pool: pool, Tunnels: runtime,
		Garlic: dataplane.GarlicNewSessionManager(dataplane.GarlicSessionManagerConfig{}), Now: func() uint64 { return now },
		PreparationCapacity: 1, WaiterCapacity: 2, PrepareTunnel: prepare,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.ReleaseSensitive)
	return sender, deliveries, wire
}

func TestWarmSenderProgressesWhileMissesAreCoalescedAndBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var blocked atomic.Bool
		var once sync.Once
		defer once.Do(func() { close(release) })
		sender, deliveries, _ := routeControlFixture(t, func(ctx context.Context, _ foundation.Hash) error {
			if !blocked.Load() {
				return nil
			}
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		if err := sender.SendTunnel(t.Context(), deliveries[0]); err != nil {
			t.Fatal(err)
		}
		blocked.Store(true)
		cold := make(chan error, 2)
		go func() { cold <- sender.SendTunnel(t.Context(), deliveries[1]) }()
		<-entered
		if err := sender.SendTunnel(t.Context(), deliveries[0]); err != nil {
			t.Fatalf("warm send stalled behind lookup: %v", err)
		}
		if err := sender.SendTunnel(t.Context(), deliveries[2]); !errors.Is(err, dataplane.RouterErrRoutePreparationBusy) {
			t.Fatalf("excess distinct miss = %v", err)
		}
		go func() { cold <- sender.SendTunnel(t.Context(), deliveries[1]) }()
		synctest.Wait()
		if err := sender.SendTunnel(t.Context(), deliveries[1]); !errors.Is(err, dataplane.RouterErrRoutePreparationBusy) {
			t.Fatalf("excess waiting caller = %v", err)
		}
		once.Do(func() { close(release) })
		for range 2 {
			if err := <-cold; err != nil {
				t.Fatalf("coalesced miss = %v", err)
			}
		}
	})
}

func TestELSPolicyReplacementRejectsInflightPlaintextPreparation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		defer once.Do(func() { close(release) })
		sender, deliveries, wire := routeControlFixture(t, func(ctx context.Context, _ foundation.Hash) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		pending := make(chan error, 1)
		go func() { pending <- sender.SendTunnel(t.Context(), deliveries[0]) }()
		<-entered
		legacy, ok := sender.database.LeaseSet(deliveries[0].To)
		if !ok {
			t.Fatal("missing plaintext fixture")
		}
		if err := sender.UpdateRemoteELS(map[foundation.Hash]RemoteELSContext{deliveries[0].To: {Identity: legacy.Destination}}); err != nil {
			t.Fatal(err)
		}
		once.Do(func() { close(release) })
		if err := <-pending; !errors.Is(err, dataplane.RouterErrRouteGeneration) {
			t.Fatalf("old plaintext preparation = %v", err)
		}
		if err := sender.SendTunnel(t.Context(), deliveries[0]); err == nil {
			t.Fatal("encrypted policy downgraded to plaintext")
		}
		wire.mu.Lock()
		defer wire.mu.Unlock()
		if len(wire.messages) != 0 {
			t.Fatal("stale plaintext route transmitted")
		}
	})
}

func TestLocalPublicationRefreshReplacesWarmBundle(t *testing.T) {
	sender, deliveries, _ := routeControlFixture(t, nil)
	if err := sender.SendTunnel(t.Context(), deliveries[0]); err != nil {
		t.Fatal(err)
	}
	sender.pool = controlplanetunnel.NewPool(1)
	if err := sender.RefreshLocalLeaseSet(); err != nil {
		t.Fatal(err)
	}
	if err := sender.SendTunnel(t.Context(), deliveries[0]); err != nil {
		t.Fatalf("prepared send reselected pool: %v", err)
	}
	sender.database.ExpireLeases(90001)
	if _, _, found := sender.database.StoredLeaseSet(sender.owner); found {
		t.Fatal("local publication remains stored after its retention deadline")
	}
	if err := sender.RefreshLocalLeaseSet(); err != nil {
		t.Fatal(err)
	}
	if err := sender.SendTunnel(t.Context(), deliveries[0]); !errors.Is(err, dataplane.TunnelErrCircuitNotFound) {
		t.Fatalf("publication refresh kept old circuit/bundle: %v", err)
	}
}

func TestSenderRetirementCancelsBlockedPreparation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		sender, deliveries, _ := routeControlFixture(t, func(ctx context.Context, _ foundation.Hash) error { close(entered); <-ctx.Done(); return ctx.Err() })
		result := make(chan error, 1)
		go func() { result <- sender.SendTunnel(t.Context(), deliveries[0]) }()
		<-entered
		sender.ReleaseSensitive()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("retired preparation = %v", err)
		}
		if err := sender.SendTunnel(t.Context(), deliveries[0]); !errors.Is(err, dataplane.RouterErrDataPlaneConfig) {
			t.Fatalf("retired sender accepted work: %v", err)
		}
	})
}

func TestRatchetReplyAdmissionBoundsOwnedPacketBytes(t *testing.T) {
	sender, _, _ := routeControlFixture(t, nil)
	reservation, err := sender.ReserveRatchetReply(foundation.Hash{8})
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Release()
	if err := reservation.Activate(); err != nil {
		t.Fatal(err)
	}
	if err := reservation.Send(t.Context(), make([]byte, foundation.I2NPI2PDMaxPayload)); !errors.Is(err, foundation.I2NPErrPayloadTooLarge) {
		t.Fatalf("oversize reply admission = %v", err)
	}
}

func TestRatchetReplyMissQueuesWithoutBlockingReceive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		sender, deliveries, wire := routeControlFixture(t, func(ctx context.Context, _ foundation.Hash) error { close(entered); <-ctx.Done(); return ctx.Err() })
		reservation, err := sender.ReserveRatchetReply(deliveries[0].To)
		if err != nil {
			t.Fatal(err)
		}
		defer reservation.Release()
		if err := reservation.Activate(); err != nil {
			t.Fatal(err)
		}
		if err := reservation.Send(t.Context(), []byte{1}); err != nil {
			t.Fatal(err)
		}
		<-entered
		if _, err := sender.ReserveRatchetReply(deliveries[0].To); !errors.Is(err, dataplane.RouterErrRoutePreparationBusy) {
			t.Fatalf("excess queued reply = %v", err)
		}
		sender.ReleaseSensitive()
		wire.mu.Lock()
		defer wire.mu.Unlock()
		if len(wire.messages) != 0 {
			t.Fatal("retired reply queue transmitted")
		}
	})
}

func TestELSPolicyReplacementRetiresWarmPlaintextRoute(t *testing.T) {
	sender, deliveries, wire := routeControlFixture(t, nil)
	if err := sender.SendTunnel(t.Context(), deliveries[0]); err != nil {
		t.Fatal(err)
	}
	legacy, ok := sender.database.LeaseSet(deliveries[0].To)
	if !ok {
		t.Fatal("missing plaintext fixture")
	}
	wire.mu.Lock()
	before := len(wire.messages)
	wire.mu.Unlock()
	if err := sender.UpdateRemoteELS(map[foundation.Hash]RemoteELSContext{deliveries[0].To: {Identity: legacy.Destination}}); err != nil {
		t.Fatal(err)
	}
	if err := sender.SendTunnel(t.Context(), deliveries[0]); err == nil {
		t.Fatal("encrypted policy reused warm plaintext route")
	}
	wire.mu.Lock()
	defer wire.mu.Unlock()
	if len(wire.messages) != before {
		t.Fatal("encrypted policy transmitted through old plaintext route")
	}
}

func TestRoutePreparationRejectsReusedOrForeignCircuit(t *testing.T) {
	for _, scenario := range []string{"stale token", "ownerless replacement", "foreign replacement"} {
		t.Run(scenario, func(t *testing.T) {
			sender, deliveries, wire := routeControlFixture(t, nil)
			selected, ok := sender.pool.Select(controlplanetunnel.Outbound, 1000)
			if !ok {
				t.Fatal("missing selected circuit")
			}
			if !sender.tunnels.RemoveCircuit(selected.Circuit) {
				t.Fatal("failed to retire selected installation")
			}
			owner := sender.owner
			if scenario == "ownerless replacement" {
				owner = foundation.Hash{}
			}
			if scenario == "foreign replacement" {
				owner = foundation.Hash{42}
			}
			replacement, err := sender.tunnels.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: selected.ID, Owner: owner, FirstHop: foundation.Hash{8}, NextTunnelID: 9, ExpiresAt: 100000})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { sender.tunnels.RemoveCircuit(replacement) })
			if scenario != "stale token" {
				if !sender.pool.Remove(selected) {
					t.Fatal("failed to replace pool selection")
				}
				selected.Circuit = replacement
				if err := sender.pool.Add(selected, 1000); err != nil {
					t.Fatal(err)
				}
			}
			if err := sender.SendTunnel(t.Context(), deliveries[0]); !errors.Is(err, dataplane.TunnelErrCircuitNotFound) {
				t.Fatalf("reused circuit preparation = %v", err)
			}
			wire.mu.Lock()
			defer wire.mu.Unlock()
			if len(wire.messages) != 0 {
				t.Fatal("payload escaped through an unselected installation")
			}
		})
	}
}
