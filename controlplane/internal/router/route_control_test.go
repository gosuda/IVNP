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

func routeControlFixture(t *testing.T, prepare func(context.Context, foundation.Hash) error, localLeases ...foundation.NetworkDatabaseLease) (*StreamingTunnelSender, []dataplane.StreamingTunnelDelivery, *controlPlaneTunnelSender) {
	t.Helper()
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	return routeControlFixtureForOwner(t, local, prepare, localLeases...)
}

func routeControlFixtureForOwner(t *testing.T, local foundation.LocalAddress, prepare func(context.Context, foundation.Hash) error, localLeases ...foundation.NetworkDatabaseLease) (*StreamingTunnelSender, []dataplane.StreamingTunnelDelivery, *controlPlaneTunnelSender) {
	t.Helper()
	const now = uint64(1000)
	owner := local.Hash
	database := controlplanenetdb.NewDatabase(owner, controlplanenetdb.DefaultBucketCapacity)
	if len(localLeases) == 0 {
		localLeases = []foundation.NetworkDatabaseLease{{Gateway: foundation.Hash{6}, TunnelID: 7, EndDate: 90000}}
	}
	storeControlLegacyLeaseSet(t, database, local, localLeases...)
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
		if err := <-pending; err == nil {
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

func TestLocalPublicationRenewalDoesNotRejectUnsentPayload(t *testing.T) {
	for _, phase := range []string{"during preparation", "after installation"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, err := foundation.GenerateLocalAddress()
				if err != nil {
					t.Fatal(err)
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var unblock, first sync.Once
				defer unblock.Do(func() { close(release) })
				sender, deliveries, _ := routeControlFixtureForOwner(t, local, func(ctx context.Context, _ foundation.Hash) error {
					var err error
					first.Do(func() {
						close(entered)
						select {
						case <-release:
						case <-ctx.Done():
							err = ctx.Err()
						}
					})
					return err
				}, foundation.NetworkDatabaseLease{Gateway: foundation.Hash{6}, TunnelID: 7, EndDate: 30000})
				result := make(chan error, 1)
				go func() { result <- sender.SendTunnel(t.Context(), deliveries[0]) }()
				<-entered
				var reply dataplane.RouterRatchetReplyReservation
				if phase == "after installation" {
					reply, err = sender.ReserveRatchetReply(deliveries[0].To)
					if err != nil {
						t.Fatal(err)
					}
					defer reply.Release()
					unblock.Do(func() { close(release) })
					synctest.Wait()
					if _, ok := sender.execution.RouteReceipt(deliveries[0].To); !ok {
						t.Fatal("route was not installed before publication renewal")
					}
				}
				storeControlLegacyLeaseSet(t, sender.database, local, foundation.NetworkDatabaseLease{Gateway: foundation.Hash{8}, TunnelID: 9, EndDate: 90000})
				if err := sender.RefreshLocalLeaseSet(); err != nil {
					t.Fatal(err)
				}
				unblock.Do(func() { close(release) })
				if reply != nil {
					reply.Release()
				}
				if err := <-result; err != nil {
					t.Fatalf("renewal rejected unsent payload: %v", err)
				}
				receipt, ok := sender.execution.RouteReceipt(deliveries[0].To)
				if !ok || receipt.Expires != 90000 {
					t.Fatalf("replacement route = %+v, present=%t; want renewed return lease deadline 90000", receipt, ok)
				}
			})
		})
	}
}

func TestRouteReacquisitionStopsWhenCallerCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var sender *StreamingTunnelSender
	prepare := func(context.Context, foundation.Hash) error {
		if err := sender.UpdateRemoteELS(nil); err != nil {
			return err
		}
		cancel()
		return nil
	}
	sender, deliveries, wire := routeControlFixture(t, prepare)
	if err := sender.SendTunnel(ctx, deliveries[0]); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled route re-acquisition = %v", err)
	}
	wire.mu.Lock()
	defer wire.mu.Unlock()
	if len(wire.messages) != 0 {
		t.Fatal("canceled route re-acquisition transmitted payload")
	}
}

func TestRouteReacquisitionDoesNotReplayTransportFailure(t *testing.T) {
	sender, deliveries, wire := routeControlFixture(t, nil)
	failure := errors.New("tunnel write failed after admission")
	wire.handle = func(context.Context, foundation.I2NPMessage) error { return failure }
	if err := sender.SendTunnel(t.Context(), deliveries[0]); !errors.Is(err, failure) {
		t.Fatalf("admitted tunnel write = %v", err)
	}
	wire.mu.Lock()
	defer wire.mu.Unlock()
	if len(wire.messages) != 1 {
		t.Fatalf("failed tunnel write was replayed: %d frames", len(wire.messages))
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

func TestDestinationPreparationIsReusedWithoutSendingPayload(t *testing.T) {
	var preparations atomic.Int32
	sender, deliveries, wire := routeControlFixture(t, func(context.Context, foundation.Hash) error {
		preparations.Add(1)
		return nil
	})
	if err := sender.PrepareDestination(t.Context(), deliveries[0].To); err != nil {
		t.Fatal(err)
	}
	wire.mu.Lock()
	sentBeforeDial := len(wire.messages)
	wire.mu.Unlock()
	if sentBeforeDial != 0 {
		t.Fatalf("preparation sent %d application frames", sentBeforeDial)
	}
	if err := sender.SendTunnel(t.Context(), deliveries[0]); err != nil {
		t.Fatal(err)
	}
	if got := preparations.Load(); got != 1 {
		t.Fatalf("prepared route was not reused: preparations=%d", got)
	}
}

func TestLastPreparationWaiterCancelsAndJoinsWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, stopped := make(chan struct{}), make(chan struct{})
		sender, deliveries, _ := routeControlFixture(t, func(ctx context.Context, _ foundation.Hash) error {
			close(entered)
			<-ctx.Done()
			defer close(stopped)
			return ctx.Err()
		})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		result := make(chan error, 1)
		go func() { result <- sender.PrepareDestination(ctx, deliveries[0].To) }()
		<-entered
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled preparation = %v", err)
		}
		select {
		case <-stopped:
		default:
			t.Fatal("preparation returned before worker stopped")
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

func TestSilentRouteRecoverySelectsAlternatePreparedCircuit(t *testing.T) {
	sender, deliveries, _ := routeControlFixture(t, nil)
	first, err := sender.PrepareHandshake(t.Context(), deliveries[0].To)
	if err != nil {
		t.Fatal(err)
	}
	receipt, ok := sender.execution.RouteReceipt(deliveries[0].To)
	if !ok {
		t.Fatal("missing prepared route")
	}
	// Both circuits remain eligible; failure must not tear down a shared tunnel.
	pool := controlplanetunnel.NewOwnedPool(sender.owner, 2)
	for _, entry := range sender.pool.Snapshot(1000) {
		if err := pool.Add(entry, 1000); err != nil {
			t.Fatal(err)
		}
	}
	alternate, err := sender.tunnels.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 11, Owner: sender.owner, FirstHop: foundation.Hash{8}, NextTunnelID: 12, ExpiresAt: 95000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sender.tunnels.RemoveCircuit(alternate) })
	if err := pool.Add(controlplanetunnel.Entry{ID: 11, Owner: sender.owner, Circuit: alternate, Direction: controlplanetunnel.Outbound, Expires: 95000}, 1000); err != nil {
		t.Fatal(err)
	}
	sender.pool = pool
	first.NoResponse()
	if sender.execution.HasRoute(deliveries[0].To, 1) {
		t.Fatal("silent route remained cached")
	}
	second, err := sender.PrepareHandshake(t.Context(), deliveries[0].To)
	if err != nil {
		t.Fatal(err)
	}
	replacement, ok := sender.execution.RouteReceipt(deliveries[0].To)
	if !ok || replacement.Circuit != alternate || replacement.Circuit == receipt.Circuit {
		t.Fatalf("replacement route = %+v", replacement)
	}
	if err := sender.SendTunnel(t.Context(), deliveries[0]); err != nil {
		t.Fatalf("alternate route send = %v", err)
	}
	second.Established()
	first.NoResponse()
	if err := sender.SendTunnel(t.Context(), deliveries[0]); err != nil {
		t.Fatalf("stale timeout retired connected replacement: %v", err)
	}
	if pool.Count(controlplanetunnel.Outbound, 1000) != 2 {
		t.Fatal("per-destination timeout retired shared circuit")
	}
}

func TestSilentRouteDoesNotReuseOnlyFailedPath(t *testing.T) {
	sender, deliveries, _ := routeControlFixture(t, nil)
	feedback, err := sender.PrepareHandshake(t.Context(), deliveries[0].To)
	if err != nil {
		t.Fatal(err)
	}
	feedback.NoResponse()
	if err := sender.PrepareDestination(t.Context(), deliveries[0].To); !errors.Is(err, dataplane.TunnelErrCircuitNotFound) {
		t.Fatalf("only silent path was reused: %v", err)
	}
}

func TestConnectedRouteSurvivesAnotherHandshakeTimeout(t *testing.T) {
	sender, deliveries, _ := routeControlFixture(t, nil)
	silent, err := sender.PrepareHandshake(t.Context(), deliveries[0].To)
	if err != nil {
		t.Fatal(err)
	}
	connected, err := sender.PrepareHandshake(t.Context(), deliveries[0].To)
	if err != nil {
		t.Fatal(err)
	}
	connected.Established()
	silent.NoResponse()
	if err := sender.SendTunnel(t.Context(), deliveries[0]); err != nil {
		t.Fatalf("connected route retired: %v", err)
	}
}

func TestSilentRoutesExhaustRemoteLeasesBeforeReusingFailure(t *testing.T) {
	sender, _, _ := routeControlFixture(t, nil)
	remote, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer remote.ReleaseSensitive()
	local, err := controlplanenetdb.NewLocalLeaseSet2(remote)
	if err != nil {
		t.Fatal(err)
	}
	if err := local.ReplaceInboundLeases([]foundation.NetworkDatabaseLease{
		{Gateway: foundation.Hash{10}, TunnelID: 11, EndDate: 90000},
		{Gateway: foundation.Hash{20}, TunnelID: 21, EndDate: 90000},
	}); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, foundation.NetworkDatabaseMaxLeaseSetBytes)
	n, err := local.MarshalTo(raw, 1000, remote.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.database.HandleDatabaseStore(foundation.I2NPDatabaseStoreMessage{Key: remote.Hash(), Type: foundation.I2NPStoreLeaseSet2, Data: raw[:n]}, false, 1000); err != nil {
		t.Fatal(err)
	}
	first, err := sender.PrepareHandshake(t.Context(), remote.Hash())
	if err != nil {
		t.Fatal(err)
	}
	initial, ok := sender.execution.RouteReceipt(remote.Hash())
	if !ok {
		t.Fatal("missing first lease route")
	}
	first.NoResponse()
	second, err := sender.PrepareHandshake(t.Context(), remote.Hash())
	if err != nil {
		t.Fatal(err)
	}
	alternate, ok := sender.execution.RouteReceipt(remote.Hash())
	if !ok || alternate.Circuit != initial.Circuit || alternate.TunnelID == initial.TunnelID {
		t.Fatalf("alternate lease = %+v; first = %+v", alternate, initial)
	}
	second.NoResponse()
	if err := sender.PrepareDestination(t.Context(), remote.Hash()); !errors.Is(err, dataplane.TunnelErrCircuitNotFound) {
		t.Fatalf("exhausted silent leases were reused: %v", err)
	}
}

func TestPreparedRouteSurvivesFirstLocalLeaseExpiry(t *testing.T) {
	sender, deliveries, _ := routeControlFixture(t, nil,
		foundation.NetworkDatabaseLease{Gateway: foundation.Hash{6}, TunnelID: 7, EndDate: 500},
		foundation.NetworkDatabaseLease{Gateway: foundation.Hash{8}, TunnelID: 9, EndDate: 90000},
	)
	if err := sender.SendTunnel(t.Context(), deliveries[0]); err != nil {
		t.Fatalf("live return lease was rejected after another lease expired: %v", err)
	}
	receipt, ok := sender.execution.RouteReceipt(deliveries[0].To)
	if !ok || receipt.Expires != 90000 {
		t.Fatalf("route deadline = %d, present=%t; want last return lease deadline 90000", receipt.Expires, ok)
	}
}

func TestLocalLeaseSet2RemainsUsableUntilLastLeaseExpiry(t *testing.T) {
	const now = uint64(1_750_000_000_000)
	destination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destination.ReleaseSensitive)
	local, err := controlplanenetdb.NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := local.ReplaceInboundLeases([]foundation.NetworkDatabaseLease{
		{Gateway: foundation.Hash{1}, TunnelID: 11, EndDate: now - 1000},
		{Gateway: foundation.Hash{2}, TunnelID: 22, EndDate: now + 60000},
	}); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, foundation.NetworkDatabaseMaxLeaseSetBytes)
	n, err := local.MarshalTo(raw, now-60000, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := localLeaseSetDeadline(foundation.I2NPStoreLeaseSet2, raw[:n], now)
	if err != nil || deadline != now+60000 {
		t.Fatalf("local LS2 deadline = %d, %v; want %d", deadline, err, now+60000)
	}
	if _, err := localLeaseSetDeadline(foundation.I2NPStoreLeaseSet2, raw[:n], now+60000); !errors.Is(err, dataplane.RouterErrLeaseSetExpired) {
		t.Fatalf("LS2 with no live return lease = %v, want expired", err)
	}
}

type routeLookupSender func(context.Context, controlplanenetdb.RouterRef, foundation.I2NPMessage) error

func (f routeLookupSender) Send(ctx context.Context, peer controlplanenetdb.RouterRef, message foundation.I2NPMessage) error {
	return f(ctx, peer, message)
}

func TestRoutePreparationRefreshesExpiredCachedLeaseSet(t *testing.T) {
	sender, _, _ := routeControlFixture(t, nil)
	remote, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	storeControlLegacyLeaseSet(t, sender.database, remote, foundation.NetworkDatabaseLease{Gateway: foundation.Hash{4}, TunnelID: 5, EndDate: 500})
	refreshed := controlplanenetdb.NewDatabase(sender.owner, controlplanenetdb.DefaultBucketCapacity)
	storeControlLegacyLeaseSet(t, refreshed, remote, foundation.NetworkDatabaseLease{Gateway: foundation.Hash{6}, TunnelID: 7, EndDate: 50000})
	kind, raw, ok := refreshed.StoredLeaseSet(remote.Hash)
	if !ok {
		t.Fatal("missing refreshed LeaseSet")
	}
	store := foundation.I2NPDatabaseStoreMessage{Key: remote.Hash, Type: kind, Data: raw}
	if err := sender.database.AdmitRouterInfo(dataPlaneFloodfill(t), true, 1000); err != nil {
		t.Fatal(err)
	}
	var requests *controlplanenetdb.RequestManager
	lookupSender := routeLookupSender(func(ctx context.Context, _ controlplanenetdb.RouterRef, message foundation.I2NPMessage) error {
		if err := sender.database.HandleDatabaseStore(store, false, 1000); err != nil {
			return err
		}
		requests.HandleDatabaseStore(ctx, store)
		return nil
	})
	requests, err = controlplanenetdb.NewRequestManager(sender.database, lookupSender, dataPlaneReplyRoute{}, controlplanenetdb.RequestManagerConfig{Capacity: 4, TimeoutMillis: 60000, Now: func() uint64 { return 1000 }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := requests.Close(); err != nil {
			t.Error(err)
		}
	})
	sender.requests = requests
	if err := sender.SendTunnel(t.Context(), dataplane.StreamingTunnelDelivery{From: sender.owner, To: remote.Hash, Protocol: 6, Payload: []byte("after renewal")}); err != nil {
		t.Fatalf("expired cache entry prevented route refresh: %v", err)
	}
	receipt, ok := sender.execution.RouteReceipt(remote.Hash)
	if !ok || receipt.TunnelID != 7 || receipt.Expires != 50000 {
		t.Fatalf("refreshed route = %+v, present=%t", receipt, ok)
	}
}
