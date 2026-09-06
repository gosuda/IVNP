package router

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"

	dataplanegarlic "gosuda.org/ivnp/dataplane/internal/garlic"
	dataplanestreamingtunnel "gosuda.org/ivnp/dataplane/internal/streaming/tunnel"
	dataplanetunnel "gosuda.org/ivnp/dataplane/internal/tunnel"
	"gosuda.org/ivnp/foundation"
)

type preparedTestWriter func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error

func (f preparedTestWriter) SendBlockPrepared(ctx context.Context, token dataplanetunnel.CircuitToken, block dataplanetunnel.Block) error {
	return f(ctx, token, block)
}

func preparedTestSender(t *testing.T, now func() uint64, capacity int, writer preparedTestWriter) (*PreparedRouteSender, PreparedRoute) {
	t.Helper()
	runtime := dataplanetunnel.NewRuntime(dataplanetunnel.RuntimeConfig{Now: now})
	token, err := runtime.RegisterOutbound(dataplanetunnel.OutboundCircuit{ID: 1, NextTunnelID: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.RemoveCircuit(token) })
	sender, err := NewPreparedRouteSender(PreparedRouteSenderConfig{
		Owner: foundation.Hash{1}, Garlic: dataplanegarlic.NewSessionManager(dataplanegarlic.SessionManagerConfig{}),
		Tunnels: writer, Now: now, RouteCapacity: capacity,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.ReleaseSensitive)
	return sender, PreparedRoute{Owner: foundation.Hash{1}, Remote: foundation.Hash{2}, Generation: 1,
		KeyType: foundation.CryptoX25519, KeyData: append([]byte{9}, make([]byte, 31)...), Circuit: token,
		Gateway: foundation.Hash{3}, TunnelID: 4, Expires: 2000, LocalLeaseSet: []byte("private local bundle")}
}

func TestPreparedRoutesExpireAtDependencyBoundary(t *testing.T) {
	now := uint64(1000)
	sent := 0
	sender, route := preparedTestSender(t, func() uint64 { return now }, 1, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error { sent++; return nil })
	if err := sender.InstallRoute(route); err != nil {
		t.Fatal(err)
	}
	if err := sender.SendRatchetReply(t.Context(), route.Remote, []byte{1}); err != nil {
		t.Fatal(err)
	}
	now = route.Expires
	if err := sender.SendRatchetReply(t.Context(), route.Remote, []byte{2}); !errors.Is(err, ErrPreparedRouteMissing) {
		t.Fatalf("expired reply = %v", err)
	}
	if sent != 1 {
		t.Fatalf("expired route sent packet: %d writes", sent)
	}
}

func TestPreparedRoutesBoundCacheAndRejectForeignOwner(t *testing.T) {
	sender, first := preparedTestSender(t, func() uint64 { return 1000 }, 1, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error { return nil })
	if err := sender.InstallRoute(first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Remote = foundation.Hash{4}
	if err := sender.InstallRoute(second); err != nil {
		t.Fatal(err)
	}
	if err := sender.SendRatchetReply(t.Context(), first.Remote, []byte{1}); !errors.Is(err, ErrPreparedRouteMissing) {
		t.Fatalf("evicted route = %v", err)
	}
	if err := sender.SendRatchetReply(t.Context(), second.Remote, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := sender.SendTunnel(t.Context(), dataplanestreamingtunnel.Delivery{From: foundation.Hash{9}, To: second.Remote, Protocol: 6}); !errors.Is(err, ErrGarlicDestination) {
		t.Fatalf("foreign destination send = %v", err)
	}
}

func TestPreparedRouteRetirementWaitsBeforeWiping(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		defer once.Do(func() { close(release) })
		sender, route := preparedTestSender(t, func() uint64 { return 1000 }, 1, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error {
			close(entered)
			<-release
			return nil
		})
		if err := sender.InstallRoute(route); err != nil {
			t.Fatal(err)
		}
		retained := sender.routes[route.Remote].route
		sent := make(chan error, 1)
		go func() { sent <- sender.SendRatchetReply(t.Context(), route.Remote, []byte{1}) }()
		<-entered
		retired := make(chan struct{})
		go func() { sender.InvalidateRoutes(2); close(retired) }()
		synctest.Wait()
		select {
		case <-retired:
			t.Fatal("retirement passed active writer")
		default:
		}
		if retained.KeyData[0] != 9 || string(retained.LocalLeaseSet) != "private local bundle" {
			t.Fatal("active route was wiped")
		}
		if err := sender.SendRatchetReply(t.Context(), route.Remote, []byte{1}); !errors.Is(err, ErrPreparedRouteMissing) {
			t.Fatalf("retired route admitted: %v", err)
		}
		once.Do(func() { close(release) })
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
		<-retired
		for _, b := range append(retained.KeyData, retained.LocalLeaseSet...) {
			if b != 0 {
				t.Fatal("retired route retained sensitive bytes")
			}
		}
		if err := sender.InstallRoute(route); !errors.Is(err, ErrRouteGeneration) {
			t.Fatalf("stale preparation installed: %v", err)
		}
	})
}

func TestPolicyInvalidationWaitsForDetachedRouteUses(t *testing.T) {
	for _, mutation := range []string{"eviction", "retirement", "invalidation", "same generation"} {
		t.Run(mutation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				defer once.Do(func() { close(release) })
				sender, route := preparedTestSender(t, func() uint64 { return 1000 }, 1, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error {
					close(entered)
					<-release
					return nil
				})
				if err := sender.InstallRoute(route); err != nil {
					t.Fatal(err)
				}
				sent := make(chan error, 1)
				go func() { sent <- sender.SendRatchetReply(t.Context(), route.Remote, []byte{1}) }()
				<-entered
				detached := make(chan error, 1)
				go func() {
					switch mutation {
					case "eviction":
						replacement := route
						replacement.Remote = foundation.Hash{4}
						detached <- sender.InstallRoute(replacement)
					case "retirement":
						sender.RetireRoute(route.Remote)
						detached <- nil
					case "invalidation":
						sender.InvalidateRoutes(2)
						detached <- nil
					case "same generation":
						sender.InvalidateRoutes(3)
						detached <- nil
					}
				}()
				synctest.Wait()
				if sender.HasRoute(route.Remote, 1) {
					t.Fatal("active route was not detached")
				}
				invalidated := make(chan struct{})
				go func() { sender.InvalidateRoutes(3); close(invalidated) }()
				synctest.Wait()
				select {
				case <-invalidated:
					t.Fatal("policy invalidation skipped a detached active route")
				default:
				}
				once.Do(func() { close(release) })
				if err := <-sent; err != nil {
					t.Fatal(err)
				}
				if err := <-detached; err != nil {
					t.Fatal(err)
				}
				<-invalidated
			})
		})
	}
}

func TestNewGenerationProgressesWhileRetiredWriteDrains(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		defer once.Do(func() { close(release) })
		sender, route := preparedTestSender(t, func() uint64 { return 1000 }, 2, func(_ context.Context, _ dataplanetunnel.CircuitToken, block dataplanetunnel.Block) error {
			if block.TunnelID == 4 {
				close(entered)
				<-release
			}
			return nil
		})
		if err := sender.InstallRoute(route); err != nil {
			t.Fatal(err)
		}
		sent := make(chan error, 1)
		go func() { sent <- sender.SendRatchetReply(t.Context(), route.Remote, []byte{1}) }()
		<-entered
		invalidated := make(chan struct{})
		go func() { sender.InvalidateRoutes(2); close(invalidated) }()
		synctest.Wait()
		next := route
		next.Remote, next.Generation, next.TunnelID = foundation.Hash{5}, 2, 5
		if err := sender.InstallRoute(next); err != nil {
			t.Fatalf("new generation installation = %v", err)
		}
		if err := sender.SendRatchetReply(t.Context(), next.Remote, []byte{2}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-invalidated:
			t.Fatal("old write escaped retirement barrier")
		default:
		}
		once.Do(func() { close(release) })
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
		<-invalidated
	})
}

func TestDetachedRouteAdmissionIsBoundedAndReclaimed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		defer once.Do(func() { close(release) })
		sender, route := preparedTestSender(t, func() uint64 { return 1000 }, 1, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error {
			close(entered)
			<-release
			return nil
		})
		if err := sender.InstallRoute(route); err != nil {
			t.Fatal(err)
		}
		sent := make(chan error, 1)
		go func() { sent <- sender.SendRatchetReply(t.Context(), route.Remote, []byte{1}) }()
		<-entered
		replacement := route
		replacement.Remote = foundation.Hash{5}
		installed := make(chan error, 1)
		go func() { installed <- sender.InstallRoute(replacement) }()
		synctest.Wait()
		excess := route
		excess.Remote = foundation.Hash{6}
		if err := sender.InstallRoute(excess); !errors.Is(err, ErrRoutePreparationBusy) {
			t.Fatalf("excess detached snapshot admission = %v", err)
		}
		once.Do(func() { close(release) })
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
		if err := <-installed; err != nil {
			t.Fatal(err)
		}
		if err := sender.InstallRoute(excess); err != nil {
			t.Fatalf("reclaimed snapshot capacity = %v", err)
		}
	})
}

func TestStaleHandshakeReceiptCannotRetireNewInstallation(t *testing.T) {
	sender, route := preparedTestSender(t, func() uint64 { return 1000 }, 1, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error { return nil })
	if err := sender.InstallRoute(route); err != nil {
		t.Fatal(err)
	}
	old, ok := sender.RouteReceipt(route.Remote)
	if !ok {
		t.Fatal("missing initial route")
	}
	// Identical route content in the same generation is still a new installation.
	if err := sender.InstallRoute(route); err != nil {
		t.Fatal(err)
	}
	delivery := dataplanestreamingtunnel.Delivery{From: route.Owner, To: route.Remote, Protocol: 6, Payload: []byte{1}}
	if err := sender.SendTunnelOnRoute(t.Context(), delivery, old); !errors.Is(err, ErrPreparedRouteMissing) {
		t.Fatalf("old SYN used newer installation: %v", err)
	}
	if sender.RetireUnresponsiveRoute(old) {
		t.Fatal("old handshake retired newer installation")
	}
	if err := sender.SendRatchetReply(t.Context(), route.Remote, []byte{1}); err != nil {
		t.Fatalf("replacement cannot send: %v", err)
	}
}

func TestFreshHandshakeFailureCanRetirePreviouslyResponsiveRoute(t *testing.T) {
	sender, route := preparedTestSender(t, func() uint64 { return 1000 }, 1, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error { return nil })
	if err := sender.InstallRoute(route); err != nil {
		t.Fatal(err)
	}
	earlier, ok := sender.RouteReceipt(route.Remote)
	if !ok {
		t.Fatal("missing route before successful handshake")
	}
	sender.MarkRouteResponsive(earlier)
	if sender.RetireUnresponsiveRoute(earlier) {
		t.Fatal("stale failure overrode a subsequent successful handshake")
	}
	later, ok := sender.RouteReceipt(route.Remote)
	if !ok || !sender.RetireUnresponsiveRoute(later) {
		t.Fatal("historical success prevented recovery from a new handshake failure")
	}
	if err := sender.SendRatchetReply(t.Context(), route.Remote, []byte{1}); !errors.Is(err, ErrPreparedRouteMissing) {
		t.Fatalf("failed route admitted another send: %v", err)
	}
}

func TestHandshakeRetirementDoesNotWaitForAdmittedWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		defer once.Do(func() { close(release) })
		sender, route := preparedTestSender(t, func() uint64 { return 1000 }, 1, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error {
			close(entered)
			<-release
			return nil
		})
		if err := sender.InstallRoute(route); err != nil {
			t.Fatal(err)
		}
		receipt, ok := sender.RouteReceipt(route.Remote)
		if !ok {
			t.Fatal("missing route")
		}
		retained := sender.routes[route.Remote].route
		sent := make(chan error, 1)
		go func() { sent <- sender.SendRatchetReply(t.Context(), route.Remote, []byte{1}) }()
		<-entered
		if !sender.RetireUnresponsiveRoute(receipt) {
			t.Fatal("unresponsive installation not retired")
		}
		if err := sender.SendRatchetReply(t.Context(), route.Remote, []byte{2}); !errors.Is(err, ErrPreparedRouteMissing) {
			t.Fatalf("retired route admitted payload: %v", err)
		}
		if retained.KeyData[0] != 9 {
			t.Fatal("active write lost encryption key ownership")
		}
		once.Do(func() { close(release) })
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		for _, value := range retained.KeyData {
			if value != 0 {
				t.Fatal("drained route retained key material")
			}
		}
	})
}
