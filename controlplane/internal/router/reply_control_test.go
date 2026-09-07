package router

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	controlplanetunnel "gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

type replyTestWriter func(context.Context, dataplane.TunnelCircuitToken, dataplane.TunnelBlock) error

func (f replyTestWriter) SendBlockPrepared(ctx context.Context, token dataplane.TunnelCircuitToken, block dataplane.TunnelBlock) error {
	return f(ctx, token, block)
}

func replyExchange(t *testing.T, writer replyTestWriter) (*StreamingTunnelSender, dataplane.StreamingTunnelDelivery, *dataplane.GarlicRatchetManager, dataplane.RouterRatchetReplyReservation, []byte, *foundation.LocalDestination) {
	t.Helper()
	const now = uint64(1000)
	local, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	remote, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	localRatchet, err := dataplane.GarlicNewRatchetManager(local, dataplane.GarlicRatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	remoteRatchet, err := dataplane.GarlicNewRatchetManager(remote, dataplane.GarlicRatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		localRatchet.ReleaseSensitive()
		remoteRatchet.ReleaseSensitive()
		local.ReleaseSensitive()
		remote.ReleaseSensitive()
	})
	database := controlplanenetdb.NewDatabase(local.Hash(), controlplanenetdb.DefaultBucketCapacity)
	localSet, err := controlplanenetdb.NewLocalLeaseSet2(remote)
	if err != nil {
		t.Fatal(err)
	}
	if err := localSet.ReplaceInboundLeases([]foundation.NetworkDatabaseLease{{Gateway: foundation.Hash{3}, TunnelID: 4, EndDate: 60000}}); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, foundation.NetworkDatabaseMaxLeaseSetBytes)
	n, err := localSet.MarshalTo(raw, now, remote.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.HandleDatabaseStore(foundation.I2NPDatabaseStoreMessage{Key: remote.Hash(), Type: foundation.I2NPStoreLeaseSet2, Data: raw[:n]}, false, now); err != nil {
		t.Fatal(err)
	}
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Now: func() uint64 { return now }})
	token, err := runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 1, Owner: local.Hash(), FirstHop: foundation.Hash{5}, NextTunnelID: 6, ExpiresAt: 60000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.RemoveCircuit(token) })
	pool := controlplanetunnel.NewOwnedPool(local.Hash(), 1)
	if err := pool.Add(controlplanetunnel.Entry{ID: 1, Circuit: token, Owner: local.Hash(), Direction: controlplanetunnel.Outbound, Expires: 60000}, now); err != nil {
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
	sender, err := NewStreamingTunnelSender(StreamingTunnelSenderConfig{Owner: local.Hash(), Database: database, Requests: requests, Tunnels: runtime, Pool: pool, Ratchet: localRatchet, Now: func() uint64 { return now }, RouteCapacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	sender.execution.ReleaseSensitive()
	sender.execution, err = dataplane.RouterNewPreparedRouteSender(dataplane.RouterPreparedRouteSenderConfig{Owner: local.Hash(), Ratchet: localRatchet, Tunnels: writer, Now: func() uint64 { return now }, RouteCapacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.ReleaseSensitive)
	if err := sender.prepare(t.Context(), remote.Hash()); err != nil {
		t.Fatal(err)
	}
	reservation, err := sender.ReserveRatchetReply(remote.Hash())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reservation.Release)
	key := local.X25519Public()
	incoming, err := remoteRatchet.Encrypt(make([]byte, 4096), local.Hash(), key[:], uint16(foundation.CryptoX25519), nil, now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := localRatchet.Receive(make([]byte, 4096), make([]byte, 4096), incoming, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Candidate == nil {
		t.Fatal("New Session did not produce a candidate")
	}
	defer result.Candidate.Discard()
	if err := reservation.Activate(); err != nil {
		t.Fatal(err)
	}
	if _, err := localRatchet.CommitNew(result.Candidate, remote.Hash(), now); err != nil {
		t.Fatal(err)
	}
	return sender, dataplane.StreamingTunnelDelivery{From: local.Hash(), To: remote.Hash(), Protocol: 6, Payload: []byte("application reply")}, remoteRatchet, reservation, append([]byte(nil), result.Reply...), local
}

func TestWarmApplicationReplyWaitsForNSRHandoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		defer once.Do(func() { close(release) })
		handed := make(chan string, 2)
		var reply []byte
		var remote *dataplane.GarlicRatchetManager
		writer := replyTestWriter(func(_ context.Context, _ dataplane.TunnelCircuitToken, block dataplane.TunnelBlock) error {
			packet := block.Data[foundation.I2NPStandardHeaderLen+4:]
			kind := "ES"
			if bytes.Equal(packet, reply) {
				kind = "NSR"
				close(entered)
				<-release
			}
			if _, err := remote.Receive(make([]byte, 4096), make([]byte, 4096), packet, 1000); err != nil {
				return err
			}
			handed <- kind
			return nil
		})
		sender, delivery, peer, reservation, packet, _ := replyExchange(t, writer)
		remote, reply = peer, packet
		if err := reservation.Send(t.Context(), reply); err != nil {
			t.Fatal(err)
		}
		reservation.Release()
		<-entered
		application := make(chan error, 1)
		go func() { application <- sender.SendTunnel(t.Context(), delivery) }()
		synctest.Wait()
		select {
		case err := <-application:
			t.Fatalf("application passed pending NSR: %v", err)
		default:
		}
		select {
		case kind := <-handed:
			t.Fatalf("premature packet handoff: %s", kind)
		default:
		}
		once.Do(func() { close(release) })
		if err := <-application; err != nil {
			t.Fatal(err)
		}
		if first, second := <-handed, <-handed; first != "NSR" || second != "ES" {
			t.Fatalf("handoff order = %s, %s", first, second)
		}
	})
}

func TestEstablishedControlReplyFailureDoesNotBlockApplication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		defer once.Do(func() { close(release) })
		control := []byte("lost control response")
		delivered := make(chan struct{}, 2)
		var remote *dataplane.GarlicRatchetManager
		writer := replyTestWriter(func(_ context.Context, _ dataplane.TunnelCircuitToken, block dataplane.TunnelBlock) error {
			packet := block.Data[foundation.I2NPStandardHeaderLen+4:]
			if bytes.Equal(packet, control) {
				close(entered)
				<-release
				return context.DeadlineExceeded
			}
			result, err := remote.Receive(make([]byte, 4096), make([]byte, 4096), packet, 1000)
			if err == nil && !result.NewSession {
				delivered <- struct{}{}
			}
			return err
		})
		sender, delivery, peer, initial, reply, _ := replyExchange(t, writer)
		remote = peer
		if err := initial.Send(t.Context(), reply); err != nil {
			t.Fatal(err)
		}
		sender.replies.Wait()
		reservation, err := sender.ReserveRatchetReply(delivery.To)
		if err != nil {
			t.Fatal(err)
		}
		defer reservation.Release()
		if err := reservation.SendEstablished(t.Context(), control); err != nil {
			t.Fatal(err)
		}
		<-entered
		application := make(chan error, 1)
		go func() { application <- sender.SendTunnel(t.Context(), delivery) }()
		synctest.Wait()
		select {
		case err := <-application:
			if err != nil {
				t.Fatalf("application while ACK handoff is pending: %v", err)
			}
		default:
			t.Fatal("established control response blocked application data")
		}
		once.Do(func() { close(release) })
		sender.replies.Wait()
		if err := sender.SendTunnel(t.Context(), delivery); err != nil {
			t.Fatalf("failed ACK handoff poisoned later application data: %v", err)
		}
		if len(delivered) != 2 {
			t.Fatalf("recipient decrypted %d application packets, want 2", len(delivered))
		}
	})
}

func TestLocalPublicationRefreshPreservesPendingNSR(t *testing.T) {
	for _, phase := range []string{"before handoff", "during preparation"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				handed := make(chan string, 2)
				var remote *dataplane.GarlicRatchetManager
				var reply []byte
				sender, delivery, peer, reservation, packet, local := replyExchange(t, func(_ context.Context, _ dataplane.TunnelCircuitToken, block dataplane.TunnelBlock) error {
					encrypted := block.Data[foundation.I2NPStandardHeaderLen+4:]
					if _, err := remote.Receive(make([]byte, 4096), make([]byte, 4096), encrypted, 1000); err != nil {
						return err
					}
					kind := "ES"
					if bytes.Equal(encrypted, reply) {
						kind = "NSR"
					}
					handed <- kind
					return nil
				})
				remote, reply = peer, packet
				entered, release := make(chan struct{}), make(chan struct{})
				var unblock, first sync.Once
				defer unblock.Do(func() { close(release) })
				if phase == "during preparation" {
					sender.execution.RetireRoute(delivery.To)
					sender.prepareTunnel = func(ctx context.Context, _ foundation.Hash) error {
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
					}
					if err := reservation.Send(t.Context(), reply); err != nil {
						t.Fatal(err)
					}
					<-entered
				}
				localSet, err := controlplanenetdb.NewLocalLeaseSet2(local)
				if err != nil {
					t.Fatal(err)
				}
				if err := localSet.ReplaceInboundLeases([]foundation.NetworkDatabaseLease{{Gateway: foundation.Hash{8}, TunnelID: 9, EndDate: 90000}}); err != nil {
					t.Fatal(err)
				}
				raw := make([]byte, foundation.NetworkDatabaseMaxLeaseSetBytes)
				n, err := localSet.MarshalTo(raw, 1000, local.Sign)
				if err != nil {
					t.Fatal(err)
				}
				if err := sender.database.HandleDatabaseStore(foundation.I2NPDatabaseStoreMessage{Key: local.Hash(), Type: foundation.I2NPStoreLeaseSet2, Data: raw[:n]}, false, 1000); err != nil {
					t.Fatal(err)
				}
				if err := sender.RefreshLocalLeaseSet(); err != nil {
					t.Fatal(err)
				}
				unblock.Do(func() { close(release) })
				if phase == "before handoff" {
					if err := reservation.Send(t.Context(), reply); err != nil {
						t.Fatal(err)
					}
				}
				if err := sender.SendTunnel(t.Context(), delivery); err != nil {
					t.Fatalf("publication refresh poisoned reply handoff: %v", err)
				}
				if first, second := <-handed, <-handed; first != "NSR" || second != "ES" {
					t.Fatalf("handoff across refresh = %s, %s; want NSR then ES", first, second)
				}
			})
		})
	}
}

func TestRemoteELSReplacementRejectsPendingNSR(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		writes := 0
		sender, delivery, _, reservation, reply, _ := replyExchange(t, func(context.Context, dataplane.TunnelCircuitToken, dataplane.TunnelBlock) error {
			writes++
			return nil
		})
		remote, ok := sender.database.LeaseSet2(delivery.To)
		if !ok {
			t.Fatal("missing remote LeaseSet2")
		}
		if err := sender.UpdateRemoteELS(map[foundation.Hash]RemoteELSContext{delivery.To: {Identity: remote.Header.Destination}}); err != nil {
			t.Fatal(err)
		}
		if err := reservation.Send(t.Context(), reply); err != nil {
			t.Fatal(err)
		}
		if err := sender.SendTunnel(t.Context(), delivery); !errors.Is(err, dataplane.RouterErrRouteGeneration) {
			t.Fatalf("reply under replaced authorization = %v", err)
		}
		if writes != 0 {
			t.Fatalf("replaced authorization transmitted %d frames", writes)
		}
	})
}

func TestFailedNSRHandoffBlocksESUntilPeerRetirement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		failure := errors.New("reply handoff failed")
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		defer once.Do(func() { close(release) })
		writes := 0
		var remote *dataplane.GarlicRatchetManager
		recovered := false
		sender, delivery, peer, reservation, reply, _ := replyExchange(t, func(_ context.Context, _ dataplane.TunnelCircuitToken, block dataplane.TunnelBlock) error {
			writes++
			if writes == 1 {
				close(entered)
				<-release
				return failure
			}
			result, err := remote.Receive(make([]byte, 4096), make([]byte, 4096), block.Data[foundation.I2NPStandardHeaderLen+4:], 1000)
			if err != nil {
				return err
			}
			recovered = result.Candidate != nil
			if result.Candidate != nil {
				result.Candidate.Discard()
			}
			return nil
		})
		remote = peer
		if err := reservation.Send(t.Context(), reply); err != nil {
			t.Fatal(err)
		}
		<-entered
		application := make(chan error, 1)
		go func() { application <- sender.SendTunnel(t.Context(), delivery) }()
		synctest.Wait()
		once.Do(func() { close(release) })
		if err := <-application; !errors.Is(err, failure) {
			t.Fatalf("application after failed NSR = %v", err)
		}
		if err := sender.SendTunnel(t.Context(), delivery); !errors.Is(err, failure) {
			t.Fatalf("warm retry bypassed NSR failure: %v", err)
		}
		if writes != 1 {
			t.Fatalf("failed NSR caused %d writes, want 1", writes)
		}
		retained, err := sender.ReserveRatchetReply(delivery.To)
		if err != nil {
			t.Fatal(err)
		}
		retained.Release()
		retained.Release()
		if err := sender.SendTunnel(t.Context(), delivery); !errors.Is(err, failure) {
			t.Fatalf("retained-session rollback forgot NSR failure: %v", err)
		}
		// Capacity recovery retires the failed peer before removing its tombstone.
		next, err := sender.ReserveRatchetReply(foundation.Hash{99})
		if err != nil {
			t.Fatal(err)
		}
		next.Release()
		if err := sender.SendTunnel(t.Context(), delivery); err != nil {
			t.Fatal(err)
		}
		if !recovered {
			t.Fatal("failed-gate eviction reused ES instead of establishing a fresh session")
		}
	})
}

func TestUnsentReplyReservationRollsBackIdempotently(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sender, deliveries, _ := routeControlFixture(t, nil)
		reservation, err := sender.ReserveRatchetReply(deliveries[0].To)
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- sender.SendTunnel(t.Context(), deliveries[0]) }()
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("application passed unsent reservation: %v", err)
		default:
		}
		reservation.Release()
		reservation.Release()
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	})
}

func TestShutdownCancelsUnactivatedReplyReservation(t *testing.T) {
	sender, deliveries, _ := routeControlFixture(t, nil)
	reservation, err := sender.ReserveRatchetReply(deliveries[0].To)
	if err != nil {
		t.Fatal(err)
	}
	sender.ReleaseSensitive()
	if err := reservation.Activate(); !errors.Is(err, dataplane.RouterErrDataPlaneConfig) {
		t.Fatalf("commit admission after shutdown = %v", err)
	}
	reservation.Release()
}
