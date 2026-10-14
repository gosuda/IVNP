package router

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"gosuda.org/ivnp/cryptography"
	dataplanedatagram "gosuda.org/ivnp/dataplane/internal/datagram"
	dataplanegarlic "gosuda.org/ivnp/dataplane/internal/garlic"
	dataplanestreamingtunnel "gosuda.org/ivnp/dataplane/internal/streaming/tunnel"
	dataplanetunnel "gosuda.org/ivnp/dataplane/internal/tunnel"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
)

var errTestDecryptedSenderPayloadChanged = errors.New("decrypted sender payload changed")

func preparedTestSenderWithConfig(t testing.TB, config PreparedRouteSenderConfig, writer preparedTestWriter) (*PreparedRouteSender, PreparedRoute) {
	t.Helper()
	if config.Now == nil {
		config.Now = func() uint64 { return 1000 }
	}
	if config.Owner == (foundation.Hash{}) {
		config.Owner = foundation.Hash{1}
	}
	if config.RouteCapacity == 0 {
		config.RouteCapacity = 1
	}
	if config.Garlic == nil && config.Ratchet == nil {
		sessions := dataplanegarlic.NewSessionManager(dataplanegarlic.SessionManagerConfig{})
		t.Cleanup(func() {
			if err := sessions.Close(); err != nil {
				t.Error(err)
			}
		})
		config.Garlic = sessions
	}
	config.Tunnels = writer
	runtime := dataplanetunnel.NewRuntime(dataplanetunnel.RuntimeConfig{Now: config.Now})
	token, err := runtime.RegisterOutbound(dataplanetunnel.OutboundCircuit{ID: 1, NextTunnelID: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.RemoveCircuit(token) })
	sender, err := NewPreparedRouteSender(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.ReleaseSensitive)
	return sender, PreparedRoute{
		Owner:         config.Owner,
		Remote:        foundation.Hash{2},
		Generation:    1,
		KeyType:       foundation.CryptoX25519,
		KeyData:       append([]byte{9}, make([]byte, 31)...),
		Circuit:       token,
		Gateway:       foundation.Hash{3},
		TunnelID:      4,
		Expires:       2000,
		LocalLeaseSet: []byte("private local bundle"),
	}
}

func TestPreparedSenderCanceledScratchAdmission(t *testing.T) {
	writes := 0
	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.ReleaseSensitive)
	ratchet, err := dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ratchet.ReleaseSensitive)
	sender, route := preparedTestSenderWithConfig(t, PreparedRouteSenderConfig{Ratchet: ratchet}, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error {
		writes++
		return nil
	})
	if err := sender.InstallRoute(route); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	delivery := dataplanestreamingtunnel.Delivery{
		From:     route.Owner,
		To:       route.Remote,
		Protocol: dataplanedatagram.ProtocolRaw,
		Payload:  []byte("canceled payload"),
	}
	if err := sender.SendTunnel(ctx, delivery); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled SendTunnel = %v, want %v", err, context.Canceled)
	}
	if writes != 0 {
		t.Fatalf("canceled SendTunnel invoked writer %d times", writes)
	}
	if err := sender.SendTunnel(t.Context(), delivery); err != nil {
		t.Fatalf("subsequent live SendTunnel failed after canceled admission: %v", err)
	}
	if writes != 1 {
		t.Fatalf("writer calls after live send = %d, want 1", writes)
	}
}

func TestPreparedSenderScratchExhaustionWaitsForCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		slots := parallelism.CPUs()
		local, err := foundation.GenerateLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(local.ReleaseSensitive)
		ratchet, err := dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ratchet.ReleaseSensitive)
		checkedOut := make(chan struct{}, slots)
		releaseHold := make(chan struct{})
		sender, route := preparedTestSenderWithConfig(t, PreparedRouteSenderConfig{
			Ratchet: ratchet,
			NextID: func() (uint32, error) {
				checkedOut <- struct{}{}
				<-releaseHold
				return 1, nil
			},
		}, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error {
			return nil
		})
		if err := sender.InstallRoute(route); err != nil {
			t.Fatal(err)
		}
		delivery := dataplanestreamingtunnel.Delivery{
			From:     route.Owner,
			To:       route.Remote,
			Protocol: dataplanedatagram.ProtocolRaw,
			Payload:  []byte("scratch exhaustion probe"),
		}
		holders := make(chan error, slots)
		for range slots {
			go func() {
				holders <- sender.SendTunnel(t.Context(), delivery)
			}()
		}
		for range slots {
			<-checkedOut
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- sender.SendTunnel(ctx, delivery)
		}()
		synctest.Wait()
		select {
		case err := <-done:
			close(releaseHold)
			t.Fatalf("exhausted admission returned early: %v", err)
		default:
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			close(releaseHold)
			t.Fatalf("exhausted acquisition = %v, want %v", err, context.Canceled)
		}
		close(releaseHold)
		for range slots {
			if err := <-holders; err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestPreparedSenderMaintainScratchSkipsCheckedOutSlots(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, err := foundation.GenerateLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(local.ReleaseSensitive)
		remote, err := foundation.GenerateLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(remote.ReleaseSensitive)
		receiver, err := dataplanegarlic.NewRatchetManager(remote, dataplanegarlic.RatchetConfig{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(receiver.ReleaseSensitive)
		ratchet, err := dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ratchet.ReleaseSensitive)

		var blockNextID sync.Mutex
		pauseID := false
		inFlight := make(chan struct{})
		releaseInFlight := make(chan struct{})
		var nextID uint32

		var decryptedMu sync.Mutex
		var decrypted [][]byte
		sender, route := preparedTestSenderWithConfig(t, PreparedRouteSenderConfig{
			Ratchet: ratchet,
			NextID: func() (uint32, error) {
				blockNextID.Lock()
				shouldPause := pauseID
				pauseID = false
				nextID++
				id := nextID
				blockNextID.Unlock()
				if shouldPause {
					close(inFlight)
					<-releaseInFlight
				}
				return id, nil
			},
		}, func(_ context.Context, _ dataplanetunnel.CircuitToken, block dataplanetunnel.Block) error {
			result, recvErr := receiver.Receive(make([]byte, foundation.I2NPI2PDMaxPayload), make([]byte, 2048), block.Data[foundation.I2NPStandardHeaderLen+4:], 1000)
			if recvErr != nil {
				return recvErr
			}
			decryptedMu.Lock()
			decrypted = append(decrypted, append([]byte(nil), result.Payload...))
			decryptedMu.Unlock()
			return nil
		})
		key := remote.X25519Public()
		route.KeyData = key[:]
		if err := sender.InstallRoute(route); err != nil {
			t.Fatal(err)
		}

		largePayload := bytes.Repeat([]byte{0x5a}, 32*1024)
		if err := sender.SendTunnel(t.Context(), dataplanestreamingtunnel.Delivery{
			From: route.Owner, To: route.Remote, Protocol: dataplanedatagram.ProtocolRaw, Payload: largePayload,
		}); err != nil {
			t.Fatal(err)
		}

		blockNextID.Lock()
		pauseID = true
		blockNextID.Unlock()
		heldPayload := bytes.Repeat([]byte{0x6b}, 16*1024)
		heldDone := make(chan error, 1)
		go func() {
			heldDone <- sender.SendTunnel(t.Context(), dataplanestreamingtunnel.Delivery{
				From: route.Owner, To: route.Remote, Protocol: dataplanedatagram.ProtocolRaw, Payload: heldPayload,
			})
		}()
		<-inFlight

		sender.MaintainScratch()
		sender.MaintainScratch()

		close(releaseInFlight)
		if err := <-heldDone; err != nil {
			t.Fatalf("in-flight send across MaintainScratch failed: %v", err)
		}

		smallPayload := bytes.Repeat([]byte{0x7c}, 128)
		if err := sender.SendTunnel(t.Context(), dataplanestreamingtunnel.Delivery{
			From: route.Owner, To: route.Remote, Protocol: dataplanedatagram.ProtocolRaw, Payload: smallPayload,
		}); err != nil {
			t.Fatalf("post-MaintainScratch small send failed: %v", err)
		}

		decryptedMu.Lock()
		defer decryptedMu.Unlock()
		if len(decrypted) != 3 ||
			!bytes.Contains(decrypted[0], largePayload) ||
			!bytes.Contains(decrypted[1], heldPayload) ||
			!bytes.Contains(decrypted[2], smallPayload) {
			t.Fatal("MaintainScratch corrupted in-flight or subsequent sender payloads")
		}
	})
}

func TestPreparedSenderWipesPartiallySerializedLeaseSet(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "ratchet", true: "legacy"}[legacy], func(t *testing.T) {
			local, err := foundation.GenerateLocalDestination()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(local.ReleaseSensitive)
			ratchet, err := dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(ratchet.ReleaseSensitive)
			garlicSessions := dataplanegarlic.NewSessionManager(dataplanegarlic.SessionManagerConfig{})
			t.Cleanup(func() {
				if err := garlicSessions.Close(); err != nil {
					t.Error(err)
				}
			})
			injected := errors.New("ID source failed after payload write")
			calls := 0
			sender, route := preparedTestSenderWithConfig(t, PreparedRouteSenderConfig{
				Garlic:  garlicSessions,
				Ratchet: ratchet,
				NextID: func() (uint32, error) {
					calls++
					if calls == 2 {
						return 0, injected
					}
					return uint32(calls), nil
				},
			}, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error {
				t.Fatal("failed serialization reached writer")
				return nil
			})
			route.LocalLeaseSet2 = true
			route.Legacy = legacy
			if legacy {
				route.KeyType = foundation.CryptoElGamal
			}
			if err = sender.InstallRoute(route); err != nil {
				t.Fatal(err)
			}
			err = sender.SendTunnel(t.Context(), dataplanestreamingtunnel.Delivery{
				From:     route.Owner,
				To:       route.Remote,
				Protocol: dataplanedatagram.ProtocolDatagram1,
				Payload:  []byte("secret application payload"),
			})
			if !errors.Is(err, injected) {
				t.Fatalf("send = %v, want %v", err, injected)
			}
		})
	}
}

func TestPreparedSenderWipesCiphertextWhenSessionAdmissionFails(t *testing.T) {
	writes := 0
	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.ReleaseSensitive)
	ratchet, err := dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{MaxSessions: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ratchet.ReleaseSensitive)
	sender, route := preparedTestSenderWithConfig(t, PreparedRouteSenderConfig{Ratchet: ratchet}, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error {
		writes++
		return nil
	})
	if err = sender.InstallRoute(route); err != nil {
		t.Fatal(err)
	}
	delivery := dataplanestreamingtunnel.Delivery{
		From:     route.Owner,
		To:       route.Remote,
		Protocol: dataplanedatagram.ProtocolDatagram1,
		Payload:  []byte("secret before pending-session rejection"),
	}
	if err = sender.SendTunnel(t.Context(), delivery); err != nil {
		t.Fatal(err)
	}
	// The second handshake seals its output before pending-session admission fails.
	if err = sender.SendTunnel(t.Context(), delivery); !errors.Is(err, dataplanegarlic.ErrRatchet) {
		t.Fatalf("full session admission = %v, want %v", err, dataplanegarlic.ErrRatchet)
	}
	if writes != 1 {
		t.Fatalf("writer calls = %d, want 1", writes)
	}
}

func TestPreparedSenderReleaseSensitiveDrainsScratch(t *testing.T) {
	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.ReleaseSensitive)
	ratchet, err := dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ratchet.ReleaseSensitive)
	inSend := make(chan struct{})
	callingRelease := make(chan struct{})
	var inSendOnce sync.Once
	var nextIDSeq atomic.Uint32
	var tunnelDispatched atomic.Bool
	var releaseReturned atomic.Bool
	sender, route := preparedTestSenderWithConfig(t, PreparedRouteSenderConfig{
		Ratchet: ratchet,
		NextID: func() (uint32, error) {
			inSendOnce.Do(func() {
				close(inSend)
				<-callingRelease
			})
			return nextIDSeq.Add(1), nil
		},
	}, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error {
		if releaseReturned.Load() {
			t.Error("ReleaseSensitive returned while an admitted SendTunnel was still in flight")
		}
		tunnelDispatched.Store(true)
		return nil
	})
	if err := sender.InstallRoute(route); err != nil {
		t.Fatal(err)
	}
	delivery := dataplanestreamingtunnel.Delivery{
		From:     route.Owner,
		To:       route.Remote,
		Protocol: dataplanedatagram.ProtocolRaw,
		Payload:  bytes.Repeat([]byte{1}, 1024),
	}
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- sender.SendTunnel(t.Context(), delivery)
	}()
	<-inSend

	done := make(chan struct{})
	go func() {
		close(callingRelease)
		sender.ReleaseSensitive()
		releaseReturned.Store(true)
		close(done)
	}()
	<-done
	if !tunnelDispatched.Load() {
		t.Fatal("ReleaseSensitive returned before in-flight SendTunnel completed")
	}
	if err := <-sendDone; err != nil {
		t.Fatal(err)
	}
	if err := sender.SendTunnel(t.Context(), delivery); !errors.Is(err, ErrDataPlaneConfig) {
		t.Fatalf("SendTunnel after ReleaseSensitive = %v, want %v", err, ErrDataPlaneConfig)
	}
}

type scratchTrafficFixture struct {
	sender   *PreparedRouteSender
	route    PreparedRoute
	expected []byte
	decrypt  func([]byte) ([]byte, error)
	sequence byte
}

func newScratchTrafficFixture(t *testing.T, config PreparedRouteSenderConfig) *scratchTrafficFixture {
	t.Helper()
	f := new(scratchTrafficFixture)
	writer := func(_ context.Context, _ dataplanetunnel.CircuitToken, block dataplanetunnel.Block) error {
		decoded, err := f.decrypt(block.Data[foundation.I2NPStandardHeaderLen+4:])
		if err != nil {
			return err
		}
		if !bytes.Contains(decoded, f.expected) {
			return errTestDecryptedSenderPayloadChanged
		}
		return nil
	}
	f.sender, f.route = preparedTestSenderWithConfig(t, config, writer)
	return f
}

func (f *scratchTrafficFixture) send(t *testing.T, protocol uint8, size int) error {
	t.Helper()
	f.sequence++
	f.expected = bytes.Repeat([]byte{0xa0 + f.sequence}, size)
	delivery := dataplanestreamingtunnel.Delivery{From: f.route.Owner, To: f.route.Remote, Protocol: protocol, Payload: f.expected}
	return f.sender.SendTunnel(t.Context(), delivery)
}

func TestPreparedSenderLegacyMixedTrafficUsesBoundedScratch(t *testing.T) {
	garlicSessions := dataplanegarlic.NewSessionManager(dataplanegarlic.SessionManagerConfig{})
	t.Cleanup(func() {
		if err := garlicSessions.Close(); err != nil {
			t.Error(err)
		}
	})
	f := newScratchTrafficFixture(t, PreparedRouteSenderConfig{Garlic: garlicSessions})
	public, private, err := cryptography.GenerateElGamalKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private[:])
	receiver := dataplanegarlic.NewSessionManager(dataplanegarlic.SessionManagerConfig{})
	t.Cleanup(func() {
		if err := receiver.Close(); err != nil {
			t.Error(err)
		}
	})
	f.decrypt = func(packet []byte) ([]byte, error) {
		decoded, _, _, err := receiver.Receive(make([]byte, foundation.I2NPI2PDMaxPayload), packet, private, 1000)
		return decoded, err
	}
	f.route.Legacy, f.route.LegacyKey = true, public
	if err := f.sender.InstallRoute(f.route); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{128, 48 * 1024, 128} {
		if err := f.send(t, dataplanestreamingtunnel.ProtocolStreaming, size); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		garlicSessions.ConfirmOutboundTags(f.route.Remote, 1000)
	}
}

func newRatchetScratchTraffic(t *testing.T) *scratchTrafficFixture {
	t.Helper()
	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.ReleaseSensitive)
	remote, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remote.ReleaseSensitive)
	receiver, err := dataplanegarlic.NewRatchetManager(remote, dataplanegarlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(receiver.ReleaseSensitive)
	ratchet, err := dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ratchet.ReleaseSensitive)
	f := newScratchTrafficFixture(t, PreparedRouteSenderConfig{Ratchet: ratchet})
	f.decrypt = func(packet []byte) ([]byte, error) {
		result, err := receiver.Receive(make([]byte, foundation.I2NPI2PDMaxPayload), make([]byte, 2048), packet, 1000)
		if err != nil {
			return nil, err
		}
		if result.Candidate != nil {
			if _, err := receiver.CommitNew(result.Candidate, result.Peer, 1000); err != nil {
				return nil, err
			}
			if _, err := ratchet.Receive(make([]byte, 2048), nil, result.Reply, 1000); err != nil {
				return nil, err
			}
		}
		return result.Payload, nil
	}
	key := remote.X25519Public()
	f.route.KeyData = key[:]
	if err := f.sender.InstallRoute(f.route); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestPreparedSenderRepliableMixedTrafficUsesBoundedScratch(t *testing.T) {
	f := newRatchetScratchTraffic(t)
	for _, size := range []int{128, 48 * 1024, 128} {
		if err := f.send(t, dataplanestreamingtunnel.ProtocolStreaming, size); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
	}
}

func TestPreparedSenderUnboundMixedTrafficAndFrameLimits(t *testing.T) {
	f := newRatchetScratchTraffic(t)
	for _, size := range []int{128, 48 * 1024, 128} {
		if err := f.send(t, dataplanedatagram.ProtocolRaw, size); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
	}
	packetOverhead, _, err := dataplanegarlic.RatchetEncryptBufferSizes(0, uint16(f.route.KeyType))
	if err != nil {
		t.Fatal(err)
	}
	maxPayload := foundation.I2NPI2PDMaxPayload - 4 - packetOverhead - (3 + 1 + foundation.HashLength + 9) - (4 + destinationDataHeaderLen)
	if err := f.send(t, dataplanedatagram.ProtocolRaw, maxPayload); err != nil {
		t.Fatalf("maximum frame: %v", err)
	}
	if err := f.send(t, dataplanedatagram.ProtocolRaw, maxPayload+1); !errors.Is(err, foundation.I2NPErrPayloadTooLarge) {
		t.Fatalf("oversized frame = %v", err)
	}
}

func BenchmarkPreparedSenderScratchReuse(b *testing.B) {
	for _, workload := range []struct {
		name  string
		large bool
		size  int
	}{
		{"small", false, 128}, {"large", true, 48 * 1024}, {"small-after-large", true, 128},
	} {
		b.Run(workload.name, func(b *testing.B) {
			local, err := foundation.GenerateLocalDestination()
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(local.ReleaseSensitive)
			ratchet, err := dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{})
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(ratchet.ReleaseSensitive)
			sender, route := preparedTestSenderWithConfig(b, PreparedRouteSenderConfig{
				Ratchet: ratchet,
				NextID:  func() (uint32, error) { return 1, nil },
			}, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error {
				return nil
			})
			if err := sender.InstallRoute(route); err != nil {
				b.Fatal(err)
			}
			if workload.large {
				warm := dataplanestreamingtunnel.Delivery{
					From: route.Owner, To: route.Remote, Protocol: dataplanedatagram.ProtocolRaw,
					Payload: make([]byte, 48*1024),
				}
				if err := sender.SendTunnel(b.Context(), warm); err != nil {
					b.Fatal(err)
				}
			}
			delivery := dataplanestreamingtunnel.Delivery{
				From: route.Owner, To: route.Remote, Protocol: dataplanedatagram.ProtocolRaw,
				Payload: make([]byte, workload.size),
			}
			b.ReportAllocs()
			b.SetBytes(int64(workload.size))
			b.ResetTimer()
			for b.Loop() {
				if err := sender.SendTunnel(b.Context(), delivery); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
