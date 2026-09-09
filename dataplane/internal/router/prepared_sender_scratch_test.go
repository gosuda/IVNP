package router

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"testing/synctest"

	"gosuda.org/ivnp/cryptography"
	dataplanedatagram "gosuda.org/ivnp/dataplane/internal/datagram"
	dataplanegarlic "gosuda.org/ivnp/dataplane/internal/garlic"
	dataplanestreamingtunnel "gosuda.org/ivnp/dataplane/internal/streaming/tunnel"
	dataplanetunnel "gosuda.org/ivnp/dataplane/internal/tunnel"
	"gosuda.org/ivnp/foundation"
)

func assertSenderScratchWiped(t testing.TB, scratch *streamingSenderScratch) {
	t.Helper()
	for _, buffer := range []*senderScratchBuffer{&scratch.data, &scratch.clove, &scratch.ratchet, &scratch.plain, &scratch.encrypted} {
		for _, value := range buffer.exposed[:cap(buffer.exposed)] {
			if value != 0 {
				t.Fatal("scratch retained sensitive output")
			}
		}
	}
}

func TestPreparedSenderCanceledScratchAdmission(t *testing.T) {
	sender, _ := preparedTestSender(t, func() uint64 { return 1000 }, 1, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error { return nil })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	scratch, err := sender.acquireScratch(ctx)
	if scratch != nil {
		sender.releaseScratch(scratch)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled acquisition = %v", err)
	}
	if len(sender.scratch) != sender.scratchSlots {
		t.Fatal("canceled acquisition consumed admission capacity")
	}
}

func TestPreparedSenderScratchExhaustionWaitsForCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sender := &PreparedRouteSender{scratch: make(chan *streamingSenderScratch, 1)}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { _, err := sender.acquireScratch(ctx); done <- err }()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("exhausted admission returned early: %v", err)
		default:
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("exhausted acquisition = %v", err)
		}
	})
}

func TestSenderScratchWipesPartialWritesAndRetiredBacking(t *testing.T) {
	var scratch streamingSenderScratch
	for _, buffer := range []*senderScratchBuffer{&scratch.data, &scratch.clove, &scratch.ratchet, &scratch.plain, &scratch.encrypted} {
		small := buffer.bytes(100)
		copy(small, bytes.Repeat([]byte{0xa1}, len(small)))
		large := buffer.bytes(8192)
		if &small[0] != &large[0] {
			for _, value := range small {
				if value != 0 {
					t.Fatal("growing scratch abandoned sensitive backing")
				}
			}
		}
		large[len(large)-1] = 0xb2
		buffer.bytes(1)[0] = 0xc3
	}
	clearStreamingSenderScratch(&scratch)
	assertSenderScratchWiped(t, &scratch)
	for _, buffer := range []*senderScratchBuffer{&scratch.data, &scratch.clove, &scratch.ratchet, &scratch.plain, &scratch.encrypted} {
		view := buffer.bytes(17)
		if len(view) != 17 || cap(view) != 17 {
			t.Fatalf("small writable view = %d/%d", len(view), cap(view))
		}
		view[16] = 0xd4
	}
	clearStreamingSenderScratch(&scratch)
	assertSenderScratchWiped(t, &scratch)
}

// TestSenderScratchBufferShrinksOnlyWhenUnusedAtLargeSinceLastWindow checks
// senderScratchBuffer.shrinkIdle's core contract: a buffer that grew past
// the baseline stays grown as long as bytes() keeps asking for large sizes
// window over window, but releases its backing array the first window it
// doesn't.
func TestSenderScratchBufferShrinksOnlyWhenUnusedAtLargeSinceLastWindow(t *testing.T) {
	var buffer senderScratchBuffer
	buffer.bytes(senderScratchBaselineCapacity + 1)
	if cap(buffer.exposed) <= senderScratchBaselineCapacity {
		t.Fatalf("cap after large use = %d, want > %d", cap(buffer.exposed), senderScratchBaselineCapacity)
	}

	// Still being used at a large size every window: must not shrink.
	for i := 0; i < 3; i++ {
		buffer.shrinkIdle()
		buffer.bytes(senderScratchBaselineCapacity + 1)
	}
	if cap(buffer.exposed) <= senderScratchBaselineCapacity {
		t.Fatalf("cap while still used large = %d, want > %d (should not have shrunk)", cap(buffer.exposed), senderScratchBaselineCapacity)
	}

	// The loop above ends on a bytes() call, so one shrinkIdle just closes
	// out that window (usedAtLarge is still set from it) without shrinking.
	buffer.shrinkIdle()
	if cap(buffer.exposed) <= senderScratchBaselineCapacity {
		t.Fatalf("cap right after the last large use = %d, want > %d (should not have shrunk yet)", cap(buffer.exposed), senderScratchBaselineCapacity)
	}

	// Now a full window has passed with no bytes() call in between: must shrink.
	buffer.shrinkIdle()
	if buffer.exposed != nil {
		t.Fatalf("exposed after idle shrink = %v, want nil", buffer.exposed)
	}

	// Below baseline afterward, growth/shrink churn is not worth avoiding,
	// so small requests keep working against the released backing.
	view := buffer.bytes(17)
	if len(view) != 17 || cap(view) != 17 {
		t.Fatalf("post-shrink small view = %d/%d, want 17/17", len(view), cap(view))
	}
}

// TestPreparedSenderMaintainScratchSkipsCheckedOutSlots checks that
// MaintainScratch only shrinks slots currently sitting free in the pool,
// leaving a slot an in-flight send is holding untouched, and that it puts
// every drained slot back so scratch admission capacity is unchanged.
func TestPreparedSenderMaintainScratchSkipsCheckedOutSlots(t *testing.T) {
	sender := &PreparedRouteSender{scratch: make(chan *streamingSenderScratch, 2), scratchSlots: 2}
	idle := &streamingSenderScratch{}
	idle.data.bytes(senderScratchBaselineCapacity + 1)
	held := &streamingSenderScratch{}
	held.data.bytes(senderScratchBaselineCapacity + 1)
	sender.scratch <- idle

	// The first pass just closes out the window idle.data grew in (bytes()
	// marked it used-at-large); it must not shrink yet.
	sender.MaintainScratch()
	if cap(idle.data.exposed) <= senderScratchBaselineCapacity {
		t.Fatal("idle slot shrunk on the same window it grew in")
	}
	// A full window with no further large use of the now-idle slot: shrink.
	sender.MaintainScratch()

	if len(sender.scratch) != 1 {
		t.Fatalf("scratch admission capacity after maintenance = %d, want 1 (held slot stays checked out)", len(sender.scratch))
	}
	if idle.data.exposed != nil {
		t.Fatal("idle slot's oversized buffer was not shrunk")
	}
	if cap(held.data.exposed) <= senderScratchBaselineCapacity {
		t.Fatal("checked-out slot was shrunk despite never being observed idle")
	}

	sender.scratch <- held
	if len(sender.scratch) != 2 {
		t.Fatal("MaintainScratch dropped a returned slot")
	}
}

func TestPreparedSenderWipesPartiallySerializedLeaseSet(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "ratchet", true: "legacy"}[legacy], func(t *testing.T) {
			sender, route := preparedTestSender(t, func() uint64 { return 1000 }, 1, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error {
				t.Fatal("failed serialization reached writer")
				return nil
			})
			local, err := foundation.GenerateLocalDestination()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(local.ReleaseSensitive)
			sender.ratchet, err = dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(sender.ratchet.ReleaseSensitive)
			route.LocalLeaseSet2 = true
			route.Legacy = legacy
			if legacy {
				route.KeyType = foundation.CryptoElGamal
			}
			if err = sender.InstallRoute(route); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("ID source failed after payload write")
			calls := 0
			sender.nextID = func() (uint32, error) {
				calls++
				if calls == 2 {
					return 0, injected
				}
				return 1, nil
			}
			err = sender.SendTunnel(t.Context(), dataplanestreamingtunnel.Delivery{From: route.Owner, To: route.Remote, Protocol: dataplanedatagram.ProtocolDatagram1, Payload: []byte("secret application payload")})
			if !errors.Is(err, injected) {
				t.Fatalf("send = %v", err)
			}
			for range sender.scratchSlots {
				scratch := <-sender.scratch
				sender.scratch <- scratch
				assertSenderScratchWiped(t, scratch)
			}
		})
	}
}

func TestPreparedSenderWipesCiphertextWhenSessionAdmissionFails(t *testing.T) {
	writes := 0
	sender, route := preparedTestSender(t, func() uint64 { return 1000 }, 1, func(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error { writes++; return nil })
	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.ReleaseSensitive)
	sender.ratchet, err = dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{MaxSessions: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.ratchet.ReleaseSensitive)
	if err = sender.InstallRoute(route); err != nil {
		t.Fatal(err)
	}
	delivery := dataplanestreamingtunnel.Delivery{From: route.Owner, To: route.Remote, Protocol: dataplanedatagram.ProtocolDatagram1, Payload: []byte("secret before pending-session rejection")}
	if err = sender.SendTunnel(t.Context(), delivery); err != nil {
		t.Fatal(err)
	}
	// The second handshake seals its output before pending-session admission fails.
	if err = sender.SendTunnel(t.Context(), delivery); !errors.Is(err, dataplanegarlic.ErrRatchet) {
		t.Fatalf("full session admission = %v", err)
	}
	if writes != 1 {
		t.Fatalf("writer calls = %d, want 1", writes)
	}
	for range sender.scratchSlots {
		scratch := <-sender.scratch
		sender.scratch <- scratch
		assertSenderScratchWiped(t, scratch)
	}
}

func TestPreparedSenderReleaseSensitiveDrainsScratch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sender := &PreparedRouteSender{scratch: make(chan *streamingSenderScratch, 1), scratchSlots: 1}
		scratch := &streamingSenderScratch{}
		view := scratch.data.bytes(1024)
		view[1023] = 1
		done := make(chan struct{})
		go func() { sender.ReleaseSensitive(); close(done) }()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("shutdown abandoned an admitted scratch owner")
		default:
		}
		sender.releaseScratch(scratch)
		<-done
		assertSenderScratchWiped(t, scratch)
		if sender.scratch != nil {
			t.Fatal("shutdown retained admission storage")
		}
	})
}

type scratchTrafficFixture struct {
	sender   *PreparedRouteSender
	route    PreparedRoute
	expected []byte
	decrypt  func([]byte) ([]byte, error)
	sequence byte
}

func newScratchTrafficFixture(t *testing.T) *scratchTrafficFixture {
	t.Helper()
	f := new(scratchTrafficFixture)
	writer := func(_ context.Context, _ dataplanetunnel.CircuitToken, block dataplanetunnel.Block) error {
		decoded, err := f.decrypt(block.Data[foundation.I2NPStandardHeaderLen+4:])
		if err != nil {
			return err
		}
		if !bytes.Contains(decoded, f.expected) {
			return errors.New("decrypted sender payload changed")
		}
		if len(f.sender.scratch) != f.sender.scratchSlots {
			return errors.New("scratch pinned across tunnel write")
		}
		return nil
	}
	f.sender, f.route = preparedTestSender(t, func() uint64 { return 1000 }, 1, writer)
	t.Cleanup(func() {
		if err := f.sender.garlic.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}

func (f *scratchTrafficFixture) send(t *testing.T, protocol uint8, size int) error {
	t.Helper()
	f.sequence++
	f.expected = bytes.Repeat([]byte{0xa0 + f.sequence}, size)
	delivery := dataplanestreamingtunnel.Delivery{From: f.route.Owner, To: f.route.Remote, Protocol: protocol, Payload: f.expected}
	err := f.sender.SendTunnel(t.Context(), delivery)
	for range f.sender.scratchSlots {
		scratch := <-f.sender.scratch
		f.sender.scratch <- scratch
		assertSenderScratchWiped(t, scratch)
	}
	return err
}

func TestPreparedSenderLegacyMixedTrafficUsesBoundedScratch(t *testing.T) {
	f := newScratchTrafficFixture(t)
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
		f.sender.garlic.ConfirmOutboundTags(f.route.Remote, 1000)
	}
}

func newRatchetScratchTraffic(t *testing.T) *scratchTrafficFixture {
	t.Helper()
	f := newScratchTrafficFixture(t)
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
	f.sender.ratchet, err = dataplanegarlic.NewRatchetManager(local, dataplanegarlic.RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.sender.ratchet.ReleaseSensitive)
	f.decrypt = func(packet []byte) ([]byte, error) {
		result, err := receiver.Receive(make([]byte, foundation.I2NPI2PDMaxPayload), make([]byte, 2048), packet, 1000)
		if err != nil {
			return nil, err
		}
		if result.Candidate != nil {
			if _, err := receiver.CommitNew(result.Candidate, result.Peer, 1000); err != nil {
				return nil, err
			}
			if _, err := f.sender.ratchet.Receive(make([]byte, 2048), nil, result.Reply, 1000); err != nil {
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
			var scratch streamingSenderScratch
			buffers := []*senderScratchBuffer{&scratch.data, &scratch.clove, &scratch.ratchet, &scratch.plain, &scratch.encrypted}
			warmSize := workload.size
			if workload.large {
				warmSize = 48 * 1024
			}
			for _, buffer := range buffers {
				buffer.bytes(warmSize)
			}
			clearStreamingSenderScratch(&scratch)
			b.ReportAllocs()
			b.SetBytes(int64(5 * workload.size))
			b.ResetTimer()
			for b.Loop() {
				for _, buffer := range buffers {
					view := buffer.bytes(workload.size)
					view[0], view[len(view)-1] = 1, 2
				}
				clearStreamingSenderScratch(&scratch)
			}
		})
	}
}
