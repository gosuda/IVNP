package tunnel

import (
	"context"
	"crypto/ecdh"
	"errors"
	"testing"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
)

var errRotationSource = errors.New("rotation source failed")
var errRotationSend = errors.New("rotation send failed")

type rotationSource struct {
	builds []OutboundBuild
	err    error
	calls  int
	times  []uint64
}

func (s *rotationSource) NextOutbound(ctx context.Context, now uint64) (OutboundBuild, error) {
	if err := ctx.Err(); err != nil {
		return OutboundBuild{}, err
	}
	s.calls++
	s.times = append(s.times, now)
	if s.err != nil {
		return OutboundBuild{}, s.err
	}
	if len(s.builds) == 0 {
		return OutboundBuild{}, errRotationSource
	}
	build := s.builds[0]
	s.builds = s.builds[1:]
	return build, nil
}

type rotationFailingSender struct {
	err   error
	calls int
}

func (s *rotationFailingSender) Send(context.Context, foundation.Hash, i2np.Message) error {
	s.calls++
	return s.err
}

func rotationBuild(t *testing.T, id uint32, expires uint64) OutboundBuild {
	t.Helper()
	privateBytes := make([]byte, 32)
	privateBytes[0] = byte(id)
	privateBytes[31] = 1
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var static [32]byte
	copy(static[:], private.PublicKey().Bytes())
	return OutboundBuild{
		CircuitID: id,
		Hops: []ShortBuildHop{{
			Router:          foundation.Hash{byte(id), 1},
			StaticKey:       static,
			ReceiveTunnelID: id + 100,
		}},
		ReplyRouter:   foundation.Hash{byte(id), 2},
		ReplyTunnelID: id + 200,
		ExpiresAt:     expires,
	}
}

func TestRotatorFillsTargetWithoutBackgroundWork(t *testing.T) {
	now := uint64(1_700_000_000_000)
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	pool := NewPool(4)
	builder, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: sender, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	source := &rotationSource{builds: []OutboundBuild{
		rotationBuild(t, 1, now+10_000),
		rotationBuild(t, 2, now+10_000),
	}}
	rotator, err := NewRotator(RotatorConfig{Pool: pool, Runtime: runtime, Builder: builder, Source: source, Now: func() uint64 { return now }, Target: 2})
	if err != nil {
		t.Fatal(err)
	}
	started, err := rotator.Maintain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if started != 2 || source.calls != 2 || builder.Pending() != 2 {
		t.Fatalf("started=%d source calls=%d pending=%d", started, source.calls, builder.Pending())
	}
	if sent := sender.take(); len(sent) != 2 {
		t.Fatalf("build messages=%d, want 2", len(sent))
	}
	for _, sourceNow := range source.times {
		if sourceNow != now {
			t.Fatalf("source time=%d, want %d", sourceNow, now)
		}
	}
}

func TestRotatorReplacesTunnelInsideRenewalWindow(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	pool := NewPool(4)
	if err := pool.Add(Entry{ID: 10, Direction: Outbound, Expires: now + 101}, now); err != nil {
		t.Fatal(err)
	}
	if err := pool.Add(Entry{ID: 11, Direction: Outbound, Expires: now + 100}, now); err != nil {
		t.Fatal(err)
	}
	builder, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: sender, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	source := &rotationSource{builds: []OutboundBuild{rotationBuild(t, 1, now+10_000)}}
	rotator, err := NewRotator(RotatorConfig{Pool: pool, Runtime: runtime, Builder: builder, Source: source, Now: func() uint64 { return now }, Target: 2, RenewBefore: 100})
	if err != nil {
		t.Fatal(err)
	}
	started, err := rotator.Maintain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if started != 1 || source.calls != 1 || builder.Pending() != 1 {
		t.Fatalf("started=%d source calls=%d pending=%d", started, source.calls, builder.Pending())
	}
}

func TestRotatorRenewsAtPoolCapacityWithoutEvictingHealthyTunnel(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	pool := NewPool(1)
	old := Entry{ID: 10, Direction: Outbound, Expires: now + 100}
	if err := pool.Add(old, now); err != nil {
		t.Fatal(err)
	}
	if err := runtime.RegisterOutbound(OutboundCircuit{ID: old.ID, NextTunnelID: 11, ExpiresAt: old.Expires}); err != nil {
		t.Fatal(err)
	}
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: sender, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	build := rotationBuild(t, 1, now+10_000)
	source := &rotationSource{builds: []OutboundBuild{build}}
	rotator, err := NewRotator(RotatorConfig{Pool: pool, Runtime: runtime, Builder: manager, Source: source, Now: func() uint64 { return now }, Target: 1, RenewBefore: 100})
	if err != nil {
		t.Fatal(err)
	}
	started, err := rotator.Maintain(context.Background())
	if err != nil || started != 1 {
		t.Fatalf("maintain started=%d err=%v", started, err)
	}
	var pending *pendingOutboundBuild
	for _, candidate := range manager.pending {
		pending = candidate
	}
	if pending == nil || pending.build.retireID != old.ID {
		t.Fatalf("pending retirement = %#v", pending)
	}
	payload := make([]byte, 1+int(pending.recordCount)*ShortBuildRecordSize)
	payload[0] = pending.recordCount
	for index, key := range pending.keys {
		offset := 1 + int(pending.positions[index])*ShortBuildRecordSize
		if _, err = SealShortBuildReply(payload[offset:], make([]byte, ShortBuildReplyPlainSize), key, pending.positions[index]); err != nil {
			t.Fatal(err)
		}
	}
	if err = manager.HandleReply(i2np.Message{
		Header:  i2np.Header{Type: i2np.OutboundTunnelBuildReply, ID: pending.replyID},
		Payload: payload,
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := pool.Get(old.ID, now); ok {
		t.Fatal("retired tunnel retained in pool")
	}
	if entry, ok := pool.Get(build.CircuitID, now); !ok || entry.ID != build.CircuitID {
		t.Fatalf("replacement entry = %#v, %t", entry, ok)
	}
	if err = runtime.SendBlock(context.Background(), old.ID, Block{Delivery: DeliveryLocal, Last: true, Data: []byte{1}}); err != ErrCircuitNotFound {
		t.Fatalf("retired runtime circuit error = %v, want %v", err, ErrCircuitNotFound)
	}
}

func TestRotatorCountsPendingBuildsTowardTarget(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	pool := NewPool(4)
	builder, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: sender, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	source := &rotationSource{builds: []OutboundBuild{
		rotationBuild(t, 1, now+10_000),
		rotationBuild(t, 2, now+10_000),
	}}
	rotator, err := NewRotator(RotatorConfig{Pool: pool, Runtime: runtime, Builder: builder, Source: source, Now: func() uint64 { return now }, Target: 2})
	if err != nil {
		t.Fatal(err)
	}
	if started, err := rotator.Maintain(context.Background()); err != nil || started != 2 {
		t.Fatalf("first maintain started=%d err=%v", started, err)
	}
	if started, err := rotator.Maintain(context.Background()); err != nil || started != 0 {
		t.Fatalf("second maintain started=%d err=%v", started, err)
	}
	if source.calls != 2 || builder.Pending() != 2 {
		t.Fatalf("source calls=%d pending=%d", source.calls, builder.Pending())
	}
}

func TestRotatorExpiresPoolRuntimeAndPendingState(t *testing.T) {
	now := uint64(100)
	sender := new(captureTunnelSender)
	runtime := NewRuntime(RuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	pool := NewPool(2)
	if err := pool.Add(Entry{ID: 1, Direction: Outbound, Expires: now + 1}, now); err != nil {
		t.Fatal(err)
	}
	if err := runtime.RegisterOutbound(OutboundCircuit{ID: 1, NextTunnelID: 2, ExpiresAt: now + 1}); err != nil {
		t.Fatal(err)
	}
	builder, err := NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: sender, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = builder.StartOutbound(context.Background(), rotationBuild(t, 3, now+1)); err != nil {
		t.Fatal(err)
	}
	now++
	source := &rotationSource{err: errRotationSource}
	rotator, err := NewRotator(RotatorConfig{Pool: pool, Runtime: runtime, Builder: builder, Source: source, Now: func() uint64 { return now }, Target: 1})
	if err != nil {
		t.Fatal(err)
	}
	if started, err := rotator.Maintain(context.Background()); err != errRotationSource || started != 0 {
		t.Fatalf("maintain started=%d err=%v", started, err)
	}
	if pool.Count(Outbound, now) != 0 || builder.Pending() != 0 {
		t.Fatalf("expired state retained pool=%d pending=%d", pool.Count(Outbound, now), builder.Pending())
	}
	if err = runtime.SendBlock(context.Background(), 1, Block{Delivery: DeliveryLocal, Last: true, Data: []byte{1}}); err != ErrCircuitNotFound {
		t.Fatalf("expired runtime circuit error=%v, want %v", err, ErrCircuitNotFound)
	}
}

func TestRotatorReturnsSourceAndBuildFailuresWithoutRetainingPending(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	pool := NewPool(2)
	runtime := NewRuntime(RuntimeConfig{Now: func() uint64 { return now }})
	source := &rotationSource{err: errRotationSource}
	builder, err := NewBuildManager(BuildManagerConfig{Runtime: runtime, Pool: pool, Sender: discardTunnelSender{}, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	rotator, err := NewRotator(RotatorConfig{Pool: pool, Runtime: runtime, Builder: builder, Source: source, Now: func() uint64 { return now }, Target: 1})
	if err != nil {
		t.Fatal(err)
	}
	if started, err := rotator.Maintain(context.Background()); err != errRotationSource || started != 0 {
		t.Fatalf("source failure started=%d err=%v", started, err)
	}
	if source.calls != 1 || builder.Pending() != 0 {
		t.Fatalf("source failure calls=%d pending=%d", source.calls, builder.Pending())
	}

	failedSender := &rotationFailingSender{err: errRotationSend}
	builder, err = NewBuildManager(BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: failedSender, ReplyKeys: newBuildReplyRegistry(), Now: func() uint64 { return now }, Random: new(buildCounterReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	source = &rotationSource{builds: []OutboundBuild{rotationBuild(t, 1, now+10_000)}}
	rotator, err = NewRotator(RotatorConfig{Pool: pool, Runtime: runtime, Builder: builder, Source: source, Now: func() uint64 { return now }, Target: 1})
	if err != nil {
		t.Fatal(err)
	}
	if started, err := rotator.Maintain(context.Background()); err != errRotationSend || started != 0 {
		t.Fatalf("build failure started=%d err=%v", started, err)
	}
	if source.calls != 1 || failedSender.calls != 1 || builder.Pending() != 0 {
		t.Fatalf("build failure source calls=%d sends=%d pending=%d", source.calls, failedSender.calls, builder.Pending())
	}
}
