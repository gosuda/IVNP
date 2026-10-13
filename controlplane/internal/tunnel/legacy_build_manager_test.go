package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"errors"
	"testing"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

func TestVariableTransitUnauthenticatedBuildsDoNotExhaustReplayCapacity(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	const maxPending = 2

	privateBytes := [32]byte{1, 2, 3, 4}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes[:])
	if err != nil {
		t.Fatal(err)
	}
	local := sha256.Sum256([]byte("variable-transit-replay"))
	var publicKey [32]byte
	copy(publicKey[:], private.PublicKey().Bytes())

	creatorSender := new(buildCaptureSender)
	creator, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: creatorSender, Now: func() uint64 { return now }}),
		Sender:  creatorSender, ReplyKeys: newBuildReplyRegistry(), LocalRouter: foundation.Hash{7},
		Now: func() uint64 { return now }, Random: new(buildCounterReader), MaxPending: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(creator.ReleaseSensitive)
	for index := range maxPending + 1 {
		_, err := creator.StartVariableOutbound(context.Background(), VariableOutboundBuild{
			CircuitID: uint32(10 + index),
			Hops: []VariableBuildHop{{
				Router: local, Kind: VariableBuildLongECIES, StaticKey: publicKey,
				ReceiveTunnelID: uint32(100 + index),
			}},
			ReplyRouter: foundation.Hash{8}, ReplyTunnelID: uint32(200 + index),
			ExpiresAt: now + legacyBuildLifetimeSeconds*1_000,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	messages := creatorSender.take()
	if len(messages) != maxPending+1 {
		t.Fatalf("created %d Variable builds, want %d", len(messages), maxPending+1)
	}

	transitSender := new(buildCaptureSender)
	transit, err := NewBuildManager(BuildManagerConfig{
		Runtime: dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: transitSender, Now: func() uint64 { return now }}),
		Sender:  transitSender, ReplyKeys: newBuildReplyRegistry(), LocalRouter: local,
		StaticPrivate: privateBytes[:], LocalDelivery: func(foundation.I2NPMessage) error { return nil },
		Now: func() uint64 { return now }, Random: new(buildCounterReader), MaxPending: maxPending,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(transit.ReleaseSensitive)

	original := messages[0].message
	ciphertextOffset := -1
	for slot := range int(original.Payload[0]) {
		offset := 1 + slot*VariableBuildRecordSize
		if bytes.Equal(original.Payload[offset:offset+legacyBuildPeerSize], local[:legacyBuildPeerSize]) {
			ciphertextOffset = offset + longBuildCipherOffset
			break
		}
	}
	if ciphertextOffset < 0 {
		t.Fatal("created Variable build has no local record")
	}

	for index := range defaultMaxPendingBuilds + 1 {
		invalid := original
		invalid.Header.ID = uint32(1_000 + index)
		invalid.Payload = bytes.Clone(original.Payload)
		invalid.Payload[ciphertextOffset] ^= byte(index + 1)
		if err := transit.handleVariableTransit(context.Background(), invalid); !errors.Is(err, ErrLegacyBuildRecord) {
			t.Fatalf("invalid Variable build %d: error = %v, want unauthenticated record error", index, err)
		}
	}
	if len(transit.transit) != 0 || len(transit.transitRecords) != 0 {
		t.Fatalf("invalid Variable builds consumed replay capacity: IDs=%d, records=%d", len(transit.transit), len(transit.transitRecords))
	}

	for index := range maxPending + 1 {
		message := messages[index].message
		message.Payload = bytes.Clone(message.Payload)
		err := transit.handleVariableTransit(context.Background(), message)
		if index < maxPending {
			if err != nil {
				t.Fatalf("authenticated Variable build %d: %v", index, err)
			}
		} else if !errors.Is(err, ErrBuildTransit) {
			t.Fatalf("build above replay capacity: error = %v, want %v", err, ErrBuildTransit)
		}
	}
	if len(transit.transit) != maxPending || len(transit.transitRecords) != maxPending {
		t.Fatalf("replay capacity: IDs=%d, records=%d, want %d", len(transit.transit), len(transit.transitRecords), maxPending)
	}
	if got := len(transitSender.take()); got != maxPending {
		t.Fatalf("forwarded %d authenticated builds, want %d", got, maxPending)
	}

	replay := messages[0].message
	replay.Payload = bytes.Clone(replay.Payload)
	if err := transit.handleVariableTransit(context.Background(), replay); !errors.Is(err, ErrBuildTransit) {
		t.Fatalf("replayed Variable build: error = %v, want %v", err, ErrBuildTransit)
	}
}
