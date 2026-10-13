package tunnel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"testing"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

func TestVariableTransitMalformedBuildsDoNotExhaustReplayCapacity(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	manager, local, public := newVariableTransitReplayTestManager(t, now, defaultMaxPendingBuilds)

	for index := range defaultMaxPendingBuilds + 1 {
		payload := make([]byte, 1+legacyBuildMinRecords*VariableBuildRecordSize)
		payload[0] = legacyBuildMinRecords
		copy(payload[1:1+legacyBuildPeerSize], local[:legacyBuildPeerSize])
		payload[len(payload)-1] = byte(index)
		message := foundation.I2NPMessage{
			Header:  foundation.I2NPHeader{Type: foundation.I2NPVariableTunnelBuild, ID: uint32(index + 1)},
			Payload: payload,
		}
		if err := manager.handleVariableTransit(t.Context(), message); err != ErrLegacyBuildKey {
			t.Fatalf("invalid variable build %d: %v, want %v", index, err, ErrLegacyBuildKey)
		}
	}
	if len(manager.transit) != 0 || len(manager.transitRecords) != 0 {
		t.Fatalf("invalid builds retained replay state: ids=%d records=%d", len(manager.transit), len(manager.transitRecords))
	}

	stale := variableTransitReplayTestMessage(t, local, public, now-120_000, 100, 200)
	if err := manager.handleVariableTransit(t.Context(), stale); err != ErrBuildRejected {
		t.Fatalf("stale authenticated build: %v, want %v", err, ErrBuildRejected)
	}
	if len(manager.transit) != 0 || len(manager.transitRecords) != 0 {
		t.Fatal("invalid authenticated build retained replay state")
	}

	valid := variableTransitReplayTestMessage(t, local, public, now, 101, 201)
	if err := manager.handleVariableTransit(t.Context(), valid); err != nil {
		t.Fatalf("valid variable build denied after malformed builds: %v", err)
	}
	if len(manager.transit) != 1 || len(manager.transitRecords) != 1 {
		t.Fatal("valid variable build did not reserve replay state")
	}
}

func TestVariableTransitAuthenticatedReplayCapacity(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	manager, local, public := newVariableTransitReplayTestManager(t, now, 2)

	first := variableTransitReplayTestMessage(t, local, public, now, 1, 11)
	replay := first
	replay.Payload = bytes.Clone(first.Payload)
	if err := manager.handleVariableTransit(t.Context(), first); err != nil {
		t.Fatalf("first authenticated build: %v", err)
	}
	if err := manager.handleVariableTransit(t.Context(), replay); err != ErrBuildTransit {
		t.Fatalf("duplicate message ID: %v, want %v", err, ErrBuildTransit)
	}
	replay.Header.ID = 2
	if err := manager.handleVariableTransit(t.Context(), replay); err != ErrBuildTransit {
		t.Fatalf("duplicate record hash: %v, want %v", err, ErrBuildTransit)
	}

	second := variableTransitReplayTestMessage(t, local, public, now, 3, 12)
	if err := manager.handleVariableTransit(t.Context(), second); err != nil {
		t.Fatalf("second authenticated build: %v", err)
	}
	third := variableTransitReplayTestMessage(t, local, public, now, 4, 13)
	if err := manager.handleVariableTransit(t.Context(), third); err != ErrBuildTransit {
		t.Fatalf("above-capacity authenticated build: %v, want %v", err, ErrBuildTransit)
	}
	if len(manager.transitRecords) != 2 {
		t.Fatalf("replay records = %d, want 2", len(manager.transitRecords))
	}
}

func newVariableTransitReplayTestManager(t *testing.T, now uint64, maxPending int) (*BuildManager, foundation.Hash, []byte) {
	t.Helper()
	privateBytes := bytes.Repeat([]byte{0x42}, 32)
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	local := sha256.Sum256([]byte("variable-transit-replay-local"))
	sender := buildDiscardSender{}
	manager, err := NewBuildManager(BuildManagerConfig{
		Runtime:       dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }}),
		Sender:        sender,
		ReplyKeys:     newBuildReplyRegistry(),
		LocalRouter:   local,
		StaticPrivate: privateBytes,
		Now:           func() uint64 { return now },
		Random:        new(buildCounterReader),
		MaxPending:    maxPending,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.ReleaseSensitive)
	return manager, local, privateKey.PublicKey().Bytes()
}

func variableTransitReplayTestMessage(t *testing.T, local foundation.Hash, public []byte, requestTime uint64, messageID, receiveID uint32) foundation.I2NPMessage {
	t.Helper()
	request := variableBuildTestRequest(foundation.Hash{9}, receiveID, receiveID+100, messageID+1_000)
	request.RequestMinutes = uint32(requestTime / 60_000)
	var plaintext [LongBuildRequestPlainSize]byte
	if err := MarshalLongECIESBuildRequest(plaintext[:], request); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1+legacyBuildMinRecords*VariableBuildRecordSize)
	payload[0] = legacyBuildMinRecords
	record := payload[1 : 1+VariableBuildRecordSize]
	if _, err := encryptLongECIESBuildRequest(record, local, public, plaintext[:], bytes.NewReader(bytes.Repeat([]byte{0x66}, 32))); err != nil {
		t.Fatal(err)
	}
	return foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPVariableTunnelBuild, ID: messageID},
		Payload: payload,
	}
}
