package tunnel

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

type buildCapturedMessage struct {
	peer    foundation.Hash
	message foundation.I2NPMessage
}

type buildCaptureSender struct {
	mu       sync.Mutex
	messages []buildCapturedMessage
}

func (s *buildCaptureSender) Send(_ context.Context, peer foundation.Hash, message foundation.I2NPMessage) error {
	message.Payload = append([]byte(nil), message.Payload...)
	s.mu.Lock()
	s.messages = append(s.messages, buildCapturedMessage{peer: peer, message: message})
	s.mu.Unlock()
	return nil
}

func (s *buildCaptureSender) take() []buildCapturedMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	messages := s.messages
	s.messages = nil
	return messages
}

type buildDiscardSender struct{}

func (buildDiscardSender) Send(context.Context, foundation.Hash, foundation.I2NPMessage) error {
	return nil
}

func buildStatusFrame(t *testing.T, id uint32) []byte {
	t.Helper()
	payload := make([]byte, 12)
	binary.BigEndian.PutUint32(payload[:4], id)
	binary.BigEndian.PutUint64(payload[4:], 1234)
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: id, Expiration: 1_000_000}, Payload: payload}
	frame := make([]byte, message.EncodedLen())
	if _, err := message.MarshalTo(frame); err != nil {
		t.Fatal(err)
	}
	return frame
}

func buildCircuitToken(t *testing.T, runtime dataplane.TunnelCircuitRuntime, id uint32) dataplane.TunnelCircuitToken {
	t.Helper()
	info, exists := runtime.InspectCircuit(id)
	if !exists {
		t.Fatalf("circuit %d is not installed", id)
	}
	return info.Token
}
