package ivnp

import (
	"context"
	"errors"
	"math"
	"net"
	"os"
	"time"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/internal/packet"
)

type packetOperation struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	write  bool
	timer  *time.Timer
}

type packetDeadline uint8

const (
	packetReadDeadline packetDeadline = 1 << iota
	packetWriteDeadline
	packetBothDeadlines = packetReadDeadline | packetWriteDeadline
)

// Timers are changed under the same lock as operation admission. A stale timer
// callback rechecks the current deadline instead of cancelling an extended call.
func (s *packetSocket) armLocked(op *packetOperation) {
	if op.timer != nil {
		op.timer.Stop()
		op.timer = nil
	}
	deadline := s.readDeadline
	if op.write {
		deadline = s.writeDeadline
	}
	if deadline.IsZero() || op.ctx.Err() != nil {
		return
	}
	if !time.Now().Before(deadline) {
		op.cancel(os.ErrDeadlineExceeded)
		return
	}
	op.timer = time.AfterFunc(time.Until(deadline), func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.operations[op]; ok {
			s.armLocked(op)
		}
	})
}
func (s *packetSocket) setDeadline(t time.Time, directions packetDeadline) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.owner.ctx.Err() != nil {
		return net.ErrClosed
	}
	if directions&packetReadDeadline != 0 {
		s.readDeadline = t
	}
	if directions&packetWriteDeadline != 0 {
		s.writeDeadline = t
	}
	for op := range s.operations {
		direction := packetReadDeadline
		if op.write {
			direction = packetWriteDeadline
		}
		if directions&direction != 0 {
			s.armLocked(op)
		}
	}
	return nil
}
func (s *packetSocket) begin(write bool) (*packetOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.owner.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	ctx, cancel := context.WithCancelCause(s.owner.ctx)
	op := &packetOperation{ctx: ctx, cancel: cancel, write: write}
	s.operations[op] = struct{}{}
	s.active.Add(1)
	s.armLocked(op)
	return op, nil
}
func (s *packetSocket) finish(op *packetOperation) {
	s.mu.Lock()
	delete(s.operations, op)
	if op.timer != nil {
		op.timer.Stop()
	}
	s.mu.Unlock()
	op.cancel(context.Canceled)
	s.active.Done()
}
func (s *packetSocket) operationError(op *packetOperation, err error) error {
	if op.ctx.Err() == nil {
		return err
	}
	cause := context.Cause(op.ctx)
	if errors.Is(cause, os.ErrDeadlineExceeded) {
		return os.ErrDeadlineExceeded
	}
	return net.ErrClosed
}
func (s *packetSocket) opError(op string, remote net.Addr, err error) error {
	if err == nil {
		return nil
	}
	return &net.OpError{Op: op, Net: s.network, Source: s.local, Addr: remote, Err: err}
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, source, _, err := c.socket.read(p)
	if err == nil || errors.Is(err, ErrMessageTruncated) {
		addr = source
	}
	return n, addr, err
}
func (c *UnauthPacketConn) ReadPacket(p []byte) (int, UnauthPacket, error) {
	n, _, meta, err := c.socket.read(p)
	return n, meta, err
}
func (s *packetSocket) read(p []byte) (n int, source Addr, meta UnauthPacket, err error) {
	defer func() { err = s.opError("read", nil, err) }()
	op, err := s.begin(false)
	if err != nil {
		return 0, source, meta, err
	}
	defer s.finish(op)
	for {
		if op.ctx.Err() != nil {
			return 0, Addr{}, UnauthPacket{}, s.operationError(op, op.ctx.Err())
		}
		message, receiveErr := s.subscription.Receive(op.ctx)
		if receiveErr != nil {
			return 0, Addr{}, UnauthPacket{}, s.operationError(op, receiveErr)
		}
		if message == nil {
			continue
		}
		payload, from, info, valid := s.decode(message.Delivery)
		if !valid {
			message.Release()
			continue
		}
		if op.ctx.Err() != nil {
			message.Release()
			return 0, Addr{}, UnauthPacket{}, s.operationError(op, op.ctx.Err())
		}
		n = copy(p, payload)
		if n < len(payload) {
			err = ErrMessageTruncated
		}
		message.Release()
		return n, from, info, err
	}
}
func (s *packetSocket) decode(delivery destination.Delivery) ([]byte, Addr, UnauthPacket, bool) {
	var source Addr
	var meta UnauthPacket
	if delivery.Protocol != s.protocol || delivery.ToPort != s.local.Port || len(delivery.Payload) > MaxReceiveDatagramSize {
		return nil, source, meta, false
	}
	if delivery.To != (Hash{}) && delivery.To != s.local.Hash {
		return nil, source, meta, false
	}
	var payload []byte
	switch s.protocol {
	case 17:
		packet, err := dataplane.DatagramParseV1(delivery.Payload)
		if err != nil {
			return nil, source, meta, false
		}
		valid, err := packet.Verify()
		if err != nil || !valid {
			return nil, source, meta, false
		}
		source.Hash = packet.From.Hash()
		payload = packet.Payload
	case 19:
		packet, err := dataplane.DatagramParseV2(delivery.Payload)
		if err != nil {
			return nil, source, meta, false
		}
		now := time.Now().Unix()
		if now < 0 || now > math.MaxUint32 {
			return nil, source, meta, false
		}
		valid, err := packet.VerifyTargetAt(s.local.Hash, uint32(now))
		if err != nil || !valid {
			return nil, source, meta, false
		}
		source.Hash = packet.From.Hash()
		payload = packet.Payload
	case 20:
		packet, err := dataplane.DatagramParseV3(delivery.Payload)
		if err != nil {
			return nil, source, meta, false
		}
		meta = UnauthPacket{ClaimedSource: packet.From, HasClaimedSource: true, FromPort: delivery.FromPort}
		payload = packet.Payload
	case 18:
		meta.FromPort = delivery.FromPort
		payload = delivery.Payload
	default:
		return nil, source, meta, false
	}
	if s.protocol == 17 || s.protocol == 19 {
		if delivery.From != (Hash{}) && delivery.From != source.Hash {
			return nil, Addr{}, UnauthPacket{}, false
		}
		source.Port = delivery.FromPort
	}
	return payload, source, meta, true
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	var target Addr
	switch value := addr.(type) {
	case Addr:
		target = value
	case *Addr:
		if value != nil {
			target = *value
		}
	}
	return c.socket.write(p, target)
}
func (c *UnauthPacketConn) WriteTo(p []byte, target Addr) (int, error) {
	return c.socket.write(p, target)
}
func (s *packetSocket) write(p []byte, target Addr) (n int, err error) {
	defer func() { err = s.opError("write", target, err) }()
	op, err := s.begin(true)
	if err != nil {
		return 0, err
	}
	defer s.finish(op)
	if op.ctx.Err() != nil {
		return 0, s.operationError(op, op.ctx.Err())
	}
	if target.Hash == (Hash{}) || target.Port == 0 {
		return 0, ErrAddressInvalid
	}
	if len(p) > s.maxPayload {
		return 0, ErrMessageTooLarge
	}
	select {
	case s.owner.owner.packetWrites <- struct{}{}:
		defer func() { <-s.owner.owner.packetWrites }()
	default:
		return 0, ErrResourceLimit
	}
	if op.ctx.Err() != nil {
		return 0, s.operationError(op, op.ctx.Err())
	}
	if target.Hash != s.local.Hash {
		preparing, ok := s.owner.endpoint.(destination.PreparingDestinationEndpoint)
		if !ok {
			return 0, ErrUnsupportedIdentity
		}
		if err = preparing.PrepareDestination(op.ctx, target.Hash); err != nil {
			return 0, s.operationError(op, err)
		}
	}
	if op.ctx.Err() != nil {
		return 0, s.operationError(op, op.ctx.Err())
	}
	frameSize := len(p) + MaxSendDatagramSize - s.maxPayload
	storage, ok := packet.Acquire(0, frameSize)
	if !ok {
		return 0, ErrResourceLimit
	}
	defer storage.Release()
	buffer, ok := storage.Append(frameSize)
	if !ok {
		return 0, ErrResourceLimit
	}
	defer clear(buffer)
	var encoded int
	switch s.protocol {
	case 17:
		encoded, err = s.owner.endpoint.MarshalDatagramV1To(buffer[:], p)
	case 19:
		encoded, err = s.owner.endpoint.(destination.ModernDatagramEndpoint).MarshalDatagramV2To(buffer[:], target.Hash, p)
	case 20:
		encoded, err = s.owner.endpoint.(destination.ModernDatagramEndpoint).MarshalDatagramV3To(buffer[:], p)
	case 18:
		encoded = copy(buffer[:], p)
	}
	if err != nil {
		return 0, s.operationError(op, err)
	}
	if encoded < 0 || encoded > len(buffer) {
		return 0, ErrMessageTooLarge
	}
	if op.ctx.Err() != nil {
		return 0, s.operationError(op, op.ctx.Err())
	}
	err = s.owner.endpoint.SendMessage(op.ctx, destination.Delivery{From: s.local.Hash, To: target.Hash, FromPort: s.local.Port, ToPort: target.Port, Protocol: s.protocol, Payload: buffer[:encoded]})
	if err != nil {
		return 0, s.operationError(op, err)
	}
	return len(p), nil
}
