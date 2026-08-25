package router

import (
	"context"
	"encoding/binary"

	ivnp "gosuda.org/ivnp"
	"gosuda.org/ivnp/network/tunnel"
	"gosuda.org/ivnp/protocol/garlic/ecies"
	"gosuda.org/ivnp/protocol/i2np"
)

// BuildReplySenderConfig wires the short-build endpoint reply path. Sender
// delivers the TunnelGateway envelope directly to the remote inbound gateway.
// Service handles the interoperable same-router unwrapped case.
type BuildReplySenderConfig struct {
	Sender      tunnel.Sender
	Service     *Service
	LocalRouter ivnp.Hash
	Now         func() uint64
	NextID      MessageIDSource
}

// BuildReplySender is the production tunnel.BuildReplySender. Remote replies
// are one-time ECIES existing-session Garlic frames inside a TunnelGateway
// message sent directly to the requested IBGW. A reply gateway equal to
// LocalRouter injects the unwrapped build reply into the configured local
// TunnelGateway path.
type BuildReplySender struct {
	sender  tunnel.Sender
	service *Service
	local   ivnp.Hash
	now     func() uint64
	nextID  MessageIDSource
}

func NewBuildReplySender(config BuildReplySenderConfig) (*BuildReplySender, error) {
	if config.Sender == nil || config.Service == nil || config.LocalRouter == (ivnp.Hash{}) || config.Now == nil {
		return nil, ErrDataPlaneConfig
	}
	if config.NextID == nil {
		config.NextID = randomMessageID
	}
	return &BuildReplySender{
		sender: config.Sender, service: config.Service, local: config.LocalRouter, now: config.Now, nextID: config.NextID,
	}, nil
}

// SendBuildReply implements tunnel.BuildReplySender. Remote replies go
// directly to the IBGW as TunnelGateway messages; they do not require or use a
// local outbound tunnel.
func (s *BuildReplySender) SendBuildReply(ctx context.Context, gateway ivnp.Hash, gatewayTunnelID uint32, key tunnel.GarlicReplyKey, reply i2np.Message) error {
	if s == nil || s.sender == nil || s.service == nil || s.now == nil || s.nextID == nil || gateway == (ivnp.Hash{}) || gatewayTunnelID == 0 || reply.Header.Type != i2np.OutboundTunnelBuildReply {
		return ErrDataPlaneConfig
	}

	// The outer envelope IDs share the router replay namespace with the reply.
	// Never reuse the reply's ID (or each other) or a valid reply could be
	// dropped as a replay after traversing its inbound gateway.
	count := 1
	if gateway != s.local {
		count++
	}
	ids, err := s.replyEnvelopeIDs(reply.Header.ID, count)
	if err != nil {
		return err
	}
	gatewayID := ids[count-1]

	embedded := reply
	if gateway != s.local {
		payloadLen := 4 + len(reply.Payload) + 8 + 16 + 13
		if payloadLen > i2np.I2PDMaxPayload {
			return ErrGarlicPacket
		}
		payload := make([]byte, payloadLen)
		sealed, err := ecies.SealOneTimeReplyExistingSession(payload[4:], key.Key, key.Tag, reply, nil)
		if err != nil {
			return err
		}
		payload = payload[:4+len(sealed)]
		binary.BigEndian.PutUint32(payload[:4], uint32(len(sealed)))
		embedded = i2np.Message{
			Header:  i2np.Header{Type: i2np.Garlic, ID: ids[0], Expiration: reply.Header.Expiration},
			Payload: payload,
		}
	}
	if embedded.EncodedLen() > i2np.MaxTunnelGatewayEmbedded {
		return ErrGarlicPacket
	}
	frame := make([]byte, embedded.EncodedLen())
	if _, err := embedded.MarshalTo(frame); err != nil {
		return err
	}
	gatewayPayload := make([]byte, i2np.TunnelGatewayHeaderLen+len(frame))
	binary.BigEndian.PutUint32(gatewayPayload[:4], gatewayTunnelID)
	binary.BigEndian.PutUint16(gatewayPayload[4:6], uint16(len(frame)))
	copy(gatewayPayload[6:], frame)
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.TunnelGateway, ID: gatewayID, Expiration: reply.Header.Expiration},
		Payload: gatewayPayload,
	}
	if gateway == s.local {
		// Service routes the parsed gateway to Runtime.HandleGateway (or another
		// configured injector) with the raw outbound build reply.
		return s.service.HandleI2NP(message, s.now(), false)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return s.sender.Send(ctx, gateway, message)
}

func (s *BuildReplySender) replyEnvelopeIDs(replyID uint32, count int) ([2]uint32, error) {
	var ids [2]uint32
	for index := range count {
		for range 16 {
			id, err := s.nextID()
			if err != nil {
				return ids, err
			}
			if id == 0 || id == replyID {
				continue
			}
			duplicate := false
			for previous := range index {
				if ids[previous] == id {
					duplicate = true
					break
				}
			}
			if !duplicate {
				ids[index] = id
				break
			}
		}
		if ids[index] == 0 {
			return ids, ErrDataPlaneConfig
		}
	}
	return ids, nil
}
