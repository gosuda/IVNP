package router

import (
	"context"
	"encoding/binary"
	"log/slog"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

// BuildReplySenderConfig wires the short-build endpoint reply path. Sender
// delivers the TunnelGateway envelope directly to the remote inbound gateway.
// Service handles the interoperable same-router unwrapped case.
type BuildReplySenderConfig struct {
	Sender      dataplane.TunnelSender
	Service     *dataplane.RouterService
	LocalRouter foundation.Hash
	Now         func() uint64
	NextID      dataplane.RouterMessageIDSource
	Logger      *slog.Logger
}

// BuildReplySender is the production tunnel.BuildReplySender. Remote replies
// are one-time ECIES existing-session Garlic frames inside a TunnelGateway
// message sent directly to the requested IBGW. A reply gateway equal to
// LocalRouter injects the unwrapped build reply into the configured local
// TunnelGateway path.
type BuildReplySender struct {
	sender  dataplane.TunnelSender
	service *dataplane.RouterService
	local   foundation.Hash
	now     func() uint64
	nextID  dataplane.RouterMessageIDSource
	logger  *slog.Logger
}

func NewBuildReplySender(config BuildReplySenderConfig) (*BuildReplySender, error) {
	if config.Sender == nil || config.Service == nil || config.LocalRouter == (foundation.Hash{}) || config.Now == nil {
		return nil, dataplane.RouterErrDataPlaneConfig
	}
	if config.NextID == nil {
		config.NextID = dataplane.RouterRandomMessageID
	}
	return &BuildReplySender{
		sender: config.Sender, service: config.Service, local: config.LocalRouter, now: config.Now, nextID: config.NextID, logger: config.Logger,
	}, nil
}

// SendBuildReply implements tunnel.BuildReplySender. Remote replies go
// directly to the IBGW as TunnelGateway messages; they do not require or use a
// local outbound tunnel.
func (s *BuildReplySender) SendBuildReply(ctx context.Context, gateway foundation.Hash, gatewayTunnelID uint32, key dataplane.GarlicReplyKey, reply foundation.I2NPMessage) error {
	sendBuildReplyRejected := s == nil || s.sender == nil || s.service == nil || s.now == nil || s.nextID == nil || gateway == (foundation.Hash{}) || gatewayTunnelID == 0
	if !sendBuildReplyRejected {
		sendBuildReplyRejected = reply.Header.Type != foundation.I2NPOutboundTunnelBuildReply
	}
	if sendBuildReplyRejected { // The outer envelope IDs share the router replay namespace with the reply.
		// Never reuse the reply's ID (or each other) or a valid reply could be
		// dropped as a replay after traversing its inbound gateway.

		return dataplane.RouterErrDataPlaneConfig
	}

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
		if payloadLen > foundation.I2NPI2PDMaxPayload {
			return dataplane.RouterErrGarlicPacket
		}
		payload := make([]byte, payloadLen)
		sealed, err := dataplane.GarlicECIESSealOneTimeReplyExistingSession(payload[4:], key.Key, key.Tag, reply, nil)
		if err != nil {
			return err
		}
		payload = payload[:4+len(sealed)]
		binary.BigEndian.PutUint32(payload[:4], uint32(len(sealed)))
		embedded = foundation.I2NPMessage{
			Header:  foundation.I2NPHeader{Type: foundation.I2NPGarlic, ID: ids[0], Expiration: reply.Header.Expiration},
			Payload: payload,
		}
	}
	if embedded.EncodedLen() > foundation.I2NPMaxTunnelGatewayEmbedded {
		return dataplane.RouterErrGarlicPacket
	}
	frame := make([]byte, embedded.EncodedLen())
	if _, err := embedded.MarshalTo(frame); err != nil {
		return err
	}
	gatewayPayload := make([]byte, foundation.I2NPTunnelGatewayHeaderLen+len(frame))
	binary.BigEndian.PutUint32(gatewayPayload[:4], gatewayTunnelID)
	binary.BigEndian.PutUint16(gatewayPayload[4:6], uint16(len(frame)))
	copy(gatewayPayload[6:], frame)
	message := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPTunnelGateway, ID: gatewayID, Expiration: reply.Header.Expiration},
		Payload: gatewayPayload,
	}
	if s.logger != nil {
		s.logger.Info("tunnel build reply stage", "stage", "obep_wrapped", "reply_id", reply.Header.ID, "reply_router", foundation.EncodeI2PBase64(gateway[:]), "reply_tunnel_id", gatewayTunnelID, "garlic", gateway != s.local)
	}
	var sendErr error
	if gateway == s.local {
		// Service routes the parsed gateway to Runtime.HandleGateway (or another
		// configured injector) with the raw outbound build reply.
		sendErr = s.service.HandleI2NP(message, s.now(), false)
	} else {
		if ctx == nil {
			ctx = context.Background()
		}
		sendErr = s.sender.Send(ctx, gateway, message)
	}
	if s.logger != nil {
		if sendErr != nil {
			s.logger.Warn("tunnel build reply stage", "stage", "obep_send_failed", "reply_id", reply.Header.ID, "reply_router", foundation.EncodeI2PBase64(gateway[:]), "reply_tunnel_id", gatewayTunnelID, "garlic", gateway != s.local, "error", sendErr)
		} else {
			s.logger.Info("tunnel build reply stage", "stage", "obep_sent", "reply_id", reply.Header.ID, "reply_router", foundation.EncodeI2PBase64(gateway[:]), "reply_tunnel_id", gatewayTunnelID, "garlic", gateway != s.local)
		}
	}
	return sendErr
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
			return ids, dataplane.RouterErrDataPlaneConfig
		}
	}
	return ids, nil
}
