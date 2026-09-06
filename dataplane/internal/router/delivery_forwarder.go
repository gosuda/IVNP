package router

import (
	"context"
	"encoding/binary"

	"gosuda.org/ivnp/dataplane/internal/tunnel"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/packet"
)

type DeliveryForwarderConfig struct {
	Local   foundation.Hash
	Sender  tunnel.Sender
	Tunnels *tunnel.Runtime
	NextID  func() uint32
}

type DeliveryForwarder struct{ config DeliveryForwarderConfig }

func NewDeliveryForwarder(config DeliveryForwarderConfig) (*DeliveryForwarder, error) {
	if config.Local == (foundation.Hash{}) || config.Sender == nil || config.NextID == nil {
		return nil, ErrDataPlaneConfig
	}
	return &DeliveryForwarder{config: config}, nil
}

func (f *DeliveryForwarder) ForwardRouter(target foundation.Hash, message foundation.I2NPMessage) error {
	if target == (foundation.Hash{}) || target == f.config.Local {
		return ErrDataPlaneConfig
	}
	return f.config.Sender.Send(context.Background(), target, message)
}

func (f *DeliveryForwarder) ForwardTunnel(target foundation.Hash, tunnelID uint32, message foundation.I2NPMessage) error {
	if target == (foundation.Hash{}) || tunnelID == 0 {
		return ErrDataPlaneConfig
	}
	if target == f.config.Local {
		if f.config.Tunnels == nil {
			return ErrDataPlaneConfig
		}
		return f.config.Tunnels.HandleGateway(tunnelID, message)
	}
	length := message.EncodedLen()
	if length > foundation.I2NPMaxTunnelGatewayEmbedded {
		return foundation.I2NPErrPayloadTooLarge
	}
	buffer, ok := packet.Acquire(foundation.I2NPTunnelGatewayHeaderLen, length)
	if !ok {
		return foundation.I2NPErrPayloadTooLarge
	}
	defer buffer.Release()
	frame, ok := buffer.Append(length)
	if !ok {
		return foundation.I2NPErrPayloadTooLarge
	}
	if _, err := message.MarshalTo(frame); err != nil {
		return err
	}
	header, ok := buffer.Push(foundation.I2NPTunnelGatewayHeaderLen)
	if !ok {
		return foundation.I2NPErrPayloadTooLarge
	}
	binary.BigEndian.PutUint32(header[:4], tunnelID)
	binary.BigEndian.PutUint16(header[4:6], uint16(length))
	payload, ok := buffer.Bytes()
	if !ok {
		return foundation.I2NPErrPayloadTooLarge
	}
	gateway := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPTunnelGateway, ID: f.config.NextID(), Expiration: message.Header.Expiration},
		Payload: payload,
	}
	return f.config.Sender.Send(context.Background(), target, gateway)
}
