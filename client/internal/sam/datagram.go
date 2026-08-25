package sam

import "gosuda.org/ivnp/networking"

import (
	"encoding/base32"
	"fmt"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/internal/ingress"

	"io"
	"strings"
)

func (s *Server) handleSend(connection *serverConnection, cmd command) error {
	if !onlyOptions(cmd.values, "ID", "DESTINATION", "SIZE", "FROM_PORT", "TO_PORT", "PROTOCOL") {
		return connection.writeLine(cmd.verb + " STATUS RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_OPTIONS")
	}
	id := cmd.values["ID"]
	session := s.session(id)
	if session == nil {
		return connection.writeLine(cmd.verb + " STATUS RESULT=INVALID_ID")
	}
	if cmd.verb == "DATAGRAM" && session.style != styleDatagram {
		return connection.writeLine("DATAGRAM STATUS RESULT=I2P_ERROR MESSAGE=WRONG_STYLE")
	}
	if cmd.verb == "RAW" && session.style != styleRaw {
		return connection.writeLine("RAW STATUS RESULT=I2P_ERROR MESSAGE=WRONG_STYLE")
	}
	size, err := uintValue(cmd.values, "SIZE", 32, 0)
	_, sizePresent := cmd.values["SIZE"]
	if !sizePresent || err != nil || size > uint64(s.config.MaxDatagramBytes) {
		return connection.writeLine(cmd.verb + " STATUS RESULT=I2P_ERROR MESSAGE=INVALID_SIZE")
	}
	body := make([]byte, int(size))
	if _, err = io.ReadFull(connection.reader, body); err != nil {
		clear(body)
		return err
	}
	defer clear(body)
	target := cmd.values["DESTINATION"]
	resolved, err := s.resolveTarget(session.ctx, target)
	if err != nil {
		return connection.writeLine(cmd.verb + " STATUS RESULT=CANT_REACH_PEER")
	}
	hash, err := destinationHash(resolved)
	if err != nil {
		return connection.writeLine(cmd.verb + " STATUS RESULT=INVALID_KEY")
	}
	fromPort, err1 := uintValue(cmd.values, "FROM_PORT", 16, uint64(session.fromPort))
	toPort, err2 := uintValue(cmd.values, "TO_PORT", 16, uint64(session.toPort))
	if err1 != nil || err2 != nil {
		return connection.writeLine(cmd.verb + " STATUS RESULT=I2P_ERROR MESSAGE=INVALID_PORT")
	}
	protocol := session.protocol
	payload := body
	var framed []byte
	if cmd.verb == "DATAGRAM" {
		framed = make([]byte, s.config.MaxDatagramBytes)
		n, marshalErr := session.endpoint.MarshalDatagramV1To(framed, body)
		if marshalErr != nil {
			clear(framed)
			return connection.writeLine("DATAGRAM STATUS RESULT=I2P_ERROR")
		}
		payload = framed[:n]
		protocol = networking.DatagramProtocolDatagram1
	}
	if cmd.verb == "RAW" {
		if _, ok := cmd.values["PROTOCOL"]; ok {
			parsed, parseErr := uintValue(cmd.values, "PROTOCOL", 8, uint64(protocol))
			if parseErr != nil || reservedRawProtocol(uint8(parsed)) {
				return connection.writeLine("RAW STATUS RESULT=I2P_ERROR MESSAGE=INVALID_PROTOCOL")
			}
			protocol = uint8(parsed)
		}
	}
	err = session.endpoint.SendMessage(session.ctx, networking.StreamingTunnelDelivery{From: session.endpoint.Hash(), To: hash, FromPort: uint16(fromPort), ToPort: uint16(toPort), Protocol: protocol, Payload: payload})
	if framed != nil {
		clear(framed)
	}
	if err != nil {
		return connection.writeLine(cmd.verb + " STATUS RESULT=CANT_REACH_PEER")
	}
	return connection.writeLine(cmd.verb + " STATUS RESULT=OK")
}

func (s *samSession) receiveLoop(subscription destination.MessageSubscription) {
	defer func() {
		if value := recover(); value != nil {
			_ = ingress.Report(value, s.server.config.PanicReporter, ingress.BoundarySAMWorker, s.control.RemoteAddr())
		}
	}()
	defer subscription.Close()
	for {
		message, err := subscription.Receive(s.ctx)
		if err != nil {
			return
		}
		func() {
			defer func() {
				if value := recover(); value != nil {
					_ = ingress.Report(value, s.server.config.PanicReporter, ingress.BoundarySAMWorker, s.control.RemoteAddr())
				}
			}()
			defer message.Release()
			delivery := message.Delivery
			switch s.style {
			case styleDatagram:
				packet, parseErr := networking.DatagramParsePacket(networking.DatagramProtocolDatagram1, delivery.Payload)
				if parseErr != nil {
					return
				}
				valid, verifyErr := packet.V1.Verify()
				if verifyErr != nil || !valid || packet.V1.From.Hash() != delivery.From {
					return
				}
				source := foundation.EncodeI2PBase64(packet.V1.From.Bytes())
				if s.udpTarget != nil {
					header := fmt.Sprintf("%s\nFROM_PORT=%d\nTO_PORT=%d\n\n", source, delivery.FromPort, delivery.ToPort)
					wire := make([]byte, len(header)+len(packet.V1.Payload))
					copy(wire, header)
					copy(wire[len(header):], packet.V1.Payload)
					_, _ = s.server.udp.WriteTo(wire, s.udpTarget)
					clear(wire)
					return
				}
				header := fmt.Sprintf("DATAGRAM RECEIVED DESTINATION=%s FROM_PORT=%d TO_PORT=%d SIZE=%d", source, delivery.FromPort, delivery.ToPort, len(packet.V1.Payload))
				_ = s.control.writeFrame(header, packet.V1.Payload)
			case styleRaw:
				if s.udpTarget != nil {
					payload := delivery.Payload
					var wire []byte
					if s.rawHeader {
						header := fmt.Sprintf("FROM_PORT=%d\nTO_PORT=%d\nPROTOCOL=%d\n\n", delivery.FromPort, delivery.ToPort, delivery.Protocol)
						wire = make([]byte, len(header)+len(payload))
						copy(wire, header)
						copy(wire[len(header):], payload)
						payload = wire
					}
					_, _ = s.server.udp.WriteTo(payload, s.udpTarget)
					clear(wire)
					return
				}
				header := fmt.Sprintf("RAW RECEIVED PROTOCOL=%d FROM_PORT=%d TO_PORT=%d SIZE=%d", delivery.Protocol, delivery.FromPort, delivery.ToPort, len(delivery.Payload))
				_ = s.control.writeFrame(header, delivery.Payload)
			}
		}()
	}
}

func destinationHash(value string) (foundation.Hash, error) {
	if identity, err := foundation.ParseDestination([]byte(value)); err == nil {
		return identity.Hash(), nil
	}
	var hash foundation.Hash
	lower := strings.ToLower(value)
	if !strings.HasSuffix(lower, ".b32.i2p") {
		return hash, ErrProtocol
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSuffix(lower, ".b32.i2p")))
	if err != nil || len(decoded) != len(hash) {
		return hash, ErrProtocol
	}
	copy(hash[:], decoded)
	return hash, nil
}
