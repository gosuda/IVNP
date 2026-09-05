package sam

import (
	"encoding/base32"
	"io"
	"strconv"
	"strings"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/internal/ingress"
	"gosuda.org/ivnp/internal/pool"
	"gosuda.org/ivnp/networking"
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
	if cmd.verb == "DATAGRAM" && !isDatagramStyle(session.style) {
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
	bodyLease, ok := pool.AcquireLease(int(size))
	if !ok {
		return connection.writeLine(cmd.verb + " STATUS RESULT=I2P_ERROR MESSAGE=INVALID_SIZE")
	}
	body, _ := bodyLease.Bytes(int(size))
	if _, err = io.ReadFull(connection.reader, body); err != nil {
		bodyLease.ReleaseSensitive()
		return err
	}
	defer bodyLease.ReleaseSensitive()
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
	var framedLease *pool.Lease
	if cmd.verb == "DATAGRAM" {
		framed, lease, frameOK := session.datagramFrame(len(body))
		if !frameOK {
			return connection.writeLine("DATAGRAM STATUS RESULT=I2P_ERROR")
		}
		framedLease = lease
		defer framedLease.ReleaseSensitive()
		n, marshalErr := marshalSessionDatagram(session, framed, hash, body)
		if marshalErr != nil || n != len(framed) {
			return connection.writeLine("DATAGRAM STATUS RESULT=I2P_ERROR")
		}
		payload = framed
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
		s.forwardReceivedMessage(message)
	}
}

func (s *samSession) forwardReceivedMessage(message *destination.ReceivedMessage) {
	defer func() {
		if value := recover(); value != nil {
			_ = ingress.Report(value, s.server.config.PanicReporter, ingress.BoundarySAMWorker, s.control.RemoteAddr())
		}
	}()
	defer message.Release()
	switch {
	case isDatagramStyle(s.style):
		s.forwardDatagram(message.Delivery)
	case s.style == styleRaw:
		s.forwardRaw(message.Delivery)
	}
}

func marshalSessionDatagram(session *samSession, dst []byte, target foundation.Hash, payload []byte) (int, error) {
	switch session.protocol {
	case networking.DatagramProtocolDatagram1:
		return session.endpoint.MarshalDatagramV1To(dst, payload)
	case networking.DatagramProtocolDatagram2:
		modern, ok := session.endpoint.(destination.ModernDatagramEndpoint)
		if !ok {
			return 0, ErrUnsupported
		}
		return modern.MarshalDatagramV2To(dst, target, payload)
	case networking.DatagramProtocolDatagram3:
		modern, ok := session.endpoint.(destination.ModernDatagramEndpoint)
		if !ok {
			return 0, ErrUnsupported
		}
		return modern.MarshalDatagramV3To(dst, payload)
	}
	return 0, ErrProtocol
}

func (s *samSession) forwardDatagram(delivery networking.StreamingTunnelDelivery) {
	source, payload, ok := s.parseReceivedDatagram(delivery)
	if !ok {
		return
	}
	if s.udpTarget != nil {
		wire, lease, ok := datagramUDPWire(source, delivery.FromPort, delivery.ToPort, payload)
		if !ok {
			return
		}
		defer lease.ReleaseSensitive()
		_, _ = s.server.udp.WriteTo(wire, s.udpTarget)
		return
	}
	header, lease, ok := datagramReceivedHeader(source, delivery.FromPort, delivery.ToPort, len(payload))
	if !ok {
		return
	}
	defer lease.Release()
	_ = s.control.writeFrame(header, payload)
}

func (s *samSession) parseReceivedDatagram(delivery networking.StreamingTunnelDelivery) (string, []byte, bool) {
	packet, err := networking.DatagramParsePacket(s.protocol, delivery.Payload)
	if err != nil {
		return "", nil, false
	}
	switch s.protocol {
	case networking.DatagramProtocolDatagram1:
		valid, err := packet.V1.Verify()
		if err != nil || !valid || packet.V1.From.Hash() != delivery.From {
			return "", nil, false
		}
		return foundation.EncodeI2PBase64(packet.V1.From.Bytes()), packet.V1.Payload, true
	case networking.DatagramProtocolDatagram2:
		valid, err := packet.V2.VerifyTarget(s.endpoint.Hash())
		if err != nil || !valid || packet.V2.From.Hash() != delivery.From {
			return "", nil, false
		}
		return foundation.EncodeI2PBase64(packet.V2.From.Bytes()), packet.V2.Payload, true
	case networking.DatagramProtocolDatagram3:
		// Datagram3 is unauthenticated by spec: no signature to verify and the
		// source is a bare 32-byte hash, not a full destination.
		return foundation.EncodeI2PBase64(packet.V3.From[:]), packet.V3.Payload, true
	}
	return "", nil, false
}

func (s *samSession) forwardRaw(delivery networking.StreamingTunnelDelivery) {
	if s.udpTarget == nil {
		header, lease, ok := rawReceivedHeader(delivery.Protocol, delivery.FromPort, delivery.ToPort, len(delivery.Payload))
		if !ok {
			return
		}
		defer lease.Release()
		_ = s.control.writeFrame(header, delivery.Payload)
		return
	}
	if !s.rawHeader {
		_, _ = s.server.udp.WriteTo(delivery.Payload, s.udpTarget)
		return
	}
	wire, lease, ok := rawUDPWire(delivery.FromPort, delivery.ToPort, delivery.Protocol, delivery.Payload)
	if !ok {
		return
	}
	defer lease.ReleaseSensitive()
	_, _ = s.server.udp.WriteTo(wire, s.udpTarget)
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

func datagramOverhead(protocol uint8, endpoint destination.DestinationEndpoint, offline *foundation.OfflineSignature) int {
	if endpoint == nil {
		return 0
	}
	if protocol == networking.DatagramProtocolDatagram3 {
		return 34
	}
	if protocol != networking.DatagramProtocolDatagram1 && protocol != networking.DatagramProtocolDatagram2 {
		return 0
	}
	identity, err := foundation.ParseDestination(endpoint.Destination())
	if err != nil {
		return 0
	}
	signatureLen, ok := identity.SigningKeyType().SignatureLen()
	if !ok {
		return 0
	}
	overhead := identity.EncodedLen() + signatureLen
	if protocol == networking.DatagramProtocolDatagram2 {
		// Flags word; options section is absent.
		overhead += 2
		if offline != nil {
			transientLen, ok := offline.Type.SignatureLen()
			if !ok {
				return 0
			}
			// Expires, transient key type, transient public key, and the
			// authorization signature; the payload signature uses the
			// transient key.
			overhead += 6 + len(offline.PublicKey) + transientLen
		}
	}
	return overhead
}

func (s *samSession) datagramFrame(payloadLen int) ([]byte, *pool.Lease, bool) {
	if s == nil || s.server == nil || payloadLen < 0 {
		return nil, nil, false
	}
	overhead := s.datagramOverhead
	if overhead == 0 || payloadLen > s.server.config.MaxDatagramBytes-overhead {
		return nil, nil, false
	}
	size := overhead + payloadLen
	lease, ok := pool.AcquireLease(size)
	if !ok {
		return nil, nil, false
	}
	frame, ok := lease.Bytes(size)
	if !ok {
		lease.Release()
		return nil, nil, false
	}
	return frame, lease, true
}

func decimalLen(value uint64) int {
	length := 1
	for value >= 10 {
		value /= 10
		length++
	}
	return length
}

func appendDecimal(dst []byte, offset int, value uint64) int {
	return len(strconv.AppendUint(dst[:offset], value, 10))
}

func datagramUDPWire(source string, fromPort, toPort uint16, payload []byte) ([]byte, *pool.Lease, bool) {
	const fixed = "\nFROM_PORT=\nTO_PORT=\n\n"
	headerLen := len(source) + len(fixed) + decimalLen(uint64(fromPort)) + decimalLen(uint64(toPort))
	lease, ok := pool.AcquireLease(headerLen + len(payload))
	if !ok {
		return nil, nil, false
	}
	wire, _ := lease.Bytes(headerLen + len(payload))
	offset := copy(wire, source)
	offset += copy(wire[offset:], "\nFROM_PORT=")
	offset = appendDecimal(wire, offset, uint64(fromPort))
	offset += copy(wire[offset:], "\nTO_PORT=")
	offset = appendDecimal(wire, offset, uint64(toPort))
	offset += copy(wire[offset:], "\n\n")
	copy(wire[offset:], payload)
	return wire, lease, true
}

func rawUDPWire(fromPort, toPort uint16, protocol uint8, payload []byte) ([]byte, *pool.Lease, bool) {
	const fixed = "FROM_PORT=\nTO_PORT=\nPROTOCOL=\n\n"
	headerLen := len(fixed) + decimalLen(uint64(fromPort)) + decimalLen(uint64(toPort)) + decimalLen(uint64(protocol))
	lease, ok := pool.AcquireLease(headerLen + len(payload))
	if !ok {
		return nil, nil, false
	}
	wire, _ := lease.Bytes(headerLen + len(payload))
	offset := copy(wire, "FROM_PORT=")
	offset = appendDecimal(wire, offset, uint64(fromPort))
	offset += copy(wire[offset:], "\nTO_PORT=")
	offset = appendDecimal(wire, offset, uint64(toPort))
	offset += copy(wire[offset:], "\nPROTOCOL=")
	offset = appendDecimal(wire, offset, uint64(protocol))
	offset += copy(wire[offset:], "\n\n")
	copy(wire[offset:], payload)
	return wire, lease, true
}

func datagramReceivedHeader(source string, fromPort, toPort uint16, payloadLen int) ([]byte, *pool.Lease, bool) {
	const prefix = "DATAGRAM RECEIVED DESTINATION="
	const fixed = " FROM_PORT= TO_PORT= SIZE=\n"
	size := len(prefix) + len(source) + len(fixed) + decimalLen(uint64(fromPort)) + decimalLen(uint64(toPort)) + decimalLen(uint64(payloadLen))
	lease, ok := pool.AcquireLease(size)
	if !ok {
		return nil, nil, false
	}
	header, _ := lease.Bytes(size)
	offset := copy(header, prefix)
	offset += copy(header[offset:], source)
	offset += copy(header[offset:], " FROM_PORT=")
	offset = appendDecimal(header, offset, uint64(fromPort))
	offset += copy(header[offset:], " TO_PORT=")
	offset = appendDecimal(header, offset, uint64(toPort))
	offset += copy(header[offset:], " SIZE=")
	offset = appendDecimal(header, offset, uint64(payloadLen))
	header[offset] = '\n'
	return header, lease, true
}

func rawReceivedHeader(protocol uint8, fromPort, toPort uint16, payloadLen int) ([]byte, *pool.Lease, bool) {
	const fixed = "RAW RECEIVED PROTOCOL= FROM_PORT= TO_PORT= SIZE=\n"
	size := len(fixed) + decimalLen(uint64(protocol)) + decimalLen(uint64(fromPort)) + decimalLen(uint64(toPort)) + decimalLen(uint64(payloadLen))
	lease, ok := pool.AcquireLease(size)
	if !ok {
		return nil, nil, false
	}
	header, _ := lease.Bytes(size)
	offset := copy(header, "RAW RECEIVED PROTOCOL=")
	offset = appendDecimal(header, offset, uint64(protocol))
	offset += copy(header[offset:], " FROM_PORT=")
	offset = appendDecimal(header, offset, uint64(fromPort))
	offset += copy(header[offset:], " TO_PORT=")
	offset = appendDecimal(header, offset, uint64(toPort))
	offset += copy(header[offset:], " SIZE=")
	offset = appendDecimal(header, offset, uint64(payloadLen))
	header[offset] = '\n'
	return header, lease, true
}
