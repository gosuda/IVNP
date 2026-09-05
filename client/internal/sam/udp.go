package sam

import (
	"bytes"
	"net"
	"strconv"
	"strings"

	"gosuda.org/ivnp/internal/ingress"
	"gosuda.org/ivnp/internal/pool"
	"gosuda.org/ivnp/networking"
)

type udpPacket struct {
	session  *samSession
	target   string
	payload  []byte
	lease    *pool.Lease
	fromPort uint16
	toPort   uint16
	protocol uint8
	charged  int64
}

func (p *udpPacket) releasePayload() {
	if p.lease != nil {
		p.lease.ReleaseSensitive()
		p.lease = nil
	} else {
		clear(p.payload)
	}
	p.payload = nil
}

func (s *Server) udpReadLoop() {
	defer s.wg.Done()
	defer func() {
		if value := recover(); value != nil {
			_ = ingress.Report(value, s.config.PanicReporter, ingress.BoundarySAMUDP, s.udp.LocalAddr())
			_ = s.udp.Close()
		}
	}()
	buffer := make([]byte, s.config.MaxCommandBytes+s.config.MaxDatagramBytes+2)
	for {
		n, source, err := s.udp.ReadFrom(buffer)
		if err != nil {
			return
		}
		packet, ok := s.parseUDPPacket(buffer[:n], source)
		if !ok {
			if s.config.Metrics != nil {
				s.config.Metrics.IncSAMUDPInvalid()
			}
			continue
		}
		packet.charged = int64(n)
		if !packet.session.reserve(packet.charged) {
			packet.releasePayload()
			if s.config.Metrics != nil {
				s.config.Metrics.IncSAMUDPBackpressureRejected()
			}
			continue
		}
		select {
		case s.udpIngress <- packet:
		case <-s.ctx.Done():
			packet.session.release(packet.charged)
			packet.releasePayload()
			return
		default:
			if s.config.Metrics != nil {
				s.config.Metrics.IncSAMUDPBackpressureRejected()
			}
			packet.session.release(packet.charged)
			packet.releasePayload()
		}
	}
}

func (s *Server) udpSendLoop() {
	defer s.wg.Done()
	defer func() {
		if value := recover(); value != nil {
			_ = ingress.Report(value, s.config.PanicReporter, ingress.BoundarySAMUDP, s.udp.LocalAddr())
			for {
				select {
				case packet := <-s.udpIngress:
					packet.session.release(packet.charged)
					packet.releasePayload()
				default:
					return
				}
			}
		}
	}()
	for {
		select {
		case packet := <-s.udpIngress:
			s.processUDPPacket(packet)
		case <-s.ctx.Done():
			for {
				select {
				case packet := <-s.udpIngress:
					packet.session.release(packet.charged)
					packet.releasePayload()
				default:
					return
				}
			}
		}
	}
}

func (s *Server) processUDPPacket(packet udpPacket) {
	defer packet.session.release(packet.charged)
	defer packet.releasePayload()
	defer func() {
		if value := recover(); value != nil {
			_ = ingress.Report(value, s.config.PanicReporter, ingress.BoundarySAMUDP, nil)
		}
	}()
	s.sendUDPPacket(packet)
}

func (s *Server) parseUDPPacket(wire []byte, source net.Addr) (udpPacket, bool) {
	newline := bytes.IndexByte(wire, '\n')
	if newline <= 0 || newline > s.config.MaxCommandBytes || len(wire)-newline-1 < 1 || len(wire)-newline-1 > s.config.MaxDatagramBytes {
		return udpPacket{}, false
	}
	header := wire[:newline]
	if bytes.IndexAny(header, "\r\t") >= 0 || len(header) == 0 || header[0] == ' ' || header[len(header)-1] == ' ' || bytes.Contains(header, []byte("  ")) {
		return udpPacket{}, false
	}
	parts := strings.Split(string(header), " ")
	if len(parts) < 3 || !validUDPVersion(parts[0]) || !validID(parts[1]) || parts[2] == "" {
		return udpPacket{}, false
	}
	session := s.session(parts[1])
	parseUDPPacketRejected := session == nil || (!isDatagramStyle(session.style) && session.style != styleRaw)
	if !parseUDPPacketRejected {
		parseUDPPacketRejected = !sameSourceIP(session.sourceIP, source)
	}
	if parseUDPPacketRejected {
		return udpPacket{}, false
	}
	packet := udpPacket{session: session, target: parts[2], fromPort: session.fromPort, toPort: session.toPort, protocol: session.protocol}
	seen := make(map[string]bool, 3)
	for _, option := range parts[3:] {
		key, value, found := strings.Cut(option, "=")
		if !found || value == "" || seen[key] {
			return udpPacket{}, false
		}
		seen[key] = true
		parsed, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return udpPacket{}, false
		}
		switch key {
		case "FROM_PORT":
			packet.fromPort = uint16(parsed)
		case "TO_PORT":
			packet.toPort = uint16(parsed)
		case "PROTOCOL":
			if session.style != styleRaw || parsed > 255 || reservedRawProtocol(uint8(parsed)) {
				return udpPacket{}, false
			}
			packet.protocol = uint8(parsed)
		default:
			return udpPacket{}, false
		}
	}
	payloadLen := len(wire) - newline - 1
	if isDatagramStyle(session.style) && (session.datagramOverhead <= 0 || payloadLen > s.config.MaxDatagramBytes-session.datagramOverhead) {
		return udpPacket{}, false
	}
	lease, ok := pool.AcquireLease(payloadLen)
	if !ok {
		return udpPacket{}, false
	}
	packet.payload, _ = lease.Bytes(payloadLen)
	packet.lease = lease
	copy(packet.payload, wire[newline+1:])
	return packet, true
}

func validUDPVersion(value string) bool {
	if !strings.HasPrefix(value, "3.") || len(value) < 3 {
		return false
	}
	minor, err := strconv.ParseUint(value[2:], 10, 8)
	return err == nil && minor <= 3
}

func sameSourceIP(expected interface {
	IsValid() bool
	String() string
}, source net.Addr) bool {
	if !expected.IsValid() {
		return false
	}
	host, _, err := net.SplitHostPort(source.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.String() == expected.String()
}

func (s *Server) sendUDPPacket(packet udpPacket) {
	session := packet.session
	resolved, err := s.resolveTarget(session.ctx, packet.target)
	if err != nil {
		return
	}
	hash, err := destinationHash(resolved)
	if err != nil {
		return
	}
	payload := packet.payload
	protocol := packet.protocol
	var framedLease *pool.Lease
	if isDatagramStyle(session.style) {
		framed, lease, ok := session.datagramFrame(len(packet.payload))
		if !ok {
			return
		}
		framedLease = lease
		defer framedLease.ReleaseSensitive()
		n, marshalErr := marshalSessionDatagram(session, framed, hash, packet.payload)
		if marshalErr != nil || n != len(framed) {
			return
		}
		payload = framed
	}
	_ = session.endpoint.SendMessage(session.ctx, networking.StreamingTunnelDelivery{From: session.endpoint.Hash(), To: hash, FromPort: packet.fromPort, ToPort: packet.toPort, Protocol: protocol, Payload: payload})
}
