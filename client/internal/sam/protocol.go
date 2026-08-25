package sam

import (
	"gosuda.org/ivnp/networking"

	"cmp"

	"context"
	"errors"
	"fmt"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"

	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *Server) dispatch(connection *serverConnection, cmd command) (bool, error) {
	if cmd.verb == "PING" {
		suffix := ""
		if cmd.argument != "" {
			suffix = " " + cmd.argument
		}
		return false, connection.writeLine("PONG" + suffix)
	}
	if cmd.verb == "PONG" {
		return false, nil
	}
	if cmd.verb == "QUIT" || cmd.verb == "STOP" || cmd.verb == "EXIT" {
		return true, nil
	}
	switch cmd.verb + " " + cmd.subverb {
	case "DEST GENERATE":
		if connection.root != nil {
			return false, connection.writeLine("DEST REPLY RESULT=I2P_ERROR MESSAGE=SESSION_ACTIVE")
		}
		if !onlyOptions(cmd.values, "SIGNATURE_TYPE") {
			return false, connection.writeLine("DEST REPLY RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_OPTIONS")
		}
		signatureType := cmd.values["SIGNATURE_TYPE"]
		var local *foundation.LocalDestination
		var err error
		switch {
		case signatureType == "" || signatureType == "7" || strings.EqualFold(signatureType, "EdDSA_SHA512_Ed25519"):
			local, err = foundation.GenerateLegacyLocalDestination()
		case signatureType == "11" || strings.EqualFold(signatureType, "RedDSA_SHA512_Ed25519"):
			local, err = foundation.GenerateEncryptedLocalDestination()
		default:
			return false, connection.writeLine("DEST REPLY RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_SIGNATURE_TYPE")
		}
		if err != nil {
			return false, connection.writeLine("DEST REPLY RESULT=I2P_ERROR")
		}
		private, err := encodePrivateDestination(local)
		public := local.Destination()
		local.ReleaseSensitive()
		if err != nil {
			return false, connection.writeLine("DEST REPLY RESULT=I2P_ERROR")
		}
		defer clear(private)
		return false, connection.writeLine("DEST REPLY PUB=" + string(public) + " PRIV=" + string(private))
	case "NAMING LOOKUP":
		if !onlyOptions(cmd.values, "NAME") {
			return false, connection.writeLine("NAMING REPLY RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_OPTIONS")
		}
		name := cmd.values["NAME"]
		if strings.EqualFold(name, "ME") && connection.root != nil {
			return false, connection.writeLine("NAMING REPLY RESULT=OK NAME=ME VALUE=" + string(connection.root.endpoint.Destination()))
		}
		if name == "" || s.config.Resolver == nil {
			return false, connection.writeLine("NAMING REPLY RESULT=KEY_NOT_FOUND NAME=" + quoteToken(name))
		}
		value, err := s.config.Resolver.ResolveDestination(context.Background(), name)
		if err != nil {
			return false, connection.writeLine("NAMING REPLY RESULT=KEY_NOT_FOUND NAME=" + quoteToken(name))
		}
		return false, connection.writeLine("NAMING REPLY RESULT=OK NAME=" + quoteToken(name) + " VALUE=" + value)
	case "SESSION CREATE":
		return false, s.createSession(connection, cmd)
	case "SESSION ADD":
		return false, s.addSubsession(connection, cmd)
	case "SESSION REMOVE":
		return false, s.removeSubsession(connection, cmd)
	case "STREAM CONNECT", "STREAM ACCEPT", "STREAM FORWARD":
		return s.handleStream(connection, cmd)
	case "DATAGRAM SEND", "RAW SEND":
		return false, s.handleSend(connection, cmd)
	case "PING PONG":
		return false, connection.writeLine("PONG")
	case "QUIT STOP", "QUIT EXIT":
		return true, nil
	default:
		return false, connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_COMMAND")
	}
}

func (s *Server) createSession(connection *serverConnection, cmd command) error {
	if !onlyOptions(cmd.values, "ID", "STYLE", "DESTINATION", "PORT", "HOST", "FROM_PORT", "TO_PORT", "PROTOCOL", "HEADER", "SIGNATURE_TYPE", "I2CP.LEASESETTYPE", "I2CP.LEASESETENCTYPE", "I2CP.LEASESETAUTHTYPE", "I2CP.LEASESETSECRET", "I2CP.LEASESETCLIENT.*") {
		return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_OPTIONS")
	}
	if connection.root != nil {
		return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=SESSION_ACTIVE")
	}
	id := cmd.values["ID"]
	if !validID(id) {
		return connection.writeLine("SESSION STATUS RESULT=INVALID_ID")
	}
	style, ok := parseStyle(cmd.values["STYLE"])
	if !ok {
		return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_STYLE")
	}
	fromPort, toPort, listenPort, protocol, listenProtocol, rawHeader, udpTarget, err := s.sessionTransport(connection, style, cmd.values, false)
	if err != nil {
		return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=INVALID_OPTION")
	}
	policy, err := sessionPolicy(cmd.values)
	if err != nil {
		return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_OPTIONS")
	}
	defer clearLeaseSetPolicy(&policy)
	var local *foundation.LocalDestination
	destinationValue := cmd.values["DESTINATION"]
	if destinationValue == "" || strings.EqualFold(destinationValue, "TRANSIENT") {
		signatureType := cmd.values["SIGNATURE_TYPE"]
		switch {
		case signatureType == "":
		case (signatureType == "7" || strings.EqualFold(signatureType, "EdDSA_SHA512_Ed25519")) && !policy.Encrypted:
		case (signatureType == "11" || strings.EqualFold(signatureType, "RedDSA_SHA512_Ed25519")) && policy.Encrypted:
		default:
			return connection.writeLine("SESSION STATUS RESULT=INVALID_KEY")
		}
		if policy.Encrypted {
			local, err = foundation.GenerateEncryptedLocalDestination()
		} else {
			local, err = foundation.GenerateLegacyLocalDestination()
		}
	} else {
		if cmd.values["SIGNATURE_TYPE"] != "" {
			return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_OPTIONS")
		}
		local, err = decodePrivateDestination(destinationValue)
	}
	if err != nil {
		return connection.writeLine("SESSION STATUS RESULT=INVALID_KEY")
	}
	private, err := encodePrivateDestination(local)
	if err != nil {
		local.ReleaseSensitive()
		return connection.writeLine("SESSION STATUS RESULT=INVALID_KEY")
	}
	defer clear(private)
	endpoint, err := s.config.Controller.CreateDestination(s.ctx, destination.DestinationSpec{Local: local, Policy: policy})
	local.ReleaseSensitive()
	clearLeaseSetPolicy(&policy)
	if err != nil {
		result := "I2P_ERROR"
		if strings.Contains(err.Error(), "already exists") {
			result = "DUPLICATED_DEST"
		}
		return connection.writeLine("SESSION STATUS RESULT=" + result)
	}
	if ready, ok := endpoint.(destination.ReadyDestinationEndpoint); ok {
		readyCtx, cancel := context.WithTimeout(s.ctx, s.config.ReadinessTimeout)
		err = waitReadyConnection(readyCtx, connection, ready)
		cancel()
		if err != nil {
			_ = s.config.Controller.DestroyDestination(context.Background(), endpoint)
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=SESSION_NOT_READY")
		}
	}
	root := newRootSession(s, id, style, endpoint, connection, fromPort, toPort, listenPort, protocol, listenProtocol, rawHeader, udpTarget)
	if err = s.addRoot(root); err != nil {
		_ = s.config.Controller.DestroyDestination(context.Background(), endpoint)
		result := "I2P_ERROR"
		if err.Error() == "DUPLICATED_ID" {
			result = "DUPLICATED_ID"
		}
		if err.Error() == "DUPLICATED_DEST" {
			result = "DUPLICATED_DEST"
		}
		return connection.writeLine("SESSION STATUS RESULT=" + result)
	}
	connection.root = root
	if style == styleDatagram {
		err = root.startReceiver(destination.DestinationRoute{Protocol: networking.DatagramProtocolDatagram1, ToPort: listenPort}, s.config.SessionQueue)
	}
	if style == styleRaw {
		err = root.startReceiver(destination.DestinationRoute{Protocol: listenProtocol, ToPort: listenPort}, s.config.SessionQueue)
	}
	if err != nil {
		connection.root = nil
		root.close()
		return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=ROUTE_UNAVAILABLE")
	}
	return connection.writeLine("SESSION STATUS RESULT=OK DESTINATION=" + string(private))
}
func waitReadyConnection(parent context.Context, connection *serverConnection, ready destination.ReadyDestinationEndpoint) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	readyDone := make(chan error, 1)
	monitorDone := make(chan error, 1)
	go func() {
		_, err := connection.reader.Peek(1)
		monitorDone <- err
	}()
	go func() { readyDone <- ready.WaitReady(ctx) }()
	select {
	case monitorErr := <-monitorDone:
		if monitorErr != nil {
			cancel()
			<-readyDone
			return net.ErrClosed
		}
		// A pipelined byte is buffered, not consumed. It proves the connection
		// is still live; readiness may finish without another socket reader.
		return <-readyDone
	case readyErr := <-readyDone:
		// Wake the disconnect monitor before the command loop resumes reading.
		_ = connection.SetReadDeadline(time.Now())
		monitorErr := <-monitorDone
		_ = connection.SetReadDeadline(time.Time{})
		if monitorErr != nil {
			if networkErr, ok := monitorErr.(net.Error); ok && networkErr.Timeout() {
				return readyErr
			}
			if readyErr == nil {
				return net.ErrClosed
			}
		}
		return readyErr
	}
}

func (s *Server) addSubsession(connection *serverConnection, cmd command) error {
	if !onlyOptions(cmd.values, "ID", "STYLE", "PORT", "HOST", "FROM_PORT", "TO_PORT", "PROTOCOL", "LISTEN_PORT", "LISTEN_PROTOCOL", "HEADER") {
		return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_OPTIONS")
	}
	root := connection.root
	if root == nil || root.style != stylePrimary {
		return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=NOT_PRIMARY")
	}
	id := cmd.values["ID"]
	if !validID(id) {
		return connection.writeLine("SESSION STATUS RESULT=INVALID_ID")
	}
	style, ok := parseStyle(cmd.values["STYLE"])
	if !ok || style == stylePrimary {
		return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_STYLE")
	}
	fromPort, toPort, listenPort, protocol, listenProtocol, rawHeader, udpTarget, err := s.sessionTransport(connection, style, cmd.values, true)
	if err != nil {
		return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=INVALID_OPTION")
	}
	ctx, cancel := context.WithCancel(root.ctx)
	child := &samSession{server: s, root: root, id: id, style: style, endpoint: root.endpoint, control: connection, ctx: ctx, cancel: cancel, sourceIP: root.sourceIP, fromPort: fromPort, toPort: toPort, listenPort: listenPort, protocol: protocol, listenProtocol: listenProtocol, rawHeader: rawHeader, udpTarget: udpTarget, children: make(map[string]*samSession), attachments: make(map[net.Conn]struct{}), queueBytes: newByteBudget(s.config.MaxSessionQueueBytes), acceptRequests: make(chan acceptRequest, s.config.SessionQueue)}
	if err = s.addChild(child); err != nil {
		cancel()
		return connection.writeLine("SESSION STATUS RESULT=DUPLICATED_ID")
	}
	root.mu.Lock()
	root.children[id] = child
	root.mu.Unlock()
	if style == styleDatagram {
		err = child.startReceiver(destination.DestinationRoute{Protocol: networking.DatagramProtocolDatagram1, ToPort: listenPort}, s.config.SessionQueue)
	}
	if style == styleRaw {
		err = child.startReceiver(destination.DestinationRoute{Protocol: listenProtocol, ToPort: listenPort}, s.config.SessionQueue)
	}
	if err != nil {
		_ = root.removeChild(id)
		return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=ROUTE_UNAVAILABLE")
	}
	return connection.writeLine("SESSION STATUS RESULT=OK")
}
func (s *Server) removeSubsession(connection *serverConnection, cmd command) error {
	if !onlyOptions(cmd.values, "ID") {
		return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_OPTIONS")
	}
	root := connection.root
	if root == nil || root.style != stylePrimary {
		return connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=NOT_PRIMARY")
	}
	if err := root.removeChild(cmd.values["ID"]); err != nil {
		return connection.writeLine("SESSION STATUS RESULT=INVALID_ID")
	}
	return connection.writeLine("SESSION STATUS RESULT=OK")
}

func parseStyle(value string) (sessionStyle, bool) {
	switch sessionStyle(strings.ToUpper(value)) {
	case styleStream, styleDatagram, styleRaw, stylePrimary:
		return sessionStyle(strings.ToUpper(value)), true
	}
	return "", false
}
func validID(id string) bool {
	if id == "" || len(id) > 255 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if c < 0x21 || c > 0x7e || c == '=' || c == '"' {
			return false
		}
	}
	return true
}

func onlyOptions(values map[string]string, allowed ...string) bool {
	for key := range values {
		found := false
		for _, candidate := range allowed {
			if key == candidate || (strings.HasSuffix(candidate, "*") && strings.HasPrefix(key, strings.TrimSuffix(candidate, "*"))) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func reservedRawProtocol(protocol uint8) bool {
	return protocol == 0 || protocol == 6 || protocol == 17 || protocol == 19 || protocol == 20
}
func quoteToken(value string) string { return fmt.Sprintf("%q", value) }

func sessionPolicy(values map[string]string) (destination.LeaseSetPolicy, error) {
	policy := destination.LeaseSetPolicy{CryptoTypes: []uint16{7, 6, 4}}
	if value := values["I2CP.LEASESETTYPE"]; value != "" {
		switch value {
		case "3":
		case "5":
			policy.Encrypted = true
		default:
			return policy, ErrUnsupported
		}
	}
	if value := values["I2CP.LEASESETENCTYPE"]; value != "" {
		parts := strings.Split(value, ",")
		if len(parts) == 0 || len(parts) > 3 {
			return policy, ErrUnsupported
		}
		types := make([]uint16, 0, len(parts))
		seen := make(map[uint16]bool, len(parts))
		for _, part := range parts {
			parsed, err := strconv.ParseUint(part, 10, 16)
			cryptoType := uint16(parsed)
			sessionPolicyRejected := err != nil || (cryptoType != 7 && cryptoType != 6 && cryptoType != 4)
			if !sessionPolicyRejected {
				sessionPolicyRejected = seen[cryptoType]
			}
			if sessionPolicyRejected {
				return policy, ErrUnsupported
			}
			seen[cryptoType] = true
			types = append(types, cryptoType)
		}
		policy.CryptoTypes = types
	}
	authType := values["I2CP.LEASESETAUTHTYPE"]
	switch authType {
	case "", "0":
	case "1", "2":
		policy.Encrypted = true
		keys := make([]string, 0)
		for key := range values {
			if strings.HasPrefix(key, "I2CP.LEASESETCLIENT.") {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			encoded := values[key]
			raw, err := foundation.DecodeI2PBase64([]byte(encoded))
			if err != nil || len(raw) != 32 {
				clear(raw)
				return policy, ErrUnsupported
			}
			var client [32]byte
			copy(client[:], raw)
			clear(raw)
			if authType == "1" {
				policy.DHClients = append(policy.DHClients, client)
			} else {
				policy.PSKClients = append(policy.PSKClients, client)
			}
		}
		if len(policy.DHClients)+len(policy.PSKClients) == 0 {
			return policy, ErrUnsupported
		}
	default:
		return policy, ErrUnsupported
	}
	if secret := values["I2CP.LEASESETSECRET"]; secret != "" {
		policy.Encrypted = true
		policy.Secret = []byte(secret)
	}
	return policy, nil
}

type sessionTransportConfig struct {
	fromPort       uint16
	toPort         uint16
	listenPort     uint16
	protocol       uint8
	listenProtocol uint8
	rawHeader      bool
	udpTarget      *net.UDPAddr
}

func (s *Server) sessionTransport(connection *serverConnection, style sessionStyle, values map[string]string, child bool) (fromPort, toPort, listenPort uint16, protocol, listenProtocol uint8, rawHeader bool, udpTarget *net.UDPAddr, err error) {
	fromRaw, fromErr := uintValue(values, "FROM_PORT", 16, 0)
	toRaw, toErr := uintValue(values, "TO_PORT", 16, 0)
	if fromErr != nil || toErr != nil {
		return 0, 0, 0, 0, 0, false, nil, ErrProtocol
	}
	config := sessionTransportConfig{fromPort: uint16(fromRaw), toPort: uint16(toRaw)}
	switch style {
	case styleStream:
		err = s.configureStreamTransport(&config, values, child)
	case styleDatagram, styleRaw:
		err = s.configurePacketTransport(connection, &config, style, values, child)
	case stylePrimary:
		if child || values["PORT"] != "" || values["HOST"] != "" || values["HEADER"] != "" || values["PROTOCOL"] != "" {
			err = ErrProtocol
		}
	default:
		err = ErrProtocol
	}
	return config.fromPort, config.toPort, config.listenPort, config.protocol, config.listenProtocol, config.rawHeader, config.udpTarget, err
}

func (s *Server) configureStreamTransport(config *sessionTransportConfig, values map[string]string, child bool) error {
	config.protocol, config.listenProtocol = 6, 6
	config.listenPort = config.toPort
	if child {
		listenRaw, err := uintValue(values, "LISTEN_PORT", 16, uint64(config.fromPort))
		if err != nil || (listenRaw != 0 && listenRaw != uint64(config.fromPort)) {
			return ErrProtocol
		}
		config.listenPort = uint16(listenRaw)
	}
	if values["HOST"] != "" || values["HEADER"] != "" || values["PROTOCOL"] != "" || values["LISTEN_PROTOCOL"] != "" {
		return ErrProtocol
	}
	portValue, exists := values["PORT"]
	if !exists {
		return nil
	}
	if s.config.UDPAddress != "" {
		return ErrProtocol
	}
	portRaw, err := uintValue(values, "PORT", 16, 0)
	if err != nil || portValue == "" {
		return ErrProtocol
	}
	config.listenPort = uint16(portRaw)
	return nil
}

func (s *Server) configurePacketTransport(connection *serverConnection, config *sessionTransportConfig, style sessionStyle, values map[string]string, child bool) error {
	if style == styleDatagram {
		config.protocol, config.listenProtocol = networking.DatagramProtocolDatagram1, networking.DatagramProtocolDatagram1
		if values["PROTOCOL"] != "" || values["HEADER"] != "" || values["LISTEN_PROTOCOL"] != "" {
			return ErrProtocol
		}
	} else {
		protocolRaw, err := uintValue(values, "PROTOCOL", 8, uint64(networking.DatagramProtocolRaw))
		if err != nil || reservedRawProtocol(uint8(protocolRaw)) {
			return ErrProtocol
		}
		config.protocol = uint8(protocolRaw)
		config.listenProtocol = config.protocol
		config.rawHeader, err = boolValue(values, "HEADER")
		if err != nil {
			return err
		}
	}
	config.listenPort = config.fromPort
	if child {
		listenRaw, err := uintValue(values, "LISTEN_PORT", 16, uint64(config.fromPort))
		if err != nil {
			return ErrProtocol
		}
		config.listenPort = uint16(listenRaw)
		if style == styleRaw {
			listenProtocolRaw, err := uintValue(values, "LISTEN_PROTOCOL", 8, uint64(config.protocol))
			if err != nil || reservedRawProtocol(uint8(listenProtocolRaw)) {
				return ErrProtocol
			}
			config.listenProtocol = uint8(listenProtocolRaw)
		}
	}
	return s.configurePacketTarget(connection, config, values)
}

func (s *Server) configurePacketTarget(connection *serverConnection, config *sessionTransportConfig, values map[string]string) error {
	portText, exists := values["PORT"]
	if !exists {
		if values["HOST"] != "" {
			return ErrProtocol
		}
		return nil
	}
	portRaw, err := uintValue(values, "PORT", 16, 0)
	if err != nil || portRaw == 0 || portText == "" {
		return ErrProtocol
	}
	if s.config.UDPAddress == "" && values["HOST"] == "" {
		// Compatibility for an explicitly TCP-only bridge: historical
		// ivnp used PORT as the incoming I2P route selector.
		config.listenPort = uint16(portRaw)
		return nil
	}
	source := connectionIP(connection.Conn)
	if !source.IsValid() {
		return ErrProtocol
	}
	host := cmp.Or(values["HOST"], source.String())
	if !s.samTargetMatchesSource(host, source) {
		return ErrProtocol
	}
	config.udpTarget = &net.UDPAddr{IP: append(net.IP(nil), source.AsSlice()...), Port: int(portRaw)}
	return nil
}

func (s *Server) samTargetMatchesSource(host string, source netip.Addr) bool {
	if !source.IsLoopback() {
		return false
	}
	if targetIP := net.ParseIP(host); targetIP != nil {
		return targetIP.IsLoopback() && targetIP.String() == source.String()
	}
	lookupCtx, cancel := context.WithTimeout(s.ctx, s.config.HandshakeTimeout)
	addresses, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip", host)
	cancel()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		if address.Unmap() == source {
			return true
		}
	}
	return false
}

func clearLeaseSetPolicy(policy *destination.LeaseSetPolicy) {
	if policy == nil {
		return
	}
	clear(policy.Secret)
	for index := range policy.DHClients {
		clear(policy.DHClients[index][:])
	}
	for index := range policy.PSKClients {
		clear(policy.PSKClients[index][:])
	}
	policy.DHClients, policy.PSKClients = nil, nil
}
