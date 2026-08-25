package sam

import (
	"context"
	"errors"
	ivnp "gosuda.org/ivnp/foundation"
	clientapi "gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/internal/ingress"
	internalrelay "gosuda.org/ivnp/internal/relay"
	"net"
	"strings"
	"sync"
	"time"
)

type destinationConnection interface {
	net.Conn
	RemoteDestination() []byte
	LocalI2PPort() uint16
	RemoteI2PPort() uint16
}

func (s *Server) handleStream(connection *serverConnection, cmd command) (bool, error) {
	switch cmd.subverb {
	case "CONNECT":
		if !onlyOptions(cmd.values, "ID", "DESTINATION", "SILENT", "FROM_PORT", "TO_PORT") {
			return true, connection.writeLine("STREAM STATUS RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_OPTIONS")
		}
	case "ACCEPT":
		if !onlyOptions(cmd.values, "ID", "SILENT") {
			return true, connection.writeLine("STREAM STATUS RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_OPTIONS")
		}
	case "FORWARD":
		if !onlyOptions(cmd.values, "ID", "HOST", "PORT", "SSL") {
			return true, connection.writeLine("STREAM STATUS RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_OPTIONS")
		}
	}
	id := cmd.values["ID"]
	session := s.session(id)
	if session == nil || session.style != styleStream {
		return true, connection.writeLine("STREAM STATUS RESULT=INVALID_ID")
	}
	if err := session.attach(connection.Conn); err != nil {
		return true, err
	}
	defer session.detach(connection.Conn)
	silent, err := boolValue(cmd.values, "SILENT")
	if err != nil {
		return true, connection.writeLine("STREAM STATUS RESULT=I2P_ERROR MESSAGE=INVALID_OPTION")
	}
	switch cmd.subverb {
	case "CONNECT":
		target := cmd.values["DESTINATION"]
		if target == "" {
			return true, connection.writeLine("STREAM STATUS RESULT=INVALID_KEY")
		}
		resolved, resolveErr := s.resolveTarget(session.ctx, target)
		if resolveErr != nil {
			return true, connection.writeLine("STREAM STATUS RESULT=CANT_REACH_PEER")
		}
		port, portErr := uintValue(cmd.values, "TO_PORT", 16, uint64(session.toPort))
		fromPort, fromPortErr := uintValue(cmd.values, "FROM_PORT", 16, uint64(session.fromPort))
		if portErr != nil || fromPortErr != nil {
			return true, connection.writeLine("STREAM STATUS RESULT=I2P_ERROR MESSAGE=INVALID_PORT")
		}
		address := net.JoinHostPort(resolved, itoa16(uint16(port)))
		var outbound net.Conn
		var dialErr error
		if fromPort != 0 {
			source, ok := session.endpoint.(clientapi.SourcePortDestinationEndpoint)
			if !ok {
				return true, connection.writeLine("STREAM STATUS RESULT=I2P_ERROR MESSAGE=FROM_PORT_UNSUPPORTED")
			}
			outbound, dialErr = source.DialI2PFromPort(session.ctx, address, uint16(fromPort))
		} else {
			outbound, dialErr = session.endpoint.DialI2P(session.ctx, address)
		}
		if dialErr != nil {
			return true, connection.writeLine("STREAM STATUS RESULT=CANT_REACH_PEER")
		}
		defer outbound.Close()
		if err = session.attach(outbound); err != nil {
			_ = outbound.Close()
			return true, err
		}
		defer session.detach(outbound)
		if !session.reserve(s.config.RelayReservationBytes) {
			return true, connection.writeLine("STREAM STATUS RESULT=I2P_ERROR MESSAGE=BACKPRESSURE")
		}
		defer session.release(s.config.RelayReservationBytes)
		if !silent {
			if err = connection.writeLine("STREAM STATUS RESULT=OK"); err != nil {
				return true, err
			}
		}
		_ = connection.SetDeadline(timeZero)
		return true, s.relay(connection.Conn, outbound, connection.Conn)
	case "ACCEPT":
		acceptCtx, stopWatching := s.attachmentContext(session.ctx, connection.Conn)
		inbound, acceptErr := session.acceptAttachment(acceptCtx)
		stopWatching()
		if acceptErr != nil {
			message := "I2P_ERROR"
			if errors.Is(acceptErr, errQueueBudget) {
				message += " MESSAGE=BACKPRESSURE"
			}
			return true, connection.writeLine("STREAM STATUS RESULT=" + message)
		}
		defer inbound.Close()
		if err = session.attach(inbound); err != nil {
			_ = inbound.Close()
			return true, err
		}
		defer session.detach(inbound)
		if !session.reserve(s.config.RelayReservationBytes) {
			return true, connection.writeLine("STREAM STATUS RESULT=I2P_ERROR MESSAGE=BACKPRESSURE")
		}
		defer session.release(s.config.RelayReservationBytes)
		if err = connection.writeLine("STREAM STATUS RESULT=OK"); err != nil {
			return true, err
		}
		if !silent {
			metadata, ok := inbound.(destinationConnection)
			if !ok {
				return true, errors.New("sam: accepted connection lacks Destination metadata")
			}
			if err = connection.writeLine(string(metadata.RemoteDestination()) + " FROM_PORT=" + itoa16(metadata.RemoteI2PPort()) + " TO_PORT=" + itoa16(metadata.LocalI2PPort())); err != nil {
				return true, err
			}
		}
		_ = connection.SetDeadline(timeZero)
		return true, s.relay(connection.Conn, inbound, connection.Conn)
	case "FORWARD":
		if !session.beginForward() {
			return true, connection.writeLine("STREAM STATUS RESULT=I2P_ERROR MESSAGE=FORWARD_EXISTS")
		}
		defer session.endForward()
		ssl, sslErr := boolValue(cmd.values, "SSL")
		if sslErr != nil || ssl {
			return true, connection.writeLine("STREAM STATUS RESULT=I2P_ERROR MESSAGE=SSL_UNSUPPORTED")
		}
		host := cmd.values["HOST"]
		if host == "" {
			remoteHost, _, _ := net.SplitHostPort(connection.RemoteAddr().String())
			host = remoteHost
		}
		address := net.JoinHostPort(host, cmd.values["PORT"])
		parsed, parseErr := net.ResolveTCPAddr("tcp", address)
		if parseErr != nil || parsed.Port == 0 || !s.config.AllowLoopbackForward || !parsed.IP.IsLoopback() {
			return true, connection.writeLine("STREAM STATUS RESULT=I2P_ERROR MESSAGE=FORWARD_DENIED")
		}
		listener, listenErr := session.ensureListener()
		if listenErr != nil {
			return true, connection.writeLine("STREAM STATUS RESULT=I2P_ERROR")
		}
		if err = connection.writeLine("STREAM STATUS RESULT=OK"); err != nil {
			return true, err
		}
		session.wg.Add(1)
		go s.forwardWatcher(session, connection.Conn, listener)
		for {
			inbound, acceptErr := listener.Accept()
			if acceptErr != nil {
				return true, acceptErr
			}
			local, dialErr := net.DialTCP("tcp", nil, parsed)
			if dialErr != nil {
				_ = inbound.Close()
				continue
			}
			if !session.reserve(s.config.RelayReservationBytes) {
				_ = inbound.Close()
				_ = local.Close()
				continue
			}
			session.wg.Add(1)
			go s.forwardRelay(session, inbound, local)
		}
	}
	return true, connection.writeLine("STREAM STATUS RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_COMMAND")
}

func (s *Server) forwardWatcher(session *samSession, connection net.Conn, listener net.Listener) {
	defer session.wg.Done()
	defer func() {
		if value := recover(); value != nil {
			_ = ingress.Report(value, s.config.PanicReporter, ingress.BoundarySAMWorker, connection.RemoteAddr())
		}
		_ = listener.Close()
	}()
	var scratch [1]byte
	for {
		if _, err := connection.Read(scratch[:]); err != nil {
			return
		}
	}
}

func (s *Server) forwardRelay(session *samSession, inbound, local net.Conn) {
	defer session.wg.Done()
	defer session.release(s.config.RelayReservationBytes)
	defer inbound.Close()
	defer local.Close()
	defer func() {
		if value := recover(); value != nil {
			_ = ingress.Report(value, s.config.PanicReporter, ingress.BoundarySAMWorker, inbound.RemoteAddr())
		}
	}()
	_ = s.relay(inbound, local, inbound)
}

func (s *Server) relay(left, right net.Conn, leftReader net.Conn) error {
	return internalrelay.BidirectionalContained(left, right, leftReader, func(value any) error {
		return ingress.Report(value, s.config.PanicReporter, ingress.BoundarySAMWorker, right.RemoteAddr())
	})
}

func (s *Server) attachmentContext(parent context.Context, connection net.Conn) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	stop := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		defer func() {
			if value := recover(); value != nil {
				_ = ingress.Report(value, s.config.PanicReporter, ingress.BoundarySAMWorker, connection.RemoteAddr())
				cancel()
			}
		}()
		var scratch [1]byte
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, err := connection.Read(scratch[:])
			if err == nil {
				cancel()
				return
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			cancel()
			return
		}
	}()
	return ctx, func() {
		once.Do(func() {
			close(stop)
			_ = connection.SetReadDeadline(time.Now())
			<-done
			_ = connection.SetReadDeadline(time.Time{})
			cancel()
		})
	}
}

var timeZero = func() (zeroTime time.Time) { return }()

func (s *Server) resolveTarget(ctx context.Context, target string) (string, error) {
	if strings.HasSuffix(strings.ToLower(target), ".b32.i2p") {
		return target, nil
	}
	if _, err := ivnp.ParseDestination([]byte(target)); err == nil {
		return target, nil
	}
	if s.config.Resolver == nil {
		return "", ErrProtocol
	}
	return s.config.Resolver.ResolveDestination(ctx, target)
}
