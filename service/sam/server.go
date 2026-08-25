package sam

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	ivnp "gosuda.org/ivnp"
	"gosuda.org/ivnp/internal/ingress"
	"gosuda.org/ivnp/service/clientapi"
	"gosuda.org/ivnp/support/observability"
)

const (
	defaultMaxCommandBytes  = 8192
	defaultMaxDatagramBytes = 32768
)

type ListenFunc func(context.Context, string, string) (net.Listener, error)
type ListenPacketFunc func(context.Context, string, string) (net.PacketConn, error)

// ServerConfig configures the embedded inbound SAM 3.3 endpoint.
type ServerConfig struct {
	Address                string
	UDPAddress             string
	Listen                 ListenFunc
	ListenPacket           ListenPacketFunc
	Controller             clientapi.DestinationController
	Resolver               clientapi.DestinationResolver
	PanicReporter          ingress.Reporter
	Metrics                *observability.Registry
	MaxConnections         int
	MaxSessions            int
	MaxCommandBytes        int
	MaxDatagramBytes       int
	SessionQueue           int
	MaxSessionQueueBytes   int64
	MaxServerQueueBytes    int64
	AcceptReservationBytes int64
	RelayReservationBytes  int64
	HandshakeTimeout       time.Duration
	CommandTimeout         time.Duration
	ReadinessTimeout       time.Duration
	AllowLoopbackForward   bool
}

// Server serves inbound SAM while Network remains the external SAM client.
type Server struct {
	config       ServerConfig
	mu           sync.RWMutex
	sessions     map[string]*samSession
	destinations map[ivnp.Hash]*samSession
	listener     net.Listener
	connections  map[net.Conn]struct{}
	udp          net.PacketConn
	udpIngress   chan udpPacket
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	wg           sync.WaitGroup
	started      bool
	closed       bool
	sem          chan struct{}
	queueBytes   *byteBudget
}

func NewServer(config ServerConfig) (*Server, error) {
	newServerRejected := config.Address == "" || config.Controller == nil || !loopbackSocketAddress(config.Address)
	if !newServerRejected {
		newServerRejected = (config.UDPAddress != "" && !loopbackSocketAddress(config.UDPAddress))
	}
	if newServerRejected {
		return nil, ErrProtocol
	}
	if config.Listen == nil {
		config.Listen = func(ctx context.Context, network, address string) (net.Listener, error) {
			return (&net.ListenConfig{}).Listen(ctx, network, address)
		}
	}
	if config.UDPAddress != "" && config.ListenPacket == nil {
		config.ListenPacket = func(ctx context.Context, network, address string) (net.PacketConn, error) {
			return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
		}
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = 128
	}
	if config.MaxSessions <= 0 {
		config.MaxSessions = 128
	}
	if config.MaxCommandBytes <= 0 {
		config.MaxCommandBytes = defaultMaxCommandBytes
	}
	if config.MaxDatagramBytes <= 0 {
		config.MaxDatagramBytes = defaultMaxDatagramBytes
	}
	if config.MaxCommandBytes > 1<<20 || config.MaxDatagramBytes > 65535 || config.MaxSessions > 65536 {
		return nil, ErrProtocol
	}
	if config.SessionQueue <= 0 {
		config.SessionQueue = 64
	}
	if config.MaxSessionQueueBytes <= 0 {
		config.MaxSessionQueueBytes = 4 << 20
	}
	if config.MaxServerQueueBytes <= 0 {
		config.MaxServerQueueBytes = 64 << 20
	}
	if config.MaxSessionQueueBytes > config.MaxServerQueueBytes {
		return nil, ErrProtocol
	}
	if config.AcceptReservationBytes <= 0 {
		config.AcceptReservationBytes = 64 << 10
	}
	if config.RelayReservationBytes <= 0 {
		config.RelayReservationBytes = 256 << 10
	}
	if config.HandshakeTimeout <= 0 {
		config.HandshakeTimeout = 10 * time.Second
	}
	if config.CommandTimeout <= 0 {
		config.CommandTimeout = 5 * time.Minute
	}
	if config.ReadinessTimeout <= 0 {
		config.ReadinessTimeout = 2 * time.Minute
	}
	return &Server{config: config, sessions: make(map[string]*samSession), destinations: make(map[ivnp.Hash]*samSession), connections: make(map[net.Conn]struct{}), done: make(chan struct{}), sem: make(chan struct{}, config.MaxConnections), queueBytes: newByteBudget(config.MaxServerQueueBytes)}, nil
}

func (s *Server) Start(parent context.Context) error {
	if parent == nil {
		parent = context.Background()
	}

	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	ctx, cancel := context.WithCancel(parent)
	listener, err := s.config.Listen(ctx, "tcp", s.config.Address)
	if err != nil {
		cancel()
		s.mu.Unlock()
		return err
	}
	var udp net.PacketConn
	if s.config.UDPAddress != "" {
		udp, err = s.config.ListenPacket(ctx, "udp", s.config.UDPAddress)
		if err != nil {
			_ = listener.Close()
			cancel()
			s.mu.Unlock()
			return err
		}
		s.udpIngress = make(chan udpPacket, s.config.SessionQueue)
	}
	s.ctx, s.cancel, s.listener, s.udp, s.started = ctx, cancel, listener, udp, true
	s.mu.Unlock()
	s.wg.Add(1)
	go s.acceptLoop()
	if udp != nil {
		s.wg.Add(2)
		go s.udpReadLoop()
		go s.udpSendLoop()
	}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	return nil
}

func (s *Server) Addr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *Server) UDPAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.udp == nil {
		return nil
	}
	return s.udp.LocalAddr()
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	defer func() {
		if value := recover(); value != nil {
			_ = ingress.Report(value, s.config.PanicReporter, ingress.BoundarySAMWorker, s.listener.Addr())
			_ = s.Close()
		}
	}()
	defer close(s.done)
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			if s.ctx.Err() == nil { /* Wait reports through Close only. */
			}
			return
		}
		select {
		case s.sem <- struct{}{}:
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				<-s.sem
				_ = connection.Close()
				continue
			}
			s.connections[connection] = struct{}{}
			s.mu.Unlock()
			s.wg.Go(func() {
				defer func() { <-s.sem }()
				defer func() {
					s.mu.Lock()
					delete(s.connections, connection)
					s.mu.Unlock()
				}()
				_ = s.serveConnection(connection)
			})
		default:
			_ = connection.Close()
		}
	}
}

type serverConnection struct {
	net.Conn
	reader  *bufio.Reader
	writeMu sync.Mutex
	root    *samSession
}

func (c *serverConnection) writeLine(line string) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := io.WriteString(c.Conn, line+"\n")
	return err
}
func (c *serverConnection) writeFrame(header string, body []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := io.WriteString(c.Conn, header+"\n"); err != nil {
		return err
	}
	_, err := c.Conn.Write(body)
	return err
}

func (s *Server) serveConnection(raw net.Conn) (result error) {
	defer ingress.Recover(&result, s.config.PanicReporter, ingress.BoundaryClientConnection, raw.RemoteAddr())
	defer raw.Close()
	connection := &serverConnection{Conn: raw, reader: bufio.NewReaderSize(raw, s.config.MaxCommandBytes+1)}
	_ = raw.SetReadDeadline(time.Now().Add(s.config.HandshakeTimeout))
	line, err := connection.readLine(s.config.MaxCommandBytes)
	if err != nil {
		return err
	}
	cmd, err := parseCommand(line, 64)
	if err != nil || cmd.verb != "HELLO" || cmd.subverb != "VERSION" {
		if s.config.Metrics != nil {
			s.config.Metrics.IncSAMProtocolFailures()
		}
		_ = connection.writeLine("HELLO REPLY RESULT=I2P_ERROR MESSAGE=EXPECTED_HELLO")
		return ErrProtocol
	}
	min, minErr := parseVersion(cmd.values["MIN"], [2]int{3, 0})
	max, maxErr := parseVersion(cmd.values["MAX"], [2]int{3, 3})
	if minErr != nil || maxErr != nil || compareVersion(min, [2]int{3, 3}) > 0 || compareVersion(max, [2]int{3, 3}) < 0 {
		if s.config.Metrics != nil {
			s.config.Metrics.IncSAMProtocolFailures()
		}
		_ = connection.writeLine("HELLO REPLY RESULT=NOVERSION")
		return ErrProtocol
	}
	if err = connection.writeLine("HELLO REPLY RESULT=OK VERSION=3.3"); err != nil {
		return err
	}
	_ = raw.SetReadDeadline(time.Time{})
	defer func() {
		if connection.root != nil {
			connection.root.close()
		}
	}()
	for {
		if connection.root != nil {
			// A root SAM control socket owns the Destination for the full
			// session lifetime and is normally idle while STREAM attachments
			// carry traffic. CommandTimeout protects pre-session clients only.
			_ = raw.SetReadDeadline(time.Time{})
		} else if s.config.CommandTimeout > 0 {
			_ = raw.SetReadDeadline(time.Now().Add(s.config.CommandTimeout))
		}
		line, err = connection.readLine(s.config.MaxCommandBytes)
		if err != nil {
			return err
		}
		cmd, err = parseCommand(line, 64)
		if err != nil {
			if s.config.Metrics != nil {
				s.config.Metrics.IncSAMProtocolFailures()
			}
			if writeErr := connection.writeLine("SESSION STATUS RESULT=I2P_ERROR MESSAGE=MALFORMED_COMMAND"); writeErr != nil {
				return writeErr
			}
			continue
		}
		stop, dispatchErr := s.dispatch(connection, cmd)
		if stop {
			return dispatchErr
		}
		if dispatchErr != nil && errors.Is(dispatchErr, net.ErrClosed) {
			return dispatchErr
		}
		if dispatchErr != nil && s.config.Metrics != nil {
			s.config.Metrics.IncSAMProtocolFailures()
		}
	}
}

func (c *serverConnection) readLine(max int) (string, error) {
	line, err := c.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > max+1 {
		return "", ErrLineTooLong
	}
	if err != nil {
		return "", err
	}
	line = line[:len(line)-1]
	if len(line) != 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	return string(line), nil
}

func parseVersion(value string, fallback [2]int) ([2]int, error) {
	if value == "" {
		return fallback, nil
	}
	majorRaw, minorRaw, ok := strings.Cut(value, ".")
	if !ok {
		return [2]int{}, ErrProtocol
	}
	major, err1 := strconv.Atoi(majorRaw)
	minor, err2 := strconv.Atoi(minorRaw)
	if err1 != nil || err2 != nil || major < 0 || minor < 0 {
		return [2]int{}, ErrProtocol
	}
	return [2]int{major, minor}, nil
}
func compareVersion(a, b [2]int) int {
	if a[0] != b[0] {
		return a[0] - b[0]
	}
	return a[1] - b[1]
}
func itoa16(value uint16) string { return strconv.FormatUint(uint64(value), 10) }

func loopbackSocketAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	listener := s.listener
	udp := s.udp
	roots := make([]*samSession, 0, len(s.destinations))
	for _, root := range s.destinations {
		roots = append(roots, root)
	}
	connections := make([]net.Conn, 0, len(s.connections))
	for connection := range s.connections {
		connections = append(connections, connection)
	}
	s.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	if udp != nil {
		_ = udp.Close()
	}
	for _, connection := range connections {
		_ = connection.Close()
	}
	for _, root := range roots {
		root.close()
	}
	return nil
}
func (s *Server) Wait() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	started := s.started
	done := s.done
	s.mu.RUnlock()
	if started {
		<-done
		s.wg.Wait()
	}
	return nil
}

func (s *Server) addRoot(root *samSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.sessions) >= s.config.MaxSessions {
		return net.ErrClosed
	}
	if _, exists := s.sessions[root.id]; exists {
		return errors.New("DUPLICATED_ID")
	}
	if _, exists := s.destinations[root.endpoint.Hash()]; exists {
		return errors.New("DUPLICATED_DEST")
	}
	s.sessions[root.id], s.destinations[root.endpoint.Hash()] = root, root
	return nil
}
func (s *Server) addChild(child *samSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= s.config.MaxSessions {
		return net.ErrClosed
	}
	if _, exists := s.sessions[child.id]; exists {
		return errors.New("DUPLICATED_ID")
	}
	s.sessions[child.id] = child
	return nil
}
func (s *Server) session(id string) *samSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[id]
}
func (s *Server) removeSession(session *samSession) {
	s.mu.Lock()
	if s.sessions[session.id] == session {
		delete(s.sessions, session.id)
	}
	s.mu.Unlock()
}
func (s *Server) removeRoot(root *samSession) {
	s.mu.Lock()
	for id, session := range s.sessions {
		if session.root == root {
			delete(s.sessions, id)
		}
	}
	delete(s.destinations, root.endpoint.Hash())
	s.mu.Unlock()
}

var _ = fmt.Sprintf
