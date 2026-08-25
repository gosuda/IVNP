// Package sam provides a zero-dependency SAM v3 StreamNetwork adapter. It is
// an integration backend for a running I2P router, not a substitute for IVNP's
// embedded router/tunnel runtime.
package sam

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gosuda.org/ivnp"
)

const defaultAddress = "127.0.0.1:7656"

var (
	ErrUnavailable = errors.New("sam: network has not started")
	ErrClosed      = errors.New("sam: network is closed")
	ErrProtocol    = errors.New("sam: invalid bridge response")
	ErrAddress     = errors.New("sam: invalid I2P address")
	ErrListener    = errors.New("sam: stream listener already exists")
)

// Config defines one long-lived SAM STREAM session. Destination is either a
// persistent SAM private destination or empty for TRANSIENT. A persistent value
// belongs in caller-owned encrypted storage, never in source code.
type Config struct {
	Address          string
	ID               string
	Destination      string
	LeaseSetEncTypes []ivnp.CryptoKeyType
	// LeaseSetType is the I2CP LeaseSet type requested from the router. Zero
	// leaves the router default unchanged; 3 requests LeaseSet2.
	LeaseSetType  uint8
	SignatureType ivnp.SigningKeyType
	// SessionOptions carries validated I2CP tunnel options to the external
	// router. It is intended for standard options such as explicitPeers and
	// inbound/outbound length; values containing SAM token separators fail New.
	SessionOptions map[string]string
	Dialer         net.Dialer
}

// Network implements ivnp.StreamNetwork over an external SAM v3 bridge.
type Network struct {
	cfg Config

	mu                sync.Mutex
	control           *control
	privateDest       string
	publicDest        string
	local             samAddr
	listener          *listener
	closed            bool
	done              chan struct{}
	keepaliveDone     chan struct{}
	keepaliveInterval time.Duration
}

// New validates configuration without opening a bridge connection.
func New(cfg Config) (*Network, error) {
	if cfg.Address == "" {
		cfg.Address = defaultAddress
	}
	if cfg.ID == "" {
		var randomID [12]byte
		if _, err := rand.Read(randomID[:]); err != nil {
			return nil, err
		}
		cfg.ID = "ivnp-" + hex.EncodeToString(randomID[:])
	}
	if strings.ContainsAny(cfg.ID, " \t\r\n") {
		return nil, ErrAddress
	}
	if cfg.SignatureType == 0 {
		cfg.SignatureType = ivnp.SigningEdDSASHA512Ed25519
	}
	if len(cfg.LeaseSetEncTypes) == 0 {
		cfg.LeaseSetEncTypes = []ivnp.CryptoKeyType{ivnp.CryptoX25519}
	}
	for _, cryptoType := range cfg.LeaseSetEncTypes {
		if cryptoType != ivnp.CryptoX25519 && cryptoType != ivnp.CryptoMLKEM768X25519 && cryptoType != ivnp.CryptoMLKEM1024X25519 {
			return nil, ErrAddress
		}
	}
	for key, value := range cfg.SessionOptions {
		if !validSessionOption(key, value) {
			return nil, ErrAddress
		}
	}
	return &Network{cfg: cfg, done: make(chan struct{}), keepaliveInterval: time.Minute}, nil
}

// Start creates the long-lived SAM STREAM session. Router tunnel construction
// may take minutes, so callers should supply a context matching that reality.
func (n *Network) Start(ctx context.Context) error {
	if n == nil {
		return ErrUnavailable
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return ErrClosed
	}
	if n.control != nil {
		return nil
	}
	control, err := n.open(ctx)
	if err != nil {
		return err
	}
	destination := n.cfg.Destination
	transient := destination == ""
	if transient {
		destination = "TRANSIENT"
	}
	line := "SESSION CREATE STYLE=STREAM ID=" + n.cfg.ID + " DESTINATION=" + destination
	if transient {
		line += " SIGNATURE_TYPE=" + strconv.Itoa(int(n.cfg.SignatureType))
	}
	line += " i2cp.leaseSetEncType=" + cryptoTypes(n.cfg.LeaseSetEncTypes)
	if n.cfg.LeaseSetType != 0 {
		line += " i2cp.leaseSetType=" + strconv.Itoa(int(n.cfg.LeaseSetType))
	}
	keys := make([]string, 0, len(n.cfg.SessionOptions))
	for key := range n.cfg.SessionOptions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		line += " " + key + "=" + n.cfg.SessionOptions[key]
	}
	fields, err := control.commandContext(ctx, line)
	if err != nil {
		control.Close()
		return err
	}
	if fields["RESULT"] != "OK" || fields["DESTINATION"] == "" {
		control.Close()
		return statusError("SESSION STATUS", fields)
	}
	privateDest := fields["DESTINATION"]
	publicDest, addr, err := publicAddress(privateDest)
	if err != nil {
		control.Close()
		return err
	}
	n.control, n.privateDest, n.publicDest, n.local = control, privateDest, publicDest, addr
	if compareVersion(control.version, [2]int{3, 2}) >= 0 {
		n.keepaliveDone = make(chan struct{})
		go n.keepalive(control, n.keepaliveDone)
	}
	return nil
}

// PrivateDestination returns the SAM private destination generated or accepted
// by Start. Callers that need persistence must store it securely; it is empty
// before Start and after Close.
func (n *Network) PrivateDestination() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.privateDest
}

// PublicDestination returns the I2P-base64 public destination of this session.
func (n *Network) PublicDestination() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.publicDest
}

// B32 returns the b32.i2p hostname assigned to this session destination.
func (n *Network) B32() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.local.host
}

func (n *Network) DialI2P(ctx context.Context, address string) (net.Conn, error) {
	if n == nil {
		return nil, ErrUnavailable
	}
	host, port, err := parseAddress(address)
	if err != nil {
		return nil, err
	}
	if err = n.running(); err != nil {
		return nil, err
	}
	control, err := n.open(ctx)
	if err != nil {
		return nil, err
	}
	line := "STREAM CONNECT ID=" + n.cfg.ID + " DESTINATION=" + host + " TO_PORT=" + strconv.Itoa(port)
	fields, err := control.commandContext(ctx, line)
	if err != nil {
		control.Close()
		return nil, err
	}
	if fields["RESULT"] != "OK" {
		control.Close()
		return nil, statusError("STREAM STATUS", fields)
	}
	return &streamConn{Conn: control.Conn, reader: control.reader, local: n.local, remote: samAddr{host: host, port: port}}, nil
}

func (n *Network) ListenI2P(ctx context.Context, address string) (net.Listener, error) {
	if n == nil {
		return nil, ErrUnavailable
	}
	_, port, err := parseListenAddress(address)
	if err != nil {
		return nil, err
	}
	if err = n.running(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.listener != nil {
		return nil, ErrListener
	}
	listener := &listener{network: n, local: samAddr{host: n.local.host, port: port}, done: make(chan struct{})}
	n.listener = listener
	return listener, nil
}

// Close terminates the SAM session and any pending Accept. It invalidates the
// private destination string held by this Network but never deletes caller
// persistence of that key.
func (n *Network) Close() error {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return ErrClosed
	}
	n.closed = true
	listener := n.listener
	control := n.control
	keepaliveDone := n.keepaliveDone
	n.listener, n.control, n.privateDest, n.publicDest, n.keepaliveDone = nil, nil, "", "", nil
	close(n.done)
	n.mu.Unlock()
	var err error
	if listener != nil {
		err = listener.Close()
	}
	if control != nil {
		if closeErr := control.Close(); err == nil {
			err = closeErr
		}
	}
	if keepaliveDone != nil {
		<-keepaliveDone
	}
	return err
}

func (n *Network) keepalive(control *control, stopped chan struct{}) {
	defer close(stopped)
	ticker := time.NewTicker(n.keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.done:
			return
		case <-ticker.C:
			fields, err := control.command("PING ivnp-keepalive")
			if err != nil || fields["COMMAND"] != "PONG" {
				return
			}
		}
	}
}

func (n *Network) running() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return ErrClosed
	}
	if n.control == nil {
		return ErrUnavailable
	}
	return nil
}

func (n *Network) open(ctx context.Context) (*control, error) {
	connection, err := n.cfg.Dialer.DialContext(ctx, "tcp", n.cfg.Address)
	if err != nil {
		return nil, err
	}
	control := &control{Conn: connection, reader: bufio.NewReader(connection)}
	fields, err := control.commandContext(ctx, "HELLO VERSION MIN=3.1 MAX=3.3")
	if err != nil {
		control.Close()
		return nil, err
	}
	version, versionErr := parseVersion(fields["VERSION"], [2]int{})
	if fields["RESULT"] != "OK" || versionErr != nil {
		control.Close()
		if versionErr != nil {
			return nil, ErrProtocol
		}
		return nil, statusError("HELLO REPLY", fields)
	}
	control.version = version
	return control, nil
}

type control struct {
	net.Conn
	reader  *bufio.Reader
	version [2]int
}

func (c *control) command(line string) (map[string]string, error) {
	if _, err := c.Write(append([]byte(line), '\n')); err != nil {
		return nil, err
	}
	response, err := c.reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	return parseResponse(response)
}

func (c *control) commandContext(ctx context.Context, line string) (map[string]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		if err := c.SetDeadline(deadline); err != nil {
			return nil, err
		}
		defer c.SetDeadline(time.Time{})
	}
	fields, err := c.command(line)
	if err == nil {
		return fields, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	var networkError net.Error
	if hasDeadline && errors.As(err, &networkError) && networkError.Timeout() && !time.Now().Before(deadline) {
		// A socket deadline can fire just before the context timer publishes
		// Done. The socket deadline came from this context, so expose the
		// context contract rather than the transport-specific timeout.
		return nil, context.DeadlineExceeded
	}
	return nil, err
}

func parseResponse(line string) (map[string]string, error) {
	parts, err := splitSAMResponse(strings.TrimSpace(line))
	if err != nil || len(parts) < 2 {
		return nil, ErrProtocol
	}
	fields := make(map[string]string, len(parts))
	fields["COMMAND"], fields["SUBCOMMAND"] = parts[0], parts[1]
	for _, part := range parts[2:] {
		key, value, found := strings.Cut(part, "=")
		if !found || key == "" {
			return nil, ErrProtocol
		}
		fields[key] = value
	}
	return fields, nil
}

func splitSAMResponse(line string) ([]string, error) {
	parts := make([]string, 0, 8)
	var token strings.Builder
	quoted, escaped := false, false
	flush := func() {
		if token.Len() != 0 {
			parts = append(parts, token.String())
			token.Reset()
		}
	}
	for _, current := range line {
		switch {
		case escaped:
			token.WriteRune(current)
			escaped = false
		case quoted && current == '\\':
			escaped = true
		case current == '"':
			quoted = !quoted
		case !quoted && (current == ' ' || current == '\t'):
			flush()
		default:
			token.WriteRune(current)
		}
	}
	if quoted || escaped {
		return nil, ErrProtocol
	}
	flush()
	return parts, nil
}

func statusError(kind string, fields map[string]string) error {
	if fields == nil {
		return ErrProtocol
	}
	if message := fields["MESSAGE"]; message != "" {
		return fmt.Errorf("sam: %s %s: %s", kind, fields["RESULT"], message)
	}
	return fmt.Errorf("sam: %s %s", kind, fields["RESULT"])
}

type listener struct {
	network *Network
	local   samAddr

	mu     sync.Mutex
	active net.Conn
	done   chan struct{}
	closed bool
}

func (l *listener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	l.mu.Unlock()
	if err := l.network.running(); err != nil {
		return nil, err
	}
	control, err := l.network.open(context.Background())
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		control.Close()
		return nil, net.ErrClosed
	}
	l.active = control.Conn
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		if l.active == control.Conn {
			l.active = nil
		}
		l.mu.Unlock()
	}()
	fields, err := control.command("STREAM ACCEPT ID=" + l.network.cfg.ID)
	if err != nil || fields["RESULT"] != "OK" {
		control.Close()
		if err != nil {
			return nil, err
		}
		return nil, statusError("STREAM STATUS", fields)
	}
	peer, err := control.reader.ReadString('\n')
	if err != nil {
		control.Close()
		return nil, err
	}
	peer = strings.TrimSpace(peer)
	if strings.HasPrefix(peer, "STREAM STATUS ") {
		control.Close()
		fields, parseErr := parseResponse(peer)
		if parseErr != nil {
			return nil, parseErr
		}
		return nil, statusError("STREAM STATUS", fields)
	}
	remote, toPort, err := parseAcceptedPeer(peer)
	if err != nil {
		control.Close()
		return nil, err
	}
	local := l.local
	if toPort != 0 {
		if local.port != 0 && local.port != toPort {
			control.Close()
			return nil, ErrAddress
		}
		local.port = toPort
	}
	return &streamConn{Conn: control.Conn, reader: control.reader, local: local, remote: remote}, nil
}

func (l *listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return net.ErrClosed
	}
	l.closed = true
	active := l.active
	close(l.done)
	l.mu.Unlock()
	if active != nil {
		return active.Close()
	}
	return nil
}

func (l *listener) Addr() net.Addr { return l.local }

type streamConn struct {
	net.Conn
	reader        *bufio.Reader
	local, remote net.Addr
}

func (c *streamConn) Read(dst []byte) (int, error) { return c.reader.Read(dst) }
func (c *streamConn) LocalAddr() net.Addr          { return c.local }
func (c *streamConn) RemoteAddr() net.Addr         { return c.remote }

type samAddr struct {
	host string
	port int
}

func (a samAddr) Network() string { return "i2p" }
func (a samAddr) String() string {
	if a.port == 0 {
		return a.host
	}
	return net.JoinHostPort(a.host, strconv.Itoa(a.port))
}

func parseAcceptedPeer(line string) (samAddr, int, error) {
	parts := strings.Fields(line)
	if len(parts) == 0 || parts[0] == "" {
		return samAddr{}, 0, ErrProtocol
	}
	remote := samAddr{host: parts[0]}
	toPort := 0
	for _, field := range parts[1:] {
		key, value, found := strings.Cut(field, "=")
		if !found {
			return samAddr{}, 0, ErrProtocol
		}
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return samAddr{}, 0, ErrProtocol
		}
		switch key {
		case "FROM_PORT":
			if remote.port != 0 {
				return samAddr{}, 0, ErrProtocol
			}
			remote.port = int(port)
		case "TO_PORT":
			if toPort != 0 {
				return samAddr{}, 0, ErrProtocol
			}
			toPort = int(port)
		default:
			return samAddr{}, 0, ErrProtocol
		}
	}
	return remote, toPort, nil
}

func parseAddress(address string) (string, int, error) {
	if address == "" {
		return "", 0, ErrAddress
	}
	host, port, err := net.SplitHostPort(address)
	if err == nil {
		value, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || host == "" {
			return "", 0, ErrAddress
		}
		return host, int(value), nil
	}
	if strings.Contains(address, ":") {
		return "", 0, ErrAddress
	}
	return address, 0, nil
}

func parseListenAddress(address string) (string, int, error) {
	if address == "" {
		return "", 0, nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, ErrAddress
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", 0, ErrAddress
	}
	return host, int(value), nil
}

func cryptoTypes(types []ivnp.CryptoKeyType) string {
	values := make([]string, len(types))
	for index, cryptoType := range types {
		values[index] = strconv.Itoa(int(cryptoType))
	}
	return strings.Join(values, ",")
}

func validSessionOption(key, value string) bool {
	if key == "" || value == "" || strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	for _, character := range key {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func publicAddress(privateDestination string) (string, samAddr, error) {
	encoding := base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~")
	decoded := make([]byte, encoding.DecodedLen(len(privateDestination)))
	n, err := encoding.Decode(decoded, []byte(privateDestination))
	if err != nil {
		return "", samAddr{}, err
	}
	identity, used, err := ivnp.ParseIdentity(decoded[:n])
	if err != nil || used == 0 {
		return "", samAddr{}, ErrProtocol
	}
	public := string(privateDestination[:encoding.EncodedLen(used)])
	hash := identity.Hash()
	b32 := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])) + ".b32.i2p"
	return public, samAddr{host: b32}, nil
}
