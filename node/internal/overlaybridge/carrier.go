package overlaybridge

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"sort"
	"sync"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/overlay"
)

// carrierTransportToken is the Endpoint transport token for the IVNP-TLS
// direct carrier ("ivnp-tls@ip:port").
const carrierTransportToken = "ivnp-tls"

var errUnknownEndpointSNI = errors.New("overlaybridge: unknown endpoint sni")

var errSignerRawEd25519 = errors.New("overlaybridge: destination signer is raw Ed25519 only")

const (
	frameMagic      = "IVNPA1"
	replyMagic      = "IVNPR1"
	frameMaxBytes   = 8192
	frameFixedBytes = 111 // fabric|netID|realm|endpoint|port|selector|protocol|class|exposure|policyGen
	setupDeadline   = 15 * time.Second
	inboundQueueCap = 32
	exporterLabel   = "ivnp-admission-v1"
)

// carrierMux is the host-level provider: it dispatches Setup to the fabric
// the candidate names and merges inbound deliveries per service across every
// fabric listener the service's realm binds.
type carrierMux struct {
	secrets *staticSecrets
	mu      sync.Mutex
	fabrics map[overlay.FabricID]*fabricCarrier
	// services indexes (fabric, endpoint, port) to the service's merged
	// inbound queue; bySvc tracks a service's keys for cleanup.
	services map[routeKey]*serviceQueue
	bySvc    map[*overlay.Service]map[routeKey]struct{}
	closed   bool
}

type routeKey struct {
	fabric   overlay.FabricID
	endpoint overlay.EndpointID
	port     uint16
}

type serviceQueue struct {
	svc   *overlay.Service
	queue chan inboundDelivery
}

type inboundDelivery struct {
	channel overlay.Channel
	scope   overlay.ChannelScope
}

// Carrier names the single carrier implementation; every fabric channel this
// mux produces is ivnp-tls.
func (m *carrierMux) Carrier() string { return carrierTransportToken }

// Capabilities reports honest limits: TLS 1.3 exporter, direct binding only,
// and setup that is safe to race — a canceled handshake never reaches remote
// acceptance because admission completes before the channel exists.
func (m *carrierMux) Capabilities() overlay.TransportCapabilities {
	return overlay.TransportCapabilities{Exporter: true, DirectBinding: true, Speculative: true}
}

// Setup delegates to the carrier owning the candidate's fabric; an unknown
// fabric can never produce a channel.
func (m *carrierMux) Setup(ctx context.Context, candidate overlay.RouteCandidate, scope overlay.ChannelScope, admission *overlay.AdmissionRequest) (overlay.Channel, error) {
	m.mu.Lock()
	carrier := m.fabrics[candidate.Fabric]
	closed := m.closed
	m.mu.Unlock()
	if closed || carrier == nil {
		return nil, overlay.CodeFabricMismatch.Wrap("no carrier for the candidate's fabric")
	}
	if carrier.fabric != scope.Fabric || carrier.netID != scope.NetworkID {
		return nil, overlay.CodeFabricMismatch.Wrap("scope does not name the candidate's fabric")
	}
	return carrier.setup(ctx, candidate, scope, admission)
}

// Accept returns the next inbound channel routed to svc. The first call
// materializes the service's queue registration.
func (m *carrierMux) Accept(ctx context.Context, svc *overlay.Service) (overlay.Channel, overlay.ChannelScope, error) {
	entry, err := m.queueFor(svc)
	if err != nil {
		return nil, overlay.ChannelScope{}, err
	}
	select {
	case delivery := <-entry.queue:
		return delivery.channel, delivery.scope, nil
	case <-ctx.Done():
		return nil, overlay.ChannelScope{}, ctx.Err()
	}
}

// queueFor resolves a service's merged inbound queue; the bridge registers
// services at OpenService, so an unknown service cannot accept inbound.
func (m *carrierMux) queueFor(svc *overlay.Service) (*serviceQueue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errBridgeDown
	}
	keys, ok := m.bySvc[svc]
	if !ok {
		return nil, overlay.CodeUnsupportedCapability.Wrap("service is not registered for inbound")
	}
	for key := range keys {
		if entry := m.services[key]; entry != nil {
			return entry, nil
		}
	}
	return nil, overlay.CodeUnsupportedCapability.Wrap("service is not registered for inbound")
}

// trackService registers a service's inbound routing on the realm's bound
// IVNP fabrics only; a channel arriving on a fabric the realm does not bind
// can never be routed to the service.
func (m *carrierMux) trackService(svc *overlay.Service, fabrics map[overlay.FabricID]struct{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errBridgeDown
	}
	if _, ok := m.bySvc[svc]; ok {
		return nil
	}
	entry := &serviceQueue{svc: svc, queue: make(chan inboundDelivery, inboundQueueCap)}
	keys := make(map[routeKey]struct{}, len(fabrics))
	for fabricID := range fabrics {
		if m.fabrics[fabricID] == nil {
			continue
		}
		key := routeKey{fabric: fabricID, endpoint: svc.Endpoint().ID, port: svc.Port()}
		m.services[key] = entry
		keys[key] = struct{}{}
	}
	m.bySvc[svc] = keys
	return nil
}

// registerServiceKey installs the service endpoint's TLS contact key: the
// destination's Ed25519 signing key, presented per SNI.
func (m *carrierMux) registerServiceKey(svc *overlay.Service, destination *foundation.LocalDestination) error {
	if destination == nil {
		return overlay.CodeInvalidConfig.Wrap("service key requires a destination")
	}
	if destination.SigningKeyType() != foundation.SigningEdDSASHA512Ed25519 {
		return overlay.CodeInvalidConfig.Wrap("ivnp-tls contact keys require Ed25519 signing")
	}
	cert, err := selfSignedCert(&destinationSigner{destination: destination})
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errBridgeDown
	}
	for key := range m.bySvc[svc] {
		if carrier := m.fabrics[key.fabric]; carrier != nil {
			carrier.certsMu.Lock()
			carrier.certs[key.endpoint] = cert
			carrier.certsMu.Unlock()
		}
	}
	return nil
}

// untrackService drops a closed service's inbound routes and TLS contact
// keys; OpenService watches Service.Done to call it. Endpoint ownership is
// exclusive, so the contact key can go with the service.
func (m *carrierMux) untrackService(svc *overlay.Service) {
	m.mu.Lock()
	keys := m.bySvc[svc]
	delete(m.bySvc, svc)
	carriers := make(map[*fabricCarrier]struct{}, len(keys))
	for key := range keys {
		delete(m.services, key)
		if carrier := m.fabrics[key.fabric]; carrier != nil {
			carriers[carrier] = struct{}{}
		}
	}
	m.mu.Unlock()
	for carrier := range carriers {
		carrier.certsMu.Lock()
		delete(carrier.certs, svc.Endpoint().ID)
		carrier.certsMu.Unlock()
	}
}

// presenceContact selects the realm-bound fabric whose carrier holds the
// endpoint's contact key and returns its public contact endpoints. The pick
// is deterministic — lowest fabric identity — so a republish of unchanged
// content reuses its durable position instead of consuming a new one.
func (m *carrierMux) presenceContact(endpoint overlay.EndpointID, realmFabrics map[overlay.FabricID]struct{}) (overlay.FabricID, *fabricCarrier, []overlay.Endpoint) {
	m.mu.Lock()
	candidates := make([]*fabricCarrier, 0, len(m.fabrics))
	for id, carrier := range m.fabrics {
		if _, bound := realmFabrics[id]; bound {
			candidates = append(candidates, carrier)
		}
	}
	m.mu.Unlock()
	sort.Slice(candidates, func(i, j int) bool {
		return bytes.Compare(candidates[i].fabric[:], candidates[j].fabric[:]) < 0
	})
	for _, carrier := range candidates {
		if carrier.hasCert(endpoint) {
			return carrier.fabric, carrier, carrier.publicEndpoints()
		}
	}
	return overlay.FabricID{}, nil, nil
}

// openFabric binds a fabric's listeners and registers its carrier.
func (m *carrierMux) openFabric(cfg overlay.FabricConfig) (*fabricCarrier, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errBridgeDown
	}
	carrier := &fabricCarrier{
		mux: m, fabric: cfg.Descriptor.ID, netID: cfg.Descriptor.NetworkID,
		maxPeers: cfg.Descriptor.MaxPeers, certs: make(map[overlay.EndpointID]*tls.Certificate),
		done: make(chan struct{}),
	}
	for _, listen := range cfg.Listeners {
		addr, err := net.ResolveTCPAddr("tcp", listen)
		if err != nil {
			return nil, overlay.CodeInvalidConfig.Wrap("fabric listener address")
		}
		listener, err := net.ListenTCP("tcp", addr)
		if err != nil {
			carrier.close()
			return nil, err
		}
		carrier.listeners = append(carrier.listeners, listener)
		carrier.acceptWG.Add(1)
		go carrier.acceptLoop(listener)
	}
	m.fabrics[carrier.fabric] = carrier
	return carrier, nil
}

// bootstrapRefs projects the configured fabric membership into discovery
// hints for one realm.
func (m *carrierMux) bootstrapRefs(realm overlay.RealmID, limit int) []overlay.PeerRef {
	m.mu.Lock()
	fabrics := make([]*fabricCarrier, 0, len(m.fabrics))
	for _, carrier := range m.fabrics {
		fabrics = append(fabrics, carrier)
	}
	m.mu.Unlock()
	var out []overlay.PeerRef
	for _, carrier := range fabrics {
		if carrier.table == nil {
			continue
		}
		carrier.table.mu.Lock()
		for hash := range carrier.table.peers {
			if limit > 0 && len(out) >= limit {
				carrier.table.mu.Unlock()
				return out
			}
			out = append(out, overlay.PeerRef{
				Realm: realm,
				Locator: overlay.Locator{
					Kind: overlay.LocatorDestinationHash, Hash: hash,
				},
			})
		}
		carrier.table.mu.Unlock()
	}
	return out
}

// deliver routes one verified inbound channel into the addressed service's
// queue, stamping the policy generation at delivery.
func (m *carrierMux) deliver(key routeKey, channel *tlsChannel) bool {
	m.mu.Lock()
	entry := m.services[key]
	m.mu.Unlock()
	if entry == nil {
		return false
	}
	channel.scope.PolicyGen = entry.svc.PolicyGen()
	select {
	case entry.queue <- inboundDelivery{channel: channel, scope: channel.scope}:
		return true
	default:
		return false
	}
}

func (m *carrierMux) close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	carriers := make([]*fabricCarrier, 0, len(m.fabrics))
	for _, carrier := range m.fabrics {
		carriers = append(carriers, carrier)
	}
	m.mu.Unlock()
	if m.secrets != nil {
		m.secrets.wipe()
	}
	var result error
	for _, carrier := range carriers {
		result = errors.Join(result, carrier.close())
	}
	return result
}

// fabricCarrier owns one fabric's listeners and service keys. Its identity is
// never a per-fabric node key: channels authenticate the service's own
// destination key, pinned by the candidate's ContactKey. table is the owning
// context's membership table, set when the runtime opens.
type fabricCarrier struct {
	mux       *carrierMux
	fabric    overlay.FabricID
	netID     overlay.WireNetworkID
	maxPeers  int
	listeners []*net.TCPListener
	// advertise carries the operator-declared public contact endpoints a
	// presence projection may list; listener addresses join only when they
	// are themselves public.
	advertise []overlay.Endpoint
	certsMu   sync.Mutex
	certs     map[overlay.EndpointID]*tls.Certificate
	table     *fabricRuntime
	done      chan struct{}
	closeOnce sync.Once
	acceptWG  sync.WaitGroup
	serveMu   sync.Mutex
	serving   sync.WaitGroup
	closed    bool
}

// live reports whether at least one listener is bound and the carrier is not
// closed.
func (c *fabricCarrier) live() bool {
	select {
	case <-c.done:
		return false
	default:
		return len(c.listeners) > 0
	}
}

// hasCert reports whether the endpoint's contact key is registered for
// inbound TLS on this fabric.
func (c *fabricCarrier) hasCert(endpoint overlay.EndpointID) bool {
	c.certsMu.Lock()
	defer c.certsMu.Unlock()
	_, ok := c.certs[endpoint]
	return ok
}

// publicEndpoints returns the fabric's configured advertise endpoints plus
// listener addresses public enough for a cleartext record, deduplicated and
// capped at the presence format's two-endpoint limit.
func (c *fabricCarrier) publicEndpoints() []overlay.Endpoint {
	seen := make(map[overlay.Endpoint]struct{})
	out := make([]overlay.Endpoint, 0, 2)
	appendPublic := func(ep overlay.Endpoint) {
		if _, dup := seen[ep]; dup || len(out) >= 2 || !ep.Public() {
			return
		}
		seen[ep] = struct{}{}
		out = append(out, ep)
	}
	for _, ep := range c.advertise {
		appendPublic(ep)
	}
	for _, listener := range c.listeners {
		if tcp, ok := listener.Addr().(*net.TCPAddr); ok {
			appendPublic(overlay.Endpoint{Transport: carrierTransportToken, Address: tcp.AddrPort()})
		}
	}
	return out
}

func (c *fabricCarrier) close() error {
	c.closeOnce.Do(func() {
		c.serveMu.Lock()
		c.closed = true
		c.serveMu.Unlock()
		close(c.done)
		for _, listener := range c.listeners {
			_ = listener.Close()
		}
	})
	c.acceptWG.Wait()
	c.serving.Wait()
	return nil
}

// setup establishes an outbound ivnp-tls channel: TCP connect, TLS 1.3 with
// the peer's contact key pinned, exporter-bound admission frame, then the
// verified scope echo. The returned channel's Binding equals the requested
// scope or the attempt fails.
func (c *fabricCarrier) setup(ctx context.Context, candidate overlay.RouteCandidate, scope overlay.ChannelScope, admission *overlay.AdmissionRequest) (overlay.Channel, error) {
	if candidate.Contact == nil {
		return nil, overlay.CodeUnreachable.Wrap("candidate carries no direct contact")
	}
	if candidate.ContactKey == ([32]byte{}) {
		return nil, overlay.CodeEndpointBindingInvalid.Wrap("direct candidate requires a pinned contact key")
	}
	dialer := &net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp", candidate.Contact.Address.String())
	if err != nil {
		return nil, err
	}
	pin := candidate.ContactKey
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         hex.EncodeToString(candidate.Endpoint[:]),
		InsecureSkipVerify: true, // the pinned contact key is the verification
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPinnedKey(rawCerts, pin)
		},
	}
	conn := tls.Client(raw, tlsConfig)
	failTLS := func(err error) (overlay.Channel, error) {
		_ = conn.Close()
		return nil, err
	}
	if err := handshakeContext(ctx, conn); err != nil {
		return failTLS(err)
	}
	exporter, err := exporterKey(conn)
	if err != nil {
		return failTLS(err)
	}
	var credential []byte
	if admission != nil && admission.Credential != nil {
		credential = admission.Credential.Credential
	}
	frame, err := encodeFrame(scope, credential, admissionKey(admission), exporter)
	if err != nil {
		return failTLS(err)
	}
	if err := writeAll(conn, frame); err != nil {
		return failTLS(err)
	}
	replyScope, replyCredential, err := readReply(conn)
	if err != nil {
		return failTLS(err)
	}
	if replyScope != scope {
		return failTLS(overlay.CodeEndpointBindingInvalid.Wrap("responder did not commit the requested scope"))
	}
	_ = conn.SetDeadline(time.Time{})
	return &tlsChannel{
		Conn: conn, scope: scope, peerKey: pin,
		member: &overlay.IdentityProof{Realm: scope.Realm, Credential: replyCredential},
	}, nil
}

// acceptLoop serves one listener until the carrier closes; a listener error
// after close is expected shutdown, not a reportable failure.
func (c *fabricCarrier) acceptLoop(listener *net.TCPListener) {
	defer c.acceptWG.Done()
	for {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		c.serveMu.Lock()
		if c.closed {
			c.serveMu.Unlock()
			_ = raw.Close()
			return
		}
		c.serving.Add(1)
		c.serveMu.Unlock()
		go func() {
			defer c.serving.Done()
			c.serve(raw)
		}()
	}
}

// serve completes one inbound channel: TLS handshake, admission frame,
// per-service routing, and scope verification against the addressed
// service's live policy.
func (c *fabricCarrier) serve(raw net.Conn) {
	fail := func() { _ = raw.Close() }
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequestClientCert,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return c.certificateFor(hello.ServerName)
		},
	}
	conn := tls.Server(raw, tlsConfig)
	ctx, cancel := context.WithTimeout(context.Background(), setupDeadline)
	defer cancel()
	if err := handshakeContext(ctx, conn); err != nil {
		fail()
		return
	}
	exporter, err := exporterKey(conn)
	if err != nil {
		fail()
		return
	}
	scope, credential, mac, rawScope, err := readFrame(conn)
	if err != nil {
		fail()
		return
	}
	if scope.Fabric != c.fabric || scope.NetworkID != c.netID ||
		scope.Class != overlay.RouteDirect || scope.Exposure != overlay.PrivacyExplicitDirect {
		fail()
		return
	}
	key := routeKey{fabric: c.fabric, endpoint: scope.Endpoint, port: scope.Port}
	c.mux.mu.Lock()
	entry := c.mux.services[key]
	c.mux.mu.Unlock()
	if entry == nil || entry.svc.RealmID() != scope.Realm {
		c.reject(conn)
		return
	}
	if err := c.admitInbound(entry.svc, scope, mac, rawScope, exporter); err != nil {
		c.reject(conn)
		return
	}
	var peerKey [32]byte
	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		if pub, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey); ok && len(pub) == 32 {
			copy(peerKey[:], pub)
		}
	}
	channel := &tlsChannel{
		Conn: conn, scope: scope, peerKey: peerKey,
		member: &overlay.IdentityProof{Realm: scope.Realm, Credential: credential, ChannelKey: peerKey},
	}
	if !c.mux.deliver(key, channel) {
		c.reject(conn)
		return
	}
	// The reply echoes the claims as received. PolicyGen is a host-local
	// counter: the client compares its own generation, and this realm's
	// listener independently rejects a channel delivered under a superseded
	// local generation, so neither side may evaluate the other's value.
	if err := writeReply(conn, scope, nil); err != nil {
		fail()
		return
	}
	_ = conn.SetDeadline(time.Time{})
}

// admitInbound evaluates the realm's current admission mode against the
// presented material at delivery time, never at listener setup time.
func (c *fabricCarrier) admitInbound(svc *overlay.Service, scope overlay.ChannelScope, mac, rawScope, exporter []byte) error {
	switch svc.Admission() {
	case overlay.AdmissionPSK, overlay.AdmissionCredentialPSK:
		if err := c.verifyPSK(scope.Realm, mac, rawScope, exporter); err != nil {
			return err
		}
	}
	return nil
}

// verifyPSK recomputes the exporter-bound proof under the realm's leased key
// in constant time. The lease is released before returning.
func (c *fabricCarrier) verifyPSK(realm overlay.RealmID, mac, rawScope, exporter []byte) error {
	if c.mux.secrets == nil {
		return overlay.CodeUnsupportedCapability.Wrap("psk realm has no secret provider")
	}
	lease, err := c.mux.secrets.Lease(context.Background(), realm, overlay.KeyPurposeNetworkAdmission)
	if err != nil {
		return err
	}
	defer lease.Release()
	if subtle.ConstantTimeCompare(mac, admissionMAC(lease.Key(), exporter, rawScope)) != 1 {
		return overlay.CodeMembershipDenied.Wrap("admission proof mismatch")
	}
	return nil
}

// certificateFor resolves the service's contact-key certificate by SNI. An
// unknown endpoint has no certificate — the handshake fails.
func (c *fabricCarrier) certificateFor(serverName string) (*tls.Certificate, error) {
	raw, err := hex.DecodeString(serverName)
	if err != nil || len(raw) != 32 {
		return nil, errUnknownEndpointSNI
	}
	var endpoint overlay.EndpointID
	copy(endpoint[:], raw)
	c.certsMu.Lock()
	defer c.certsMu.Unlock()
	cert, ok := c.certs[endpoint]
	if !ok {
		return nil, errUnknownEndpointSNI
	}
	return cert, nil
}

// reject reports a failed admission honestly then closes.
func (c *fabricCarrier) reject(conn *tls.Conn) {
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte{0})
	_ = conn.Close()
}

// tlsChannel is an authenticated setup result over TLS 1.3.
type tlsChannel struct {
	*tls.Conn
	scope   overlay.ChannelScope
	peerKey [32]byte
	member  *overlay.IdentityProof
}

func (c *tlsChannel) Binding() (overlay.ChannelScope, [32]byte) { return c.scope, c.peerKey }

// PeerMembership returns the credential evidence the peer presented, if any.
// Only the document is authoritative; realm/key fields are parse hints.
func (c *tlsChannel) PeerMembership() (overlay.IdentityProof, bool) {
	if c.member == nil || len(c.member.Credential) == 0 {
		return overlay.IdentityProof{}, false
	}
	return *c.member, true
}

// streamSessions binds the negotiated endpoint protocol to admitted
// channels; the channel itself is the byte stream.
type streamSessions struct{}

func (streamSessions) Open(ctx context.Context, channel overlay.Channel, target overlay.ServiceTarget) (overlay.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scope, _ := channel.Binding()
	return &streamSession{channel: channel, protocol: scope.Protocol}, nil
}

type streamSession struct {
	channel  overlay.Channel
	protocol overlay.EndpointProtocol
}

func (s *streamSession) Protocol() overlay.EndpointProtocol { return s.protocol }

// Resume reports no negotiated resumption contract; a reconnect is a fresh
// session.
func (s *streamSession) Resume() (overlay.ResumeContract, error) {
	return overlay.ResumeContract{Supported: false}, nil
}

func (s *streamSession) Close() error { return s.channel.Close() }

var _ overlay.TransportProvider = (*carrierMux)(nil)
var _ overlay.InboundProvider = (*carrierMux)(nil)
var _ overlay.SessionProvider = streamSessions{}
var _ overlay.Channel = (*tlsChannel)(nil)
var _ overlay.MembershipChannel = (*tlsChannel)(nil)

// admissionKey extracts the leased network key for the MAC, when the realm's
// mode provided one.
func admissionKey(admission *overlay.AdmissionRequest) []byte {
	if admission == nil || len(admission.NetworkKey) == 0 {
		return nil
	}
	return admission.NetworkKey
}

// admissionMAC computes the exporter-bound admission proof over the frame
// body exactly as received: magic || scope || credential — so a forged field
// anywhere in the frame invalidates the proof.
func admissionMAC(key, exporter, body []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(exporterLabel))
	h.Write(exporter)
	h.Write(body)
	return h.Sum(nil)
}

// exporterKey returns the channel's RFC 8446 exporter, the admission proof's
// channel binding.
func exporterKey(conn *tls.Conn) ([]byte, error) {
	state := conn.ConnectionState()
	return state.ExportKeyingMaterial(exporterLabel, nil, 32)
}

// handshakeContext runs the TLS handshake under the caller's deadline.
func handshakeContext(ctx context.Context, conn *tls.Conn) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(setupDeadline))
	}
	return conn.HandshakeContext(ctx)
}

// verifyPinnedKey authenticates the peer certificate by the candidate's
// pinned contact key: the certificate's Ed25519 public key must equal it.
// TLS 1.3's CertificateVerify then proves private-key possession.
func verifyPinnedKey(rawCerts [][]byte, pin [32]byte) error {
	if len(rawCerts) == 0 {
		return overlay.CodeEndpointBindingInvalid.Wrap("peer presented no certificate")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return overlay.CodeEndpointBindingInvalid.Wrap("peer certificate does not parse")
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(pub) != 32 || subtle.ConstantTimeCompare(pub, pin[:]) != 1 {
		return overlay.CodeEndpointBindingInvalid.Wrap("peer certificate does not hold the pinned contact key")
	}
	return nil
}

// destinationSigner adapts an owned LocalDestination to crypto.Signer so the
// destination's signing key serves as its TLS contact key without exporting
// private material.
type destinationSigner struct {
	destination *foundation.LocalDestination
}

func (s *destinationSigner) Public() crypto.PublicKey {
	return s.destination.SigningPublic()
}

func (s *destinationSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errSignerRawEd25519
	}
	return s.destination.Sign(digest)
}

// selfSignedCert builds a minimal self-signed certificate over the service's
// Ed25519 key. The certificate is a key container; the TLS handshake's
// CertificateVerify carries the actual proof.
func selfSignedCert(signer crypto.Signer) (*tls.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ivnp-contact"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: signer}, nil
}
