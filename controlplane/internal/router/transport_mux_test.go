package router

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

type muxIPv4Listener struct{}

func (muxIPv4Listener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (muxIPv4Listener) Close() error              { return nil }
func (muxIPv4Listener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

type muxTestTransport struct {
	mu sync.Mutex

	startErr error
	closeErr error
	waitErr  error
	sendErr  error
	status   dataplane.RouterTransportStatus

	starts        int
	closes        int
	waits         int
	sends         int
	authenticated bool
}

func (m *muxTestTransport) Start(context.Context, dataplane.RouterTransportBindings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.starts++
	return m.startErr
}

func (m *muxTestTransport) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closes++
	m.authenticated = false
	return m.closeErr
}

func (m *muxTestTransport) Wait() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.waits++
	return m.waitErr
}

func (m *muxTestTransport) Send(context.Context, foundation.Hash, foundation.I2NPMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sends++
	return m.sendErr
}

func (m *muxTestTransport) Status() dataplane.RouterTransportStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *muxTestTransport) counts() (starts, closes, waits, sends int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.starts, m.closes, m.waits, m.sends
}

type muxMessageSender func(context.Context, foundation.I2NPMessage) error

func (s muxMessageSender) Send(ctx context.Context, message foundation.I2NPMessage) error {
	return s(ctx, message)
}

func (m *muxTestTransport) EnsureSession(context.Context, foundation.Hash) error {
	m.mu.Lock()
	m.authenticated = true
	m.mu.Unlock()
	return nil
}

func (m *muxTestTransport) PreparedSession(peer foundation.Hash) (dataplane.RouterSessionSender, error) {
	m.mu.Lock()
	authenticated := m.authenticated
	m.mu.Unlock()
	if !authenticated {
		return nil, dataplane.RouterErrSessionUnavailable
	}
	return muxMessageSender(func(ctx context.Context, message foundation.I2NPMessage) error {
		return m.Send(ctx, peer, message)
	}), nil
}

type muxSessionTransport struct {
	*muxTestTransport
	ensureStarted chan struct{}
	ensureRelease chan error
	session       bool
	drops         int
}

func newMuxSessionTransport() *muxSessionTransport {
	return &muxSessionTransport{
		muxTestTransport: new(muxTestTransport),
		ensureStarted:    make(chan struct{}, 1),
		ensureRelease:    make(chan error, 1),
	}
}

func (m *muxSessionTransport) EnsureSession(ctx context.Context, _ foundation.Hash) error {
	m.ensureStarted <- struct{}{}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-m.ensureRelease:
		if err == nil {
			m.mu.Lock()
			m.session = true
			m.mu.Unlock()
		}
		return err
	}
}

func (m *muxSessionTransport) HasSession(foundation.Hash) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.session
}

func (m *muxSessionTransport) PreparedSession(peer foundation.Hash) (dataplane.RouterSessionSender, error) {
	if !m.HasSession(peer) {
		return nil, dataplane.RouterErrSessionUnavailable
	}
	return muxMessageSender(func(ctx context.Context, message foundation.I2NPMessage) error {
		if !m.HasSession(peer) {
			return dataplane.RouterErrSessionUnavailable
		}
		return m.Send(ctx, peer, message)
	}), nil
}

func (m *muxSessionTransport) DropSession(foundation.Hash) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.session {
		return false
	}
	m.session = false
	m.drops++
	return true
}

type muxCountedSessionTransport struct {
	*muxSessionTransport
	count int
}

func (m *muxCountedSessionTransport) ActiveSessionCount() int { return m.count }

func TestTransportMuxSelectsPreferredSSU2BidBelowMinimum(t *testing.T) {
	database, peer := muxTestPeer(t, true, true)
	ntcp2 := newMuxSessionTransport()
	ssu2 := &muxCountedSessionTransport{muxSessionTransport: newMuxSessionTransport()}
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
	if err != nil {
		t.Fatal(err)
	}
	mux.random = bytes.NewReader([]byte{1})
	done := make(chan error, 1)
	go func() { done <- mux.EnsureSession(context.Background(), peer) }()
	<-ssu2.ensureStarted
	select {
	case <-ntcp2.ensureStarted:
		t.Fatal("lower SSU2 bid started an NTCP2 handshake")
	default:
	}
	ssu2.ensureRelease <- nil
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTransportMuxUsesRandomMinimumPeerPreference(t *testing.T) {
	ssu2 := &muxCountedSessionTransport{muxSessionTransport: newMuxSessionTransport()}
	mux := &TransportMux{random: bytes.NewReader([]byte{1, 0, 1})}
	ipv4 := transportCapabilities{ssu2: ssu2, directSSU2: true}
	if !mux.preferSSU2(ipv4) {
		t.Fatal("nonzero random choice did not prefer SSU2 below the IPv4 minimum")
	}
	if mux.preferSSU2(ipv4) {
		t.Fatal("zero random choice did not give NTCP2 its Java-compatible chance")
	}
	ssu2.count = minimumSSU2IPv4Peers
	if mux.preferSSU2(ipv4) {
		t.Fatal("SSU2 remained preferred at the IPv4 minimum")
	}
	ipv6 := ipv4
	ipv6.ssu2IPv6 = true
	if !mux.preferSSU2(ipv6) {
		t.Fatal("SSU2 was not preferred below the IPv6 minimum")
	}
	ssu2.count = minimumSSU2IPv6Peers
	if mux.preferSSU2(ipv6) {
		t.Fatal("SSU2 remained preferred at the IPv6 minimum")
	}
}

func TestTransportMuxStartsOnlyWinningNTCP2Bid(t *testing.T) {
	database, peer := muxTestPeer(t, true, true)
	ntcp2, ssu2 := newMuxSessionTransport(), newMuxSessionTransport()
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
	if err != nil {
		t.Fatal(err)
	}
	mux.random = bytes.NewReader([]byte{0})
	done := make(chan error, 1)
	go func() { done <- mux.EnsureSession(context.Background(), peer) }()
	<-ntcp2.ensureStarted
	select {
	case <-ssu2.ensureStarted:
		t.Fatal("lower NTCP2 bid started an SSU2 handshake")
	default:
	}
	ntcp2.ensureRelease <- nil
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTransportMuxReusesExistingAuthenticatedSession(t *testing.T) {
	database, peer := muxTestPeer(t, true, true)
	ntcp2, ssu2 := newMuxSessionTransport(), newMuxSessionTransport()
	ntcp2.session = true
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
	if err != nil {
		t.Fatal(err)
	}
	if err = mux.EnsureSession(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ssu2.ensureStarted:
		t.Fatal("existing NTCP2 session triggered an SSU2 dial")
	default:
	}
}

func TestTransportMuxReusesSessionWithoutRouterInfoLookup(t *testing.T) {
	peer := foundation.Hash{1}
	ntcp2 := newMuxSessionTransport()
	ntcp2.session = true
	mux, err := NewTransportMux(TransportMuxConfig{
		Database: controlplanenetdb.NewDatabase(foundation.Hash{}, 8),
		NTCP2:    ntcp2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = mux.EnsureSession(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ntcp2.ensureStarted:
		t.Fatal("existing session triggered RouterInfo-dependent dial")
	default:
	}
}

func TestTransportMuxChoosesEstablishedNTCP2BidWithoutDroppingSSU2(t *testing.T) {
	database, peer := muxTestPeer(t, true, true)
	ntcp2, ssu2 := newMuxSessionTransport(), newMuxSessionTransport()
	ntcp2.session, ssu2.session = true, true
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
	if err != nil {
		t.Fatal(err)
	}
	if err = mux.EnsureSession(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	if !ntcp2.HasSession(peer) || !ssu2.HasSession(peer) || ntcp2.drops != 0 {
		t.Fatalf("existing sessions = NTCP2 %t SSU2 %t drops %d", ntcp2.HasSession(peer), ssu2.HasSession(peer), ntcp2.drops)
	}
}

func TestTransportMuxFallsBackBeforeDelivery(t *testing.T) {
	database, peer := muxTestPeer(t, true, true)
	ssu2 := &muxCountedSessionTransport{muxSessionTransport: newMuxSessionTransport()}
	ssu2.ensureRelease <- dataplane.RouterErrSSU2Session
	ntcp2 := &muxTestTransport{}
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
	if err != nil {
		t.Fatal(err)
	}
	mux.random = bytes.NewReader([]byte{1})
	if err = mux.Send(t.Context(), peer, foundation.I2NPMessage{Payload: []byte("borrowed")}); err != nil {
		t.Fatalf("Send fallback error = %v", err)
	}
	_, _, _, ssuSends := ssu2.counts()
	_, _, _, ntcpSends := ntcp2.counts()
	if ssuSends != 0 || ntcpSends != 1 {
		t.Fatalf("delivery calls = SSU2 %d, NTCP2 %d; want 0, 1", ssuSends, ntcpSends)
	}
}

func TestTransportMuxFallsBackAfterAttemptDeadline(t *testing.T) {
	for _, test := range []struct {
		name     string
		deadline time.Duration
	}{
		{name: "short caller deadline", deadline: 8 * time.Second},
		{name: "long caller deadline", deadline: time.Minute},
		{name: "no caller deadline"},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				database, peer := muxTestPeer(t, true, true)
				ntcp2, ssu2 := newMuxSessionTransport(), newMuxSessionTransport()
				ssu2.ensureRelease <- nil
				mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
				if err != nil {
					t.Fatal(err)
				}
				ctx := t.Context()
				if test.deadline != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, test.deadline)
					defer cancel()
				}
				started := time.Now()
				if err := mux.Send(ctx, peer, foundation.I2NPMessage{Payload: []byte("once")}); err != nil {
					t.Fatalf("Send after primary timeout = %v", err)
				}
				if err := ctx.Err(); err != nil {
					t.Fatalf("fallback exhausted caller deadline: %v", err)
				}
				if elapsed := time.Since(started); elapsed > transportSessionAttemptTimeout {
					t.Fatalf("primary stalled for %v, limit %v", elapsed, transportSessionAttemptTimeout)
				}
				_, _, _, primaryWrites := ntcp2.counts()
				_, _, _, alternateWrites := ssu2.counts()
				if primaryWrites != 0 || alternateWrites != 1 {
					t.Fatalf("message writes = primary %d, alternate %d; want 0, 1", primaryWrites, alternateWrites)
				}
			})
		})
	}
}

func TestTransportMuxCancellationStopsSetupWithoutFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		database, peer := muxTestPeer(t, true, true)
		ntcp2, ssu2 := newMuxSessionTransport(), newMuxSessionTransport()
		mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- mux.Send(ctx, peer, foundation.I2NPMessage{}) }()
		<-ntcp2.ensureStarted
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("Send after cancellation = %v, want context.Canceled", err)
		}
		select {
		case <-ssu2.ensureStarted:
			t.Fatal("caller cancellation started alternate setup")
		default:
		}
		_, _, _, primaryWrites := ntcp2.counts()
		_, _, _, alternateWrites := ssu2.counts()
		if primaryWrites != 0 || alternateWrites != 0 {
			t.Fatalf("canceled setup wrote messages: primary %d, alternate %d", primaryWrites, alternateWrites)
		}
	})
}

func TestTransportMuxDoesNotFallbackOnPermanentSetupFailure(t *testing.T) {
	database, peer := muxTestPeer(t, true, true)
	ntcp2, ssu2 := newMuxSessionTransport(), newMuxSessionTransport()
	want := errors.New("invalid local credentials")
	ntcp2.ensureRelease <- want
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.EnsureSession(t.Context(), peer); !errors.Is(err, want) {
		t.Fatalf("EnsureSession = %v, want %v", err, want)
	}
	select {
	case <-ssu2.ensureStarted:
		t.Fatal("permanent setup failure started alternate setup")
	default:
	}
}

func TestTransportMuxBoundsAlternateSetupWithoutCallerDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		database, peer := muxTestPeer(t, true, true)
		ntcp2, ssu2 := newMuxSessionTransport(), newMuxSessionTransport()
		ntcp2.ensureRelease <- dataplane.RouterErrNTCP2Session
		mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		err = mux.EnsureSession(t.Context(), peer)
		if !errors.Is(err, dataplane.RouterErrNTCP2Session) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("EnsureSession = %v, want primary failure and alternate deadline", err)
		}
		if elapsed := time.Since(started); elapsed > transportSessionAttemptTimeout {
			t.Fatalf("alternate stalled for %v, limit %v", elapsed, transportSessionAttemptTimeout)
		}
	})
}

func TestTransportMuxDoesNotRetryEstablishedWrite(t *testing.T) {
	database, peer := muxTestPeer(t, true, true)
	ntcp2, ssu2 := newMuxSessionTransport(), newMuxSessionTransport()
	ntcp2.session, ssu2.session = true, true
	ntcp2.sendErr = dataplane.RouterErrNTCP2Session
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
	if err != nil {
		t.Fatal(err)
	}
	if err = mux.Send(t.Context(), peer, foundation.I2NPMessage{}); !errors.Is(err, dataplane.RouterErrNTCP2Session) {
		t.Fatalf("write error = %v, want %v", err, dataplane.RouterErrNTCP2Session)
	}
	if _, _, _, sends := ssu2.counts(); sends != 0 {
		t.Fatalf("alternate delivered %d messages after write attempt", sends)
	}
}

func TestTransportMuxRoutesFirewalledSSU2PeerThroughManager(t *testing.T) {
	database, peer := muxTestFirewalledSSU2Peer(t)
	ref, ok := database.Routers().Get(peer)
	if !ok {
		t.Fatal("firewalled peer was not admitted")
	}
	if dataplane.RouterInspectSSU2Peer(ref.Info, uint64(time.Now().Unix())).Direct {
		t.Fatal("firewalled SSU2 RouterInfo unexpectedly has a direct endpoint")
	}
	if !dataplane.RouterSSU2PeerCapable(ref.Info, uint64(time.Now().Unix())) {
		t.Fatal("firewalled SSU2 RouterInfo with an introducer is not capable")
	}

	ssu2 := &muxTestTransport{}
	ntcp2 := &muxTestTransport{}
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
	if err != nil {
		t.Fatal(err)
	}
	if !mux.CanSend(peer) {
		t.Fatal("introduced SSU2 peer was unavailable for ordinary delivery")
	}
	if mux.CanBuildTunnel(peer) {
		t.Fatal("introduced-only SSU2 peer was eligible for tunnel construction")
	}
	if err = mux.Send(context.Background(), peer, foundation.I2NPMessage{Payload: []byte("introduced")}); err != nil {
		t.Fatalf("Send to firewalled SSU2 peer: %v", err)
	}
	_, _, _, ssuSends := ssu2.counts()
	_, _, _, ntcpSends := ntcp2.counts()
	if ssuSends != 1 || ntcpSends != 0 {
		t.Fatalf("send calls = SSU2 %d, NTCP2 %d; want 1, 0", ssuSends, ntcpSends)
	}
}

func TestTransportMuxTunnelEligibilityAcceptsDirectPeer(t *testing.T) {
	database, peer := muxTestPeer(t, true, true)
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: newMuxSessionTransport(), SSU2: newMuxSessionTransport()})
	if err != nil {
		t.Fatal(err)
	}
	if !mux.CanBuildTunnel(peer) {
		t.Fatal("direct NTCP2 and SSU2 peer was ineligible for tunnel construction")
	}
}

func TestTransportMuxTunnelEligibilityUsesSSU2OnlyWithoutNTCP2(t *testing.T) {
	database, peer := muxTestPeer(t, false, true)
	ssuOnly, err := NewTransportMux(TransportMuxConfig{Database: database, SSU2: newMuxSessionTransport()})
	if err != nil {
		t.Fatal(err)
	}
	if !ssuOnly.CanBuildTunnel(peer) {
		t.Fatal("direct SSU2 peer was ineligible on an SSU2-only node")
	}
	withNTCP2, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: newMuxSessionTransport(), SSU2: newMuxSessionTransport()})
	if err != nil {
		t.Fatal(err)
	}
	if !withNTCP2.CanBuildTunnel(peer) {
		t.Fatal("direct SSU2 peer was ineligible while NTCP2 was also configured")
	}
}

func TestTransportMuxTunnelEligibilityMatchesIPv4Binding(t *testing.T) {
	database, peer := muxTestPeerAtHost(t, true, false, "2001:db8::1")
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{NetworkID: 2, Local: local})
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.ReplaceAddresses([]PublishedAddress{{Transport: "NTCP2", Options: []MappingOption{
		{Key: "host", Value: "127.0.0.1"}, {Key: "port", Value: "1"},
		{Key: "s", Value: foundation.EncodeI2PBase64(key.PublicKey().Bytes())},
		{Key: "i", Value: foundation.EncodeI2PBase64(make([]byte, 16))}, {Key: "v", Value: "2"},
	}}}); err != nil {
		t.Fatal(err)
	}
	if err = owner.Publish(t.Context()); err != nil {
		t.Fatal(err)
	}
	manager, err := dataplane.RouterNewNTCP2Manager(dataplane.RouterNTCP2ManagerConfig{NetworkID: 2, Peers: NewTransportPeerSource(database), StaticPrivate: key.Bytes(), StaticIV: make([]byte, 16)})
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Start(t.Context(), dataplane.RouterTransportBindings{NTCP2: muxIPv4Listener{}, LocalInfo: owner, Clock: dataplane.RouterWallClock{}, HandleI2NP: func(foundation.I2NPMessage, uint64, bool) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = manager.Close()
		if err := manager.Wait(); err != nil {
			t.Error(err)
		}
	})
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: manager})
	if err != nil {
		t.Fatal(err)
	}
	if !mux.CanSend(peer) {
		t.Fatal("generic send capability did not expose the IPv6 NTCP2 address")
	}
	if mux.CanBuildTunnel(peer) {
		t.Fatal("IPv6-only peer was eligible for an IPv4-bound tunnel builder")
	}
}

func TestTransportMuxTunnelEligibilityRejectsUnavailableIPv6SSU2(t *testing.T) {
	database, peer := muxTestPeerAtHost(t, false, true, "2001:db8::1")
	manager := new(dataplane.RouterSSU2Manager)
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, SSU2: manager})
	if err != nil {
		t.Fatal(err)
	}
	if mux.CanBuildTunnel(peer) {
		t.Fatal("IPv6-only SSU2 peer was eligible without a global IPv6 interface")
	}
}

func TestTransportMuxRequiresAdmittedPeerAndWorksWithOneManager(t *testing.T) {
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	database := controlplanenetdb.NewDatabase(local.Hash, 8)
	ntcp2 := &muxTestTransport{}
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2})
	if err != nil {
		t.Fatal(err)
	}

	peerDatabase, peer := muxTestPeer(t, true, false)
	ref, ok := peerDatabase.Routers().Get(peer)
	if !ok {
		t.Fatal("test peer was not admitted")
	}
	if err = mux.Send(context.Background(), peer, foundation.I2NPMessage{}); !errors.Is(err, ErrTransportUnavailable) {
		t.Fatalf("Send with unadmitted peer error = %v, want ErrTransportUnavailable", err)
	}
	if _, _, _, sends := ntcp2.counts(); sends != 0 {
		t.Fatalf("unadmitted peer sent %d messages", sends)
	}
	if err = database.AdmitRouterInfo(ref.Info, false, ref.Info.Published); err != nil {
		t.Fatal(err)
	}

	if err = mux.Start(context.Background(), dataplane.RouterTransportBindings{}); err != nil {
		t.Fatal(err)
	}
	if err = mux.Send(context.Background(), peer, foundation.I2NPMessage{}); err != nil {
		t.Fatal(err)
	}
	if err = mux.Close(); err != nil {
		t.Fatal(err)
	}
	if err = mux.Wait(); err != nil {
		t.Fatal(err)
	}
	starts, closes, waits, sends := ntcp2.counts()
	if starts != 1 || closes != 1 || waits != 1 || sends != 1 {
		t.Fatalf("single manager calls = start %d close %d wait %d send %d; want 1 each", starts, closes, waits, sends)
	}
}

func TestTransportMuxCoalescesLifecycleErrors(t *testing.T) {
	database, _ := muxTestPeer(t, true, true)
	ssuClose := errors.New("ssu close")
	ntcpClose := errors.New("ntcp close")
	ssuWait := errors.New("ssu wait")
	ntcpWait := errors.New("ntcp wait")
	ssuStatus := errors.New("ssu status")
	ntcpStatus := errors.New("ntcp status")
	ssu2 := &muxTestTransport{closeErr: ssuClose, waitErr: ssuWait, status: dataplane.RouterTransportStatus{Running: true, Error: ssuStatus}}
	ntcp2 := &muxTestTransport{closeErr: ntcpClose, waitErr: ntcpWait, status: dataplane.RouterTransportStatus{Running: true, Error: ntcpStatus}}
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
	if err != nil {
		t.Fatal(err)
	}
	if err = mux.Start(context.Background(), dataplane.RouterTransportBindings{}); err != nil {
		t.Fatal(err)
	}
	if err = mux.Close(); !errors.Is(err, ssuClose) || !errors.Is(err, ntcpClose) {
		t.Fatalf("Close error = %v, want both close errors", err)
	}
	if err = mux.Wait(); !errors.Is(err, ssuClose) || !errors.Is(err, ntcpClose) || !errors.Is(err, ssuWait) || !errors.Is(err, ntcpWait) {
		t.Fatalf("Wait error = %v, want close and wait errors", err)
	}
	status := mux.Status()
	if status.Running {
		t.Fatal("closed mux reported running")
	}
	if !errors.Is(status.Error, ssuClose) || !errors.Is(status.Error, ntcpClose) || !errors.Is(status.Error, ssuStatus) || !errors.Is(status.Error, ntcpStatus) {
		t.Fatalf("Status error = %v, want close and status errors", status.Error)
	}
	ssuStarts, ssuCloses, ssuWaits, _ := ssu2.counts()
	ntcpStarts, ntcpCloses, ntcpWaits, _ := ntcp2.counts()
	transportMuxCoalescesLifecycleErrorsRejected := ssuStarts != 1 || ssuCloses != 1 || ssuWaits != 1 || ntcpStarts != 1 || ntcpCloses != 1
	if !transportMuxCoalescesLifecycleErrorsRejected {
		transportMuxCoalescesLifecycleErrorsRejected = ntcpWaits != 1
	}
	if transportMuxCoalescesLifecycleErrorsRejected {
		t.Fatalf("lifecycle calls = SSU2 (%d, %d, %d), NTCP2 (%d, %d, %d); want one each", ssuStarts, ssuCloses, ssuWaits, ntcpStarts, ntcpCloses, ntcpWaits)
	}
}

func TestTransportMuxClosesStartedManagerWhenLaterStartFails(t *testing.T) {
	database, _ := muxTestPeer(t, true, true)
	startErr := errors.New("ntcp start")
	closeErr := errors.New("ssu close")
	ssu2 := &muxTestTransport{closeErr: closeErr}
	ntcp2 := &muxTestTransport{startErr: startErr}
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
	if err != nil {
		t.Fatal(err)
	}

	if err = mux.Start(context.Background(), dataplane.RouterTransportBindings{}); !errors.Is(err, startErr) || !errors.Is(err, closeErr) {
		t.Fatalf("Start error = %v, want start and cleanup errors", err)
	}
	if err = mux.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("second Close error = %v, want original close error", err)
	}
	_, ssuCloses, _, _ := ssu2.counts()
	_, ntcpCloses, _, _ := ntcp2.counts()
	if ssuCloses != 1 || ntcpCloses != 0 {
		t.Fatalf("cleanup closes = SSU2 %d, NTCP2 %d; want 1, 0", ssuCloses, ntcpCloses)
	}
}

func TestTransportMuxUsableCountRejectsExpiredAddress(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := controlplanenetdb.NewLocalRouterInfo(controlplanenetdb.LocalRouterInfoConfig{
		Local: local,
		Contacts: controlplanenetdb.RouterInfoContacts{Addresses: []controlplanenetdb.LocalRouterAddress{{
			Expiration:     now - 1,
			TransportStyle: []byte("NTCP2"),
			Options: []foundation.MappingEntry{
				{Key: []byte("host"), Value: []byte("127.0.0.1")},
				{Key: []byte("i"), Value: []byte(foundation.EncodeI2PBase64(make([]byte, 16)))},
				{Key: []byte("port"), Value: []byte("12345")},
				{Key: []byte("s"), Value: []byte(foundation.EncodeI2PBase64(make([]byte, 32)))},
				{Key: []byte("v"), Value: []byte("2")},
			},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := owner.Publish(now)
	if err != nil {
		t.Fatal(err)
	}
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, 8)
	if err = database.AdmitRouterInfo(info, false, now); err != nil {
		t.Fatal(err)
	}
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: &muxTestTransport{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := mux.UsableRemoteRouterInfos(time.UnixMilli(int64(now))); got != 0 {
		t.Fatalf("usable peers with expired address = %d, want 0", got)
	}
}

func muxTestPeer(t *testing.T, ntcp2, ssu2 bool) (*controlplanenetdb.Database, foundation.Hash) {
	return muxTestPeerAtHost(t, ntcp2, ssu2, "127.0.0.1")
}

func muxTestPeerAtHost(t *testing.T, ntcp2, ssu2 bool, host string) (*controlplanenetdb.Database, foundation.Hash) {
	t.Helper()
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{NetworkID: 2, Local: local, RouterVersion: "mux-test"})
	if err != nil {
		t.Fatal(err)
	}
	addresses := make([]PublishedAddress, 0, 2)
	if ntcp2 {
		addresses = append(addresses, PublishedAddress{Transport: "NTCP2", Options: []MappingOption{
			{Key: "host", Value: host},
			{Key: "i", Value: foundation.EncodeI2PBase64(make([]byte, 16))},
			{Key: "port", Value: "12345"},
			{Key: "s", Value: foundation.EncodeI2PBase64(make([]byte, 32))},
			{Key: "v", Value: "2"},
		}})
	}
	if ssu2 {
		addresses = append(addresses, PublishedAddress{Transport: "SSU", Options: []MappingOption{
			{Key: "host", Value: host},
			{Key: "i", Value: foundation.EncodeI2PBase64(make([]byte, 32))},
			{Key: "port", Value: "12346"},
			{Key: "s", Value: foundation.EncodeI2PBase64(make([]byte, 32))},
			{Key: "v", Value: "2"},
		}})
	}
	if err = owner.ReplaceAddresses(addresses); err != nil {
		t.Fatal(err)
	}
	owner.SetReachability(ReachabilityReachable)
	if err = owner.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, 8)
	info := owner.Snapshot()
	if err = database.AdmitRouterInfo(info, false, info.Published); err != nil {
		t.Fatal(err)
	}
	return database, owner.Hash()
}

func muxTestFirewalledSSU2Peer(t *testing.T) (*controlplanenetdb.Database, foundation.Hash) {
	t.Helper()
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	introducer, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{NetworkID: 2, Local: local, RouterVersion: "mux-test"})
	if err != nil {
		t.Fatal(err)
	}
	introducerHash := introducer.Hash
	if err = owner.ReplaceAddresses([]PublishedAddress{{
		Transport: "SSU",
		Cost:      3,
		Options: []MappingOption{
			{Key: "i", Value: foundation.EncodeI2PBase64(make([]byte, 32))},
			{Key: "ih0", Value: foundation.EncodeI2PBase64(introducerHash[:])},
			{Key: "itag0", Value: "1"},
			{Key: "s", Value: foundation.EncodeI2PBase64(make([]byte, 32))},
			{Key: "v", Value: "2"},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	owner.SetReachability(ReachabilityFirewalled)
	if err = owner.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, 8)
	info := owner.Snapshot()
	if err = database.AdmitRouterInfo(info, false, info.Published); err != nil {
		t.Fatal(err)
	}
	return database, owner.Hash()
}

func TestMissingSessionIsRecoverableWithoutRetryingUnknownWrites(t *testing.T) {
	if !IsRetryableTransportError(dataplane.RouterErrSessionUnavailable) {
		t.Fatal("missing established session was treated as a terminal control failure")
	}
	if IsRetryableTransportError(errors.New("write failed after partial delivery")) {
		t.Fatal("unknown write failure was treated as safe to retry")
	}
}
