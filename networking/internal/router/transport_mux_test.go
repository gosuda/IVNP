package router

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/netdb"
	"gosuda.org/ivnp/observability"
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
	status   TransportStatus

	starts int
	closes int
	waits  int
	sends  int
}

func (m *muxTestTransport) Start(context.Context, TransportBindings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.starts++
	return m.startErr
}

func (m *muxTestTransport) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closes++
	return m.closeErr
}

func (m *muxTestTransport) Wait() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.waits++
	return m.waitErr
}

func (m *muxTestTransport) Send(context.Context, foundation.Hash, i2np.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sends++
	return m.sendErr
}

func (m *muxTestTransport) Status() TransportStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *muxTestTransport) counts() (starts, closes, waits, sends int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.starts, m.closes, m.waits, m.sends
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

func (m *muxCountedSessionTransport) activeSessionCount() int { return m.count }

func TestTransportMuxRacesSSU2BelowJavaMinimum(t *testing.T) {
	database, peer := muxTestPeer(t, true, true)
	ntcp2 := newMuxSessionTransport()
	ssu2 := &muxCountedSessionTransport{muxSessionTransport: newMuxSessionTransport()}
	metrics := observability.NewRegistry()
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2, Metrics: metrics})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- mux.EnsureSession(context.Background(), peer) }()
	<-ntcp2.ensureStarted
	<-ssu2.ensureStarted
	ssu2.ensureRelease <- nil
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	snapshot := metrics.Snapshot().Transport
	if snapshot.RaceAttempts != 1 || snapshot.SSU2RaceWins != 1 || snapshot.SSU2Promotions != 1 {
		t.Fatalf("transport preference metrics = %+v", snapshot)
	}
}

func TestTransportMuxGivesNTCP2EveryFourthMinimumPeerAttempt(t *testing.T) {
	ssu2 := &muxCountedSessionTransport{muxSessionTransport: newMuxSessionTransport()}
	mux := new(TransportMux)
	for attempt := range 4 {
		preferred := mux.preferSSU2(ssu2)
		if preferred != (attempt != 3) {
			t.Fatalf("attempt %d SSU2 preference = %t", attempt+1, preferred)
		}
	}
	ssu2.count = minimumSSU2Peers
	if mux.preferSSU2(ssu2) {
		t.Fatal("SSU2 remained preferred at the minimum peer count")
	}
}

func TestTransportMuxReturnsFirstSSU2Session(t *testing.T) {
	database, peer := muxTestPeer(t, true, true)
	ntcp2, ssu2 := newMuxSessionTransport(), newMuxSessionTransport()
	metrics := observability.NewRegistry()
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2, Metrics: metrics})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- mux.EnsureSession(context.Background(), peer) }()
	<-ntcp2.ensureStarted
	<-ssu2.ensureStarted
	ssu2.ensureRelease <- nil
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if ntcp2.HasSession(peer) || !ssu2.HasSession(peer) {
		t.Fatalf("raced sessions = NTCP2 %t SSU2 %t", ntcp2.HasSession(peer), ssu2.HasSession(peer))
	}
	snapshot := metrics.Snapshot().Transport
	if snapshot.RaceAttempts != 1 || snapshot.SSU2RaceWins != 1 || snapshot.SSU2Promotions != 1 {
		t.Fatalf("transport race metrics = %+v", snapshot)
	}
}

func TestTransportMuxReturnsFirstNTCP2SessionWithoutGrace(t *testing.T) {
	database, peer := muxTestPeer(t, true, true)
	ntcp2, ssu2 := newMuxSessionTransport(), newMuxSessionTransport()
	metrics := observability.NewRegistry()
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2, Metrics: metrics})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- mux.EnsureSession(context.Background(), peer) }()
	<-ntcp2.ensureStarted
	<-ssu2.ensureStarted
	ntcp2.ensureRelease <- nil
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if !ntcp2.HasSession(peer) || ssu2.HasSession(peer) {
		t.Fatalf("raced sessions = NTCP2 %t SSU2 %t", ntcp2.HasSession(peer), ssu2.HasSession(peer))
	}
	snapshot := metrics.Snapshot().Transport
	if snapshot.RaceAttempts != 1 || snapshot.NTCP2RaceWins != 1 {
		t.Fatalf("transport race metrics = %+v", snapshot)
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
		Database: netdb.NewDatabase(foundation.Hash{}, 8),
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

func TestTransportMuxPrefersExistingSSU2AndDropsNTCP2(t *testing.T) {
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
	if ntcp2.HasSession(peer) || !ssu2.HasSession(peer) || ntcp2.drops != 1 {
		t.Fatalf("existing sessions = NTCP2 %t SSU2 %t drops %d", ntcp2.HasSession(peer), ssu2.HasSession(peer), ntcp2.drops)
	}
}

func TestTransportMuxFallsBackOnlyBeforeAmbiguousWrite(t *testing.T) {
	database, peer := muxTestPeer(t, true, true)
	ssu2 := &muxTestTransport{}
	ntcp2 := &muxTestTransport{sendErr: ErrNTCP2Session}
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
	if err != nil {
		t.Fatal(err)
	}

	message := i2np.Message{Payload: []byte("borrowed")}
	if err = mux.Send(context.Background(), peer, message); err != nil {
		t.Fatalf("Send fallback error = %v", err)
	}
	_, _, _, ssuSends := ssu2.counts()
	_, _, _, ntcpSends := ntcp2.counts()
	if ssuSends != 1 || ntcpSends != 1 {
		t.Fatalf("send calls = SSU2 %d, NTCP2 %d; want one each", ssuSends, ntcpSends)
	}

	writeErr := errors.New("message write outcome unknown")
	ntcp2.sendErr = writeErr
	if err = mux.Send(context.Background(), peer, message); !errors.Is(err, writeErr) {
		t.Fatalf("Send ambiguous write error = %v, want %v", err, writeErr)
	}
	_, _, _, ssuSends = ssu2.counts()
	_, _, _, ntcpSends = ntcp2.counts()
	if ssuSends != 1 || ntcpSends != 2 {
		t.Fatalf("send calls after ambiguous write = SSU2 %d, NTCP2 %d; want 1, 2", ssuSends, ntcpSends)
	}
}

func TestTransportMuxRoutesFirewalledSSU2PeerThroughManager(t *testing.T) {
	database, peer := muxTestFirewalledSSU2Peer(t)
	ref, ok := database.Routers().Get(peer)
	if !ok {
		t.Fatal("firewalled peer was not admitted")
	}
	if _, err := selectSSU2Address(ref.Info); err == nil {
		t.Fatal("firewalled SSU2 RouterInfo unexpectedly has a direct endpoint")
	}
	if !ssu2RouterInfoCapable(ref.Info, uint64(time.Now().Unix())) {
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
	if err = mux.Send(context.Background(), peer, i2np.Message{Payload: []byte("introduced")}); err != nil {
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
	manager := &NTCP2Manager{bindings: TransportBindings{NTCP2: muxIPv4Listener{}}}
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
	manager := new(SSU2Manager)
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
	database := netdb.NewDatabase(local.Hash, 8)
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
	if err = mux.Send(context.Background(), peer, i2np.Message{}); !errors.Is(err, ErrTransportUnavailable) {
		t.Fatalf("Send with unadmitted peer error = %v, want ErrTransportUnavailable", err)
	}
	if _, _, _, sends := ntcp2.counts(); sends != 0 {
		t.Fatalf("unadmitted peer sent %d messages", sends)
	}
	if err = database.AdmitRouterInfo(ref.Info, false, ref.Info.Published); err != nil {
		t.Fatal(err)
	}

	if err = mux.Start(context.Background(), TransportBindings{}); err != nil {
		t.Fatal(err)
	}
	if err = mux.Send(context.Background(), peer, i2np.Message{}); err != nil {
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
	ssu2 := &muxTestTransport{closeErr: ssuClose, waitErr: ssuWait, status: TransportStatus{Running: true, Error: ssuStatus}}
	ntcp2 := &muxTestTransport{closeErr: ntcpClose, waitErr: ntcpWait, status: TransportStatus{Running: true, Error: ntcpStatus}}
	mux, err := NewTransportMux(TransportMuxConfig{Database: database, NTCP2: ntcp2, SSU2: ssu2})
	if err != nil {
		t.Fatal(err)
	}
	if err = mux.Start(context.Background(), TransportBindings{}); err != nil {
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

	if err = mux.Start(context.Background(), TransportBindings{}); !errors.Is(err, startErr) || !errors.Is(err, closeErr) {
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
	owner, err := netdb.NewLocalRouterInfo(netdb.LocalRouterInfoConfig{
		Local: local,
		Contacts: netdb.RouterInfoContacts{Addresses: []netdb.LocalRouterAddress{{
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
	database := netdb.NewDatabase(foundation.Hash{}, 8)
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

func muxTestPeer(t *testing.T, ntcp2, ssu2 bool) (*netdb.Database, foundation.Hash) {
	return muxTestPeerAtHost(t, ntcp2, ssu2, "127.0.0.1")
}

func muxTestPeerAtHost(t *testing.T, ntcp2, ssu2 bool, host string) (*netdb.Database, foundation.Hash) {
	t.Helper()
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{Local: local, RouterVersion: "mux-test"})
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
	database := netdb.NewDatabase(foundation.Hash{}, 8)
	info := owner.Snapshot()
	if err = database.AdmitRouterInfo(info, false, info.Published); err != nil {
		t.Fatal(err)
	}
	return database, owner.Hash()
}

func muxTestFirewalledSSU2Peer(t *testing.T) (*netdb.Database, foundation.Hash) {
	t.Helper()
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	introducer, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{Local: local, RouterVersion: "mux-test"})
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
	database := netdb.NewDatabase(foundation.Hash{}, 8)
	info := owner.Snapshot()
	if err = database.AdmitRouterInfo(info, false, info.Published); err != nil {
		t.Fatal(err)
	}
	return database, owner.Hash()
}
