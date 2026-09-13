package router

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/ingress"
)

var errTestAdmissionDenied = errors.New("test admission denied")

type admissionTestReporter struct{ ch chan ingress.Panic }

func (r admissionTestReporter) ReportRecoveredPanic(p ingress.Panic) { r.ch <- p }

type admissionCall struct {
	peer      foundation.Hash
	transport PeerTransport
	inbound   bool
	remote    net.Addr
}

type recordingAdmission struct {
	calls chan admissionCall
	err   error
}

func (r *recordingAdmission) admit(_ context.Context, request PeerAdmission) error {
	r.calls <- admissionCall{peer: request.Peer, transport: request.Transport, inbound: request.Inbound, remote: request.RemoteAddr}
	return r.err
}

func TestNTCP2AdmissionRejectsInboundBeforeNetDBStore(t *testing.T) {
	owner, static, iv := newNTCP2TestLocal(t, "127.0.0.1:7654")
	info := owner.Snapshot()
	peers := newTransportTestPeers()
	recorder := &recordingAdmission{calls: make(chan admissionCall, 1), err: errTestAdmissionDenied}
	manager, err := NewNTCP2Manager(NTCP2ManagerConfig{NetworkID: 2, Peers: peers, StaticPrivate: static, StaticIV: iv, AdmitPeer: recorder.admit})
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9}
	if manager.admitInboundPeer(info, make([]byte, 32), uint64(time.Now().UnixMilli()), remote) {
		t.Fatal("denied peer was admitted")
	}
	select {
	case call := <-recorder.calls:
		if call.peer != info.Hash() || call.transport != PeerTransportNTCP2 || !call.inbound || call.remote != remote {
			t.Fatalf("admission call = %+v", call)
		}
	default:
		t.Fatal("admission callback was not invoked")
	}
	if _, ok := peers.RouterInfo(info.Hash()); ok {
		t.Fatal("denied peer RouterInfo entered the peer store")
	}
}

func TestNTCP2AdmissionAllowsInboundAndStoresRouterInfo(t *testing.T) {
	owner, static, iv := newNTCP2TestLocal(t, "127.0.0.1:7654")
	info := owner.Snapshot()
	peers := newTransportTestPeers()
	var got PeerAdmission
	manager, err := NewNTCP2Manager(NTCP2ManagerConfig{NetworkID: 2, Peers: peers, StaticPrivate: static, StaticIV: iv, AdmitPeer: func(_ context.Context, request PeerAdmission) error {
		got = request
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !manager.admitInboundPeer(info, make([]byte, 32), uint64(time.Now().UnixMilli()), nil) {
		t.Fatal("allowed peer was rejected")
	}
	if got.Peer != info.Hash() || got.Transport != PeerTransportNTCP2 || !got.Inbound {
		t.Fatalf("admission request = %+v", got)
	}
	if got.RouterInfo.Hash() != info.Hash() {
		t.Fatal("admission did not carry the verified peer RouterInfo")
	}
	if _, ok := peers.RouterInfo(info.Hash()); !ok {
		t.Fatal("allowed peer RouterInfo was not stored")
	}
}

func TestNTCP2AdmissionDeniesOutboundBeforeDial(t *testing.T) {
	// Bob's advertised endpoint is unroutable; a dial would block on TCP. The
	// admission denial must fire first and return the callback error.
	_, static, iv := newNTCP2TestLocal(t, "127.0.0.1:1")
	owner, _, _ := newNTCP2TestLocal(t, "192.0.2.1:9")
	info := owner.Snapshot()
	peers := newTransportTestPeers()
	if err := peers.AdmitRouterInfo(info, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	var got PeerAdmission
	manager, err := NewNTCP2Manager(NTCP2ManagerConfig{NetworkID: 2, Peers: peers, StaticPrivate: static, StaticIV: iv, AdmitPeer: func(_ context.Context, request PeerAdmission) error {
		got = request
		return errTestAdmissionDenied
	}})
	if err != nil {
		t.Fatal(err)
	}
	manager.ctx, manager.cancel = context.WithCancel(context.Background())
	manager.started = true
	manager.bindings = TransportBindings{Clock: WallClock{}}
	t.Cleanup(manager.cancel)
	err = manager.openOutbound(t.Context(), info.Hash())
	if !errors.Is(err, errTestAdmissionDenied) {
		t.Fatalf("outbound denial error = %v, want %v", err, errTestAdmissionDenied)
	}
	if got.Peer != info.Hash() || got.Transport != PeerTransportNTCP2 || got.Inbound {
		t.Fatalf("outbound admission request = %+v", got)
	}
	addr, ok := got.RemoteAddr.(*net.TCPAddr)
	if !ok || addr.Port != 9 || !addr.IP.Equal(net.IPv4(192, 0, 2, 1)) {
		t.Fatalf("outbound admission RemoteAddr = %v", got.RemoteAddr)
	}
	if manager.session(info.Hash()) != nil {
		t.Fatal("denied outbound peer installed a session")
	}
}

func TestNTCP2AdmissionPanicIsContainedDenial(t *testing.T) {
	owner, static, iv := newNTCP2TestLocal(t, "127.0.0.1:7654")
	info := owner.Snapshot()
	peers := newTransportTestPeers()
	manager, err := NewNTCP2Manager(NTCP2ManagerConfig{NetworkID: 2, Peers: peers, StaticPrivate: static, StaticIV: iv, AdmitPeer: func(context.Context, PeerAdmission) error {
		panic("admission blew up")
	}})
	if err != nil {
		t.Fatal(err)
	}
	if manager.admitInboundPeer(info, make([]byte, 32), uint64(time.Now().UnixMilli()), nil) {
		t.Fatal("panicking admission callback admitted the peer")
	}
	if _, ok := peers.RouterInfo(info.Hash()); ok {
		t.Fatal("panicked admission stored the peer RouterInfo")
	}
}

func TestPeerAdmissionPanicReportsToIngressReporter(t *testing.T) {
	reported := make(chan ingress.Panic, 1)
	err := runPeerAdmission(context.Background(), func(context.Context, PeerAdmission) error { panic("boom") }, admissionTestReporter{ch: reported},
		ingress.BoundaryNTCP2Handshake, PeerAdmission{Transport: PeerTransportNTCP2})
	if !errors.Is(err, ErrPeerDenied) || !errors.Is(err, ingress.ErrRecoveredPanic) {
		t.Fatalf("panic containment error = %v", err)
	}
	select {
	case p := <-reported:
		if p.Boundary != ingress.BoundaryNTCP2Handshake {
			t.Fatalf("reported boundary = %d", p.Boundary)
		}
	case <-time.After(time.Second):
		t.Fatal("panic was not reported")
	}
}

func TestPeerAdmissionNilCallbackAdmits(t *testing.T) {
	if err := runPeerAdmission(context.Background(), nil, nil, ingress.BoundaryNTCP2Handshake, PeerAdmission{}); err != nil {
		t.Fatalf("nil callback error = %v", err)
	}
}

func TestSSU2AdmissionRejectsInboundBeforeNetDBStore(t *testing.T) {
	owner, _, _ := newSSU2TestLocal(t, "127.0.0.1:7654")
	info := owner.Snapshot()
	peers := newTransportTestPeers()
	recorder := &recordingAdmission{calls: make(chan admissionCall, 1), err: errTestAdmissionDenied}
	manager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: peers,
		StaticPrivate: bytes32(1), IntroKey: bytes32(2), AdmitPeer: recorder.admit})
	if err != nil {
		t.Fatal(err)
	}
	remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:9"))
	if manager.admitSSU2Peer(info, make([]byte, 32), time.Now(), remote) {
		t.Fatal("denied peer was admitted")
	}
	select {
	case call := <-recorder.calls:
		if call.peer != info.Hash() || call.transport != PeerTransportSSU2 || !call.inbound || call.remote != remote {
			t.Fatalf("admission call = %+v", call)
		}
	default:
		t.Fatal("admission callback was not invoked")
	}
	if _, ok := peers.RouterInfo(info.Hash()); ok {
		t.Fatal("denied peer RouterInfo entered the peer store")
	}
}

func TestSSU2AdmissionAllowsInboundAndStoresRouterInfo(t *testing.T) {
	owner, _, _ := newSSU2TestLocal(t, "127.0.0.1:7654")
	info := owner.Snapshot()
	peers := newTransportTestPeers()
	manager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: peers,
		StaticPrivate: bytes32(1), IntroKey: bytes32(2), AdmitPeer: func(_ context.Context, request PeerAdmission) error {
			if request.Transport != PeerTransportSSU2 || !request.Inbound || request.Peer != info.Hash() {
				t.Errorf("admission request = %+v", request)
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if !manager.admitSSU2Peer(info, make([]byte, 32), time.Now(), nil) {
		t.Fatal("allowed peer was rejected")
	}
	if _, ok := peers.RouterInfo(info.Hash()); !ok {
		t.Fatal("allowed peer RouterInfo was not stored")
	}
}

func TestSSU2AdmissionDeniesOutboundWithoutIntroductionFallback(t *testing.T) {
	owner, _, _ := newSSU2TestLocal(t, "192.0.2.1:9")
	info := owner.Snapshot()
	peers := newTransportTestPeers()
	if err := peers.AdmitRouterInfo(info, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	manager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: peers,
		StaticPrivate: bytes32(1), IntroKey: bytes32(2), AdmitPeer: func(_ context.Context, request PeerAdmission) error {
			if request.Inbound || request.Transport != PeerTransportSSU2 || request.Peer != info.Hash() {
				t.Errorf("outbound admission request = %+v", request)
			}
			return errTestAdmissionDenied
		}})
	if err != nil {
		t.Fatal(err)
	}
	manager.ctx, manager.cancel = context.WithCancel(context.Background())
	manager.bindings = TransportBindings{Clock: WallClock{}}
	t.Cleanup(manager.cancel)
	_, _, err = manager.resolveOutbound(info.Hash())
	if !errors.Is(err, errTestAdmissionDenied) {
		t.Fatalf("outbound denial error = %v, want %v", err, errTestAdmissionDenied)
	}
	// The denial must not classify as ErrSSU2Peer: EnsureSession retries that
	// class through relay introduction, which would bypass the gate.
	if errors.Is(err, ErrSSU2Peer) {
		t.Fatal("admission denial must not wrap ErrSSU2Peer")
	}
}

func bytes32(fill byte) []byte {
	out := make([]byte, 32)
	for index := range out {
		out[index] = fill
	}
	return out
}
