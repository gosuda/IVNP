package sam

import (
	"gosuda.org/ivnp/networking"

	"context"
	"errors"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/internal/ingress"

	"net"
	"sync"
	"testing"
	"time"
)

type panicRecorder struct{ reports chan ingress.Panic }

func (r panicRecorder) ReportRecoveredPanic(report ingress.Panic) { r.reports <- report }

type panicPacketConn struct{}

func (panicPacketConn) ReadFrom([]byte) (int, net.Addr, error) { panic("packet read") }
func (panicPacketConn) WriteTo([]byte, net.Addr) (int, error)  { panic("packet write") }
func (panicPacketConn) Close() error                           { return nil }
func (panicPacketConn) LocalAddr() net.Addr                    { return testAddr("udp") }
func (panicPacketConn) SetDeadline(time.Time) error            { return nil }
func (panicPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (panicPacketConn) SetWriteDeadline(time.Time) error       { return nil }

type panicConn struct{ closed chan struct{} }

func newPanicConn() *panicConn                 { return &panicConn{closed: make(chan struct{})} }
func (c *panicConn) Read([]byte) (int, error)  { panic("connection read") }
func (c *panicConn) Write([]byte) (int, error) { panic("connection write") }
func (c *panicConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (*panicConn) LocalAddr() net.Addr              { return testAddr("local") }
func (*panicConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (*panicConn) SetDeadline(time.Time) error      { return nil }
func (*panicConn) SetReadDeadline(time.Time) error  { return nil }
func (*panicConn) SetWriteDeadline(time.Time) error { return nil }

type closeListener struct {
	closed chan struct{}
	once   sync.Once
}

func newCloseListener() *closeListener           { return &closeListener{closed: make(chan struct{})} }
func (*closeListener) Accept() (net.Conn, error) { panic("listener accept") }
func (l *closeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}
func (*closeListener) Addr() net.Addr { return testAddr("listener") }

type panicSubscription struct {
	message *destination.ReceivedMessage
	once    bool
}

func (s *panicSubscription) Receive(context.Context) (*destination.ReceivedMessage, error) {
	if !s.once && s.message != nil {
		s.once = true
		return s.message, nil
	}
	panic("subscription receive")
}
func (*panicSubscription) Close() error { return nil }

type panicSendEndpoint struct{ *loopEndpoint }

func (e *panicSendEndpoint) SendMessage(context.Context, networking.StreamingTunnelDelivery) error {
	panic("destination send")
}

func awaitPanicReport(t *testing.T, reports <-chan ingress.Panic, boundary ingress.Boundary) {
	t.Helper()
	select {
	case report := <-reports:
		if report.Boundary != boundary {
			t.Fatalf("boundary = %v, want %v", report.Boundary, boundary)
		}
	case <-time.After(time.Second):
		t.Fatal("worker panic was not reported")
	}
}

func TestSAMWorkerPanicContainmentAndCleanup(t *testing.T) {
	t.Run("UDP read", func(t *testing.T) {
		recorder := panicRecorder{reports: make(chan ingress.Panic, 4)}
		controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
		server, err := NewServer(ServerConfig{
			Address: "127.0.0.1:0", UDPAddress: "127.0.0.1:1", Controller: controller, PanicReporter: recorder,
			ListenPacket: func(context.Context, string, string) (net.PacketConn, error) { return panicPacketConn{}, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		if err = server.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		awaitPanicReport(t, recorder.reports, ingress.BoundarySAMUDP)
		_ = server.Close()
		_ = server.Wait()
	})

	t.Run("UDP send", func(t *testing.T) {
		recorder := panicRecorder{reports: make(chan ingress.Panic, 4)}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		local, err := foundation.GenerateLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		defer local.ReleaseSensitive()
		controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
		base := &loopEndpoint{local: local, controller: controller, subscriptions: make(map[destination.DestinationRoute]*loopSubscription)}
		server := &Server{config: ServerConfig{PanicReporter: recorder}, queueBytes: newByteBudget(1024)}
		session := &samSession{server: server, endpoint: &panicSendEndpoint{loopEndpoint: base}, ctx: ctx, style: styleRaw, queueBytes: newByteBudget(1024)}
		if !session.reserve(8) {
			t.Fatal("reserve failed")
		}
		server.processUDPPacket(udpPacket{session: session, target: string(local.Destination()), payload: make([]byte, 8), charged: 8})
		awaitPanicReport(t, recorder.reports, ingress.BoundarySAMUDP)
		if server.queueBytes.used.Load() != 0 || session.queueBytes.used.Load() != 0 {
			t.Fatal("panic leaked UDP queue reservation")
		}
	})

	t.Run("datagram receive", func(t *testing.T) {
		recorder := panicRecorder{reports: make(chan ingress.Panic, 4)}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		connection := newPanicConn()
		server := &Server{config: ServerConfig{PanicReporter: recorder}}
		session := &samSession{server: server, ctx: ctx, control: &serverConnection{Conn: connection}, style: styleRaw}
		message := destination.NewReceivedMessage(networking.StreamingTunnelDelivery{Payload: []byte("owned")}, nil)
		session.receiveLoop(&panicSubscription{message: message})
		awaitPanicReport(t, recorder.reports, ingress.BoundarySAMWorker)
		if message.Delivery.Payload != nil {
			t.Fatal("receive panic retained message payload")
		}
	})

	t.Run("accept worker", func(t *testing.T) {
		recorder := panicRecorder{reports: make(chan ingress.Panic, 4)}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		listener := newCloseListener()
		server := &Server{config: ServerConfig{PanicReporter: recorder}}
		session := &samSession{server: server, ctx: ctx}
		incoming := make(chan acceptResult, 1)
		session.wg.Add(1)
		go session.acceptIncomingLoop(listener, incoming)
		awaitPanicReport(t, recorder.reports, ingress.BoundarySAMWorker)
		session.wg.Wait()
		result, ok := <-incoming
		if !ok || !errors.Is(result.err, ingress.ErrRecoveredPanic) {
			t.Fatalf("accept result = %#v, open=%t", result, ok)
		}
	})

	t.Run("forward watcher", func(t *testing.T) {
		recorder := panicRecorder{reports: make(chan ingress.Panic, 4)}
		server := &Server{config: ServerConfig{PanicReporter: recorder}}
		connection := newPanicConn()
		listener := newCloseListener()
		session := &samSession{}
		session.wg.Add(1)
		server.forwardWatcher(session, connection, listener)
		awaitPanicReport(t, recorder.reports, ingress.BoundarySAMWorker)
		select {
		case <-listener.closed:
		default:
			t.Fatal("watcher panic did not close listener")
		}
	})

	t.Run("forward relay", func(t *testing.T) {
		recorder := panicRecorder{reports: make(chan ingress.Panic, 4)}
		server := &Server{config: ServerConfig{PanicReporter: recorder, RelayReservationBytes: 1}, queueBytes: newByteBudget(4)}
		session := &samSession{server: server, queueBytes: newByteBudget(4)}
		if !session.reserve(1) {
			t.Fatal("reserve failed")
		}
		inbound, local := newPanicConn(), newPanicConn()
		session.wg.Add(1)
		go server.forwardRelay(session, inbound, local)
		session.wg.Wait()
		awaitPanicReport(t, recorder.reports, ingress.BoundarySAMWorker)
		if server.queueBytes.used.Load() != 0 || session.queueBytes.used.Load() != 0 {
			t.Fatal("relay panic leaked reservation")
		}
		select {
		case <-inbound.closed:
		default:
			t.Fatal("relay panic did not close inbound")
		}
	})
}
