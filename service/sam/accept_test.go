package sam

import (
	"context"
	clientapi "gosuda.org/ivnp/api/destination"
	ivnp "gosuda.org/ivnp/i2p"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type fifoController struct {
	loop     *loopController
	endpoint chan *fifoEndpoint
}

func (c *fifoController) CreateDestination(ctx context.Context, spec clientapi.DestinationSpec) (clientapi.DestinationEndpoint, error) {
	base, err := c.loop.CreateDestination(ctx, spec)
	if err != nil {
		return nil, err
	}
	endpoint := &fifoEndpoint{loopEndpoint: base.(*loopEndpoint), listener: newFIFOListener()}
	c.endpoint <- endpoint
	return endpoint, nil
}
func (c *fifoController) DestroyDestination(_ context.Context, endpoint clientapi.DestinationEndpoint) error {
	return endpoint.Close()
}

type fifoEndpoint struct {
	*loopEndpoint
	listener *fifoListener
}

func (e *fifoEndpoint) ListenI2P(context.Context, string) (net.Listener, error) {
	return e.listener, nil
}
func (e *fifoEndpoint) Close() error {
	_ = e.listener.Close()
	return e.loopEndpoint.Close()
}

type fifoListener struct {
	incoming chan net.Conn
	done     chan struct{}
	once     sync.Once
}

func newFIFOListener() *fifoListener {
	return &fifoListener{incoming: make(chan net.Conn, 4), done: make(chan struct{})}
}
func (l *fifoListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.incoming:
		return connection, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *fifoListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *fifoListener) Addr() net.Addr { return testAddr("fifo") }

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

type metadataConn struct {
	net.Conn
	remote []byte
	from   uint16
	to     uint16
}

func (c *metadataConn) RemoteDestination() []byte { return c.remote }
func (c *metadataConn) LocalI2PPort() uint16      { return c.to }
func (c *metadataConn) RemoteI2PPort() uint16     { return c.from }

func TestStreamAcceptAttachmentsAreFIFO(t *testing.T) {
	loop := &loopController{endpoints: make(map[ivnp.Hash]*loopEndpoint)}
	controller := &fifoController{loop: loop, endpoint: make(chan *fifoEndpoint, 1)}
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: controller, SessionQueue: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()
	control, controlReader := samDial(t, server.Addr().String())
	defer control.Close()
	_, _ = io.WriteString(control, "SESSION CREATE STYLE=STREAM ID=fifo DESTINATION=TRANSIENT\n")
	if line := readSAMLine(t, controlReader); line[:24] != "SESSION STATUS RESULT=OK" {
		t.Fatal(line)
	}
	endpoint := <-controller.endpoint

	firstAttachment, firstReader := samDial(t, server.Addr().String())
	defer firstAttachment.Close()
	_, _ = io.WriteString(firstAttachment, "STREAM ACCEPT ID=fifo\n")
	waitForSAMCondition(t, time.Second, func() bool {
		server.mu.RLock()
		session := server.sessions["fifo"]
		server.mu.RUnlock()
		return session != nil && session.acceptAdmissions.Load() >= 1
	}, "first FIFO accept request admission")
	secondAttachment, secondReader := samDial(t, server.Addr().String())
	defer secondAttachment.Close()
	_, _ = io.WriteString(secondAttachment, "STREAM ACCEPT ID=fifo\n")
	waitForSAMCondition(t, time.Second, func() bool {
		server.mu.RLock()
		session := server.sessions["fifo"]
		server.mu.RUnlock()
		return session != nil && session.acceptAdmissions.Load() >= 2
	}, "second FIFO accept request admission")

	firstSAM, firstPeer := net.Pipe()
	secondSAM, secondPeer := net.Pipe()
	defer firstPeer.Close()
	defer secondPeer.Close()
	endpoint.listener.incoming <- &metadataConn{Conn: firstSAM, remote: []byte("FIRST"), from: 11, to: 21}
	endpoint.listener.incoming <- &metadataConn{Conn: secondSAM, remote: []byte("SECOND"), from: 12, to: 22}
	if line := readSAMLine(t, firstReader); line != "STREAM STATUS RESULT=OK" {
		t.Fatal(line)
	}
	if line := readSAMLine(t, firstReader); line != "FIRST FROM_PORT=11 TO_PORT=21" {
		t.Fatalf("first attachment = %q", line)
	}
	if line := readSAMLine(t, secondReader); line != "STREAM STATUS RESULT=OK" {
		t.Fatal(line)
	}
	if line := readSAMLine(t, secondReader); line != "SECOND FROM_PORT=12 TO_PORT=22" {
		t.Fatalf("second attachment = %q", line)
	}
}

func TestStreamAcceptDeadFirstAttachmentDoesNotConsumeInbound(t *testing.T) {
	loop := &loopController{endpoints: make(map[ivnp.Hash]*loopEndpoint)}
	controller := &fifoController{loop: loop, endpoint: make(chan *fifoEndpoint, 1)}
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: controller, SessionQueue: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()
	control, controlReader := samDial(t, server.Addr().String())
	defer control.Close()
	_, _ = io.WriteString(control, "SESSION CREATE STYLE=STREAM ID=dead-first DESTINATION=TRANSIENT\n")
	if line := readSAMLine(t, controlReader); line[:24] != "SESSION STATUS RESULT=OK" {
		t.Fatal(line)
	}
	endpoint := <-controller.endpoint

	first, _ := samDial(t, server.Addr().String())
	_, _ = io.WriteString(first, "STREAM ACCEPT ID=dead-first\n")
	waitForSAMCondition(t, time.Second, func() bool {
		server.mu.RLock()
		session := server.sessions["dead-first"]
		server.mu.RUnlock()
		return session != nil && session.acceptAdmissions.Load() >= 1
	}, "dead accept request admission")
	_ = first.Close()
	waitForSAMCondition(t, time.Second, func() bool {
		server.mu.RLock()
		session := server.sessions["dead-first"]
		server.mu.RUnlock()
		return session != nil && session.acceptCancellations.Load() >= 1
	}, "dead accept request cancellation")

	second, secondReader := samDial(t, server.Addr().String())
	defer second.Close()
	_, _ = io.WriteString(second, "STREAM ACCEPT ID=dead-first\n")
	inbound, peer := net.Pipe()
	defer peer.Close()
	endpoint.listener.incoming <- &metadataConn{Conn: inbound, remote: []byte("LIVE"), from: 31, to: 41}
	if line := readSAMLine(t, secondReader); line != "STREAM STATUS RESULT=OK" {
		t.Fatal(line)
	}
	if line := readSAMLine(t, secondReader); line != "LIVE FROM_PORT=31 TO_PORT=41" {
		t.Fatalf("second attachment = %q", line)
	}
}

func waitForSAMCondition(t *testing.T, timeout time.Duration, condition func() bool, name string) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	ticker := time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal(name + " did not complete")
		case <-ticker.C:
		}
	}
}
