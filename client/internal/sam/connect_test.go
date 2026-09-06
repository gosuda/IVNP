package sam

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
)

type connectEndpoint struct {
	destination.DestinationEndpoint
	dial func(context.Context, string, uint16) (net.Conn, error)
}

func (e *connectEndpoint) DialI2P(ctx context.Context, address string) (net.Conn, error) {
	return e.dial(ctx, address, 0)
}

func (e *connectEndpoint) DialI2PFromPort(ctx context.Context, address string, port uint16) (net.Conn, error) {
	return e.dial(ctx, address, port)
}

type connectResolver func(context.Context, string) (string, error)

func (r connectResolver) ResolveDestination(ctx context.Context, target string) (string, error) {
	return r(ctx, target)
}

func newConnectTestServer(t *testing.T, endpoint destination.DestinationEndpoint) (*Server, *samSession) {
	t.Helper()
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: &loopController{}})
	if err != nil {
		t.Fatal(err)
	}
	server.ctx, server.cancel = context.WithCancel(t.Context())
	t.Cleanup(server.cancel)
	session := &samSession{
		server: server, id: "root", style: styleStream, endpoint: endpoint,
		ctx: server.ctx, attachments: make(map[net.Conn]struct{}),
		queueBytes: newByteBudget(server.config.MaxSessionQueueBytes),
	}
	server.sessions[session.id] = session
	return server, session
}

func startConnectAttachment(t *testing.T, server *Server) (net.Conn, *bufio.Reader, <-chan error) {
	t.Helper()
	client, attachment := net.Pipe()
	result := make(chan error, 1)
	go func() {
		result <- server.serveConnection(attachment)
		close(result)
	}()
	t.Cleanup(func() {
		_ = client.Close()
		server.cancel()
		<-result
	})
	if _, err := io.WriteString(client, "HELLO VERSION MIN=3.3 MAX=3.3\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	if line := readSAMLine(t, reader); !strings.Contains(line, "RESULT=OK") {
		t.Fatalf("HELLO reply = %q", line)
	}
	return client, reader, result
}

func assertConnectEcho(t *testing.T, server *Server) {
	t.Helper()
	client, reader, result := startConnectAttachment(t, server)
	if _, err := io.WriteString(client, "STREAM CONNECT ID=root DESTINATION="+foundation.B32(foundation.Hash{1})+"\n"); err != nil {
		t.Fatal(err)
	}
	if line := readSAMLine(t, reader); line != "STREAM STATUS RESULT=OK" {
		t.Fatalf("CONNECT after cancellation = %q", line)
	}
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 5)
	if _, err := io.ReadFull(reader, payload); err != nil || string(payload) != "hello" {
		t.Fatalf("CONNECT echo = %q, %v", payload, err)
	}
	_ = client.Close()
	<-result
}

func TestConnectDisconnectCancelsBackendWithoutClosingSession(t *testing.T) {
	for _, phase := range []string{"resolve", "dial", "source port dial"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				entered, canceled := make(chan struct{}), make(chan struct{})
				block := func(ctx context.Context) error {
					close(entered)
					<-ctx.Done()
					close(canceled)
					return ctx.Err()
				}
				echo := &loopEndpoint{}
				endpoint := &connectEndpoint{dial: func(ctx context.Context, address string, port uint16) (net.Conn, error) {
					if phase != "resolve" {
						return nil, block(ctx)
					}
					return echo.DialI2P(ctx, address)
				}}
				server, session := newConnectTestServer(t, endpoint)
				server.config.Resolver = connectResolver(func(ctx context.Context, _ string) (string, error) {
					return "", block(ctx)
				})
				client, _, result := startConnectAttachment(t, server)
				target := foundation.B32(foundation.Hash{1})
				if phase == "resolve" {
					target = "slow.i2p"
				}
				command := "STREAM CONNECT ID=root DESTINATION=" + target
				if phase == "source port dial" {
					command += " FROM_PORT=1234"
				}
				if _, err := io.WriteString(client, command+"\npipelined payload"); err != nil {
					t.Fatal(err)
				}
				<-entered
				_ = client.Close()
				synctest.Wait()
				select {
				case <-canceled:
				default:
					t.Fatal("disconnected CONNECT left backend work alive")
				}
				select {
				case <-result:
				default:
					t.Fatal("disconnected CONNECT did not join its work")
				}
				if session.ctx.Err() != nil {
					t.Fatalf("attachment canceled root session: %v", session.ctx.Err())
				}
				if len(session.attachments) != 0 || session.queueBytes.used.Load() != 0 || server.queueBytes.used.Load() != 0 {
					t.Fatal("disconnected CONNECT retained an attachment or byte reservation")
				}
				endpoint.dial = func(ctx context.Context, address string, _ uint16) (net.Conn, error) {
					return echo.DialI2P(ctx, address)
				}
				assertConnectEcho(t, server)
			})
		})
	}
}

func TestConnectPreservesPipelinedPayload(t *testing.T) {
	for _, test := range []struct {
		name   string
		silent bool
		full   bool
	}{
		{name: "status"},
		{name: "silent", silent: true},
		{name: "full buffer silent", silent: true, full: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				entered, ready := make(chan struct{}), make(chan struct{})
				echo := &loopEndpoint{}
				endpoint := &connectEndpoint{dial: func(ctx context.Context, address string, _ uint16) (net.Conn, error) {
					close(entered)
					select {
					case <-ready:
						return echo.DialI2P(ctx, address)
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}}
				server, _ := newConnectTestServer(t, endpoint)
				client, reader, result := startConnectAttachment(t, server)
				command := "STREAM CONNECT ID=root DESTINATION=" + foundation.B32(foundation.Hash{1})
				if test.silent {
					command += " SILENT=true"
				}
				payload := "before-dial\x00after-dial"
				if test.full {
					payload += strings.Repeat("x", 2*server.config.MaxCommandBytes)
				}
				if _, err := io.WriteString(client, command+"\n"+payload[:11]); err != nil {
					t.Fatal(err)
				}
				<-entered
				written := make(chan error, 1)
				go func() {
					_, err := io.WriteString(client, payload[11:])
					written <- err
				}()
				t.Cleanup(func() { _ = client.Close(); <-written })
				synctest.Wait()
				_ = client.SetReadDeadline(time.Now().Add(time.Second))
				close(ready)
				if !test.silent {
					if line := readSAMLine(t, reader); line != "STREAM STATUS RESULT=OK" {
						t.Fatalf("CONNECT reply = %q", line)
					}
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(reader, got); err != nil || string(got) != payload {
					t.Fatalf("pipelined echo = %q, %v; want %q", got, err, payload)
				}
				_ = client.Close()
				<-result
			})
		})
	}
}

func TestConnectUsesRemainingCommandBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		endpoint := &connectEndpoint{dial: func(ctx context.Context, _ string, _ uint16) (net.Conn, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}}
		server, session := newConnectTestServer(t, endpoint)
		server.config.CommandTimeout = time.Minute
		client, _, result := startConnectAttachment(t, server)
		synctest.Wait()
		<-time.After(40 * time.Second)
		if _, err := io.WriteString(client, "STREAM CONNECT ID=root DESTINATION="+foundation.B32(foundation.Hash{1})+"\n"); err != nil {
			t.Fatal(err)
		}
		<-entered
		<-time.After(20 * time.Second)
		synctest.Wait()
		select {
		case err := <-result:
			if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("expired CONNECT = %v", err)
			}
		default:
			t.Fatal("CONNECT extended the pre-session command deadline")
		}
		if session.ctx.Err() != nil {
			t.Fatalf("command timeout canceled root session: %v", session.ctx.Err())
		}
	})
}

func TestConnectSessionCancellationJoinsMonitor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		endpoint := &connectEndpoint{dial: func(ctx context.Context, _ string, _ uint16) (net.Conn, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}}
		server, _ := newConnectTestServer(t, endpoint)
		client, _, result := startConnectAttachment(t, server)
		if _, err := io.WriteString(client, "STREAM CONNECT ID=root DESTINATION="+foundation.B32(foundation.Hash{1})+"\n"); err != nil {
			t.Fatal(err)
		}
		<-entered
		server.cancel()
		synctest.Wait()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled CONNECT = %v", err)
			}
		default:
			t.Fatal("session cancellation stranded CONNECT on its healthy attachment")
		}
	})
}
