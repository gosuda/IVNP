package sam

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp"
)

func TestNetworkStreamDialAndListen(t *testing.T) {
	privateDestination := testPrivateDestination(t)
	bridge := newFakeBridge(t, privateDestination)
	defer bridge.Close()

	network, err := New(Config{Address: bridge.listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := network.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if network.B32() == "" || network.PublicDestination() == "" || network.PrivateDestination() != privateDestination {
		t.Fatalf("session addresses: b32=%q public=%q private=%q", network.B32(), network.PublicDestination(), network.PrivateDestination())
	}

	connection, err := network.DialI2P(context.Background(), "peer.b32.i2p:80")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("dial")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(connection, got); err != nil || string(got) != "dial" {
		t.Fatalf("dial stream = %q, %v", got, err)
	}

	listener, err := network.ListenI2P(context.Background(), ":7777")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		accepted <- connection
	}()
	select {
	case connection := <-accepted:
		defer connection.Close()
		if connection.RemoteAddr().String() != "peer.b32.i2p:1234" || connection.LocalAddr().String() != listener.Addr().String() {
			t.Fatalf("accepted addresses = local %q remote %q", connection.LocalAddr(), connection.RemoteAddr())
		}
		if _, err := connection.Write([]byte("accept")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 6)
		if _, err := io.ReadFull(connection, got); err != nil || string(got) != "accept" {
			t.Fatalf("accepted stream = %q, %v", got, err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener Accept did not complete")
	}
	if err := network.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestParseResponseAcceptsQuotedSAMMessage(t *testing.T) {
	fields, err := parseResponse(`SESSION STATUS RESULT=I2P_ERROR MESSAGE="tunnel build failed: no peers"`)
	if err != nil {
		t.Fatal(err)
	}
	if fields["RESULT"] != "I2P_ERROR" || fields["MESSAGE"] != "tunnel build failed: no peers" {
		t.Fatalf("response fields = %#v", fields)
	}
}

func TestParseResponseRejectsUnterminatedQuotedSAMMessage(t *testing.T) {
	if _, err := parseResponse(`SESSION STATUS RESULT=I2P_ERROR MESSAGE="unterminated`); !errors.Is(err, ErrProtocol) {
		t.Fatalf("unterminated response error = %v", err)
	}
}

func TestControlCommandHonorsContextDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	control := &control{Conn: client, reader: bufio.NewReader(client)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := control.commandContext(ctx, "HELLO VERSION MIN=3.1 MAX=3.3"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("command deadline error = %v", err)
	}
}

func TestNetworkRequiresStart(t *testing.T) {
	network, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := network.DialI2P(context.Background(), "peer.b32.i2p"); err != ErrUnavailable {
		t.Fatalf("Dial before Start error = %v", err)
	}
	if _, err := network.ListenI2P(context.Background(), ""); err != ErrUnavailable {
		t.Fatalf("Listen before Start error = %v", err)
	}
}

func TestNetworkRejectsUnsafeSessionOptions(t *testing.T) {
	if _, err := New(Config{SessionOptions: map[string]string{"inbound.length": "1 bad"}}); err != ErrAddress {
		t.Fatalf("unsafe session option error = %v, want %v", err, ErrAddress)
	}
	if _, err := New(Config{SessionOptions: map[string]string{"bad key": "1"}}); err != ErrAddress {
		t.Fatalf("unsafe session option key error = %v, want %v", err, ErrAddress)
	}
}
func TestNetworkDoesNotPingSAM31Session(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	private := testPrivateDestination(t)
	observed := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			observed <- acceptErr
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		if _, readErr := reader.ReadString('\n'); readErr != nil {
			observed <- readErr
			return
		}
		if _, writeErr := io.WriteString(connection, "HELLO REPLY RESULT=OK VERSION=3.1\n"); writeErr != nil {
			observed <- writeErr
			return
		}
		if _, readErr := reader.ReadString('\n'); readErr != nil {
			observed <- readErr
			return
		}
		if _, writeErr := io.WriteString(connection, "SESSION STATUS RESULT=OK DESTINATION="+private+"\n"); writeErr != nil {
			observed <- writeErr
			return
		}
		_ = connection.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
		line, readErr := reader.ReadString('\n')
		var timeout net.Error
		if errors.As(readErr, &timeout) && timeout.Timeout() {
			observed <- nil
			return
		}
		observed <- errors.New("SAM 3.1 root received unexpected command: " + strings.TrimSpace(line))
	}()
	network, err := New(Config{Address: listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	network.keepaliveInterval = 10 * time.Millisecond
	if err = network.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = <-observed; err != nil {
		t.Fatal(err)
	}
	if err = network.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestNetworkPingsSAM32Session(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	private := testPrivateDestination(t)
	observed := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			observed <- acceptErr
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		_, _ = reader.ReadString('\n')
		_, _ = io.WriteString(connection, "HELLO REPLY RESULT=OK VERSION=3.2\n")
		_, _ = reader.ReadString('\n')
		_, _ = io.WriteString(connection, "SESSION STATUS RESULT=OK DESTINATION="+private+"\n")
		line, readErr := reader.ReadString('\n')
		if readErr != nil || strings.TrimSpace(line) != "PING ivnp-keepalive" {
			observed <- errors.New("SAM 3.2 root did not receive keepalive")
			return
		}
		_, _ = io.WriteString(connection, "PONG ivnp-keepalive\n")
		observed <- nil
		_, _ = io.Copy(io.Discard, reader)
	}()
	network, err := New(Config{Address: listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	network.keepaliveInterval = 10 * time.Millisecond
	if err = network.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = <-observed; err != nil {
		t.Fatal(err)
	}
	if err = network.Close(); err != nil {
		t.Fatal(err)
	}
}

type fakeBridge struct {
	listener net.Listener
	closed   chan struct{}
	wg       sync.WaitGroup
	private  string
}

func newFakeBridge(t *testing.T, private string) *fakeBridge {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bridge := &fakeBridge{listener: listener, closed: make(chan struct{}), private: private}
	bridge.wg.Add(1)
	go func() {
		defer bridge.wg.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			bridge.wg.Add(1)
			go func() {
				defer bridge.wg.Done()
				bridge.handle(connection)
			}()
		}
	}()
	return bridge
}

func (b *fakeBridge) handle(connection net.Conn) {
	defer connection.Close()
	reader := bufio.NewReader(connection)
	hello, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(hello, "HELLO VERSION") {
		return
	}
	if _, err = io.WriteString(connection, "HELLO REPLY RESULT=OK VERSION=3.3\n"); err != nil {
		return
	}
	command, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	switch {
	case strings.HasPrefix(command, "SESSION CREATE "):
		_, _ = io.WriteString(connection, "SESSION STATUS RESULT=OK DESTINATION="+b.private+"\n")
		<-b.closed
	case strings.HasPrefix(command, "STREAM CONNECT "):
		_, _ = io.WriteString(connection, "STREAM STATUS RESULT=OK\n")
		_, _ = io.Copy(connection, reader)
	case strings.HasPrefix(command, "STREAM ACCEPT "):
		_, _ = io.WriteString(connection, "STREAM STATUS RESULT=OK\npeer.b32.i2p FROM_PORT=1234 TO_PORT=7777\n")
		_, _ = io.Copy(connection, reader)
	}
}

func (b *fakeBridge) Close() {
	close(b.closed)
	_ = b.listener.Close()
	b.wg.Wait()
}

func testPrivateDestination(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := make([]byte, ivnp.IdentityBaseLength+7)
	copy(identity[352:384], public)
	identity[384] = byte(ivnp.CertificateKey)
	identity[385], identity[386] = 0, 4
	identity[387], identity[388] = 0, byte(ivnp.SigningEdDSASHA512Ed25519)
	encoding := base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~")
	encoded := make([]byte, encoding.EncodedLen(len(identity)))
	encoding.Encode(encoded, identity)
	return string(encoded)
}
