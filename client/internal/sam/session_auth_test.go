package sam

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

func samSessionAuth(t *testing.T, control net.Conn, reader *bufio.Reader) string {
	t.Helper()
	if _, err := io.WriteString(control, "SESSION AUTH\n"); err != nil {
		t.Fatal(err)
	}
	fields, err := parseResponse(readSAMLine(t, reader))
	if err != nil || fields["RESULT"] != "OK" || len(fields["IVNP_AUTH"]) != 2*sessionAuthSize {
		t.Fatalf("SESSION AUTH fields = %v, error = %v", fields, err)
	}
	return fields["IVNP_AUTH"]
}

func TestSAMSessionAuthorization(t *testing.T) {
	root := &samSession{auth: [sessionAuthSize]byte{1}}
	root.root = root
	child := &samSession{root: root}
	foreign := &samSession{}
	foreign.root = foreign
	server := &Server{sessions: map[string]*samSession{"owner": root, "child": child}}
	token := root.authString()
	for _, tt := range []struct {
		name       string
		connection *serverConnection
		id         string
		token      string
		want       *samSession
	}{
		{name: "owner control", connection: &serverConnection{root: root}, id: "owner", want: root},
		{name: "primary child", connection: &serverConnection{root: root}, id: "child", want: child},
		{name: "delegated child", id: "child", token: token, want: child},
		{name: "delegated root", id: "owner", token: token, want: root},
		{name: "missing capability", id: "owner"},
		{name: "different owner", connection: &serverConnection{root: foreign}, id: "owner"},
		{name: "wrong capability", id: "owner", token: strings.Repeat("0", 2*sessionAuthSize)},
		{name: "short capability", id: "owner", token: token[:len(token)-1]},
		{name: "long capability", id: "owner", token: token + "0"},
		{name: "invalid hex", id: "owner", token: strings.Repeat("g", 2*sessionAuthSize)},
		{name: "unknown ID", id: "missing", token: token},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := server.authorizedSession(tt.connection, tt.id, tt.token); got != tt.want {
				t.Fatalf("authorizedSession(%q) = %p, want %p", tt.id, got, tt.want)
			}
		})
	}
}

func TestSAMRejectsForeignSessionCommands(t *testing.T) {
	for _, tt := range []struct {
		style    string
		commands []string
	}{
		{style: "STREAM", commands: []string{
			"STREAM CONNECT ID=victim DESTINATION=peer.i2p",
			"STREAM ACCEPT ID=victim",
			"STREAM FORWARD ID=victim PORT=12345",
		}},
		{style: "DATAGRAM", commands: []string{"DATAGRAM SEND ID=victim DESTINATION=peer.i2p SIZE=4"}},
		{style: "RAW", commands: []string{"RAW SEND ID=victim DESTINATION=peer.i2p SIZE=4"}},
	} {
		t.Run(tt.style, func(t *testing.T) {
			controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
			server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: controller})
			if err != nil {
				t.Fatal(err)
			}
			if err = server.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close(); _ = server.Wait() })
			owner, reader := samDial(t, server.Addr().String())
			t.Cleanup(func() { _ = owner.Close() })
			_, _ = fmt.Fprintf(owner, "SESSION CREATE STYLE=%s ID=victim DESTINATION=TRANSIENT\n", tt.style)
			if line := readSAMLine(t, reader); !strings.Contains(line, "RESULT=OK DESTINATION=") {
				t.Fatalf("CREATE = %q", line)
			}
			token := samSessionAuth(t, owner, reader)
			for _, cmd := range tt.commands {
				for _, auth := range []string{"", " IVNP_AUTH=" + strings.Repeat("0", len(token))} {
					connection, response := samDial(t, server.Addr().String())
					if _, err := io.WriteString(connection, cmd+auth+"\n"); err != nil {
						t.Fatal(err)
					}
					line := readSAMLine(t, response)
					want := strings.SplitN(cmd, " ", 2)[0] + " STATUS RESULT=INVALID_ID"
					if line != want {
						t.Fatalf("unauthorized %q replied %q, want %q", cmd+auth, line, want)
					}
					_ = connection.Close()
				}
			}
			_ = owner.Close()
			waitForSAMCondition(t, time.Second, func() bool {
				return server.session("victim") == nil
			}, "session removal")
			connection, response := samDial(t, server.Addr().String())
			defer connection.Close()
			_, _ = io.WriteString(connection, tt.commands[0]+" IVNP_AUTH="+token+"\n")
			want := strings.SplitN(tt.commands[0], " ", 2)[0] + " STATUS RESULT=INVALID_ID"
			if line := readSAMLine(t, response); line != want {
				t.Fatalf("revoked capability = %q, want %q", line, want)
			}
		})
	}
}

func TestNetworkUsesEmbeddedSessionCapability(t *testing.T) {
	peer, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.ReleaseSensitive()
	controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	server, err := NewServer(ServerConfig{
		Address: "127.0.0.1:0", Controller: controller,
		Resolver: fixedResolver(string(peer.Destination())),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()
	client, err := New(Config{Address: server.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	connection, err := client.DialI2P(t.Context(), "peer.i2p:80")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = connection.Write([]byte("test")); err != nil {
		t.Fatal(err)
	}
	var response [4]byte
	if _, err = io.ReadFull(connection, response[:]); err != nil || string(response[:]) != "test" {
		t.Fatalf("authorized stream relay = %q, error = %v", response, err)
	}
}
