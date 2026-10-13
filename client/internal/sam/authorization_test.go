package sam

import (
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func testSAMAuthToken(t *testing.T, response string) string {
	t.Helper()
	fields, err := parseResponse(response)
	if err != nil || fields["RESULT"] != "OK" {
		t.Fatalf("invalid SESSION CREATE response: %q (%v)", response, err)
	}
	token := fields["IVNP_AUTH"]
	if len(token) != base64.RawURLEncoding.EncodedLen(samAuthBytes) {
		t.Fatal("SESSION CREATE did not issue a 256-bit capability")
	}
	return token
}

func testSessionToken(session *samSession) string {
	return base64.RawURLEncoding.EncodeToString(session.root.auth[:])
}

func TestSAMSessionAuthorizationIsRootScoped(t *testing.T) {
	var firstAuth, secondAuth [samAuthBytes]byte
	firstAuth[0], secondAuth[0] = 1, 2
	first := &samSession{id: "first", auth: firstAuth}
	first.root = first
	second := &samSession{id: "second", auth: secondAuth}
	second.root = second
	child := &samSession{id: "child", root: first}
	server := &Server{sessions: map[string]*samSession{
		"first": first, "second": second, "child": child,
	}}
	owner := &serverConnection{root: first}
	foreigner := &serverConnection{root: second}
	firstToken := testSessionToken(first)
	secondToken := testSessionToken(second)

	for _, test := range []struct {
		name       string
		connection *serverConnection
		id         string
		token      string
		want       *samSession
	}{
		{name: "owner", connection: owner, id: "first", want: first},
		{name: "owner child", connection: owner, id: "child", want: child},
		{name: "owner with malformed token", connection: owner, id: "first", token: "bad", want: first},
		{name: "unbound missing token", id: "first"},
		{name: "foreign root", connection: foreigner, id: "first"},
		{name: "foreign root child", connection: foreigner, id: "child"},
		{name: "wrong root token", id: "first", token: secondToken},
		{name: "short token", id: "first", token: firstToken[:len(firstToken)-1]},
		{name: "long token", id: "first", token: firstToken + "A"},
		{name: "malformed token", id: "first", token: strings.Repeat("!", len(firstToken))},
		{name: "unknown id", id: "missing", token: firstToken},
		{name: "valid token", id: "first", token: firstToken, want: first},
		{name: "valid token on child", id: "child", token: firstToken, want: child},
		{name: "valid token from another root", connection: foreigner, id: "first", token: firstToken, want: first},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := server.authorizedSession(test.connection, test.id, test.token); got != test.want {
				t.Fatalf("resolved session = %p, want %p", got, test.want)
			}
		})
	}
}

func TestSAMForeignClientCannotUseOtherSessionIDs(t *testing.T) {
	controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: controller})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()

	for _, session := range []struct{ id, style string }{
		{id: "victim-stream", style: "STREAM"},
		{id: "victim-datagram", style: "DATAGRAM"},
		{id: "victim-raw", style: "RAW"},
	} {
		control, reader := samDial(t, server.Addr().String())
		defer control.Close()
		if _, err := io.WriteString(control, "SESSION CREATE STYLE="+session.style+" ID="+session.id+" DESTINATION=TRANSIENT\n"); err != nil {
			t.Fatal(err)
		}
		testSAMAuthToken(t, readSAMLine(t, reader))
	}

	attacker, attackerReader := samDial(t, server.Addr().String())
	defer attacker.Close()
	if _, err := io.WriteString(attacker, "SESSION CREATE STYLE=PRIMARY ID=attacker DESTINATION=TRANSIENT\n"); err != nil {
		t.Fatal(err)
	}
	testSAMAuthToken(t, readSAMLine(t, attackerReader))
	for _, command := range []string{
		"DATAGRAM SEND ID=victim-datagram DESTINATION=invalid SIZE=0",
		"RAW SEND ID=victim-raw DESTINATION=invalid SIZE=0",
	} {
		if _, err := io.WriteString(attacker, command+"\n"); err != nil {
			t.Fatal(err)
		}
		if reply := readSAMLine(t, attackerReader); !strings.HasSuffix(reply, "STATUS RESULT=INVALID_ID") {
			t.Fatalf("%q => %q", command, reply)
		}
	}

	for _, command := range []string{
		"STREAM CONNECT ID=victim-stream DESTINATION=invalid",
		"STREAM ACCEPT ID=victim-stream",
		"STREAM FORWARD ID=victim-stream HOST=127.0.0.1 PORT=1234",
		"STREAM CONNECT ID=victim-stream DESTINATION=invalid IVNP_AUTH=invalid",
	} {
		connection, reader := samDial(t, server.Addr().String())
		if _, err := io.WriteString(connection, command+"\n"); err != nil {
			t.Fatal(err)
		}
		if reply := readSAMLine(t, reader); reply != "STREAM STATUS RESULT=INVALID_ID" {
			t.Fatalf("%q => %q", command, reply)
		}
		_ = connection.Close()
	}
}

func TestSAMNetworkClientUsesSessionCredential(t *testing.T) {
	controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	peer, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.ReleaseSensitive()
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: controller, Resolver: fixedResolver(string(peer.Destination()))})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()

	network, err := New(Config{Address: server.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := network.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	connection, err := network.DialI2P(t.Context(), "peer.i2p:80")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("okay")); err != nil {
		t.Fatal(err)
	}
	var received [4]byte
	if _, err := io.ReadFull(connection, received[:]); err != nil || string(received[:]) != "okay" {
		t.Fatalf("authenticated stream reply = %q (%v)", received, err)
	}
}

func TestSAMSessionAuthorizationDeniedAfterRemoval(t *testing.T) {
	var secret [samAuthBytes]byte
	secret[0] = 1
	root := &samSession{id: "root", auth: secret}
	root.root = root
	server := &Server{sessions: map[string]*samSession{"root": root}}
	token := testSessionToken(root)
	if server.authorizedSession(nil, "root", token) != root {
		t.Fatal("valid token rejected")
	}
	server.removeSession(root)
	if server.authorizedSession(nil, "root", token) != nil {
		t.Fatal("removed session remained authorized")
	}
}
