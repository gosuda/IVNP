package sam

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"strings"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

// offlineSAMPrivateDestination builds a SAM private destination whose signing
// private key is all zero followed by an Offline Signature section authorizing
// a freshly generated transient Ed25519 key.
func offlineSAMPrivateDestination(t *testing.T, expires uint32) (private, public string) {
	t.Helper()
	longTerm, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer longTerm.ReleaseSensitive()
	identityRaw, err := foundation.DecodeI2PBase64(longTerm.Destination())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(identityRaw)
	var encryption [32]byte
	if err = longTerm.CopyX25519Private(encryption[:]); err != nil {
		t.Fatal(err)
	}
	defer clear(encryption[:])
	transientPublic, transientFull, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	offline := foundation.OfflineSignature{Expires: expires, Type: foundation.SigningEdDSASHA512Ed25519, PublicKey: transientPublic}
	signed := offline.SignedContent()
	offline.Signature, err = longTerm.Sign(signed)
	if err != nil {
		t.Fatal(err)
	}
	seed := transientFull.Seed()
	defer clear(seed)
	wire := make([]byte, 0, len(identityRaw)+32+32+len(signed)+len(offline.Signature)+len(seed))
	wire = append(wire, identityRaw...)
	wire = append(wire, encryption[:]...)
	wire = append(wire, make([]byte, 32)...)
	wire = append(wire, signed...)
	wire = append(wire, offline.Signature...)
	wire = append(wire, seed...)
	encoded := foundation.EncodeI2PBase64(wire)
	clear(wire)
	return encoded, string(longTerm.Destination())
}

func TestDatagram2OfflineRoundtrip(t *testing.T) {
	controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: controller, MaxSessions: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()
	private, public := offlineSAMPrivateDestination(t, uint32(time.Now().Add(time.Hour).Unix()))
	control, reader := samDial(t, server.Addr().String())
	defer control.Close()
	_, _ = io.WriteString(control, "SESSION CREATE STYLE=DATAGRAM2 ID=offline DESTINATION="+private+"\n")
	line := readSAMLine(t, reader)
	if !strings.Contains(line, "RESULT=OK DESTINATION=") {
		t.Fatalf("offline create = %q", line)
	}
	if echoed := strings.Split(line, " DESTINATION=")[1]; echoed != private {
		t.Fatal("SESSION STATUS did not echo the offline private destination")
	}
	_, _ = io.WriteString(control, "DATAGRAM SEND ID=offline DESTINATION="+public+" SIZE=4\nDATA")
	if line = readSAMLine(t, reader); line != "DATAGRAM STATUS RESULT=OK" {
		t.Fatalf("datagram status = %q", line)
	}
	line = readSAMLine(t, reader)
	if !strings.HasPrefix(line, "DATAGRAM RECEIVED DESTINATION="+public+" ") || !strings.Contains(line, "SIZE=4") {
		t.Fatalf("datagram receive = %q", line)
	}
	body := make([]byte, 4)
	if _, err = io.ReadFull(reader, body); err != nil || string(body) != "DATA" {
		t.Fatalf("datagram body = %q, %v", body, err)
	}
}

func TestDatagram2OfflineExpiredRejected(t *testing.T) {
	controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: controller, MaxSessions: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()
	address := server.Addr().String()
	receiver, receiverReader, receiverLocal := createDatagramSession(t, address, "receiver", "DATAGRAM2")
	defer receiver.Close()
	defer receiverLocal.ReleaseSensitive()
	target := string(receiverLocal.Destination())

	private, _ := offlineSAMPrivateDestination(t, uint32(time.Now().Add(-time.Hour).Unix()))
	sender, senderReader := samDial(t, address)
	defer sender.Close()
	_, _ = io.WriteString(sender, "SESSION CREATE STYLE=DATAGRAM2 ID=sender DESTINATION="+private+"\n")
	if line := readSAMLine(t, senderReader); !strings.Contains(line, "RESULT=OK") {
		t.Fatalf("expired offline create = %q", line)
	}
	_, _ = io.WriteString(sender, "DATAGRAM SEND ID=sender DESTINATION="+target+" SIZE=4\nDATA")
	if line := readSAMLine(t, senderReader); line == "DATAGRAM STATUS RESULT=OK" {
		t.Fatal("sender signed with an expired offline signature")
	}
	if err = receiver.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err = receiverReader.ReadString('\n'); err == nil {
		t.Fatal("receiver accepted a datagram with an expired offline signature")
	}
}

func TestSessionCreateOfflineForgedSignatureRejected(t *testing.T) {
	controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: controller, MaxSessions: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()
	private, public := offlineSAMPrivateDestination(t, uint32(time.Now().Add(time.Hour).Unix()))
	raw, err := foundation.DecodeI2PBase64([]byte(private))
	if err != nil {
		t.Fatal(err)
	}
	identityRaw, err := foundation.DecodeI2PBase64([]byte(public))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit inside the authorization signature (after the identity,
	// encryption key, zero signing key, and the expires/type/public key
	// fields of the offline section).
	raw[len(identityRaw)+32+32+6+32] ^= 0xff
	clear(identityRaw)
	forged := foundation.EncodeI2PBase64(raw)
	clear(raw)
	control, reader := samDial(t, server.Addr().String())
	defer control.Close()
	_, _ = io.WriteString(control, "SESSION CREATE STYLE=DATAGRAM2 ID=forged DESTINATION="+forged+"\n")
	if line := readSAMLine(t, reader); !strings.Contains(line, "RESULT=INVALID_KEY") {
		t.Fatalf("forged offline create = %q", line)
	}
}
