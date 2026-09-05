package sam

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/networking"
)

func TestParseStyleDatagramModern(t *testing.T) {
	for _, value := range []string{"DATAGRAM2", "datagram2", "DATAGRAM3", "datagram3"} {
		style, ok := parseStyle(value)
		if !ok {
			t.Fatalf("parseStyle(%q) rejected", value)
		}
		if style != sessionStyle(strings.ToUpper(value)) {
			t.Fatalf("parseStyle(%q) = %q", value, style)
		}
	}
	if _, ok := parseStyle("DATAGRAM4"); ok {
		t.Fatal("parseStyle accepted DATAGRAM4")
	}
}

func TestConfigurePacketTransportDatagramModern(t *testing.T) {
	server := &Server{}
	cases := []struct {
		style    sessionStyle
		protocol uint8
	}{
		{styleDatagram, networking.DatagramProtocolDatagram1},
		{styleDatagram2, networking.DatagramProtocolDatagram2},
		{styleDatagram3, networking.DatagramProtocolDatagram3},
	}
	for _, tc := range cases {
		config := sessionTransportConfig{}
		if err := server.configurePacketTransport(nil, &config, tc.style, map[string]string{}, false); err != nil {
			t.Fatalf("style %s: %v", tc.style, err)
		}
		if config.protocol != tc.protocol || config.listenProtocol != tc.protocol {
			t.Fatalf("style %s protocol = %d/%d, want %d", tc.style, config.protocol, config.listenProtocol, tc.protocol)
		}
		for _, option := range []string{"PROTOCOL", "HEADER", "LISTEN_PROTOCOL"} {
			config = sessionTransportConfig{}
			if err := server.configurePacketTransport(nil, &config, tc.style, map[string]string{option: "1"}, true); err == nil {
				t.Fatalf("style %s accepted %s option", tc.style, option)
			}
		}
	}
}

func TestDatagramOverheadPerProtocol(t *testing.T) {
	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer local.ReleaseSensitive()
	endpoint := &loopEndpoint{
		local:         local,
		controller:    &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)},
		subscriptions: make(map[destination.DestinationRoute]*loopSubscription),
	}
	defer endpoint.Close()
	v1 := datagramOverhead(networking.DatagramProtocolDatagram1, endpoint, nil)
	v2 := datagramOverhead(networking.DatagramProtocolDatagram2, endpoint, nil)
	v3 := datagramOverhead(networking.DatagramProtocolDatagram3, endpoint, nil)
	if v1 <= 0 || v2 != v1+2 {
		t.Fatalf("v1 = %d, v2 = %d, want v1+2", v1, v2)
	}
	if v3 != 34 {
		t.Fatalf("v3 overhead = %d, want 34", v3)
	}
	if other := datagramOverhead(6, endpoint, nil); other != 0 {
		t.Fatalf("stream protocol overhead = %d, want 0", other)
	}
	offline := &foundation.OfflineSignature{Type: foundation.SigningEdDSASHA512Ed25519, PublicKey: make([]byte, 32)}
	identity, err := local.Identity()
	if err != nil {
		t.Fatal(err)
	}
	authorizationLen, ok := identity.SigningKeyType().SignatureLen()
	if !ok {
		t.Fatal("unknown signing key type")
	}
	transientLen, ok := offline.Type.SignatureLen()
	if !ok {
		t.Fatal("unknown transient key type")
	}
	want := identity.EncodedLen() + 2 + 6 + len(offline.PublicKey) + authorizationLen + transientLen
	if got := datagramOverhead(networking.DatagramProtocolDatagram2, endpoint, offline); got != want {
		t.Fatalf("offline v2 overhead = %d, want %d", got, want)
	}
	// Offline signatures never enter Datagram3 or Datagram1 wire formats.
	if got := datagramOverhead(networking.DatagramProtocolDatagram3, endpoint, offline); got != 34 {
		t.Fatalf("offline v3 overhead = %d, want 34", got)
	}
}

func createDatagramSession(t *testing.T, address, id, style string) (net.Conn, *bufio.Reader, *foundation.LocalDestination) {
	t.Helper()
	control, reader := samDial(t, address)
	_, _ = io.WriteString(control, "SESSION CREATE STYLE="+style+" ID="+id+" DESTINATION=TRANSIENT\n")
	line := readSAMLine(t, reader)
	if !strings.Contains(line, "RESULT=OK DESTINATION=") {
		t.Fatalf("%s create = %q", style, line)
	}
	local, err := decodePrivateDestination(strings.Split(line, " DESTINATION=")[1])
	if err != nil {
		t.Fatal(err)
	}
	return control, reader, local
}

func TestDatagramModernRoundtrip(t *testing.T) {
	for _, style := range []string{"DATAGRAM", "DATAGRAM2", "DATAGRAM3"} {
		t.Run(style, func(t *testing.T) {
			controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
			server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: controller, MaxSessions: 4})
			if err != nil {
				t.Fatal(err)
			}
			if err = server.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.Close(); _ = server.Wait() }()
			control, reader, local := createDatagramSession(t, server.Addr().String(), "dg", style)
			defer control.Close()
			defer local.ReleaseSensitive()
			target := string(local.Destination())
			_, _ = io.WriteString(control, "DATAGRAM SEND ID=dg DESTINATION="+target+" SIZE=4\nDATA")
			if line := readSAMLine(t, reader); line != "DATAGRAM STATUS RESULT=OK" {
				t.Fatalf("datagram status = %q", line)
			}
			line := readSAMLine(t, reader)
			var wantSource string
			if style == "DATAGRAM3" {
				hash := local.Hash()
				wantSource = foundation.EncodeI2PBase64(hash[:])
			} else {
				wantSource = string(local.Destination())
			}
			if !strings.HasPrefix(line, "DATAGRAM RECEIVED DESTINATION="+wantSource+" ") || !strings.Contains(line, "SIZE=4") {
				t.Fatalf("datagram receive = %q, want source %q", line, wantSource)
			}
			body := make([]byte, 4)
			if _, err = io.ReadFull(reader, body); err != nil || string(body) != "DATA" {
				t.Fatalf("datagram body = %q, %v", body, err)
			}
		})
	}
}

func TestDatagram2DropsForgedDatagrams(t *testing.T) {
	controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: controller, MaxSessions: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()
	control, reader, local := createDatagramSession(t, server.Addr().String(), "dg2", "DATAGRAM2")
	defer control.Close()
	defer local.ReleaseSensitive()

	sender, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer sender.ReleaseSensitive()
	senderEndpoint, err := controller.CreateDestination(t.Context(), destination.DestinationSpec{Local: sender})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = senderEndpoint.Close() }()
	receiverHash := local.Hash()

	craft := func(target foundation.Hash, tamper bool) []byte {
		identity, identityErr := sender.Identity()
		if identityErr != nil {
			t.Fatal(identityErr)
		}
		overhead := identity.EncodedLen() + 2 + 64
		frame := make([]byte, overhead+4)
		n, marshalErr := networking.DatagramMarshalV2To(frame, target, identity, 2, foundation.Mapping{}, networking.DatagramOfflineSignature{}, []byte("DATA"), sender.Sign)
		if marshalErr != nil || n != len(frame) {
			t.Fatalf("marshal = %d, %v", n, marshalErr)
		}
		if tamper {
			frame[len(frame)-65] ^= 0xff
		}
		return frame
	}
	deliver := func(payload []byte) {
		if err = senderEndpoint.SendMessage(t.Context(), networking.StreamingTunnelDelivery{From: sender.Hash(), To: receiverHash, Protocol: networking.DatagramProtocolDatagram2, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}

	other, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer other.ReleaseSensitive()
	deliver(craft(other.Hash(), false)) // valid signature bound to the wrong target hash
	deliver(craft(receiverHash, true))  // target hash matches but signature is broken
	deliver(craft(receiverHash, false)) // genuine datagram still arrives

	if err = control.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	line := readSAMLine(t, reader)
	if !strings.HasPrefix(line, "DATAGRAM RECEIVED DESTINATION="+string(sender.Destination())+" ") || !strings.Contains(line, "SIZE=4") {
		t.Fatalf("datagram receive = %q", line)
	}
	body := make([]byte, 4)
	if _, err = io.ReadFull(reader, body); err != nil || string(body) != "DATA" {
		t.Fatalf("datagram body = %q, %v", body, err)
	}
}

func TestRawSendRejectsModernDatagramProtocols(t *testing.T) {
	server := &Server{}
	for _, protocol := range []string{"19", "20"} {
		config := sessionTransportConfig{}
		if err := server.configurePacketTransport(nil, &config, styleRaw, map[string]string{"PROTOCOL": protocol}, false); err == nil {
			t.Fatalf("RAW accepted PROTOCOL=%s", protocol)
		}
	}
}

type v1OnlyEndpoint struct {
	destination.DestinationEndpoint
}

type v1OnlyController struct {
	inner destination.DestinationController
}

func (c *v1OnlyController) CreateDestination(ctx context.Context, spec destination.DestinationSpec) (destination.DestinationEndpoint, error) {
	endpoint, err := c.inner.CreateDestination(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &v1OnlyEndpoint{endpoint}, nil
}
func (c *v1OnlyController) DestroyDestination(ctx context.Context, endpoint destination.DestinationEndpoint) error {
	wrapped, ok := endpoint.(*v1OnlyEndpoint)
	if !ok {
		return ErrProtocol
	}
	return c.inner.DestroyDestination(ctx, wrapped.DestinationEndpoint)
}

func TestDatagramModernSendWithoutEndpointSupport(t *testing.T) {
	peer, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.ReleaseSensitive()
	loop := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: &v1OnlyController{inner: loop}, Resolver: fixedResolver(string(peer.Destination())), MaxSessions: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()
	for i, style := range []string{"DATAGRAM2", "DATAGRAM3"} {
		// Session teardown on connection close is asynchronous; use a distinct
		// ID per style instead of relying on the previous session being gone.
		id := "dg" + strconv.Itoa(i)
		control, reader := samDial(t, server.Addr().String())
		_, _ = io.WriteString(control, "SESSION CREATE STYLE="+style+" ID="+id+" DESTINATION=TRANSIENT\n")
		if line := readSAMLine(t, reader); !strings.Contains(line, "RESULT=OK") {
			t.Fatalf("%s create = %q", style, line)
		}
		_, _ = io.WriteString(control, "DATAGRAM SEND ID="+id+" DESTINATION=peer.i2p SIZE=4\nDATA")
		if line := readSAMLine(t, reader); line != "DATAGRAM STATUS RESULT=I2P_ERROR" {
			t.Fatalf("%s send = %q", style, line)
		}
		control.Close()
	}
}
