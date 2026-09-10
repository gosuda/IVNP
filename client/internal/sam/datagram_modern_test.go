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

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
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
		{styleDatagram, dataplane.DatagramProtocolDatagram1},
		{styleDatagram2, dataplane.DatagramProtocolDatagram2},
		{styleDatagram3, dataplane.DatagramProtocolDatagram3},
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
	v1 := datagramOverhead(dataplane.DatagramProtocolDatagram1, endpoint, nil)
	v2 := datagramOverhead(dataplane.DatagramProtocolDatagram2, endpoint, nil)
	v3 := datagramOverhead(dataplane.DatagramProtocolDatagram3, endpoint, nil)
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
	if got := datagramOverhead(dataplane.DatagramProtocolDatagram2, endpoint, offline); got != want {
		t.Fatalf("offline v2 overhead = %d, want %d", got, want)
	}
	// Offline signatures never enter Datagram3 or Datagram1 wire formats.
	if got := datagramOverhead(dataplane.DatagramProtocolDatagram3, endpoint, offline); got != 34 {
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
			var wantSource string
			if style == "DATAGRAM3" {
				hash := local.Hash()
				wantSource = foundation.EncodeI2PBase64(hash[:])
			} else {
				wantSource = string(local.Destination())
			}
			body := make([]byte, 4)
			var statusOK, received bool
			for !statusOK || !received {
				line := readSAMLine(t, reader)
				switch {
				case line == "DATAGRAM STATUS RESULT=OK":
					statusOK = true
				case strings.HasPrefix(line, "DATAGRAM RECEIVED DESTINATION="+wantSource+" ") && strings.Contains(line, "SIZE=4"):
					received = true
					if _, err = io.ReadFull(reader, body); err != nil {
						t.Fatal(err)
					}
				default:
					t.Fatalf("datagram reply = %q", line)
				}
			}
			if string(body) != "DATA" {
				t.Fatalf("datagram body = %q, %v", body, err)
			}
		})
	}
}

func TestDatagram2RejectsWrongRecipient(t *testing.T) {
	assertDatagram2Rejects(t, func(sender *foundation.LocalDestination, recipient foundation.Hash) []byte {
		recipient[0] ^= 1
		return marshalTestDatagram2(t, sender, recipient, "WRONG-RECIPIENT")
	})
}

func TestDatagram2RejectsInvalidSignature(t *testing.T) {
	assertDatagram2Rejects(t, func(sender *foundation.LocalDestination, recipient foundation.Hash) []byte {
		frame := marshalTestDatagram2(t, sender, recipient, "INVALID-SIGNATURE")
		frame[len(frame)-1] ^= 1
		return frame
	})
}

func marshalTestDatagram2(t *testing.T, sender *foundation.LocalDestination, recipient foundation.Hash, payload string) []byte {
	t.Helper()
	identity, err := sender.Identity()
	if err != nil {
		t.Fatal(err)
	}
	signatureLen, ok := identity.SigningKeyType().SignatureLen()
	if !ok {
		t.Fatal("sender has unsupported signing key type")
	}
	frame := make([]byte, identity.EncodedLen()+2+len(payload)+signatureLen)
	n, err := dataplane.DatagramMarshalV2To(frame, recipient, identity, 2, foundation.Mapping{}, dataplane.DatagramOfflineSignature{}, []byte(payload), sender.Sign)
	if err != nil || n != len(frame) {
		t.Fatalf("marshal datagram %q = %d, %v", payload, n, err)
	}
	return frame
}

func assertDatagram2Rejects(t *testing.T, invalidFrame func(*foundation.LocalDestination, foundation.Hash) []byte) {
	t.Helper()
	controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: controller, MaxSessions: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close SAM server: %v", err)
		}
		if err := server.Wait(); err != nil {
			t.Errorf("wait for SAM server: %v", err)
		}
	})
	control, reader, local := createDatagramSession(t, server.Addr().String(), "dg2", "DATAGRAM2")
	t.Cleanup(func() {
		if err := control.Close(); err != nil {
			t.Errorf("close SAM control: %v", err)
		}
	})
	t.Cleanup(local.ReleaseSensitive)

	sender, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.ReleaseSensitive)
	receiverHash := local.Hash()
	invalid := invalidFrame(sender, receiverHash)
	const validPayload = "VALID-AFTER-REJECTION"
	valid := marshalTestDatagram2(t, sender, receiverHash, validPayload)

	controller.mu.Lock()
	receiver := controller.endpoints[receiverHash]
	controller.mu.Unlock()
	if receiver == nil {
		t.Fatal("receiver endpoint not registered")
	}
	receiver.mu.Lock()
	subscription := receiver.subscriptions[destination.DestinationRoute{Protocol: dataplane.DatagramProtocolDatagram2}]
	receiver.mu.Unlock()
	if subscription == nil {
		t.Fatal("receiver has no Datagram2 subscription")
	}
	// SendMessage starts independent goroutines, so enqueue directly to preserve
	// order. Receiving the valid frame proves the earlier invalid frame was processed.
	for _, frame := range [][]byte{invalid, valid} {
		subscription.ch <- &destination.ReceivedMessage{Delivery: dataplane.StreamingTunnelDelivery{
			From: sender.Hash(), To: receiverHash, Protocol: dataplane.DatagramProtocolDatagram2, Payload: frame,
		}}
	}

	if err = control.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	line := readSAMLine(t, reader)
	if !strings.HasPrefix(line, "DATAGRAM RECEIVED DESTINATION="+string(sender.Destination())+" ") || !strings.Contains(line, "SIZE="+strconv.Itoa(len(validPayload))) {
		t.Fatalf("first delivery must be the valid datagram, got header %q", line)
	}
	body := make([]byte, len(validPayload))
	if _, err = io.ReadFull(reader, body); err != nil {
		t.Fatalf("read valid datagram payload: %v", err)
	}
	if string(body) != validPayload {
		t.Fatalf("first delivered payload = %q, want %q; invalid datagram was not rejected", body, validPayload)
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
		t.Run(style, func(t *testing.T) {
			// Session teardown on connection close is asynchronous; use a distinct
			// ID per style instead of relying on the previous session being gone.
			id := "dg" + strconv.Itoa(i)
			control, reader := samDial(t, server.Addr().String())
			defer control.Close()
			_, _ = io.WriteString(control, "SESSION CREATE STYLE="+style+" ID="+id+" DESTINATION=TRANSIENT\n")
			if line := readSAMLine(t, reader); !strings.Contains(line, "RESULT=OK") {
				t.Fatalf("%s create = %q", style, line)
			}
			_, _ = io.WriteString(control, "DATAGRAM SEND ID="+id+" DESTINATION=peer.i2p SIZE=4\nDATA")
			if line := readSAMLine(t, reader); line != "DATAGRAM STATUS RESULT=I2P_ERROR" {
				t.Fatalf("%s send = %q", style, line)
			}
		})
	}
}
