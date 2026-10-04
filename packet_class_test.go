package ivnp

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
)

// mockEndpoint satisfies DestinationEndpoint with stubs; the constructor-class
// tests never reach the endpoint because validation rejects first.
type mockEndpoint struct{}

func (m *mockEndpoint) Hash() foundation.Hash { return foundation.Hash{} }
func (m *mockEndpoint) B32() string           { return "" }
func (m *mockEndpoint) Destination() []byte   { return nil }
func (m *mockEndpoint) DialI2P(context.Context, string) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (m *mockEndpoint) ListenI2P(context.Context, string) (net.Listener, error) {
	return nil, net.ErrClosed
}
func (m *mockEndpoint) SendMessage(context.Context, destination.Delivery) error {
	return net.ErrClosed
}
func (m *mockEndpoint) MarshalDatagramV1To([]byte, []byte) (int, error) {
	return 0, net.ErrClosed
}
func (m *mockEndpoint) Subscribe(destination.DestinationRoute, int) (destination.MessageSubscription, error) {
	return nil, net.ErrClosed
}
func (m *mockEndpoint) Close() error { return nil }

// TestDatagramConstructorRejectsProtocolClassMismatch verifies ListenPacket
// only serves authenticated-source protocols (17, 19) and ListenUnauthPacket
// only serves claimed-source protocols (18, 20); network selection stays
// orthogonal to authentication semantics.
func TestDatagramConstructorRejectsProtocolClassMismatch(t *testing.T) {
	d := &Destination{
		endpoints: map[string]destination.DestinationEndpoint{"": &mockEndpoint{}},
		nets:      []string{""},
		owner:     &Router{defaultNetwork: ""},
		ctx:       context.Background(),
		resources: make(map[io.Closer]struct{}),
	}
	_ = d

	cases := []struct {
		listen string // network name for ListenPacket
		unauth string // network name for ListenUnauthPacket
		what   string
	}{
		{listen: "raw", what: "raw"},
		{listen: "udp-raw", what: "udp-raw"},
		{listen: "datagram3", what: "datagram3"},
		{listen: "meta", what: "meta"},
		{unauth: "udp", what: "udp"},
		{unauth: "ivnp", what: "ivnp"},
		{unauth: "packet", what: "packet"},
		{unauth: "datagram", what: "datagram"},
	}
	for _, test := range cases {
		if test.listen != "" {
			if _, err := d.ListenPacket(test.listen, ":0"); err == nil || !strings.Contains(err.Error(), "not served by ListenPacket") {
				t.Errorf("ListenPacket(%q) err = %v, want class rejection", test.listen, err)
			}
		}
		if test.unauth != "" {
			if _, err := d.ListenUnauthPacket(test.unauth, ":0"); err == nil || !strings.Contains(err.Error(), "not served by ListenUnauthPacket") {
				t.Errorf("ListenUnauthPacket(%q) err = %v, want class rejection", test.unauth, err)
			}
		}
	}

	// The generic names of the correct class must still be accepted (they reach
	// the endpoint layer, which will fail with ErrUnsupportedIdentity because the
	// mock lacks BoundedDestinationEndpoint).
	if _, err := d.ListenPacket("udp", ":0"); err == nil || !strings.Contains(err.Error(), "unsupported identity") {
		t.Errorf("ListenPacket(udp) err = %v, want endpoint-level error (class accepted)", err)
	}
	if _, err := d.ListenUnauthPacket("raw", ":0"); err == nil || !strings.Contains(err.Error(), "unsupported identity") {
		t.Errorf("ListenUnauthPacket(raw) err = %v, want endpoint-level error (class accepted)", err)
	}
}
