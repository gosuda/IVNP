package natpmp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestPublicAddressWireRequest(t *testing.T) {
	server, client := localMock(t, func(conn *net.UDPConn, peer *net.UDPAddr, packet []byte) {
		if want := []byte{0, publicAddressOpcode}; string(packet) != string(want) {
			t.Errorf("public-address request = %x, want %x", packet, want)
		}
		response := []byte{0, publicAddressOpcode | responseBit, 0, 0, 0, 0, 0, 9, 198, 51, 100, 7}
		if _, err := conn.WriteToUDP(response, peer); err != nil {
			t.Errorf("write mock response: %v", err)
		}
	})
	defer server.Close()

	address, err := client.PublicAddress(context.Background())
	if err != nil {
		t.Fatalf("PublicAddress: %v", err)
	}
	if address.Address != netip.MustParseAddr("198.51.100.7") || address.Epoch != 9 {
		t.Fatalf("PublicAddress = %+v", address)
	}
	if address.ReceivedAt.IsZero() {
		t.Fatal("ReceivedAt is zero")
	}
}

func TestMapAndUnmapWireRequests(t *testing.T) {
	requests := make(chan []byte, 2)
	server, client := localMock(t, func(conn *net.UDPConn, peer *net.UDPAddr, packet []byte) {
		requests <- append([]byte(nil), packet...)
		response := make([]byte, 16)
		response[1] = tcpMappingOpcode | responseBit
		binary.BigEndian.PutUint32(response[4:8], 23)
		binary.BigEndian.PutUint16(response[8:10], binary.BigEndian.Uint16(packet[4:6]))
		binary.BigEndian.PutUint16(response[10:12], 41000)
		binary.BigEndian.PutUint32(response[12:16], 90)
		if _, err := conn.WriteToUDP(response, peer); err != nil {
			t.Errorf("write mock response: %v", err)
		}
	})
	defer server.Close()

	mapping, err := client.Map(context.Background(), MappingRequest{
		Protocol:     TCP,
		InternalPort: 12345,
		ExternalPort: 0,
		Lifetime:     2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	mapAndUnmapWireRequestsRejected := mapping.Gateway != netip.MustParseAddr("127.0.0.1") || mapping.Protocol != TCP || mapping.InternalPort != 12345 || mapping.ExternalPort != 41000 || mapping.Lifetime != 90*time.Second
	if !mapAndUnmapWireRequestsRejected {
		mapAndUnmapWireRequestsRejected = mapping.Epoch != 23
	}
	if mapAndUnmapWireRequestsRejected {
		t.Fatalf("Mapping = %+v", mapping)
	}
	if got, want := mapping.ExpiresAt.Sub(mapping.CreatedAt), 90*time.Second; got != want {
		t.Fatalf("ExpiresAt-CreatedAt = %v, want %v", got, want)
	}
	if got, want := mapping.RenewAt.Sub(mapping.CreatedAt), 60*time.Second; got != want {
		t.Fatalf("RenewAt-CreatedAt = %v, want %v", got, want)
	}
	if err := client.Unmap(context.Background(), mapping); err != nil {
		t.Fatalf("Unmap: %v", err)
	}

	first := <-requests
	if got, want := first, []byte{0, tcpMappingOpcode, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 0, 120}; string(got) != string(want) {
		t.Errorf("Map request = %x, want %x", got, want)
	}
	second := <-requests
	if second[0] != 0 || second[1] != tcpMappingOpcode || binary.BigEndian.Uint16(second[4:6]) != 12345 || binary.BigEndian.Uint16(second[6:8]) != 41000 || binary.BigEndian.Uint32(second[8:12]) != 0 {
		t.Errorf("Unmap request = %x", second)
	}
}

func TestStrictResponseValidation(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		check    func(error) bool
	}{
		{
			name:     "wrong version",
			response: []byte{1, responseBit, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1},
			check:    func(err error) bool { return errors.Is(err, ErrMalformedResponse) },
		},
		{
			name:     "oversized packet",
			response: []byte{0, responseBit, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1, 0},
			check:    func(err error) bool { return errors.Is(err, ErrMalformedResponse) },
		},
		{
			name:     "gateway result code",
			response: []byte{0, responseBit, 0, 3, 0, 0, 0, 0, 192, 0, 2, 1},
			check: func(err error) bool {
				var result *ResultError
				return errors.As(err, &result) && result.Code == 3
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, client := localMock(t, func(conn *net.UDPConn, peer *net.UDPAddr, _ []byte) {
				if _, err := conn.WriteToUDP(test.response, peer); err != nil {
					t.Errorf("write mock response: %v", err)
				}
			})
			defer server.Close()

			_, err := client.PublicAddress(context.Background())
			if !test.check(err) {
				t.Fatalf("PublicAddress error = %v", err)
			}
		})
	}
}

func TestWrongOpcodeIsDiscardedThenRetried(t *testing.T) {
	var requests atomic.Int32
	server, client := localMock(t, func(conn *net.UDPConn, peer *net.UDPAddr, _ []byte) {
		attempt := requests.Add(1)
		opcode := publicAddressOpcode
		if attempt == 1 {
			opcode = tcpMappingOpcode
		}
		response := []byte{protocolVersion, opcode | responseBit, 0, 0, 0, 0, 0, 9, 198, 51, 100, 7}
		if _, err := conn.WriteToUDP(response, peer); err != nil {
			t.Errorf("write mock response: %v", err)
		}
	})
	defer server.Close()
	client.Timeout = time.Second
	if _, err := client.PublicAddress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests.Load() < 2 {
		t.Fatalf("requests = %d, want retry after wrong opcode", requests.Load())
	}
}

func TestMapRejectsMismatchedInternalPort(t *testing.T) {
	server, client := localMock(t, func(conn *net.UDPConn, peer *net.UDPAddr, _ []byte) {
		response := make([]byte, 16)
		response[1] = udpMappingOpcode | responseBit
		binary.BigEndian.PutUint16(response[8:10], 9999)
		if _, err := conn.WriteToUDP(response, peer); err != nil {
			t.Errorf("write mock response: %v", err)
		}
	})
	defer server.Close()

	_, err := client.Map(context.Background(), MappingRequest{Protocol: UDP, InternalPort: 1234, Lifetime: time.Second})
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("Map error = %v, want malformed response", err)
	}
}

func TestContextDeadlineInterruptsRead(t *testing.T) {
	server, client := localMock(t, func(_ *net.UDPConn, _ *net.UDPAddr, _ []byte) {})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err := client.PublicAddress(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("PublicAddress error = %v, want deadline exceeded", err)
	}
}

func localMock(t *testing.T, handler func(*net.UDPConn, *net.UDPAddr, []byte)) (*net.UDPConn, *Client) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buffer := make([]byte, 128)
		for {
			n, peer, err := server.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			handler(server, peer, append([]byte(nil), buffer[:n]...))
		}
	}()
	return server, &Client{
		Gateway: netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(server.LocalAddr().(*net.UDPAddr).Port),
		Timeout: time.Second,
	}
}
