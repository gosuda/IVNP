// Package natpmp implements the NAT Port Mapping Protocol (NAT-PMP).
package natpmp

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const (
	DefaultPort    uint16 = 5351
	DefaultTimeout        = 3 * time.Second
)

const (
	protocolVersion byte = 0

	publicAddressOpcode byte = 0
	udpMappingOpcode    byte = 1
	tcpMappingOpcode    byte = 2
	responseBit         byte = 0x80
)

var (
	ErrGatewayRequired   = errors.New("natpmp: an IPv4 gateway is required")
	ErrInvalidRequest    = errors.New("natpmp: invalid mapping request")
	ErrMalformedResponse = errors.New("natpmp: malformed response")
)

// Protocol identifies the transport protocol (UDP or TCP) for a port mapping.
type Protocol uint8

const (
	UDP Protocol = 1
	TCP Protocol = 2
)

// MappingRequest describes a requested port mapping.
type MappingRequest struct {
	Protocol     Protocol
	InternalPort uint16
	ExternalPort uint16
	Lifetime     time.Duration
}

// PublicAddress is the gateway's public IPv4 address and its NAT-PMP epoch.
// ReceivedAt is local time at which the response was received.
type PublicAddress struct {
	Address    netip.Addr
	Epoch      uint32
	ReceivedAt time.Time
}

// Mapping is a mapping acknowledged by a gateway. ExpiresAt and RenewAt are
// based on the local receipt time, rather than the gateway epoch, so callers
// can schedule lease renewal without recomputing the returned lifetime.
type Mapping struct {
	Gateway      netip.Addr
	Protocol     Protocol
	InternalPort uint16
	ExternalPort uint16
	Lifetime     time.Duration
	Epoch        uint32
	CreatedAt    time.Time
	ExpiresAt    time.Time
	RenewAt      time.Time
}

// ResultError is returned when the gateway sends a non-zero NAT-PMP result
// code. Code is the unmodified protocol result code.
type ResultError struct {
	Code uint16
}

func (e *ResultError) Error() string {
	return fmt.Sprintf("natpmp: gateway returned result %d", e.Code)
}

// DialContextFunc opens the connected UDP socket used for a request. It is
// primarily useful when an embedder needs to control socket creation.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// Client serializes requests because NAT-PMP has no transaction ID. A gateway
// response therefore cannot be safely associated with concurrent operations.
type Client struct {
	mu          sync.Mutex
	Gateway     netip.Addr
	Port        uint16
	Timeout     time.Duration
	DialContext DialContextFunc
}

// NewClient constructs a Client for gateway.
func NewClient(gateway netip.Addr) *Client {
	return &Client{Gateway: gateway}
}

// PublicAddress requests the gateway's public IPv4 address.
func (c *Client) PublicAddress(ctx context.Context) (PublicAddress, error) {
	response, receivedAt, _, err := c.exchange(ctx, publicAddressOpcode, []byte{protocolVersion, publicAddressOpcode}, 12)
	if err != nil {
		return PublicAddress{}, err
	}
	if err := validateResponse(response, publicAddressOpcode); err != nil {
		return PublicAddress{}, err
	}

	return PublicAddress{
		Address:    netip.AddrFrom4([4]byte(response[8:12])),
		Epoch:      binary.BigEndian.Uint32(response[4:8]),
		ReceivedAt: receivedAt,
	}, nil
}

// Map creates, renews, or removes a mapping according to request.Lifetime.
// A successful finite mapping includes ExpiresAt and RenewAt, with RenewAt at
// two-thirds of the granted lifetime. Gateways may return a different
// ExternalPort or Lifetime than requested.
func (c *Client) Map(ctx context.Context, request MappingRequest) (Mapping, error) {
	opcode, err := request.Protocol.opcode()
	if err != nil {
		return Mapping{}, err
	}
	if request.InternalPort == 0 || request.Lifetime < 0 || request.Lifetime%time.Second != 0 || uint64(request.Lifetime/time.Second) > uint64(^uint32(0)) {
		return Mapping{}, fmt.Errorf("%w: internal port and integral lifetime are required", ErrInvalidRequest)
	}

	packet := make([]byte, 12)
	packet[0] = protocolVersion
	packet[1] = opcode
	binary.BigEndian.PutUint16(packet[4:6], request.InternalPort)
	binary.BigEndian.PutUint16(packet[6:8], request.ExternalPort)
	binary.BigEndian.PutUint32(packet[8:12], uint32(request.Lifetime/time.Second))

	response, receivedAt, gateway, err := c.exchange(ctx, opcode, packet, 16)
	if err != nil {
		return Mapping{}, err
	}
	if err := validateResponse(response, opcode); err != nil {
		return Mapping{}, err
	}
	if internalPort := binary.BigEndian.Uint16(response[8:10]); internalPort != request.InternalPort {
		return Mapping{}, fmt.Errorf("%w: response internal port %d does not match request %d", ErrMalformedResponse, internalPort, request.InternalPort)
	}

	lifetime := time.Duration(binary.BigEndian.Uint32(response[12:16])) * time.Second
	mapping := Mapping{
		Gateway:      gateway,
		Protocol:     request.Protocol,
		InternalPort: request.InternalPort,
		ExternalPort: binary.BigEndian.Uint16(response[10:12]),
		Lifetime:     lifetime,
		Epoch:        binary.BigEndian.Uint32(response[4:8]),
		CreatedAt:    receivedAt,
	}
	if lifetime > 0 {
		mapping.ExpiresAt = receivedAt.Add(lifetime)
		mapping.RenewAt = receivedAt.Add(lifetime * 2 / 3)
	}
	return mapping, nil
}

// Unmap removes mapping by sending the same mapping tuple with a zero
// lifetime. Only mappings acknowledged by this client should be passed here.
func (c *Client) Unmap(ctx context.Context, mapping Mapping) error {
	if mapping.Gateway.IsValid() && mapping.Gateway.Unmap() != c.Gateway.Unmap() {
		return fmt.Errorf("%w: mapping belongs to a different gateway", ErrInvalidRequest)
	}
	_, err := c.Map(ctx, MappingRequest{
		Protocol:     mapping.Protocol,
		InternalPort: mapping.InternalPort,
		ExternalPort: mapping.ExternalPort,
	})
	return err
}

func (p Protocol) opcode() (byte, error) {
	switch p {
	case UDP:
		return udpMappingOpcode, nil
	case TCP:
		return tcpMappingOpcode, nil
	default:
		return 0, fmt.Errorf("%w: unknown protocol %d", ErrInvalidRequest, p)
	}
}

func (c *Client) exchange(ctx context.Context, opcode byte, request []byte, responseLength int) ([]byte, time.Time, netip.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, time.Time{}, netip.Addr{}, err
	}
	gateway := c.Gateway.Unmap()
	if !gateway.IsValid() || !gateway.Is4() {
		return nil, time.Time{}, netip.Addr{}, ErrGatewayRequired
	}
	timeout := c.Timeout

	timeout = cmp.Or(timeout, DefaultTimeout)

	if timeout < 0 {
		return nil, time.Time{}, netip.Addr{}, fmt.Errorf("%w: negative timeout", ErrInvalidRequest)
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	port := c.Port

	port = cmp.Or(port, DefaultPort)

	endpoint := net.JoinHostPort(gateway.String(), strconv.Itoa(int(port)))
	dial := c.DialContext
	if dial == nil {
		var dialer net.Dialer
		dial = dialer.DialContext
	}
	conn, err := dial(ctx, "udp4", endpoint)
	if err != nil {
		return nil, time.Time{}, netip.Addr{}, err
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	retry := 250 * time.Millisecond
	for {
		if err := ctx.Err(); err != nil {
			return nil, time.Time{}, netip.Addr{}, err
		}
		now := time.Now()
		if !now.Before(deadline) {
			return nil, time.Time{}, netip.Addr{}, context.DeadlineExceeded
		}
		attemptDeadline := now.Add(retry)
		if attemptDeadline.After(deadline) {
			attemptDeadline = deadline
		}
		if err := conn.SetDeadline(attemptDeadline); err != nil {
			return nil, time.Time{}, netip.Addr{}, err
		}
		n, err := conn.Write(request)
		if err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return nil, time.Time{}, netip.Addr{}, contextErr
			}
			return nil, time.Time{}, netip.Addr{}, err
		}
		if n != len(request) {
			return nil, time.Time{}, netip.Addr{}, fmt.Errorf("%w: wrote %d of %d bytes", ErrMalformedResponse, n, len(request))
		}
		for {
			response := make([]byte, responseLength+1)
			n, err := conn.Read(response)
			if err != nil {
				if contextErr := ctx.Err(); contextErr != nil {
					return nil, time.Time{}, netip.Addr{}, contextErr
				}
				if isTimeout(err) {
					break
				}
				return nil, time.Time{}, netip.Addr{}, err
			}
			if n != responseLength {
				return nil, time.Time{}, netip.Addr{}, fmt.Errorf("%w: received %d bytes, want %d", ErrMalformedResponse, n, responseLength)
			}
			if response[0] != protocolVersion {
				return nil, time.Time{}, netip.Addr{}, fmt.Errorf("%w: version %d", ErrMalformedResponse, response[0])
			}
			if response[1] != opcode|responseBit {
				continue
			}
			if err := validateResponse(response[:n], opcode); err != nil {
				return nil, time.Time{}, netip.Addr{}, err
			}
			return response[:n], time.Now(), gateway, nil
		}
		if retry < 64*time.Second {
			retry *= 2
			if retry > 64*time.Second {
				retry = 64 * time.Second
			}
		}
	}
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func validateResponse(response []byte, opcode byte) error {
	if response[0] != protocolVersion {
		return fmt.Errorf("%w: version %d", ErrMalformedResponse, response[0])
	}
	if response[1] != opcode|responseBit {
		return fmt.Errorf("%w: opcode %d", ErrMalformedResponse, response[1])
	}
	if code := binary.BigEndian.Uint16(response[2:4]); code != 0 {
		return &ResultError{Code: code}
	}
	return nil
}
