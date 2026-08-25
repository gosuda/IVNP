// Package upnp discovers Internet Gateway Devices and manages their port mappings.
package upnp

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// SSDPMulticastAddress is the IPv4 multicast endpoint defined by SSDP.
	SSDPMulticastAddress = "239.255.255.250:1900"
	// InternetGatewayDevice is the device search target for UPnP IGDs.
	InternetGatewayDevice = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
)

var ErrInvalidSSDPResponse = errors.New("upnp: invalid SSDP response")

// DiscoveryResponse is one response to an SSDP M-SEARCH request.
type DiscoveryResponse struct {
	Location *url.URL
	ST       string
	USN      string
	Headers  http.Header
}

// Client is a zero-dependency UPnP Internet Gateway Device client. Its zero
// value uses the standard SSDP multicast address, an MX of two seconds, and
// http.DefaultClient.
type Client struct {
	HTTPClient  *http.Client
	SSDPAddress string
	MX          int
}

// DiscoveryRequest returns a complete M-SEARCH datagram for target. MX is the
// maximum number of seconds a device may defer its response and must be 1..5.
func DiscoveryRequest(target string, mx int) ([]byte, error) {
	if target == "" || strings.ContainsAny(target, "\r\n") {
		return nil, fmt.Errorf("upnp: invalid SSDP search target")
	}
	if mx < 1 || mx > 5 {
		return nil, fmt.Errorf("upnp: SSDP MX must be between 1 and 5")
	}
	return []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: " + SSDPMulticastAddress + "\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: " + strconv.Itoa(mx) + "\r\n" +
		"ST: " + target + "\r\n\r\n"), nil
}

// ParseSSDPResponse parses one complete SSDP response datagram. It rejects
// non-HTTP/1.1 success responses, folded or duplicate headers, malformed
// header syntax, and non-whitespace bytes after the header terminator.
func ParseSSDPResponse(packet []byte) (DiscoveryResponse, error) {
	var response DiscoveryResponse
	before, after, ok := bytes.Cut(packet, []byte("\r\n\r\n"))
	if !ok {
		return response, fmt.Errorf("%w: missing header terminator", ErrInvalidSSDPResponse)
	}
	if strings.TrimSpace(string(after)) != "" {
		return response, fmt.Errorf("%w: body is not permitted", ErrInvalidSSDPResponse)
	}
	lines := strings.Split(string(before), "\r\n")
	if len(lines) < 1 || lines[0] != "HTTP/1.1 200 OK" {
		return response, fmt.Errorf("%w: expected HTTP/1.1 200 OK", ErrInvalidSSDPResponse)
	}
	headers := make(http.Header, len(lines)-1)
	for _, line := range lines[1:] {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			return response, fmt.Errorf("%w: malformed header", ErrInvalidSSDPResponse)
		}
		name, value, found := strings.Cut(line, ":")
		if !found || name == "" || !validHeaderName(name) {
			return response, fmt.Errorf("%w: malformed header", ErrInvalidSSDPResponse)
		}
		canonical := http.CanonicalHeaderKey(name)
		if _, duplicate := headers[canonical]; duplicate {
			return response, fmt.Errorf("%w: duplicate %s header", ErrInvalidSSDPResponse, canonical)
		}
		headers[canonical] = []string{strings.TrimSpace(value)}
	}
	response.Headers = headers
	response.ST = headers.Get("ST")
	response.USN = headers.Get("USN")
	location := headers.Get("Location")
	if location == "" {
		return response, fmt.Errorf("%w: missing LOCATION header", ErrInvalidSSDPResponse)
	}
	parsed, err := parseHTTPURL(location)
	if err != nil {
		return response, fmt.Errorf("%w: LOCATION: %v", ErrInvalidSSDPResponse, err)
	}
	response.Location = parsed
	return response, nil
}

// Discover performs an IGD SSDP search using the client's configured address.
func (c *Client) Discover(ctx context.Context) ([]DiscoveryResponse, error) {
	address := c.SSDPAddress

	address = cmp.Or(address, SSDPMulticastAddress)

	endpoint, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return nil, fmt.Errorf("upnp: resolve SSDP address: %w", err)
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("upnp: open SSDP socket: %w", err)
	}
	defer conn.Close()
	return c.DiscoverWithConn(ctx, conn, endpoint)
}

// DiscoverWithConn sends an IGD M-SEARCH through conn and collects responses
// until MX expires or ctx is canceled. It does not close conn.
func (c *Client) DiscoverWithConn(ctx context.Context, conn net.PacketConn, destination net.Addr) ([]DiscoveryResponse, error) {
	if conn == nil || destination == nil {
		return nil, fmt.Errorf("upnp: discovery connection and destination are required")
	}
	mx := c.MX

	mx = cmp.Or(mx, 2)

	request, err := DiscoveryRequest(InternetGatewayDevice, mx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.WriteTo(request, destination); err != nil {
		return nil, fmt.Errorf("upnp: send M-SEARCH: %w", err)
	}

	finish := time.Now().Add(time.Duration(mx) * time.Second)
	seen := make(map[string]struct{})
	var responses []DiscoveryResponse
	buffer := make([]byte, 64*1024)
	for time.Now().Before(finish) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(100 * time.Millisecond)
		if deadline.After(finish) {
			deadline = finish
		}
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return nil, fmt.Errorf("upnp: set SSDP read deadline: %w", err)
		}
		n, _, err := conn.ReadFrom(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return nil, fmt.Errorf("upnp: receive SSDP response: %w", err)
		}
		response, err := ParseSSDPResponse(buffer[:n])
		if err != nil {
			continue // SSDP is multicast; unrelated datagrams are expected.
		}
		key := response.USN + "\x00" + response.Location.String()
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		responses = append(responses, response)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return responses, nil
}

// Discover searches for IGDs with a zero-value Client.
func Discover(ctx context.Context) ([]DiscoveryResponse, error) {
	return new(Client).Discover(ctx)
}

func validHeaderName(name string) bool {
	for i := range name {
		c := name[i]
		if !validHeaderCharacter(c) {
			return false
		}
	}
	return true
}

func validHeaderCharacter(character byte) bool {
	return (character >= 'A' && character <= 'Z') ||
		(character >= 'a' && character <= 'z') ||
		(character >= '0' && character <= '9') ||
		strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character))
}

func parseHTTPURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("must be an absolute URL")
	}
	if parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("must be an unauthenticated HTTP URL")
	}
	return parsed, nil
}
