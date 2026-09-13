package overlay

import (
	"net/netip"
	"strconv"
	"strings"
)

// MaxTransportTokenLen bounds the locally registered transport token.
const MaxTransportTokenLen = 16

// Endpoint is one direct contact candidate: transport@address:port. The
// address is a canonical literal IP; DNS names, URLs, interface zones,
// multicast, broadcast, and unspecified addresses are not representable.
type Endpoint struct {
	Transport string
	Address   netip.AddrPort
}

// ParseEndpoint decodes the endpoint grammar. Parsing does not authorize
// dialing; address policy is a separate gate.
func ParseEndpoint(text string) (Endpoint, error) {
	transport, rest, ok := strings.Cut(text, "@")
	if !ok || !validTransportToken(transport) {
		return Endpoint{}, CodeInvalidConfig.Wrap("endpoint transport token")
	}
	var addr netip.AddrPort
	if strings.HasPrefix(rest, "[") {
		host, port, ok := cutBracketPort(rest)
		if !ok {
			return Endpoint{}, CodeInvalidConfig.Wrap("endpoint address")
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return Endpoint{}, CodeInvalidConfig.Wrap("endpoint ipv6 address")
		}
		addr = netip.AddrPortFrom(ip, port)
	} else {
		host, portText, ok := strings.Cut(rest, ":")
		if !ok || strings.Contains(portText, ":") {
			return Endpoint{}, CodeInvalidConfig.Wrap("endpoint address")
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || ip.Is6() {
			return Endpoint{}, CodeInvalidConfig.Wrap("endpoint ipv4 address")
		}
		port, err := parseCanonicalPort(portText)
		if err != nil {
			return Endpoint{}, err
		}
		addr = netip.AddrPortFrom(ip, port)
	}
	if !addr.IsValid() {
		return Endpoint{}, CodeInvalidConfig.Wrap("endpoint address")
	}
	return Endpoint{Transport: transport, Address: addr}, nil
}

// Public reports whether the endpoint may appear in cleartext public records.
// Loopback, link-local, multicast, broadcast, unspecified, private, and every
// IANA special-purpose range that is not globally reachable are never
// permitted; private addresses require an encrypted record and realm endpoint
// policy.
func (e Endpoint) Public() bool {
	ip := e.Address.Addr().Unmap()
	if e.Address.Port() == 0 || isLocalScope(ip) || !ip.IsGlobalUnicast() {
		return false
	}
	if ip.Is4() && ip.As4()[3] == 255 {
		return false
	}
	return true
}

// cgnatV4 is the RFC 6598 shared address space: internal reachability, never
// a public contact address.
var cgnatV4 = netip.MustParsePrefix("100.64.0.0/10")

// nonPublicV4 lists globally-unicast IPv4 ranges that are not public contact
// addresses: "this network", IETF protocol assignments, documentation,
// benchmarking, and reserved space. Benchmarking and reserved ranges in
// particular may route inside an operator's lab or enterprise network, so a
// signed record must never lure a dial toward them.
var nonPublicV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// nonPublicV6 lists the corresponding IPv6 ranges: discard-only, benchmark,
// documentation, deprecated 6to4/site-local space, and the NAT64 translation
// prefixes whose embedded IPv4 form would bypass the IPv4 checks.
var nonPublicV6 = []netip.Prefix{
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

// isLocalScope reports addresses that may never appear in cleartext records.
// IPv4-mapped IPv6 forms are unmapped first so a private IPv4 literal cannot
// hide inside a v6 wrapper.
func isLocalScope(ip netip.Addr) bool {
	ip = ip.Unmap()
	switch {
	case ip.IsUnspecified(), ip.IsLoopback(), ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(), ip.IsMulticast(), ip.IsPrivate(),
		cgnatV4.Contains(ip):
		return true
	}
	prefixes := nonPublicV6
	if ip.Is4() {
		prefixes = nonPublicV4
	}
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// String returns the canonical encoding.
func (e Endpoint) String() string {
	addr := e.Address.Addr()
	if addr.Is6() {
		return e.Transport + "@[" + addr.String() + "]:" + strconv.Itoa(int(e.Address.Port()))
	}
	return e.Transport + "@" + addr.String() + ":" + strconv.Itoa(int(e.Address.Port()))
}

func validTransportToken(token string) bool {
	if token == "" || len(token) > MaxTransportTokenLen {
		return false
	}
	for i := 0; i < len(token); i++ {
		if !isTransportChar(token[i]) {
			return false
		}
	}
	return true
}

func isTransportChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		return true
	}
	return false
}

func cutBracketPort(text string) (host string, port uint16, ok bool) {
	end := strings.IndexByte(text, ']')
	if end < 0 || end+1 >= len(text) || text[end+1] != ':' {
		return "", 0, false
	}
	p, err := parseCanonicalPort(text[end+2:])
	if err != nil {
		return "", 0, false
	}
	return text[1:end], p, true
}

// parseCanonicalPort enforces unsigned decimal without leading zeros.
func parseCanonicalPort(text string) (uint16, error) {
	n, err := parseCanonicalUint(text, 16)
	if err != nil || n == 0 {
		return 0, CodeInvalidConfig.Wrap("endpoint port")
	}
	return uint16(n), nil
}

// parseCanonicalUint enforces canonical decimal: digits only, no sign, no
// leading zero except the literal value "0".
func parseCanonicalUint(text string, bits int) (uint64, error) {
	if text == "" {
		return 0, CodeInvalidConfig.Wrap("empty decimal field")
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, CodeInvalidConfig.Wrap("non-decimal field")
		}
	}
	if len(text) > 1 && text[0] == '0' {
		return 0, CodeInvalidConfig.Wrap("decimal field has leading zero")
	}
	n, err := strconv.ParseUint(text, 10, bits)
	if err != nil {
		return 0, CodeInvalidConfig.Wrap("decimal field out of range")
	}
	return n, nil
}
