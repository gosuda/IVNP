package ivnp

import (
	"context"
	"encoding/base32"
	"net"
	"strconv"
	"strings"

	"gosuda.org/ivnp/foundation"
)

type Addr struct {
	Hash Hash
	Port uint16
}

func (a Addr) Network() string { return "i2p" }

func (a Addr) String() string {
	host := ""
	if a.Hash != (Hash{}) {
		host = foundation.B32(a.Hash)
	}
	return host + ":" + strconv.Itoa(int(a.Port))
}

type NameResolver interface {
	LookupDestination(context.Context, string) (Hash, error)
}

func splitAddress(address string) (string, uint16, error) {
	if strings.TrimSpace(address) != address {
		return "", 0, ErrAddressInvalid
	}
	host, text, err := net.SplitHostPort(address)
	if err != nil || text == "" || strings.ContainsAny(address, "[]") {
		return "", 0, ErrAddressInvalid
	}
	for _, digit := range text {
		if digit < '0' || digit > '9' {
			return "", 0, ErrAddressInvalid
		}
	}
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil {
		return "", 0, ErrAddressInvalid
	}
	return strings.ToLower(host), uint16(port), nil
}

func ParseAddr(address string) (Addr, error) {
	host, port, err := splitAddress(address)
	if err != nil {
		return Addr{}, err
	}
	if host == "" {
		return Addr{Port: port}, nil
	}
	if len(host) != 60 || !strings.HasSuffix(host, ".b32.i2p") {
		return Addr{}, ErrAddressInvalid
	}
	var hash Hash
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(host[:52]))
	if err != nil || len(decoded) != len(hash) {
		return Addr{}, ErrAddressInvalid
	}
	copy(hash[:], decoded)
	if foundation.B32(hash) != host {
		return Addr{}, ErrAddressInvalid
	}
	return Addr{Hash: hash, Port: port}, nil
}

func resolveAddr(ctx context.Context, resolver NameResolver, address string) (Addr, error) {
	if err := ctx.Err(); err != nil {
		return Addr{}, err
	}
	if addr, err := ParseAddr(address); err == nil {
		return addr, nil
	}
	host, port, err := splitAddress(address)
	if err != nil || !validI2PName(host) || strings.HasSuffix(host, ".b32.i2p") {
		return Addr{}, ErrAddressInvalid
	}
	if resolver == nil {
		return Addr{}, ErrNameResolutionUnavailable
	}
	hash, err := resolver.LookupDestination(ctx, host)
	if err != nil {
		return Addr{}, err
	}
	if hash == (Hash{}) {
		return Addr{}, ErrAddressInvalid
	}
	return Addr{Hash: hash, Port: port}, nil
}

func validI2PName(host string) bool {
	if len(host) > 253 || !strings.HasSuffix(host, ".i2p") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			letter := c >= 'a' && c <= 'z'
			digit := c >= '0' && c <= '9'
			if !letter && !digit && c != '-' {
				return false
			}
		}
	}
	return true
}

func parseBindAddress(hash Hash, address string) (Addr, error) {
	addr, err := ParseAddr(address)
	if err != nil {
		return Addr{}, err
	}
	if addr.Hash != (Hash{}) && addr.Hash != hash {
		return Addr{}, ErrAddressUnavailable
	}
	addr.Hash = hash
	return addr, nil
}
