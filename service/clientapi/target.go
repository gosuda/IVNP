package clientapi

import (
	ivnp "gosuda.org/ivnp/i2p"
	"net"
	"strconv"
	"strings"
)

const maxDestinationHost = 4096

func targetAddress(host string, port uint16) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" || len(host) > maxDestinationHost || port == 0 || net.ParseIP(host) != nil {
		return "", ErrI2PTarget
	}
	if before, ok := strings.CutSuffix(strings.ToLower(host), ".b32.i2p"); ok {
		label := before
		if len(label) != 52 {
			return "", ErrI2PTarget
		}
		for _, char := range label {
			targetAddressRejected := (char < 'a' || char > 'z')
			if targetAddressRejected {
				targetAddressRejected = (char < '2' || char > '7')
			}
			if targetAddressRejected {
				return "", ErrI2PTarget
			}
		}
	} else if _, err := ivnp.ParseDestination([]byte(host)); err != nil {
		return "", ErrI2PTarget
	}
	return net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)), nil
}

func splitTarget(value string) (string, uint16, error) {
	host, rawPort, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, ErrI2PTarget
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return "", 0, ErrI2PTarget
	}
	address, err := targetAddress(host, uint16(port))
	if err != nil {
		return "", 0, err
	}
	return address, uint16(port), nil
}
