package frontend

import (
	"io"
	"net"

	"gosuda.org/ivnp/internal/relay"
)

func relayConnections(left, right net.Conn, leftReader io.Reader) {
	_ = relay.Bidirectional(left, right, leftReader)
	_ = left.Close()
	_ = right.Close()
}
