package clientapi

import (
	"io"
	"net"

	internalrelay "gosuda.org/ivnp/internal/relay"
)

func relay(left, right net.Conn, leftReader io.Reader) {
	_ = internalrelay.Bidirectional(left, right, leftReader)
	_ = left.Close()
	_ = right.Close()
}
