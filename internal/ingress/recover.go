// Package ingress contains narrow recovery helpers for untrusted worker boundaries.
package ingress

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"runtime/debug"
)

var ErrRecoveredPanic = errors.New("ingress: recovered panic")

// Boundary identifies the worker that contained a panic without retaining
// packet bytes, credentials, or arbitrary panic text.
type Boundary uint8

const (
	BoundaryNTCP2Handshake Boundary = iota + 1
	BoundaryNTCP2Frame
	BoundarySSU2Packet
	BoundaryClientConnection
	BoundaryHTTPHandler
	BoundarySAMUDP
	BoundarySAMWorker
)

// Panic is the structured report emitted for one recovered ingress panic.
type Panic struct {
	Boundary  Boundary
	Peer      string
	ValueType string
	Stack     []byte
}

// Reporter records a contained ingress panic. Implementations must not retain
// sensitive request material and failures from Report are contained.
type Reporter interface {
	ReportRecoveredPanic(Panic)
}

// Recover is used directly in a deferred call at an untrusted worker boundary.
// It converts a panic to ErrRecoveredPanic and contains reporter failures.
func Recover(errp *error, reporter Reporter, boundary Boundary, peer net.Addr) {
	value := recover()
	if value == nil {
		return
	}
	if errp != nil {
		*errp = Report(value, reporter, boundary, peer)
	}
}

// Report records a value recovered by a boundary that must also perform local
// cleanup (for example, an HTTP handler that closes its response). It accepts
// the recovered value rather than calling recover itself.
func Report(value any, reporter Reporter, boundary Boundary, peer net.Addr) error {
	if value == nil {
		return nil
	}
	err := fmt.Errorf("%w at boundary %d", ErrRecoveredPanic, boundary)
	if reporter == nil {
		return err
	}
	valueType := "<nil>"
	if kind := reflect.TypeOf(value); kind != nil {
		valueType = kind.String()
	}
	report := Panic{Boundary: boundary, Peer: peerString(peer), ValueType: valueType, Stack: debug.Stack()}
	func() {
		defer func() { _ = recover() }()
		reporter.ReportRecoveredPanic(report)
	}()
	return err
}

func peerString(peer net.Addr) string {
	if peer == nil {
		return ""
	}
	return peer.String()
}
