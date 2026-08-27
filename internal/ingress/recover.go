// Package ingress provides panic recovery and isolation helpers for network listener workers.
package ingress

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"runtime/debug"
)

var ErrRecoveredPanic = errors.New("ingress: recovered panic")

// Boundary identifies the ingress subsystem boundary where a panic was intercepted.
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

// Panic contains diagnostic info for a recovered panic at an ingress boundary.
type Panic struct {
	Boundary  Boundary
	Peer      string
	ValueType string
	Stack     []byte
}

// Reporter receives notifications of recovered ingress panics.
type Reporter interface {
	ReportRecoveredPanic(Panic)
}

// Recover should be called within a defer statement to catch panics and format them as errors.
func Recover(errp *error, reporter Reporter, boundary Boundary, peer net.Addr) {
	value := recover()
	if value == nil {
		return
	}
	if errp != nil {
		*errp = Report(value, reporter, boundary, peer)
	}
}

// Report logs a caught panic value via the reporter and returns a wrapped ErrRecoveredPanic.
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
