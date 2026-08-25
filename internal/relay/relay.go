// Package relay provides the shared bounded bidirectional stream relay used by
// local client protocols.
package relay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

const bufferSize = 32 << 10

type buffer [bufferSize]byte

var buffers = sync.Pool{New: func() any { return new(buffer) }}

var ErrRecoveredPanic = errors.New("relay: recovered copy panic")

type result struct {
	direction uint8
	err       error
}

// Bidirectional copies both halves using fixed pooled buffers. A clean EOF
// half-closes the opposite writer; an error closes both endpoints to unblock
// the sibling copy.
func Bidirectional(left, right net.Conn, leftReader io.Reader) error {
	return BidirectionalContained(left, right, leftReader, nil)
}

// BidirectionalContained is Bidirectional with a recovery callback around each
// copy worker. The callback converts a recovered value to the error returned by
// this relay; it must not panic.
func BidirectionalContained(left, right net.Conn, leftReader io.Reader, recoverPanic func(any) error) error {
	if leftReader == nil {
		leftReader = left
	}
	done := make(chan result, 2)
	copyOne := func(direction uint8, destination net.Conn, source io.Reader) {
		var copyErr error
		scratch := buffers.Get().(*buffer)
		defer func() {
			clear(scratch[:])
			buffers.Put(scratch)
			if value := recover(); value != nil {
				if recoverPanic != nil {
					copyErr = recoverPanic(value)
				} else {
					copyErr = fmt.Errorf("%w: %v", ErrRecoveredPanic, value)
				}
			}
			done <- result{direction: direction, err: copyErr}
		}()
		_, copyErr = io.CopyBuffer(destination, source, scratch[:])
	}
	go copyOne(0, right, leftReader)
	go copyOne(1, left, right)
	first := <-done
	if first.err != nil {
		_ = left.Close()
		_ = right.Close()
		second := <-done
		return errors.Join(first.err, second.err)
	}
	if first.direction == 0 {
		closeWrite(right)
	} else {
		closeWrite(left)
	}
	second := <-done
	if second.err != nil && !errors.Is(second.err, net.ErrClosed) {
		_ = left.Close()
		_ = right.Close()
		return second.err
	}
	if second.direction == 0 {
		closeWrite(right)
	} else {
		closeWrite(left)
	}
	return nil
}

func closeWrite(connection net.Conn) {
	if closer, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
		return
	}
	_ = connection.Close()
}
