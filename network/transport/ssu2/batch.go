package ssu2

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
)

const (
	// MaxBatch is the largest number of datagrams a Batch can hold. It is kept
	// deliberately below Linux's UIO_MAXIOV limit to bound per-batch memory.
	MaxBatch = 64

	// MaxDatagramSize is the largest UDP payload accepted by this package.
	MaxDatagramSize = 65535
)

var (
	ErrInvalidBatch      = errors.New("ssu2: invalid datagram batch")
	ErrInvalidDatagram   = errors.New("ssu2: invalid datagram")
	ErrDatagramTruncated = errors.New("ssu2: received datagram exceeds packet buffer")
)

// Datagram is one UDP payload and its peer address. Data is a caller-owned
// buffer. On receive, Len is set to the number of bytes in Data; on send, only
// Data[:Len] is transmitted. Zone is the IPv6 scope ID and is zero for IPv4.
type Datagram struct {
	Data []byte
	Len  int
	Addr netip.AddrPort
	Zone uint32
}

// Batch is a fixed-size, reusable collection of independent packet buffers.
// A Batch is not safe for concurrent use. Its packet buffers remain owned by
// the caller and are valid until the caller reuses or releases the Batch.
type Batch struct {
	packets []Datagram
	state   any
}

// NewBatch allocates a bounded batch with one distinct packet buffer per slot.
// Each slot initially has a full-sized Data buffer and Len zero.
func NewBatch(count, packetSize int) (*Batch, error) {
	if count < 1 || count > MaxBatch || packetSize < 1 || packetSize > MaxDatagramSize {
		return nil, ErrInvalidBatch
	}

	storage := make([]byte, count*packetSize)
	packets := make([]Datagram, count)
	for i := range packets {
		packets[i].Data = storage[i*packetSize : (i+1)*packetSize]
	}
	b := &Batch{packets: packets}
	b.state = newBatchState(count)
	return b, nil
}

// Packets returns the fixed set of packet slots. It has length and capacity
// equal to the count passed to NewBatch; callers cannot enlarge the batch.
func (b *Batch) Packets() []Datagram {
	if b == nil {
		return nil
	}
	return b.packets
}

func (b *Batch) valid() bool {
	return b != nil && len(b.packets) != 0 && len(b.packets) <= MaxBatch && b.state != nil
}

// UDPBatchConn exclusively owns conn until Close. Do not perform I/O on conn
// directly after passing it to NewUDPBatchConn. ReadBatch and WriteBatch may
// run concurrently with different Batch values, but a Batch itself may be in
// at most one operation at a time.
type UDPBatchConn struct {
	conn                 *net.UDPConn
	raw                  syscall.RawConn
	closeOnce            sync.Once
	kernelDrops          atomic.Uint64
	kernelDropAccounting bool
}

// NewUDPBatchConn transfers ownership of conn to a batch I/O wrapper.
func NewUDPBatchConn(conn *net.UDPConn) (*UDPBatchConn, error) {
	if conn == nil {
		return nil, ErrInvalidBatch
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	result := &UDPBatchConn{conn: conn, raw: raw}
	result.kernelDropAccounting = enableKernelDropAccounting(raw)
	return result, nil
}

// ReadBatch receives up to len(b.Packets()) datagrams. The first returned n
// slots are valid. A non-nil error can accompany packets already received,
// such as ErrDatagramTruncated. Closing c unblocks a pending ReadBatch.
func (c *UDPBatchConn) ReadBatch(b *Batch) (int, error) {
	if c == nil || c.raw == nil || !b.valid() {
		return 0, ErrInvalidBatch
	}
	return readBatch(c, b)
}

// WriteBatch transmits every packet slot in b once.
func (c *UDPBatchConn) WriteBatch(b *Batch) (int, error) {
	if c == nil || c.raw == nil || !b.valid() {
		return 0, ErrInvalidBatch
	}
	return writeBatchPrefix(c, b, len(b.packets))
}

// WriteBatchPrefix transmits the first count packet slots in b once. It lets a
// long-lived writer retain a fixed 32-slot vector while flushing a smaller
// ready prefix without manufacturing empty datagrams.
func (c *UDPBatchConn) WriteBatchPrefix(b *Batch, count int) (int, error) {
	if c == nil || c.raw == nil || !b.valid() || count < 1 || count > len(b.packets) {
		return 0, ErrInvalidBatch
	}
	return writeBatchPrefix(c, b, count)
}

// VectorIOEnabled reports whether this build uses recvmmsg/sendmmsg rather
// than the portable per-datagram fallback.
func (c *UDPBatchConn) VectorIOEnabled() bool { return c != nil && usesKernelVector() }

// KernelDropAccounting reports whether SO_RXQ_OVFL was enabled on this socket.
func (c *UDPBatchConn) KernelDropAccounting() bool {
	return c != nil && c.kernelDropAccounting
}

// KernelDrops returns the cumulative receive-queue overflow count reported by
// the kernel for this socket.
func (c *UDPBatchConn) KernelDrops() uint64 {
	if c == nil {
		return 0
	}
	return c.kernelDrops.Load()
}

// Close closes the owned UDP socket. It is safe to call more than once and
// causes blocked reads to return the socket's closed error.
func (c *UDPBatchConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() { err = c.conn.Close() })
	return err
}
