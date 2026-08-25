//go:build linux && amd64

package ssu2

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
	"syscall"
	"unsafe"
)

// Linux does not expose sendmmsg through package syscall. This is the x86-64
// syscall number from arch/x86/entry/syscalls/syscall_64.tbl.
const sysSendmmsg = 307

type mmsghdr struct {
	hdr syscall.Msghdr
	len uint32
	_   uint32
}

type linuxBatchState struct {
	msgs       []mmsghdr
	iov        []syscall.Iovec
	names      []syscall.RawSockaddrAny
	controls   [][64]byte
	readCount  int
	readErr    error
	readOp     func(uintptr) bool
	writeCount int
	writeErr   error
	writeN     int
	writeOp    func(uintptr) bool
}

func newBatchState(count int) any {
	return &linuxBatchState{
		msgs:     make([]mmsghdr, count),
		iov:      make([]syscall.Iovec, count),
		names:    make([]syscall.RawSockaddrAny, count),
		controls: make([][64]byte, count),
	}
}

const soRXQOverflow = 40

func enableKernelDropAccounting(raw syscall.RawConn) bool {
	enabled := false
	if raw == nil {
		return false
	}
	if err := raw.Control(func(fd uintptr) {
		enabled = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soRXQOverflow, 1) == nil
	}); err != nil {
		return false
	}
	return enabled
}

func readBatch(c *UDPBatchConn, b *Batch) (count int, err error) {
	state := b.state.(*linuxBatchState)
	for i := range b.packets {
		packet := &b.packets[i]
		if len(packet.Data) == 0 || len(packet.Data) > MaxDatagramSize {
			return 0, ErrInvalidDatagram
		}
		packet.Len = 0
		state.iov[i].Base = unsafe.SliceData(packet.Data)
		state.iov[i].SetLen(len(packet.Data))
		state.names[i] = syscall.RawSockaddrAny{}
		state.controls[i] = [64]byte{}
		state.msgs[i] = mmsghdr{hdr: syscall.Msghdr{
			Name:       (*byte)(unsafe.Pointer(&state.names[i])),
			Namelen:    uint32(unsafe.Sizeof(state.names[i])),
			Iov:        &state.iov[i],
			Iovlen:     1,
			Control:    &state.controls[i][0],
			Controllen: uint64(len(state.controls[i])),
		}}
	}

	if state.readOp == nil {
		state.readOp = func(fd uintptr) bool {
			n, _, errno := syscall.Syscall6(syscall.SYS_RECVMMSG, fd,
				uintptr(unsafe.Pointer(unsafe.SliceData(state.msgs))), uintptr(len(state.msgs)),
				syscall.MSG_WAITFORONE, 0, 0)
			if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK || errno == syscall.EINTR {
				return false
			}
			if errno != 0 {
				state.readErr = errno
				return true
			}
			state.readCount = int(n)
			return true
		}
	}
	state.readCount, state.readErr = 0, nil
	err = c.raw.Read(state.readOp)
	if err == nil {
		err = state.readErr
	}

	count = state.readCount
	if err != nil || count == 0 {
		return count, err
	}
	for i := range count {
		length := int(state.msgs[i].hdr.Controllen)
		if length < syscall.CmsgLen(4) || length > len(state.controls[i]) {
			continue
		}
		header := (*syscall.Cmsghdr)(unsafe.Pointer(&state.controls[i][0]))
		if header.Level != syscall.SOL_SOCKET || header.Type != soRXQOverflow ||
			header.Len < uint64(syscall.CmsgLen(4)) || header.Len > uint64(length) {
			continue
		}
		offset := syscall.CmsgLen(0)
		drops := uint64(binary.LittleEndian.Uint32(state.controls[i][offset : offset+4]))
		for previous := c.kernelDrops.Load(); drops > previous && !c.kernelDrops.CompareAndSwap(previous, drops); previous = c.kernelDrops.Load() {
		}
	}

	return normalizeReadBatch(b, state, count)
}

// normalizeReadBatch writes every packet returned by recvmmsg before reporting
// a truncation. That prevents a valid count from exposing stale Len/Addr state
// from a prior batch when one earlier datagram overflowed its caller buffer.
func normalizeReadBatch(b *Batch, state *linuxBatchState, count int) (int, error) {
	truncated := false
	for i := range count {
		packet := &b.packets[i]
		packet.Len = int(state.msgs[i].len)
		addr, zone, ok := sockaddrAddr(&state.names[i])
		if !ok {
			return i, ErrInvalidDatagram
		}
		packet.Addr, packet.Zone = addr, zone
		if state.msgs[i].hdr.Flags&syscall.MSG_TRUNC != 0 {
			truncated = true
		}
	}
	if truncated {
		return count, ErrDatagramTruncated
	}
	return count, nil
}

func writeBatchPrefix(c *UDPBatchConn, b *Batch, count int) (written int, err error) {
	state := b.state.(*linuxBatchState)
	packets := b.packets[:count]
	for i := range packets {
		packet := &b.packets[i]
		if packet.Len < 0 || packet.Len > len(packet.Data) || packet.Len > MaxDatagramSize {
			return 0, ErrInvalidDatagram
		}
		if !sockaddrFromAddr(&state.names[i], packet.Addr, packet.Zone) {
			return 0, ErrInvalidDatagram
		}
		state.iov[i].Base = unsafe.SliceData(packet.Data[:packet.Len])
		state.iov[i].SetLen(packet.Len)
		state.msgs[i] = mmsghdr{hdr: syscall.Msghdr{
			Name:    (*byte)(unsafe.Pointer(&state.names[i])),
			Namelen: sockaddrLen(packet.Addr),
			Iov:     &state.iov[i],
			Iovlen:  1,
		}}
	}
	if state.writeOp == nil {
		state.writeOp = func(fd uintptr) bool {
			n, _, errno := syscall.Syscall6(sysSendmmsg, fd,
				uintptr(unsafe.Pointer(unsafe.SliceData(state.msgs))), uintptr(state.writeN), 0, 0, 0)
			if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK || errno == syscall.EINTR {
				return false
			}
			if errno != 0 {
				state.writeErr = errno
				return true
			}
			state.writeCount = int(n)
			return true
		}
	}
	state.writeCount, state.writeErr, state.writeN = 0, nil, count
	err = c.raw.Write(state.writeOp)
	if err ==
		nil {
		err = state.writeErr
	}

	return state.writeCount, err
}

func sockaddrAddr(raw *syscall.RawSockaddrAny) (netip.AddrPort, uint32, bool) {
	switch *(*uint16)(unsafe.Pointer(raw)) {
	case syscall.AF_INET:
		sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(raw))
		return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), bits.ReverseBytes16(sa.Port)), 0, true
	case syscall.AF_INET6:
		sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(raw))
		return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), bits.ReverseBytes16(sa.Port)), sa.Scope_id, true
	default:
		return netip.AddrPort{}, 0, false
	}
}

func sockaddrFromAddr(raw *syscall.RawSockaddrAny, addrPort netip.AddrPort, zone uint32) bool {
	addr := addrPort.Addr()
	if !addr.IsValid() {
		return false
	}
	if addr.Is4() || addr.Is4In6() {
		if zone != 0 {
			return false
		}
		sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(raw))
		*sa = syscall.RawSockaddrInet4{Family: syscall.AF_INET, Port: bits.ReverseBytes16(addrPort.Port()), Addr: addr.Unmap().As4()}
		return true
	}
	sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(raw))
	*sa = syscall.RawSockaddrInet6{Family: syscall.AF_INET6, Port: bits.ReverseBytes16(addrPort.Port()), Addr: addr.As16(), Scope_id: zone}
	return true
}

func sockaddrLen(addrPort netip.AddrPort) uint32 {
	if addrPort.Addr().Is4() || addrPort.Addr().Is4In6() {
		return uint32(unsafe.Sizeof(syscall.RawSockaddrInet4{}))
	}
	return uint32(unsafe.Sizeof(syscall.RawSockaddrInet6{}))
}

func usesKernelVector() bool { return true }
