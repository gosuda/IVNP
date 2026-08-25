//go:build !linux || !amd64

package ssu2

import (
	"io"
	"net"
	"net/netip"
	"strconv"
	"syscall"
)

type portableBatchState struct{}

func newBatchState(int) any { return portableBatchState{} }

func enableKernelDropAccounting(syscall.RawConn) bool { return false }

// Portable platforms preserve the same packet and error semantics with one
// datagram per receive and a bounded sequential send loop.
func readBatch(c *UDPBatchConn, b *Batch) (int, error) {
	packet := &b.packets[0]
	if len(packet.Data) == 0 || len(packet.Data) > MaxDatagramSize {
		return 0, ErrInvalidDatagram
	}
	packet.Len = 0
	n, _, flags, addr, err := c.conn.ReadMsgUDP(packet.Data, nil)
	if err != nil {
		return 0, err
	}
	peer, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return 0, ErrInvalidDatagram
	}
	packet.Len = n
	packet.Addr = netip.AddrPortFrom(peer.Unmap(), uint16(addr.Port))
	packet.Zone = zoneIndex(addr.Zone)
	if datagramTruncated(flags) {
		return 1, ErrDatagramTruncated
	}
	return 1, nil
}

func writeBatchPrefix(c *UDPBatchConn, b *Batch, count int) (int, error) {
	var addresses [MaxBatch]*net.UDPAddr
	// Match sendmmsg semantics: reject a malformed prefix before emitting any
	// datagram. This matters to callers which retry the unsent suffix.
	for i := range b.packets[:count] {
		packet := &b.packets[i]
		if packet.Len < 0 || packet.Len > len(packet.Data) || packet.Len > MaxDatagramSize {
			return 0, ErrInvalidDatagram
		}
		addr, ok := udpAddr(packet.Addr, packet.Zone)
		if !ok {
			return 0, ErrInvalidDatagram
		}
		addresses[i] = addr
	}
	for i := range b.packets[:count] {
		packet := &b.packets[i]
		n, err := c.conn.WriteToUDP(packet.Data[:packet.Len], addresses[i])
		if err != nil {
			return i, err
		}
		if n != packet.Len {
			return i, io.ErrShortWrite
		}
	}
	return count, nil
}

func udpAddr(addrPort netip.AddrPort, zone uint32) (*net.UDPAddr, bool) {
	addr := addrPort.Addr()
	if !addr.IsValid() || (zone != 0 && (addr.Is4() || addr.Is4In6())) {
		return nil, false
	}
	udpAddr := &net.UDPAddr{IP: addr.Unmap().AsSlice(), Port: int(addrPort.Port())}
	if zone != 0 {
		iface, err := net.InterfaceByIndex(int(zone))
		if err != nil {
			return nil, false
		}
		udpAddr.Zone = iface.Name
	}
	return udpAddr, true
}

func zoneIndex(zone string) uint32 {
	if zone == "" {
		return 0
	}
	if id, err := strconv.ParseUint(zone, 10, 32); err == nil {
		return uint32(id)
	}
	iface, err := net.InterfaceByName(zone)
	if err != nil {
		return 0
	}
	return uint32(iface.Index)
}

func usesKernelVector() bool { return false }

// MSG_TRUNC is 0x20 on Linux, 0x10 on BSD-derived systems, and MSG_PARTIAL
// is 0x8000 on Windows. ReadMsgUDP reports the platform flag unchanged.
func datagramTruncated(flags int) bool {
	return flags&(0x20|0x10|0x8000) != 0
}
