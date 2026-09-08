package router

import (
	"net/netip"

	dataplanessu2 "gosuda.org/ivnp/dataplane/internal/transport/ssu2"
)

type ssu2SetupPacket struct {
	data   [dataplanessu2.MaxIPv4PacketLen]byte
	length int
	remote netip.AddrPort
}

func (m *SSU2Manager) establishedPacket(packet []byte) bool {
	destination, err := dataplanessu2.PeekDestinationID(packet, m.introKey)
	if _, err := dataplanessu2.PeekSessionRequest(packet, m.introKey); err == nil {
		return false
	}
	if err != nil {
		return false
	}
	m.mu.RLock()
	known := m.sessionsByID[destination] != nil
	m.mu.RUnlock()
	return known
}

func (m *SSU2Manager) enqueueSetupPacket(packet dataplanessu2.Datagram) {
	job := m.borrowSetupPacket()
	if job == nil {
		m.ioStats.dropped.Add(1)
		if m.metrics != nil {
			m.metrics.AddSSU2ReceiveQueueDrops(1)
		}
		return
	}
	job.length = copy(job.data[:], packet.Data[:packet.Len])
	job.remote = packet.Addr
	m.setupQueue <- job
	if m.metrics != nil {
		m.metrics.AddSSU2EnqueuedDatagrams(1)
		m.metrics.IncSSU2IngressQueueDepth()
	}
}

// borrowSetupPacket reuses a released packet from setupFree, or lazily
// allocates a fresh one while setupFreeBudget still allows it. The budget
// still bounds total packets in circulation at maxPending, same as the
// eager fill this replaced, but lets an idle manager avoid paying upfront
// for maxPending 1.5KB buffers it may never need.
func (m *SSU2Manager) borrowSetupPacket() *ssu2SetupPacket {
	select {
	case job := <-m.setupFree:
		return job
	default:
	}
	if m.setupFreeBudget.Add(-1) >= 0 {
		return new(ssu2SetupPacket)
	}
	m.setupFreeBudget.Add(1)
	return nil
}

func (m *SSU2Manager) setupLoop() {
	defer m.wg.Done()
	for {
		select {
		case job := <-m.setupQueue:
			if err := m.handlePacketRecovered(job.data[:job.length], job.remote); err != nil && m.logger != nil {
				m.logger.Warn("dropped SSU2 setup datagram after recovered panic", "remote", job.remote, "error", err)
			}
			clear(job.data[:job.length])
			job.length = 0
			job.remote = netip.AddrPort{}
			m.setupFree <- job
			if m.metrics != nil {
				m.metrics.AddSSU2ProcessedDatagrams(1)
				m.metrics.DecSSU2IngressQueueDepth()
			}
		case <-m.contextDone():
			return
		}
	}
}
