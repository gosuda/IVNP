package router

import (
	"testing"

	dataplanestreamingtunnel "gosuda.org/ivnp/dataplane/internal/streaming/tunnel"
	"gosuda.org/ivnp/foundation"
)

func BenchmarkPreparedSenderDestinationFraming(b *testing.B) {
	for _, workload := range []struct {
		name string
		size int
	}{{"small", 128}, {"large", 48 * 1024}} {
		b.Run(workload.name, func(b *testing.B) {
			sender := &PreparedRouteSender{nextID: func() (uint32, error) { return 1, nil }}
			var scratch streamingSenderScratch
			delivery := dataplanestreamingtunnel.Delivery{To: foundation.Hash{2}, Protocol: dataplanestreamingtunnel.ProtocolStreaming, Payload: make([]byte, workload.size)}
			dataLen := 4 + destinationDataHeaderLen + len(delivery.Payload)
			payloadLen := 3 + 1 + foundation.HashLength + 9 + dataLen
			if _, err := sender.destinationRatchetPayloadTo(scratch.ratchet.bytes(payloadLen), scratch.data.bytes(dataLen), delivery, 10_000, nil); err != nil {
				b.Fatal(err)
			}
			clearStreamingSenderScratch(&scratch)
			b.ReportAllocs()
			b.SetBytes(int64(workload.size))
			b.ResetTimer()
			for b.Loop() {
				_, err := sender.destinationRatchetPayloadTo(scratch.ratchet.bytes(payloadLen), scratch.data.bytes(dataLen), delivery, 10_000, nil)
				clearStreamingSenderScratch(&scratch)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
