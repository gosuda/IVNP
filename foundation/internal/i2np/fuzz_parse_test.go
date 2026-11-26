package i2np

import (
	"testing"
)

func FuzzParseI2NP(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = Parse(data)
		_, _, _ = ParseWire(data)
		_, _, _ = ParseUnchecked(data)
		_, _ = ParseLegacyShortHeader(data)
		_, _ = ParseTransportHeader(data)
		_, _ = ParseDatabaseStore(data)
		_, _ = ParseDatabaseLookup(data)
		_, _ = ParseDatabaseSearchReply(data)
		_, _ = ParseDeliveryStatus(data)
		_, _ = ParseTunnelTest(data)
		_, _ = ParseGarlic(data)
		_, _ = ParseTunnelData(data)
		_, _ = ParseTunnelGateway(data)
		_, _ = ParseData(data)
		for _, kind := range []MessageType{TunnelBuild, TunnelBuildReply, VariableTunnelBuild, VariableTunnelBuildReply, ShortTunnelBuild, OutboundTunnelBuildReply} {
			_, _ = ParseBuildRecords(kind, data)
		}
	})
}
