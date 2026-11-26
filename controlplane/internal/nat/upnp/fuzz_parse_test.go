package upnp

import (
	"testing"
)

func FuzzParseSSDPResponse(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseSSDPResponse(data)
	})
}
