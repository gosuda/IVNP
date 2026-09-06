package upnp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDiscoveryRequestAndResponseParser(t *testing.T) {
	request, err := DiscoveryRequest(InternetGatewayDevice, 2)
	if err != nil {
		t.Fatalf("DiscoveryRequest() error = %v", err)
	}
	wantRequest := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
	if string(request) != wantRequest {
		t.Fatalf("DiscoveryRequest() = %q, want %q", request, wantRequest)
	}
	packet := []byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.1:5431/igd.xml\r\nST: " + InternetGatewayDevice + "\r\nUSN: uuid:router::upnp:rootdevice\r\nEXT:\r\nBOOTID.UPNP.ORG: 1\r\n\r\n")
	response, err := ParseSSDPResponse(packet)
	if err != nil {
		t.Fatalf("ParseSSDPResponse() error = %v", err)
	}
	if got, want := response.Location.String(), "http://192.0.2.1:5431/igd.xml"; got != want {
		t.Fatalf("LOCATION = %q, want %q", got, want)
	}
	for _, malformed := range [][]byte{
		[]byte("HTTP/1.1 200 OK\r\nLOCATION: /igd.xml\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.1/igd.xml\r\n\r\nbody"),
		[]byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.1/igd.xml\r\nlocation: http://192.0.2.2/igd.xml\r\n\r\n"),
	} {
		if _, err := ParseSSDPResponse(malformed); !errors.Is(err, ErrInvalidSSDPResponse) {
			t.Fatalf("ParseSSDPResponse(%q) error = %v, want ErrInvalidSSDPResponse", malformed, err)
		}
	}
}

func TestDiscoverWithConnReceivesLocalPacket(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	served := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, sender, err := server.ReadFromUDP(buffer)
		if err != nil {
			served <- err
			return
		}
		if !strings.Contains(string(buffer[:n]), "M-SEARCH * HTTP/1.1\r\n") {
			served <- errors.New("missing M-SEARCH request")
			return
		}
		_, err = server.WriteToUDP([]byte("HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1/igd.xml\r\nST: "+InternetGatewayDevice+"\r\nUSN: uuid:test\r\n\r\n"), sender)
		served <- err
	}()

	responses, err := (&Client{MX: 1}).DiscoverWithConn(context.Background(), client, server.LocalAddr())
	if err != nil {
		t.Fatalf("DiscoverWithConn() error = %v", err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if len(responses) != 1 || responses[0].USN != "uuid:test" {
		t.Fatalf("DiscoverWithConn() = %#v, want one test response", responses)
	}
}

func TestDescriptionAndSOAPMapping(t *testing.T) {
	var (
		mu       sync.Mutex
		addBody  string
		deleteOK bool
	)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/description.xml":
			writer.Header().Set("Content-Type", "text/xml")
			_, _ = writer.Write([]byte(`<?xml version="1.0"?><root><URLBase>` + serverURL(request) + `</URLBase><device><deviceList><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType><controlURL>/ppp</controlURL></service></serviceList></device><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType><controlURL>control</controlURL></service></serviceList></device></deviceList></device></root>`))
		case "/control":
			body := make([]byte, request.ContentLength)
			_, _ = request.Body.Read(body)
			mu.Lock()
			addBody = string(body)
			mu.Unlock()
			if request.Header.Get("SOAPAction") != `"urn:schemas-upnp-org:service:WANIPConnection:2#AddPortMapping"` {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = writer.Write([]byte(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2"/></s:Body></s:Envelope>`))
		case "/delete":
			mu.Lock()
			deleteOK = true
			mu.Unlock()
			_, _ = writer.Write([]byte(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:wrong:1"/></s:Body></s:Envelope>`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	location, err := url.Parse(server.URL + "/description.xml")
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{HTTPClient: server.Client()}
	gateway, err := client.Describe(context.Background(), location)
	if err != nil {
		t.Fatalf("Describe() error = %v", err)
	}
	if got, want := gateway.ControlURL.String(), server.URL+"/control"; got != want {
		t.Fatalf("ControlURL = %q, want %q", got, want)
	}
	mapping := PortMapping{ExternalPort: 4242, Protocol: "tcp", InternalPort: 4242, InternalClient: "192.0.2.20", Enabled: true, Description: "ivnp"}
	if err := client.AddPortMapping(context.Background(), gateway, mapping); err != nil {
		t.Fatalf("AddPortMapping() error = %v", err)
	}
	mu.Lock()
	gotBody := addBody
	mu.Unlock()
	for _, value := range []string{"NewExternalPort>4242<", "NewProtocol>TCP<", "NewInternalClient>192.0.2.20<"} {
		if !strings.Contains(gotBody, value) {
			t.Fatalf("AddPortMapping body %q does not contain %q", gotBody, value)
		}
	}
	gateway.ControlURL, err = url.Parse(server.URL + "/delete")
	if err != nil {
		t.Fatal(err)
	}
	err = client.DeletePortMapping(context.Background(), gateway, "", 4242, "UDP")
	if err == nil || !strings.Contains(err.Error(), "expected DeletePortMappingResponse") {
		t.Fatalf("DeletePortMapping() error = %v, want strict response validation failure", err)
	}
	mu.Lock()
	deletionWasRequested := deleteOK
	mu.Unlock()
	if !deletionWasRequested {
		t.Fatal("DeletePortMapping request was not sent")
	}
}

func serverURL(request *http.Request) string {
	return "http://" + request.Host
}

func TestExternalAddressParsesStrictSOAPResponse(t *testing.T) {
	const serviceType = "urn:schemas-upnp-org:service:WANIPConnection:2"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("SOAPAction") != `"`+serviceType+`#GetExternalIPAddress"` {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = writer.Write([]byte(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="` + serviceType + `"><NewExternalIPAddress>198.51.100.9</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`))
	}))
	defer server.Close()
	control, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	address, err := (&Client{HTTPClient: server.Client()}).ExternalAddress(context.Background(), Gateway{ControlURL: control, ServiceType: serviceType})
	if err != nil || address.String() != "198.51.100.9" {
		t.Fatalf("ExternalAddress() = %s, %v", address, err)
	}
}

func TestDiscoveryCancellation(t *testing.T) {
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = (&Client{MX: 1}).DiscoverWithConn(ctx, client, server.LocalAddr())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DiscoverWithConn() error = %v, want context deadline", err)
	}
}
