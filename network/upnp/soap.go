package upnp

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

const soapEnvelopeNamespace = "http://schemas.xmlsoap.org/soap/envelope/"

var ErrSOAPFault = errors.New("upnp: SOAP fault")

// PortMapping is the input to AddPortMapping. ExternalPort and InternalPort
// must be non-zero. Protocol is TCP or UDP. A lease duration of zero requests
// a permanent mapping, where the gateway supports it.
type PortMapping struct {
	RemoteHost     string
	ExternalPort   uint16
	Protocol       string
	InternalPort   uint16
	InternalClient string
	Enabled        bool
	Description    string
	LeaseDuration  uint32
}

// AddPortMapping creates a mapping at gateway.
func (c *Client) AddPortMapping(ctx context.Context, gateway Gateway, mapping PortMapping) error {
	if err := validateGateway(gateway); err != nil {
		return err
	}
	if err := validateMapping(mapping); err != nil {
		return err
	}
	arguments := []soapArgument{
		{"NewRemoteHost", mapping.RemoteHost},
		{"NewExternalPort", strconv.FormatUint(uint64(mapping.ExternalPort), 10)},
		{"NewProtocol", strings.ToUpper(mapping.Protocol)},
		{"NewInternalPort", strconv.FormatUint(uint64(mapping.InternalPort), 10)},
		{"NewInternalClient", mapping.InternalClient},
		{"NewEnabled", strconv.FormatBool(mapping.Enabled)},
		{"NewPortMappingDescription", mapping.Description},
		{"NewLeaseDuration", strconv.FormatUint(uint64(mapping.LeaseDuration), 10)},
	}
	return c.call(ctx, gateway, "AddPortMapping", arguments)
}

// DeletePortMapping removes the mapping identified by remote host, external
// port, and protocol at gateway.
func (c *Client) DeletePortMapping(ctx context.Context, gateway Gateway, remoteHost string, externalPort uint16, protocol string) error {
	if err := validateGateway(gateway); err != nil {
		return err
	}
	if externalPort == 0 {
		return fmt.Errorf("upnp: external port must not be zero")
	}
	protocol = strings.ToUpper(protocol)
	if protocol != "TCP" && protocol != "UDP" {
		return fmt.Errorf("upnp: protocol must be TCP or UDP")
	}
	if strings.ContainsAny(remoteHost, "\r\n") {
		return fmt.Errorf("upnp: remote host contains a line break")
	}
	return c.call(ctx, gateway, "DeletePortMapping", []soapArgument{
		{"NewRemoteHost", remoteHost},
		{"NewExternalPort", strconv.FormatUint(uint64(externalPort), 10)},
		{"NewProtocol", protocol},
	})
}

// AddPortMapping creates a mapping with a zero-value Client.
func AddPortMapping(ctx context.Context, gateway Gateway, mapping PortMapping) error {
	return new(Client).AddPortMapping(ctx, gateway, mapping)
}

// DeletePortMapping deletes a mapping with a zero-value Client.
func DeletePortMapping(ctx context.Context, gateway Gateway, remoteHost string, externalPort uint16, protocol string) error {
	return new(Client).DeletePortMapping(ctx, gateway, remoteHost, externalPort, protocol)
}

// ExternalAddress returns the public IPv4 address reported by gateway.
func (c *Client) ExternalAddress(ctx context.Context, gateway Gateway) (netip.Addr, error) {
	var text string
	err := c.callResponse(ctx, gateway, "GetExternalIPAddress", nil, func(reader io.Reader) error {
		var parseErr error
		text, parseErr = parseSOAPStringResponse(reader, gateway.ServiceType, "GetExternalIPAddress", "NewExternalIPAddress")
		return parseErr
	})
	if err != nil {
		return netip.Addr{}, err
	}
	address, err := netip.ParseAddr(text)
	if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("upnp: invalid external IPv4 address")
	}
	return address.Unmap(), nil
}

// ExternalAddress returns the public IPv4 address using a zero-value Client.
func ExternalAddress(ctx context.Context, gateway Gateway) (netip.Addr, error) {
	return new(Client).ExternalAddress(ctx, gateway)
}

type soapArgument struct {
	name  string
	value string
}

func (c *Client) call(ctx context.Context, gateway Gateway, action string, arguments []soapArgument) error {
	return c.callResponse(ctx, gateway, action, arguments, func(reader io.Reader) error {
		return validateSOAPResponse(reader, gateway.ServiceType, action)
	})
}

func (c *Client) callResponse(ctx context.Context, gateway Gateway, action string, arguments []soapArgument, parse func(io.Reader) error) error {
	body, err := marshalSOAPRequest(gateway.ServiceType, action, arguments)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, gateway.ControlURL.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("upnp: create %s request: %w", action, err)
	}
	request.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	request.Header.Set("SOAPAction", "\""+gateway.ServiceType+"#"+action+"\"")
	response, err := c.httpClient().Do(request)
	if err != nil {
		return fmt.Errorf("upnp: %s request: %w", action, err)
	}
	defer response.Body.Close()
	if response.Body == nil {
		return fmt.Errorf("upnp: %s response has no body", action)
	}
	if response.StatusCode != http.StatusOK {
		fault, faultErr := parseSOAPFault(io.LimitReader(response.Body, 1<<20))
		if faultErr == nil {
			return fmt.Errorf("%w: %s", ErrSOAPFault, fault)
		}
		return fmt.Errorf("upnp: %s returned HTTP %d", action, response.StatusCode)
	}
	if parse == nil {
		return fmt.Errorf("upnp: %s response parser is required", action)
	}
	return parse(io.LimitReader(response.Body, 1<<20))
}

func marshalSOAPRequest(serviceType, action string, arguments []soapArgument) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := xml.NewEncoder(&buffer)
	start := xml.StartElement{Name: xml.Name{Space: soapEnvelopeNamespace, Local: "Envelope"}}
	start.Attr = []xml.Attr{{Name: xml.Name{Local: "xmlns:s"}, Value: soapEnvelopeNamespace}, {Name: xml.Name{Local: "s:encodingStyle"}, Value: "http://schemas.xmlsoap.org/soap/encoding/"}}
	if err := encoder.EncodeToken(start); err != nil {
		return nil, err
	}
	if err := encoder.EncodeToken(xml.StartElement{Name: xml.Name{Space: soapEnvelopeNamespace, Local: "Body"}}); err != nil {
		return nil, err
	}
	actionStart := xml.StartElement{Name: xml.Name{Space: serviceType, Local: action}}
	actionStart.Attr = []xml.Attr{{Name: xml.Name{Local: "xmlns:u"}, Value: serviceType}}
	if err := encoder.EncodeToken(actionStart); err != nil {
		return nil, err
	}
	for _, argument := range arguments {
		if err := encoder.EncodeElement(argument.value, xml.StartElement{Name: xml.Name{Local: argument.name}}); err != nil {
			return nil, err
		}
	}
	if err := encoder.EncodeToken(actionStart.End()); err != nil {
		return nil, err
	}
	if err := encoder.EncodeToken(xml.EndElement{Name: xml.Name{Space: soapEnvelopeNamespace, Local: "Body"}}); err != nil {
		return nil, err
	}
	if err := encoder.EncodeToken(start.End()); err != nil {
		return nil, err
	}
	if err := encoder.Flush(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func validateGateway(gateway Gateway) error {
	if gateway.ControlURL == nil || !validServiceType(gateway.ServiceType) {
		return fmt.Errorf("upnp: invalid gateway")
	}
	if _, err := parseHTTPURL(gateway.ControlURL.String()); err != nil {
		return fmt.Errorf("upnp: invalid gateway control URL: %w", err)
	}
	return nil
}

func validateMapping(mapping PortMapping) error {
	if mapping.ExternalPort == 0 || mapping.InternalPort == 0 {
		return fmt.Errorf("upnp: ports must not be zero")
	}
	if strings.ToUpper(mapping.Protocol) != "TCP" && strings.ToUpper(mapping.Protocol) != "UDP" {
		return fmt.Errorf("upnp: protocol must be TCP or UDP")
	}
	if mapping.InternalClient == "" || strings.ContainsAny(mapping.InternalClient, "\r\n") || strings.ContainsAny(mapping.RemoteHost, "\r\n") || strings.ContainsAny(mapping.Description, "\r\n") {
		return fmt.Errorf("upnp: invalid port mapping text")
	}
	return nil
}

func parseSOAPFault(reader io.Reader) (string, error) {
	decoder := xml.NewDecoder(reader)
	token, err := nextSignificantToken(decoder)
	if err != nil {
		return "", err
	}
	envelope, ok := token.(xml.StartElement)
	if !ok || envelope.Name.Space != soapEnvelopeNamespace || envelope.Name.Local != "Envelope" {
		return "", errors.New("expected SOAP Envelope")
	}
	token, err = nextSignificantToken(decoder)
	if err != nil {
		return "", err
	}
	body, ok := token.(xml.StartElement)
	if !ok || body.Name.Space != soapEnvelopeNamespace || body.Name.Local != "Body" {
		return "", errors.New("expected SOAP Body")
	}
	token, err = nextSignificantToken(decoder)
	if err != nil {
		return "", err
	}
	fault, ok := token.(xml.StartElement)
	if !ok || fault.Name.Space != soapEnvelopeNamespace || fault.Name.Local != "Fault" {
		return "", errors.New("expected SOAP Fault")
	}
	message, err := readSOAPElementText(decoder, fault)
	if err != nil {
		return "", err
	}
	token, err = nextSignificantToken(decoder)
	if err != nil {
		return "", err
	}
	endBody, ok := token.(xml.EndElement)
	if !ok || endBody.Name != body.Name {
		return "", errors.New("malformed SOAP Body")
	}
	token, err = nextSignificantToken(decoder)
	if err != nil {
		return "", err
	}
	endEnvelope, ok := token.(xml.EndElement)
	if !ok || endEnvelope.Name != envelope.Name {
		return "", errors.New("malformed SOAP Envelope")
	}
	if err := requireEOF(decoder); err != nil {
		return "", err
	}
	return message, nil
}

func validateSOAPResponse(reader io.Reader, serviceType, action string) error {
	decoder := xml.NewDecoder(reader)
	token, err := nextSignificantToken(decoder)
	if err != nil {
		return fmt.Errorf("upnp: invalid SOAP response: %w", err)
	}
	envelope, ok := token.(xml.StartElement)
	if !ok || envelope.Name.Space != soapEnvelopeNamespace || envelope.Name.Local != "Envelope" {
		return fmt.Errorf("upnp: invalid SOAP response: expected SOAP Envelope")
	}
	bodySeen := false
	for {
		token, err = nextSignificantToken(decoder)
		if err != nil {
			return fmt.Errorf("upnp: invalid SOAP response: %w", err)
		}
		switch value := token.(type) {
		case xml.StartElement:
			if value.Name.Space != soapEnvelopeNamespace || value.Name.Local != "Body" || bodySeen {
				return fmt.Errorf("upnp: invalid SOAP response: expected one SOAP Body")
			}
			bodySeen = true
			if err := validateSOAPBody(decoder, serviceType, action); err != nil {
				return err
			}
		case xml.EndElement:
			if value.Name != envelope.Name || !bodySeen {
				return fmt.Errorf("upnp: invalid SOAP response: malformed envelope")
			}
			if err := requireEOF(decoder); err != nil {
				return fmt.Errorf("upnp: invalid SOAP response: %w", err)
			}
			return nil
		default:
			return fmt.Errorf("upnp: invalid SOAP response: unexpected data")
		}
	}
}

func parseSOAPStringResponse(reader io.Reader, serviceType, action, field string) (string, error) {
	decoder := xml.NewDecoder(reader)
	token, err := nextSignificantToken(decoder)
	if err != nil {
		return "", fmt.Errorf("upnp: invalid SOAP response: %w", err)
	}
	envelope, ok := token.(xml.StartElement)
	if !ok || envelope.Name.Space != soapEnvelopeNamespace || envelope.Name.Local != "Envelope" {
		return "", fmt.Errorf("upnp: invalid SOAP response: expected SOAP Envelope")
	}
	token, err = nextSignificantToken(decoder)
	if err != nil {
		return "", fmt.Errorf("upnp: invalid SOAP response: %w", err)
	}
	body, ok := token.(xml.StartElement)
	if !ok || body.Name.Space != soapEnvelopeNamespace || body.Name.Local != "Body" {
		return "", fmt.Errorf("upnp: invalid SOAP response: expected SOAP Body")
	}
	token, err = nextSignificantToken(decoder)
	if err != nil {
		return "", fmt.Errorf("upnp: invalid SOAP response: %w", err)
	}
	response, ok := token.(xml.StartElement)
	if !ok || response.Name.Space != serviceType || response.Name.Local != action+"Response" {
		return "", fmt.Errorf("upnp: invalid SOAP response: expected %sResponse", action)
	}
	token, err = nextSignificantToken(decoder)
	if err != nil {
		return "", fmt.Errorf("upnp: invalid SOAP response: %w", err)
	}
	valueStart, ok := token.(xml.StartElement)
	if !ok || valueStart.Name.Local != field || valueStart.Name.Space != "" && valueStart.Name.Space != serviceType {
		return "", fmt.Errorf("upnp: invalid SOAP response: expected %s", field)
	}
	value, err := readSOAPElementText(decoder, valueStart)
	if err != nil {
		return "", fmt.Errorf("upnp: invalid SOAP response: %w", err)
	}
	for _, expected := range []xml.Name{response.Name, body.Name, envelope.Name} {
		token, err = nextSignificantToken(decoder)
		if err != nil {
			return "", fmt.Errorf("upnp: invalid SOAP response: %w", err)
		}
		end, ok := token.(xml.EndElement)
		if !ok || end.Name != expected {
			return "", fmt.Errorf("upnp: invalid SOAP response: unexpected trailing element")
		}
	}
	if err = requireEOF(decoder); err != nil {
		return "", fmt.Errorf("upnp: invalid SOAP response: %w", err)
	}
	return strings.TrimSpace(value), nil
}

func validateSOAPBody(decoder *xml.Decoder, serviceType, action string) error {
	token, err := nextSignificantToken(decoder)
	if err != nil {
		return fmt.Errorf("upnp: invalid SOAP response: %w", err)
	}
	response, ok := token.(xml.StartElement)
	if !ok {
		return fmt.Errorf("upnp: invalid SOAP response: empty SOAP Body")
	}
	if response.Name.Space == soapEnvelopeNamespace && response.Name.Local == "Fault" {
		fault, err := readSOAPElementText(decoder, response)
		if err != nil {
			return fmt.Errorf("upnp: invalid SOAP fault: %w", err)
		}
		return fmt.Errorf("%w: %s", ErrSOAPFault, fault)
	}
	if response.Name.Space != serviceType || response.Name.Local != action+"Response" {
		return fmt.Errorf("upnp: invalid SOAP response: expected %sResponse", action)
	}
	if err := requireEmptyElement(decoder, response); err != nil {
		return fmt.Errorf("upnp: invalid SOAP response: %w", err)
	}
	token, err = nextSignificantToken(decoder)
	if err != nil {
		return fmt.Errorf("upnp: invalid SOAP response: %w", err)
	}
	end, ok := token.(xml.EndElement)
	if !ok || end.Name.Space != soapEnvelopeNamespace || end.Name.Local != "Body" {
		return fmt.Errorf("upnp: invalid SOAP response: multiple SOAP Body values")
	}
	return nil
}

func nextSignificantToken(decoder *xml.Decoder) (xml.Token, error) {
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(value)) == "" {
				continue
			}
		case xml.Comment, xml.Directive, xml.ProcInst:
			continue
		}
		return token, nil
	}
}

func requireEmptyElement(decoder *xml.Decoder, start xml.StartElement) error {
	token, err := nextSignificantToken(decoder)
	if err != nil {
		return err
	}
	end, ok := token.(xml.EndElement)
	if !ok || end.Name != start.Name {
		return errors.New("response action must be empty")
	}
	return nil
}

func readSOAPElementText(decoder *xml.Decoder, start xml.StartElement) (string, error) {
	var text strings.Builder
	depth := 1
	for depth > 0 {
		token, err := decoder.Token()
		if err != nil {
			return "", err
		}
		switch value := token.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
			if depth == 0 && value.Name != start.Name {
				return "", errors.New("malformed SOAP fault")
			}
		case xml.CharData:
			text.Write([]byte(value))
		}
	}
	return strings.TrimSpace(text.String()), nil
}
