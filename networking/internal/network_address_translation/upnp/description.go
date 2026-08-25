package upnp

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	wanIPConnection  = "urn:schemas-upnp-org:service:WANIPConnection:"
	wanPPPConnection = "urn:schemas-upnp-org:service:WANPPPConnection:"
)

// Gateway identifies the port-mapping service exposed by an IGD.
type Gateway struct {
	Location    *url.URL
	ControlURL  *url.URL
	ServiceType string
}

// Describe downloads an IGD device description and locates its WANIPConnection
// service, falling back to WANPPPConnection only when no IP service is present.
func (c *Client) Describe(ctx context.Context, location *url.URL) (Gateway, error) {
	if location == nil {
		return Gateway{}, fmt.Errorf("upnp: description location is required")
	}
	if _, err := parseHTTPURL(location.String()); err != nil {
		return Gateway{}, fmt.Errorf("upnp: invalid description location: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
	if err != nil {
		return Gateway{}, fmt.Errorf("upnp: create description request: %w", err)
	}
	response, err := c.httpClient().Do(request)
	if err != nil {
		return Gateway{}, fmt.Errorf("upnp: fetch device description: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Gateway{}, fmt.Errorf("upnp: device description returned HTTP %d", response.StatusCode)
	}
	if response.Body == nil {
		return Gateway{}, fmt.Errorf("upnp: device description has no body")
	}

	description, err := parseDescription(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return Gateway{}, err
	}
	base := location
	if description.URLBase != "" {
		baseURL, err := parseHTTPURL(description.URLBase)
		if err != nil {
			return Gateway{}, fmt.Errorf("upnp: invalid URLBase: %w", err)
		}
		base = baseURL
	}
	service, ok := description.bestMappingService()
	if !ok {
		return Gateway{}, fmt.Errorf("upnp: device description has no WAN connection service")
	}
	control, err := resolveControlURL(base, service.ControlURL)
	if err != nil {
		return Gateway{}, err
	}
	return Gateway{Location: cloneURL(location), ControlURL: control, ServiceType: service.ServiceType}, nil
}

// Describe discovers an IGD description using a zero-value Client.
func Describe(ctx context.Context, location *url.URL) (Gateway, error) {
	return new(Client).Describe(ctx, location)
}

type deviceDescription struct {
	URLBase string `xml:"URLBase"`
	Device  device `xml:"device"`
}

type device struct {
	Services []service `xml:"serviceList>service"`
	Devices  []device  `xml:"deviceList>device"`
}

type service struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

func parseDescription(reader io.Reader) (deviceDescription, error) {
	var description deviceDescription
	decoder := xml.NewDecoder(reader)
	if err := decoder.Decode(&description); err != nil {
		return deviceDescription{}, fmt.Errorf("upnp: parse device description: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return deviceDescription{}, fmt.Errorf("upnp: parse device description: %w", err)
	}
	return description, nil
}

func (description deviceDescription) bestMappingService() (service, bool) {
	var ppp service
	var visit func(device) (service, bool)
	visit = func(current device) (service, bool) {
		for _, candidate := range current.Services {
			if !validServiceType(candidate.ServiceType) || strings.TrimSpace(candidate.ControlURL) == "" {
				continue
			}
			switch {
			case strings.HasPrefix(candidate.ServiceType, wanIPConnection):
				return candidate, true
			case strings.HasPrefix(candidate.ServiceType, wanPPPConnection) && ppp.ServiceType == "":
				ppp = candidate
			}
		}
		for _, child := range current.Devices {
			if found, ok := visit(child); ok {
				return found, true
			}
		}
		return service{}, false
	}
	if mapping, ok := visit(description.Device); ok {
		return mapping, true
	}
	return ppp, ppp.ServiceType != ""
}

func validServiceType(value string) bool {
	prefix := ""
	switch {
	case strings.HasPrefix(value, wanIPConnection):
		prefix = wanIPConnection
	case strings.HasPrefix(value, wanPPPConnection):
		prefix = wanPPPConnection
	default:
		return false
	}
	version, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, 16)
	return err == nil && version > 0
}

func resolveControlURL(base *url.URL, raw string) (*url.URL, error) {
	reference, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("upnp: invalid control URL: %w", err)
	}
	if reference.User != nil {
		return nil, fmt.Errorf("upnp: control URL must not include user information")
	}
	resolved := base.ResolveReference(reference)
	if _, err := parseHTTPURL(resolved.String()); err != nil {
		return nil, fmt.Errorf("upnp: invalid control URL: %w", err)
	}
	return resolved, nil
}

func cloneURL(value *url.URL) *url.URL {
	copy := *value
	return &copy
}

func requireEOF(decoder *xml.Decoder) error {
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if chars, ok := token.(xml.CharData); !ok || strings.TrimSpace(string(chars)) != "" {
			return fmt.Errorf("unexpected trailing XML")
		}
	}
}

func (c *Client) httpClient() *http.Client {
	if c != nil && c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}
