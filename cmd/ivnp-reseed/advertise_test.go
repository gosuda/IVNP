package main

import (
	"io"
	"log/slog"
	"testing"

	"gosuda.org/ivnp/state"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestResolveAdvertisedEndpoint(t *testing.T) {
	logger := newTestLogger()
	tests := []struct {
		name           string
		host           string
		advertisedPort int
		routerPort     int
		wantHost       string
		wantPort       int
		wantErr        bool
	}{
		{
			name:       "empty host disables advertisement",
			host:       "",
			routerPort: 39898,
			wantHost:   "",
			wantPort:   0,
		},
		{
			name:           "advertise port without host is ignored",
			host:           "",
			advertisedPort: 12345,
			routerPort:     39898,
			wantHost:       "",
			wantPort:       0,
		},
		{
			name:       "host inherits router port by default",
			host:       "203.0.113.7",
			routerPort: 39898,
			wantHost:   "203.0.113.7",
			wantPort:   39898,
		},
		{
			name:           "advertise port overrides router port for NAT forwarding",
			host:           "203.0.113.7",
			advertisedPort: 12345,
			routerPort:     8080,
			wantHost:       "203.0.113.7",
			wantPort:       12345,
		},
		{
			name:       "host without router port is an error",
			host:       "203.0.113.7",
			routerPort: 0,
			wantErr:    true,
		},
		{
			name:           "advertise port below range is an error",
			host:           "203.0.113.7",
			advertisedPort: -1,
			routerPort:     39898,
			wantErr:        true,
		},
		{
			name:           "advertise port above range is an error",
			host:           "203.0.113.7",
			advertisedPort: 70000,
			routerPort:     39898,
			wantErr:        true,
		},
		{
			name:       "invalid host is an error",
			host:       "not a host",
			routerPort: 39898,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotPort, err := resolveAdvertisedEndpoint(tt.host, tt.advertisedPort, tt.routerPort, logger)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveAdvertisedEndpoint(%q, %d, %d) error = nil, want error", tt.host, tt.advertisedPort, tt.routerPort)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveAdvertisedEndpoint(%q, %d, %d) unexpected error: %v", tt.host, tt.advertisedPort, tt.routerPort, err)
			}
			if gotHost != tt.wantHost || gotPort != tt.wantPort {
				t.Fatalf("resolveAdvertisedEndpoint(%q, %d, %d) = (%q, %d), want (%q, %d)", tt.host, tt.advertisedPort, tt.routerPort, gotHost, gotPort, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestValidateAdvertisedHost(t *testing.T) {
	for _, host := range []string{"203.0.113.7", "2001:db8::1", "reseed.example.com", "a"} {
		if err := validateAdvertisedHost(host); err != nil {
			t.Errorf("validateAdvertisedHost(%q) unexpected error: %v", host, err)
		}
	}
	for _, host := range []string{"", "not a host", "foo..com", "-label.example.com", "label-.example.com", "under_score.example.com", longHostname(256)} {
		if err := validateAdvertisedHost(host); err == nil {
			t.Errorf("validateAdvertisedHost(%q) error = nil, want error", host)
		}
	}
}

func longHostname(length int) string {
	host := "a"
	for len(host) < length {
		host += ".b"
	}
	return host
}

func TestConfigureRouterAdvertisedEndpoints(t *testing.T) {
	cfg := configureActiveClientRouter(t.TempDir(), "", 2, 39898, "203.0.113.7", 12345)
	if cfg.NTCP2.Bind.Port != 39898 {
		t.Errorf("NTCP2 bind port = %d, want 39898", cfg.NTCP2.Bind.Port)
	}
	if cfg.NTCP2.Advertised.Host != "203.0.113.7" || cfg.NTCP2.Advertised.Port != 12345 {
		t.Errorf("NTCP2 advertised = %q:%d, want 203.0.113.7:12345", cfg.NTCP2.Advertised.Host, cfg.NTCP2.Advertised.Port)
	}
	if cfg.SSU2.Advertised.Host != "203.0.113.7" || cfg.SSU2.Advertised.Port != 12345 {
		t.Errorf("SSU2 advertised = %q:%d, want 203.0.113.7:12345", cfg.SSU2.Advertised.Host, cfg.SSU2.Advertised.Port)
	}

	cfg = configureActiveClientRouter(t.TempDir(), "", 2, 0, "", 0)
	if cfg.NTCP2.Advertised != (state.ConfigurationEndpoint{}) {
		t.Errorf("NTCP2 advertised = %+v, want zero value", cfg.NTCP2.Advertised)
	}
	if cfg.SSU2.Advertised != (state.ConfigurationEndpoint{}) {
		t.Errorf("SSU2 advertised = %+v, want zero value", cfg.SSU2.Advertised)
	}
}
