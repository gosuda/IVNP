package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gosuda.org/ivnp/state"
)

// Config field value kinds exposed by GET /api/config.
const (
	configKindBool     = "bool"
	configKindInt      = "int"
	configKindString   = "string"
	configKindEnum     = "enum"
	configKindList     = "list"
	configKindDuration = "duration"
)

// Config field display groups, in display order.
const (
	configGroupFeatures   = "features"
	configGroupRouter     = "router"
	configGroupTunnels    = "tunnels"
	configGroupTransports = "transports"
	configGroupServices   = "services"
	configGroupSources    = "sources"
	configGroupLogging    = "logging"
)

const (
	configApplyLive    = "live"
	configApplyRestart = "restart"
)

// Bounds mirror state/internal/configuration validation.
const (
	maxListenPort             = 65_535
	maxSessions               = 65_536
	maxRouterFamilyBytes      = 64
	maxReseedEndpointItems    = 32
	maxSubscriptionItems      = 32
	maxOutproxyItems          = 16
	minTunnelBandwidthBytes   = 1 << 10
	maxTunnelBandwidthBytes   = 1 << 30
	tunnelLifetime            = 10 * time.Minute
	maxTunnelRenewBefore      = tunnelLifetime - time.Second
	maxTransportIdleTimeout   = 24 * time.Hour
	maxReseedTimeout          = 10 * time.Minute
	maxAddressBookRefresh     = 7 * 24 * time.Hour
	configForbiddenCharacters = "#;\"\r\n"
)

var (
	errConfigValueType   = errors.New("value has the wrong JSON type")
	errConfigValueRange  = errors.New("value is out of range")
	errConfigValueOption = errors.New("value is not an allowed option")
	errConfigValueSyntax = errors.New("value contains a forbidden character")
)

// configField describes one editable operating configuration key. get reads
// the typed value from a parsed configuration; encoding to INI text is derived
// from kind so every field of a kind is validated identically.
type configField struct {
	key         string
	group       string
	label       string
	description string
	kind        string
	minInt      int64
	maxInt      int64
	minDuration time.Duration
	maxDuration time.Duration
	maxItems    int
	maxBytes    int
	options     []string
	unit        string
	live        bool
	requires    []string
	get         func(state.ConfigurationOperating) any
}

func (f configField) section() string {
	section, _, _ := strings.Cut(f.key, ".")
	return section
}

func (f configField) name() string {
	_, name, _ := strings.Cut(f.key, ".")
	return name
}

func (f configField) apply() string {
	if f.live {
		return configApplyLive
	}
	return configApplyRestart
}

// bounds returns the JSON min, max, and options for the field. Integers report
// numeric bounds, durations report compact duration strings, lists report the
// maximum item count, and strings report the maximum byte length.
func (f configField) bounds() (minimum, maximum any, options []string) {
	switch f.kind {
	case configKindInt:
		return f.minInt, f.maxInt, nil
	case configKindDuration:
		return compactDuration(f.minDuration), compactDuration(f.maxDuration), nil
	case configKindList:
		return nil, f.maxItems, nil
	case configKindString:
		return nil, f.maxBytes, nil
	case configKindEnum:
		return nil, nil, f.options
	}
	return nil, nil, nil
}

// encode validates a PATCH value against the field kind and returns the INI
// value text. remove reports that the key should be deleted so the parser
// default applies.
func (f configField) encode(raw json.RawMessage) (value string, remove bool, err error) {
	switch f.kind {
	case configKindBool:
		var parsed bool
		if err = decodeStrictJSON(raw, &parsed); err != nil {
			return "", false, errConfigValueType
		}
		return strconv.FormatBool(parsed), false, nil
	case configKindInt:
		var number json.Number
		if raw = trimJSON(raw); len(raw) > 0 && raw[0] == '"' {
			return "", false, errConfigValueType
		}
		if err = decodeStrictJSON(raw, &number); err != nil {
			return "", false, errConfigValueType
		}
		parsed, parseErr := strconv.ParseInt(number.String(), 10, 64)
		if parseErr != nil {
			return "", false, errConfigValueType
		}
		if parsed < f.minInt || parsed > f.maxInt {
			return "", false, fmt.Errorf("%w: must be between %d and %d", errConfigValueRange, f.minInt, f.maxInt)
		}
		return strconv.FormatInt(parsed, 10), false, nil
	case configKindString:
		var parsed string
		if err = decodeStrictJSON(raw, &parsed); err != nil {
			return "", false, errConfigValueType
		}
		parsed = strings.TrimSpace(parsed)
		if strings.ContainsAny(parsed, configForbiddenCharacters) {
			return "", false, errConfigValueSyntax
		}
		if len(parsed) > f.maxBytes {
			return "", false, fmt.Errorf("%w: at most %d bytes", errConfigValueRange, f.maxBytes)
		}
		return parsed, parsed == "", nil
	case configKindEnum:
		var parsed string
		if err = decodeStrictJSON(raw, &parsed); err != nil {
			return "", false, errConfigValueType
		}
		if !contains(f.options, parsed) {
			return "", false, fmt.Errorf("%w: %s", errConfigValueOption, strings.Join(f.options, ", "))
		}
		return parsed, false, nil
	case configKindList:
		var items []string
		if err = decodeStrictJSON(raw, &items); err != nil {
			return "", false, errConfigValueType
		}
		cleaned := make([]string, 0, len(items))
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if strings.ContainsAny(item, configForbiddenCharacters+",") {
				return "", false, errConfigValueSyntax
			}
			cleaned = append(cleaned, item)
		}
		if len(cleaned) > f.maxItems {
			return "", false, fmt.Errorf("%w: at most %d items", errConfigValueRange, f.maxItems)
		}
		return strings.Join(cleaned, ","), false, nil
	case configKindDuration:
		var text string
		if err = decodeStrictJSON(raw, &text); err != nil {
			return "", false, errConfigValueType
		}
		parsed, parseErr := time.ParseDuration(strings.TrimSpace(text))
		if parseErr != nil {
			return "", false, errConfigValueType
		}
		if parsed < f.minDuration || parsed > f.maxDuration {
			return "", false, fmt.Errorf("%w: must be between %s and %s", errConfigValueRange, compactDuration(f.minDuration), compactDuration(f.maxDuration))
		}
		return compactDuration(parsed), false, nil
	}
	return "", false, errConfigValueType
}

// configValuesEqual compares two values produced by configField.get.
func configValuesEqual(left, right any) bool {
	leftList, leftIsList := left.([]string)
	rightList, rightIsList := right.([]string)
	if leftIsList || rightIsList {
		if len(leftList) != len(rightList) {
			return false
		}
		for index := range leftList {
			if leftList[index] != rightList[index] {
				return false
			}
		}
		return true
	}
	return left == right
}

func decodeStrictJSON(raw json.RawMessage, target any) error {
	raw = trimJSON(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return errConfigValueType
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode(target)
}

func trimJSON(raw json.RawMessage) json.RawMessage {
	return bytes.TrimSpace(raw)
}

func compactDuration(duration time.Duration) string {
	switch {
	case duration == 0:
		return "0s"
	case duration%time.Hour == 0:
		return strconv.FormatInt(int64(duration/time.Hour), 10) + "h"
	case duration%time.Minute == 0:
		return strconv.FormatInt(int64(duration/time.Minute), 10) + "m"
	case duration%time.Second == 0:
		return strconv.FormatInt(int64(duration/time.Second), 10) + "s"
	}
	return duration.String()
}

func listValue(values []string) []string {
	return append([]string{}, values...)
}

func boolField(key, group, label, description string, get func(state.ConfigurationOperating) bool, requires ...string) configField {
	return configField{
		key: key, group: group, label: label, description: description, kind: configKindBool,
		requires: requires, get: func(config state.ConfigurationOperating) any { return get(config) },
	}
}

func intField(key, group, label, description, unit string, minimum, maximum int64, get func(state.ConfigurationOperating) int) configField {
	return configField{
		key: key, group: group, label: label, description: description, kind: configKindInt,
		minInt: minimum, maxInt: maximum, unit: unit,
		get: func(config state.ConfigurationOperating) any { return int64(get(config)) },
	}
}

func portField(key, label, description string, get func(state.ConfigurationOperating) uint16) configField {
	return configField{
		key: key, group: configGroupServices, label: label, description: description, kind: configKindInt,
		minInt: 1, maxInt: maxListenPort, unit: "port",
		get: func(config state.ConfigurationOperating) any { return int64(get(config)) },
	}
}

func durationField(key, group, label, description string, minimum, maximum time.Duration, get func(state.ConfigurationOperating) time.Duration) configField {
	return configField{
		key: key, group: group, label: label, description: description, kind: configKindDuration,
		minDuration: minimum, maxDuration: maximum,
		get: func(config state.ConfigurationOperating) any { return compactDuration(get(config)) },
	}
}

func listField(key, group, label, description string, maxItems int, get func(state.ConfigurationOperating) []string, requires ...string) configField {
	return configField{
		key: key, group: group, label: label, description: description, kind: configKindList,
		maxItems: maxItems, requires: requires,
		get: func(config state.ConfigurationOperating) any { return listValue(get(config)) },
	}
}

func enumField(key, group, label, description string, live bool, options []string, get func(state.ConfigurationOperating) string) configField {
	return configField{
		key: key, group: group, label: label, description: description, kind: configKindEnum,
		options: options, live: live,
		get: func(config state.ConfigurationOperating) any { return get(config) },
	}
}

// configFields is the editable configuration schema in display order. Paths,
// state limits, bearer tokens, listen hosts, identity type, router version,
// and network ID are intentionally absent.
var configFields = []configField{
	boolField("tunnel.enabled", configGroupFeatures, "Tunnels", "Build exploratory and client tunnels; SAM and the proxies need them.",
		func(c state.ConfigurationOperating) bool { return c.Tunnel.Enabled }),
	boolField("router.transit", configGroupFeatures, "Transit routing", "Relay tunnel traffic for other routers.",
		func(c state.ConfigurationOperating) bool { return c.Router.Transit }),
	boolField("router.floodfill", configGroupFeatures, "Floodfill", "Store and serve NetDB entries for the network as a floodfill router.",
		func(c state.ConfigurationOperating) bool { return c.Router.Floodfill }),
	boolField("ntcp2.enabled", configGroupFeatures, "NTCP2 transport", "Accept and open TCP sessions with the NTCP2 transport; NTCP2 or SSU2 must stay enabled.",
		func(c state.ConfigurationOperating) bool { return c.NTCP2.Enabled }),
	boolField("ssu2.enabled", configGroupFeatures, "SSU2 transport", "Accept and open UDP sessions with the SSU2 transport; NTCP2 or SSU2 must stay enabled.",
		func(c state.ConfigurationOperating) bool { return c.SSU2.Enabled }),
	boolField("network.ipv4", configGroupFeatures, "IPv4", "Use IPv4 addresses for transports; IPv4 or IPv6 must stay enabled.",
		func(c state.ConfigurationOperating) bool { return c.Network.IPv4 }),
	boolField("network.ipv6", configGroupFeatures, "IPv6", "Use IPv6 addresses for transports; IPv4 or IPv6 must stay enabled.",
		func(c state.ConfigurationOperating) bool { return c.Network.IPv6 }),
	boolField("reseed.enabled", configGroupFeatures, "Reseed", "Download signed RouterInfo bundles from reseed servers when the NetDB is sparse; disabling it requires an empty endpoint list.",
		func(c state.ConfigurationOperating) bool { return c.Reseed.Enabled }),
	boolField("reseed.required", configGroupFeatures, "Require reseed", "Fail startup when no reseed attempt succeeds.",
		func(c state.ConfigurationOperating) bool { return c.Reseed.Required }, "reseed.enabled"),
	boolField("http_proxy.enabled", configGroupFeatures, "HTTP proxy", "Serve the local HTTP proxy for I2P sites and outproxies.",
		func(c state.ConfigurationOperating) bool { return c.HTTPProxy.Enabled }),
	boolField("socks5.enabled", configGroupFeatures, "SOCKS5 proxy", "Serve the local SOCKS5 proxy for I2P destinations.",
		func(c state.ConfigurationOperating) bool { return c.SOCKS5.Enabled }),
	boolField("sam.enabled", configGroupFeatures, "SAM bridge", "Serve the SAM v3 application bridge.",
		func(c state.ConfigurationOperating) bool { return c.SAM.Enabled }),
	boolField("control.enabled", configGroupFeatures, "Control API", "Serve the authenticated control API; the file must define control.bearer_token.",
		func(c state.ConfigurationOperating) bool { return c.Control.Enabled }),
	boolField("metrics.enabled", configGroupFeatures, "Metrics endpoint", "Serve Prometheus metrics and health probes on a separate listener.",
		func(c state.ConfigurationOperating) bool { return c.Metrics.Enabled }),
	boolField("addressbook.enabled", configGroupFeatures, "Address book", "Resolve .i2p host names and refresh subscription feeds.",
		func(c state.ConfigurationOperating) bool { return c.AddressBook.Enabled }),

	{
		key: "router.family", group: configGroupRouter, label: "Router family", kind: configKindString, maxBytes: maxRouterFamilyBytes,
		description: "Family name published in RouterInfo; leave empty to publish none.",
		get:         func(c state.ConfigurationOperating) any { return c.Router.Family },
	},

	intField("tunnel.hops", configGroupTunnels, "Hops per tunnel", "Number of routers in each locally built tunnel.", "hops", 1, 7,
		func(c state.ConfigurationOperating) int { return c.Tunnel.Hops }),
	intField("tunnel.exploratory_inbound_target", configGroupTunnels, "Exploratory inbound target", "Inbound exploratory tunnels kept ready; the pool capacity must be at least twice this value.", "tunnels", 1, 16,
		func(c state.ConfigurationOperating) int { return c.Tunnel.ExploratoryInboundTarget }),
	intField("tunnel.exploratory_outbound_target", configGroupTunnels, "Exploratory outbound target", "Outbound exploratory tunnels kept ready; the pool capacity must be at least twice this value.", "tunnels", 1, 16,
		func(c state.ConfigurationOperating) int { return c.Tunnel.ExploratoryOutboundTarget }),
	intField("tunnel.exploratory_pool_capacity", configGroupTunnels, "Exploratory pool capacity", "Maximum exploratory tunnels held, including replacements under construction.", "tunnels", 2, 64,
		func(c state.ConfigurationOperating) int { return c.Tunnel.ExploratoryPoolCapacity }),
	intField("tunnel.client_inbound_target", configGroupTunnels, "Client inbound target", "Inbound tunnels kept ready per local destination; the pool capacity must be at least twice this value.", "tunnels", 1, 16,
		func(c state.ConfigurationOperating) int { return c.Tunnel.ClientInboundTarget }),
	intField("tunnel.client_outbound_target", configGroupTunnels, "Client outbound target", "Outbound tunnels kept ready per local destination; the pool capacity must be at least twice this value.", "tunnels", 1, 16,
		func(c state.ConfigurationOperating) int { return c.Tunnel.ClientOutboundTarget }),
	intField("tunnel.client_pool_capacity", configGroupTunnels, "Client pool capacity", "Maximum tunnels held per local destination, including replacements under construction.", "tunnels", 2, 64,
		func(c state.ConfigurationOperating) int { return c.Tunnel.ClientPoolCapacity }),
	intField("tunnel.bandwidth_rate_bytes_per_second", configGroupTunnels, "Destination bandwidth rate", "Sustained outbound byte rate allowed per local destination.", "B/s", minTunnelBandwidthBytes, maxTunnelBandwidthBytes,
		func(c state.ConfigurationOperating) int { return c.Tunnel.BandwidthRateBytesPerSecond }),
	intField("tunnel.bandwidth_burst_bytes", configGroupTunnels, "Destination bandwidth burst", "Outbound bytes a local destination may send above its sustained rate.", "B", minTunnelBandwidthBytes, maxTunnelBandwidthBytes,
		func(c state.ConfigurationOperating) int { return c.Tunnel.BandwidthBurstBytes }),
	durationField("tunnel.lifetime", configGroupTunnels, "Tunnel lifetime", "Lifetime of each locally built tunnel; the I2P protocol fixes it at 10 minutes.", tunnelLifetime, tunnelLifetime,
		func(c state.ConfigurationOperating) time.Duration { return c.Tunnel.Lifetime }),
	durationField("tunnel.renew_before", configGroupTunnels, "Renew before expiry", "Time before expiry at which a replacement tunnel is built; it must be shorter than the lifetime.", time.Second, maxTunnelRenewBefore,
		func(c state.ConfigurationOperating) time.Duration { return c.Tunnel.RenewBefore }),

	intField("ntcp2.max_sessions", configGroupTransports, "NTCP2 session limit", "Maximum concurrent NTCP2 sessions.", "sessions", 1, maxSessions,
		func(c state.ConfigurationOperating) int { return c.NTCP2.MaxSessions }),
	durationField("ntcp2.idle_timeout", configGroupTransports, "NTCP2 idle timeout", "Idle time after which an NTCP2 session is closed.", time.Second, maxTransportIdleTimeout,
		func(c state.ConfigurationOperating) time.Duration { return c.NTCP2.IdleTimeout }),
	intField("ssu2.max_sessions", configGroupTransports, "SSU2 session limit", "Maximum concurrent SSU2 sessions.", "sessions", 1, maxSessions,
		func(c state.ConfigurationOperating) int { return c.SSU2.MaxSessions }),
	durationField("ssu2.idle_timeout", configGroupTransports, "SSU2 idle timeout", "Idle time after which an SSU2 session is closed.", time.Second, maxTransportIdleTimeout,
		func(c state.ConfigurationOperating) time.Duration { return c.SSU2.IdleTimeout }),

	portField("http_proxy.listen_port", "HTTP proxy port", "Loopback TCP port of the HTTP proxy.",
		func(c state.ConfigurationOperating) uint16 { return c.HTTPProxy.Address.Port }),
	listField("http_proxy.outproxies", configGroupServices, "Outproxies", "I2P host names that carry clearnet HTTP requests, tried in order.", maxOutproxyItems,
		func(c state.ConfigurationOperating) []string { return c.HTTPProxy.Outproxies }),
	portField("socks5.listen_port", "SOCKS5 proxy port", "Loopback TCP port of the SOCKS5 proxy.",
		func(c state.ConfigurationOperating) uint16 { return c.SOCKS5.Address.Port }),
	portField("sam.listen_port", "SAM port", "TCP port of the SAM bridge.",
		func(c state.ConfigurationOperating) uint16 { return c.SAM.Address.Port }),
	portField("control.listen_port", "Control API port", "TCP port of the control API.",
		func(c state.ConfigurationOperating) uint16 { return c.Control.Address.Port }),
	portField("metrics.listen_port", "Metrics port", "TCP port of the metrics endpoint.",
		func(c state.ConfigurationOperating) uint16 { return c.Metrics.Address.Port }),

	listField("reseed.endpoints", configGroupSources, "Reseed servers", "HTTPS SU3 reseed URLs ending in ?netid=2; the list must be empty when reseed is disabled.", maxReseedEndpointItems,
		func(c state.ConfigurationOperating) []string { return c.Reseed.Endpoints }, "reseed.enabled"),
	durationField("reseed.timeout", configGroupSources, "Reseed timeout", "Time limit for one reseed attempt.", time.Second, maxReseedTimeout,
		func(c state.ConfigurationOperating) time.Duration { return c.Reseed.Timeout }),
	listField("addressbook.subscriptions", configGroupSources, "Address book subscriptions", "hosts.txt feed URLs fetched on each refresh.", maxSubscriptionItems,
		func(c state.ConfigurationOperating) []string { return c.AddressBook.Subscriptions }),
	durationField("addressbook.refresh_interval", configGroupSources, "Subscription refresh interval", "Time between address book subscription refreshes.", time.Minute, maxAddressBookRefresh,
		func(c state.ConfigurationOperating) time.Duration { return c.AddressBook.RefreshInterval }),

	enumField("log.level", configGroupLogging, "Log level", "Minimum severity written to the log; applied immediately.", true,
		[]string{"debug", "info", "warn", "error"}, func(c state.ConfigurationOperating) string { return c.Log.Level }),
	enumField("log.format", configGroupLogging, "Log format", "Encoding of log records; applied when the ivnpd process starts.", false,
		[]string{"text", "json"}, func(c state.ConfigurationOperating) string { return c.Log.Format }),
}

func lookupConfigField(key string) (configField, bool) {
	for _, field := range configFields {
		if field.key == key {
			return field, true
		}
	}
	return configField{}, false
}
