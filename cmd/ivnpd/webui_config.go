package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"gosuda.org/ivnp"
)

type webUIConfigView struct {
	Network struct {
		ID   uint32 `json:"id"`
		IPv4 bool   `json:"ipv4"`
		IPv6 bool   `json:"ipv6"`
	} `json:"network"`
	Router struct {
		Floodfill bool   `json:"floodfill"`
		Family    string `json:"family"`
		Version   string `json:"version"`
	} `json:"router"`
	Tunnel struct {
		Enabled                   bool `json:"enabled"`
		Hops                      int  `json:"hops"`
		ExploratoryInboundTarget  int  `json:"exploratory_inbound_target"`
		ExploratoryOutboundTarget int  `json:"exploratory_outbound_target"`
		ExploratoryPoolCapacity   int  `json:"exploratory_pool_capacity"`
		ClientInboundTarget       int  `json:"client_inbound_target"`
		ClientOutboundTarget      int  `json:"client_outbound_target"`
		ClientPoolCapacity        int  `json:"client_pool_capacity"`
		BandwidthRateBPS          int  `json:"bandwidth_rate_bytes_per_second"`
		BandwidthBurstBytes       int  `json:"bandwidth_burst_bytes"`
	} `json:"tunnel"`
	NTCP2  transportConfigView `json:"ntcp2"`
	SSU2   transportConfigView `json:"ssu2"`
	Reseed struct {
		Enabled   bool     `json:"enabled"`
		Required  bool     `json:"required"`
		Endpoints []string `json:"endpoints"`
	} `json:"reseed"`
	AddressBook struct {
		Enabled              bool     `json:"enabled"`
		Subscriptions        []string `json:"subscriptions"`
		RefreshIntervalHours int      `json:"refresh_interval_hours"`
	} `json:"addressbook"`
	Services struct {
		HTTPProxyEnabled bool   `json:"http_proxy_enabled"`
		HTTPProxyAddress string `json:"http_proxy_address"`
		HTTPProxyPort    uint16 `json:"http_proxy_port"`
		SOCKS5Enabled    bool   `json:"socks5_enabled"`
		SOCKS5Address    string `json:"socks5_address"`
		SOCKS5Port       uint16 `json:"socks5_port"`
		SAMEnabled       bool   `json:"sam_enabled"`
		SAMAddress       string `json:"sam_address"`
		SAMPort          uint16 `json:"sam_port"`
		MetricsEnabled   bool   `json:"metrics_enabled"`
		MetricsAddress   string `json:"metrics_address"`
		MetricsPort      uint16 `json:"metrics_port"`
	} `json:"services"`
	Log struct {
		Level  string `json:"level"`
		Format string `json:"format"`
	} `json:"log"`
	RestartRequired bool `json:"restart_required"`
}

type transportConfigView struct {
	Enabled           bool   `json:"enabled"`
	BindAddress       string `json:"bind_address"`
	AdvertisedAddress string `json:"advertised_address"`
	MaxSessions       int    `json:"max_sessions"`
}

type webUIConfigUpdate struct {
	Router struct {
		Floodfill bool   `json:"floodfill"`
		Family    string `json:"family"`
	} `json:"router"`
	Tunnel struct {
		Enabled                   bool `json:"enabled"`
		Hops                      int  `json:"hops"`
		ExploratoryInboundTarget  int  `json:"exploratory_inbound_target"`
		ExploratoryOutboundTarget int  `json:"exploratory_outbound_target"`
		ExploratoryPoolCapacity   int  `json:"exploratory_pool_capacity"`
		ClientInboundTarget       int  `json:"client_inbound_target"`
		ClientOutboundTarget      int  `json:"client_outbound_target"`
		ClientPoolCapacity        int  `json:"client_pool_capacity"`
		BandwidthRateBPS          int  `json:"bandwidth_rate_bytes_per_second"`
		BandwidthBurstBytes       int  `json:"bandwidth_burst_bytes"`
	} `json:"tunnel"`
	NTCP2 struct {
		Enabled     bool `json:"enabled"`
		MaxSessions int  `json:"max_sessions"`
	} `json:"ntcp2"`
	SSU2 struct {
		Enabled     bool `json:"enabled"`
		MaxSessions int  `json:"max_sessions"`
	} `json:"ssu2"`
	Reseed struct {
		Enabled   bool     `json:"enabled"`
		Required  bool     `json:"required"`
		Endpoints []string `json:"endpoints"`
	} `json:"reseed"`
	AddressBook struct {
		Enabled              bool     `json:"enabled"`
		Subscriptions        []string `json:"subscriptions"`
		RefreshIntervalHours int      `json:"refresh_interval_hours"`
	} `json:"addressbook"`
	Services struct {
		HTTPProxyEnabled bool   `json:"http_proxy_enabled"`
		HTTPProxyPort    uint16 `json:"http_proxy_port"`
		SOCKS5Enabled    bool   `json:"socks5_enabled"`
		SOCKS5Port       uint16 `json:"socks5_port"`
		SAMEnabled       bool   `json:"sam_enabled"`
		SAMPort          uint16 `json:"sam_port"`
		MetricsEnabled   bool   `json:"metrics_enabled"`
		MetricsPort      uint16 `json:"metrics_port"`
	} `json:"services"`
	Log struct {
		Level string `json:"level"`
	} `json:"log"`
}

type configUpdateResult struct {
	Status          string   `json:"status"`
	Applied         []string `json:"applied"`
	RestartRequired []string `json:"restart_required"`
}

type iniUpdate struct {
	section string
	key     string
	value   string
	remove  bool
}

func (s *WebUIServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.configMu.RLock()
		config := cloneConfig(s.persistedConfig)
		s.configMu.RUnlock()
		writeJSONResponse(w, http.StatusOK, newWebUIConfigView(config, s.node.Config()))
	case http.MethodPost:
		s.updateConfig(w, r)
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

func (s *WebUIServer) updateConfig(w http.ResponseWriter, r *http.Request) {
	if s.config.ConfigPath == "" {
		writeAPIError(w, http.StatusConflict, "configuration path is unavailable")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	var request webUIConfigUpdate
	if err = decoder.Decode(&request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid configuration payload: "+err.Error())
		return
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeAPIError(w, http.StatusBadRequest, "configuration payload must contain one JSON value")
		return
	}

	s.configMu.RLock()
	previous := cloneConfig(s.persistedConfig)
	s.configMu.RUnlock()
	updates := configINIUpdates(request, previous)
	current, err := os.ReadFile(s.config.ConfigPath)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "cannot read configuration")
		return
	}
	nextText := updateINI(string(current), updates)
	nextConfig, err := ivnp.ParseConfig(nextText, s.config.ConfigPath)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	applied, restartRequired := changedConfigKeys(previous, nextConfig)
	if len(applied) == 0 && len(restartRequired) == 0 {
		writeJSONResponse(w, http.StatusOK, configUpdateResult{Status: "unchanged", Applied: []string{}, RestartRequired: []string{}})
		return
	}
	if err = writePrivateFileAtomic(s.config.ConfigPath, []byte(nextText)); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "cannot save configuration")
		return
	}

	s.configMu.Lock()
	s.persistedConfig = cloneConfig(nextConfig)
	s.configMu.Unlock()
	if contains(applied, "log.level") && s.logLevel != nil {
		setSlogLevel(s.logLevel, nextConfig.Log.Level)
	}
	writeJSONResponse(w, http.StatusOK, configUpdateResult{Status: "saved", Applied: applied, RestartRequired: restartRequired})
}

func newWebUIConfigView(config, runtime ivnp.Config) webUIConfigView {
	view := webUIConfigView{}
	view.Network.ID, view.Network.IPv4, view.Network.IPv6 = config.Network.ID, config.Network.IPv4, config.Network.IPv6
	view.Router.Floodfill, view.Router.Family, view.Router.Version = config.Router.Floodfill, config.Router.Family, config.Router.Version
	view.Tunnel.Enabled = config.Tunnel.Enabled
	view.Tunnel.Hops = config.Tunnel.Hops
	view.Tunnel.ExploratoryInboundTarget = config.Tunnel.ExploratoryInboundTarget
	view.Tunnel.ExploratoryOutboundTarget = config.Tunnel.ExploratoryOutboundTarget
	view.Tunnel.ExploratoryPoolCapacity = config.Tunnel.ExploratoryPoolCapacity
	view.Tunnel.ClientInboundTarget = config.Tunnel.ClientInboundTarget
	view.Tunnel.ClientOutboundTarget = config.Tunnel.ClientOutboundTarget
	view.Tunnel.ClientPoolCapacity = config.Tunnel.ClientPoolCapacity
	view.Tunnel.BandwidthRateBPS = config.Tunnel.BandwidthRateBytesPerSecond
	view.Tunnel.BandwidthBurstBytes = config.Tunnel.BandwidthBurstBytes
	view.NTCP2 = transportConfigView{Enabled: config.NTCP2.Enabled, BindAddress: endpointString(config.NTCP2.Bind), AdvertisedAddress: endpointString(config.NTCP2.Advertised), MaxSessions: config.NTCP2.MaxSessions}
	view.SSU2 = transportConfigView{Enabled: config.SSU2.Enabled, BindAddress: endpointString(config.SSU2.Bind), AdvertisedAddress: endpointString(config.SSU2.Advertised), MaxSessions: config.SSU2.MaxSessions}
	view.Reseed.Enabled, view.Reseed.Required = config.Reseed.Enabled, config.Reseed.Required
	view.Reseed.Endpoints = append([]string{}, config.Reseed.Endpoints...)
	view.AddressBook.Enabled = config.AddressBook.Enabled
	view.AddressBook.Subscriptions = append([]string{}, config.AddressBook.Subscriptions...)
	view.AddressBook.RefreshIntervalHours = int(config.AddressBook.RefreshInterval / time.Hour)
	view.Services.HTTPProxyEnabled, view.Services.HTTPProxyAddress, view.Services.HTTPProxyPort = config.HTTPProxy.Enabled, config.HTTPProxy.Address.Host, config.HTTPProxy.Address.Port
	view.Services.SOCKS5Enabled, view.Services.SOCKS5Address, view.Services.SOCKS5Port = config.SOCKS5.Enabled, config.SOCKS5.Address.Host, config.SOCKS5.Address.Port
	view.Services.SAMEnabled, view.Services.SAMAddress, view.Services.SAMPort = config.SAM.Enabled, config.SAM.Address.Host, config.SAM.Address.Port
	view.Services.MetricsEnabled, view.Services.MetricsAddress, view.Services.MetricsPort = config.Metrics.Enabled, config.Metrics.Address.Host, config.Metrics.Address.Port
	view.Log.Level, view.Log.Format = config.Log.Level, config.Log.Format
	view.RestartRequired = configRequiresRestart(config, runtime)
	return view
}

func configINIUpdates(request webUIConfigUpdate, current ivnp.Config) []iniUpdate {
	boolean := strconv.FormatBool
	integer := strconv.Itoa
	return []iniUpdate{
		{section: "router", key: "floodfill", value: boolean(request.Router.Floodfill)},
		{section: "router", key: "family", value: strings.TrimSpace(request.Router.Family), remove: strings.TrimSpace(request.Router.Family) == ""},
		{section: "tunnel", key: "enabled", value: boolean(request.Tunnel.Enabled)},
		{section: "tunnel", key: "hops", value: integer(request.Tunnel.Hops)},
		{section: "tunnel", key: "exploratory_inbound_target", value: integer(request.Tunnel.ExploratoryInboundTarget)},
		{section: "tunnel", key: "exploratory_outbound_target", value: integer(request.Tunnel.ExploratoryOutboundTarget)},
		{section: "tunnel", key: "exploratory_pool_capacity", value: integer(request.Tunnel.ExploratoryPoolCapacity)},
		{section: "tunnel", key: "client_inbound_target", value: integer(request.Tunnel.ClientInboundTarget)},
		{section: "tunnel", key: "client_outbound_target", value: integer(request.Tunnel.ClientOutboundTarget)},
		{section: "tunnel", key: "client_pool_capacity", value: integer(request.Tunnel.ClientPoolCapacity)},
		{section: "tunnel", key: "bandwidth_rate_bytes_per_second", value: integer(request.Tunnel.BandwidthRateBPS)},
		{section: "tunnel", key: "bandwidth_burst_bytes", value: integer(request.Tunnel.BandwidthBurstBytes)},
		{section: "ntcp2", key: "enabled", value: boolean(request.NTCP2.Enabled)},
		{section: "ntcp2", key: "max_sessions", value: integer(request.NTCP2.MaxSessions)},
		{section: "ssu2", key: "enabled", value: boolean(request.SSU2.Enabled)},
		{section: "ssu2", key: "max_sessions", value: integer(request.SSU2.MaxSessions)},
		{section: "reseed", key: "enabled", value: boolean(request.Reseed.Enabled)},
		{section: "reseed", key: "required", value: boolean(request.Reseed.Required)},
		{section: "reseed", key: "endpoints", value: strings.Join(request.Reseed.Endpoints, ",")},
		{section: "addressbook", key: "enabled", value: boolean(request.AddressBook.Enabled)},
		{section: "addressbook", key: "subscriptions", value: strings.Join(request.AddressBook.Subscriptions, ",")},
		{section: "addressbook", key: "refresh_interval", value: fmt.Sprintf("%dh", request.AddressBook.RefreshIntervalHours)},
		{section: "http_proxy", key: "enabled", value: boolean(request.Services.HTTPProxyEnabled)},
		{section: "http_proxy", key: "listen_host", value: current.HTTPProxy.Address.Host},
		{section: "http_proxy", key: "listen_port", value: integer(int(request.Services.HTTPProxyPort))},
		{section: "socks5", key: "enabled", value: boolean(request.Services.SOCKS5Enabled)},
		{section: "socks5", key: "listen_host", value: current.SOCKS5.Address.Host},
		{section: "socks5", key: "listen_port", value: integer(int(request.Services.SOCKS5Port))},
		{section: "sam", key: "enabled", value: boolean(request.Services.SAMEnabled)},
		{section: "sam", key: "listen_host", value: current.SAM.Address.Host},
		{section: "sam", key: "listen_port", value: integer(int(request.Services.SAMPort))},
		{section: "metrics", key: "enabled", value: boolean(request.Services.MetricsEnabled)},
		{section: "metrics", key: "listen_host", value: current.Metrics.Address.Host},
		{section: "metrics", key: "listen_port", value: integer(int(request.Services.MetricsPort))},
		{section: "log", key: "level", value: strings.ToLower(request.Log.Level)},
	}
}

func updateINI(text string, updates []iniUpdate) string {
	bySection := make(map[string][]iniUpdate)
	sectionOrder := make([]string, 0)
	for _, update := range updates {
		if _, exists := bySection[update.section]; !exists {
			sectionOrder = append(sectionOrder, update.section)
		}
		bySection[update.section] = append(bySection[update.section], update)
	}
	seenSections := make(map[string]bool)
	seenKeys := make(map[string]bool)
	lines := strings.Split(strings.TrimRight(text, "\r\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	output := make([]string, 0, len(lines)+len(updates)+len(sectionOrder))
	currentSection := ""
	for _, line := range lines {
		if section, ok := iniSection(line); ok {
			output = appendMissingINI(output, currentSection, bySection, seenKeys)
			currentSection = section
			seenSections[currentSection] = true
			output = append(output, line)
			continue
		}
		replacement, replaced := applyINIUpdate(line, currentSection, bySection[currentSection], seenKeys)
		if replaced {
			if replacement != "" {
				output = append(output, replacement)
			}
			continue
		}
		output = append(output, line)
	}
	output = appendMissingINI(output, currentSection, bySection, seenKeys)
	for _, section := range sectionOrder {
		if seenSections[section] {
			continue
		}
		if len(output) > 0 && output[len(output)-1] != "" {
			output = append(output, "")
		}
		output = append(output, "["+section+"]")
		output = appendMissingINI(output, section, bySection, seenKeys)
	}
	return strings.Join(output, "\n") + "\n"
}

func iniSection(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]")), true
}

func appendMissingINI(output []string, section string, bySection map[string][]iniUpdate, seenKeys map[string]bool) []string {
	for _, update := range bySection[section] {
		identity := section + "\x00" + update.key
		if seenKeys[identity] || update.remove {
			continue
		}
		output = append(output, update.key+" = "+update.value)
		seenKeys[identity] = true
	}
	return output
}

func applyINIUpdate(line, section string, updates []iniUpdate, seenKeys map[string]bool) (string, bool) {
	key, _, assignment := strings.Cut(strings.TrimSpace(line), "=")
	if !assignment {
		return "", false
	}
	key = strings.TrimSpace(key)
	for _, update := range updates {
		if key != update.key {
			continue
		}
		seenKeys[section+"\x00"+update.key] = true
		if update.remove {
			return "", true
		}
		return update.key + " = " + update.value, true
	}
	return "", false
}

func changedConfigKeys(previous, next ivnp.Config) (applied, restartRequired []string) {
	applied = []string{}
	restartRequired = []string{}
	if previous.Log.Level != next.Log.Level {
		applied = append(applied, "log.level")
	}
	previous.Log.Level = next.Log.Level
	if reflect.DeepEqual(previous, next) {
		return applied, restartRequired
	}
	before, after := configComparableValues(previous), configComparableValues(next)
	for key, nextValue := range after {
		if before[key] != nextValue {
			restartRequired = append(restartRequired, key)
		}
	}
	sort.Strings(restartRequired)
	return applied, restartRequired
}

func configComparableValues(config ivnp.Config) map[string]string {
	view := newWebUIConfigView(config, config)
	updates := configINIUpdates(webUIConfigUpdateFromView(view), config)
	values := make(map[string]string, len(updates))
	for _, update := range updates {
		if update.section == "log" && update.key == "level" {
			continue
		}
		values[update.section+"."+update.key] = update.value
	}
	return values
}

func webUIConfigUpdateFromView(view webUIConfigView) webUIConfigUpdate {
	var update webUIConfigUpdate
	update.Router.Floodfill, update.Router.Family = view.Router.Floodfill, view.Router.Family
	update.Tunnel.Enabled = view.Tunnel.Enabled
	update.Tunnel.Hops = view.Tunnel.Hops
	update.Tunnel.ExploratoryInboundTarget = view.Tunnel.ExploratoryInboundTarget
	update.Tunnel.ExploratoryOutboundTarget = view.Tunnel.ExploratoryOutboundTarget
	update.Tunnel.ExploratoryPoolCapacity = view.Tunnel.ExploratoryPoolCapacity
	update.Tunnel.ClientInboundTarget = view.Tunnel.ClientInboundTarget
	update.Tunnel.ClientOutboundTarget = view.Tunnel.ClientOutboundTarget
	update.Tunnel.ClientPoolCapacity = view.Tunnel.ClientPoolCapacity
	update.Tunnel.BandwidthRateBPS = view.Tunnel.BandwidthRateBPS
	update.Tunnel.BandwidthBurstBytes = view.Tunnel.BandwidthBurstBytes
	update.NTCP2.Enabled, update.NTCP2.MaxSessions = view.NTCP2.Enabled, view.NTCP2.MaxSessions
	update.SSU2.Enabled, update.SSU2.MaxSessions = view.SSU2.Enabled, view.SSU2.MaxSessions
	update.Reseed.Enabled, update.Reseed.Required = view.Reseed.Enabled, view.Reseed.Required
	update.Reseed.Endpoints = append([]string(nil), view.Reseed.Endpoints...)
	update.AddressBook.Enabled = view.AddressBook.Enabled
	update.AddressBook.Subscriptions = append([]string(nil), view.AddressBook.Subscriptions...)
	update.AddressBook.RefreshIntervalHours = view.AddressBook.RefreshIntervalHours
	update.Services.HTTPProxyEnabled, update.Services.HTTPProxyPort = view.Services.HTTPProxyEnabled, view.Services.HTTPProxyPort
	update.Services.SOCKS5Enabled, update.Services.SOCKS5Port = view.Services.SOCKS5Enabled, view.Services.SOCKS5Port
	update.Services.SAMEnabled, update.Services.SAMPort = view.Services.SAMEnabled, view.Services.SAMPort
	update.Services.MetricsEnabled, update.Services.MetricsPort = view.Services.MetricsEnabled, view.Services.MetricsPort
	update.Log.Level = view.Log.Level
	return update
}

func configRequiresRestart(config, runtime ivnp.Config) bool {
	config.Log.Level = runtime.Log.Level
	return !reflect.DeepEqual(config, runtime)
}

func cloneConfig(config ivnp.Config) ivnp.Config {
	config.NetDB.BootstrapRouterInfoPaths = append([]string(nil), config.NetDB.BootstrapRouterInfoPaths...)
	config.Reseed.Endpoints = append([]string(nil), config.Reseed.Endpoints...)
	config.AddressBook.Subscriptions = append([]string(nil), config.AddressBook.Subscriptions...)
	return config
}

func writePrivateFileAtomic(path string, content []byte) (result error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(absolute), ".ivnp-config-*")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if temporary != nil {
			result = errors.Join(result, temporary.Close())
		}
		if temporaryPath != "" {
			if removeErr := os.Remove(temporaryPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				result = errors.Join(result, removeErr)
			}
		}
	}()
	if err = temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set temporary config permissions: %w", err)
	}
	if _, err = temporary.Write(content); err != nil {
		return fmt.Errorf("write temporary config: %w", err)
	}
	if err = temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary config: %w", err)
	}
	if err = temporary.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	temporary = nil
	if err = os.Rename(temporaryPath, absolute); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	temporaryPath = ""
	directory, err := os.Open(filepath.Dir(absolute))
	if err != nil {
		return fmt.Errorf("open config directory: %w", err)
	}
	defer func() { result = errors.Join(result, directory.Close()) }()
	if err = directory.Sync(); err != nil {
		return fmt.Errorf("sync config directory: %w", err)
	}
	return nil
}

func setSlogLevel(level *slog.LevelVar, value string) {
	switch value {
	case "debug":
		level.Set(slog.LevelDebug)
	case "warn":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	default:
		level.Set(slog.LevelInfo)
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
