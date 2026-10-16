package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gosuda.org/ivnp/state"
)

const (
	configRemoteWriteReason   = "configuration writes are limited to loopback clients; start ivnpd with -webui-remote-write to allow remote changes"
	configMemoryModeReason    = "configuration file is unavailable in memory mode"
	configPathUnavailable     = "configuration path is unavailable"
	configChangedOnDisk       = "configuration changed on disk"
	configBackupMissing       = "no configuration backup"
	configBackupSuffix        = ".bak"
	configRequestBodyLimit    = 64 << 10
	configStatusSaved         = "saved"
	configStatusUnchanged     = "unchanged"
	configUnknownKeyMessage   = "unknown or non-editable configuration key"
	configInvalidPayloadError = "invalid configuration payload"
)

type configFieldView struct {
	Key         string   `json:"key"`
	Group       string   `json:"group"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Value       any      `json:"value"`
	Running     any      `json:"running"`
	Min         any      `json:"min"`
	Max         any      `json:"max"`
	Options     []string `json:"options"`
	Unit        string   `json:"unit"`
	Apply       string   `json:"apply"`
	Requires    []string `json:"requires"`
	Pending     bool     `json:"pending"`
}

type configView struct {
	Revision           string            `json:"revision"`
	Writable           bool              `json:"writable"`
	WriteBlockedReason string            `json:"write_blocked_reason"`
	RestartRequired    bool              `json:"restart_required"`
	BackupAvailable    bool              `json:"backup_available"`
	FileError          string            `json:"file_error"`
	Fields             []configFieldView `json:"fields"`
}

type configPatchRequest struct {
	Revision string                     `json:"revision"`
	Changes  map[string]json.RawMessage `json:"changes"`
}

type configRollbackRequest struct {
	Revision string `json:"revision"`
}

type configUpdateResult struct {
	Status          string   `json:"status"`
	Revision        string   `json:"revision"`
	Applied         []string `json:"applied"`
	RestartRequired []string `json:"restart_required"`
}

type configErrorResponse struct {
	Error string `json:"error"`
	Key   string `json:"key"`
}

type configConflictResponse struct {
	Error    string `json:"error"`
	Revision string `json:"revision"`
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
		s.getConfig(w, r)
	case http.MethodPatch:
		s.withNode(s.patchConfig)(w, r)
	default:
		methodNotAllowed(w, "GET, PATCH")
	}
}

// remoteWriteAllowed applies the write policy: loopback clients may always
// write; other clients require -webui-remote-write.
func (s *WebUIServer) remoteWriteAllowed(r *http.Request) bool {
	return s.config.AllowRemoteWrite || remoteIsLoopback(r.RemoteAddr)
}

// configWriteBlockedReason explains why the requesting client cannot write
// the configuration, or returns an empty string when it can.
func (s *WebUIServer) configWriteBlockedReason(r *http.Request) string {
	if s.config.ConfigPath == "" {
		return configMemoryModeReason
	}
	if !s.remoteWriteAllowed(r) {
		return configRemoteWriteReason
	}
	return ""
}

func configRevision(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func (s *WebUIServer) configBackupPath() string {
	return s.config.ConfigPath + configBackupSuffix
}

func (s *WebUIServer) effectiveConfig(config state.ConfigurationOperating) state.ConfigurationOperating {
	if s.config.ConfigOverrides != nil {
		s.config.ConfigOverrides(&config)
	}
	return config
}

func (s *WebUIServer) getConfig(w http.ResponseWriter, r *http.Request) {
	view := configView{Fields: []configFieldView{}}
	view.WriteBlockedReason = s.configWriteBlockedReason(r)
	view.Writable = view.WriteBlockedReason == ""

	var fileConfig *state.ConfigurationOperating
	if s.config.ConfigPath != "" {
		s.configMu.Lock()
		content, readErr := os.ReadFile(s.config.ConfigPath)
		_, backupErr := os.Stat(s.configBackupPath())
		s.configMu.Unlock()
		view.BackupAvailable = backupErr == nil
		if readErr != nil {
			view.FileError = "cannot read configuration file: " + readErr.Error()
		} else {
			view.Revision = configRevision(content)
			parsed, parseErr := state.ConfigurationParseOperating(string(content), s.config.ConfigPath)
			if parseErr != nil {
				view.FileError = parseErr.Error()
			} else {
				fileConfig = &parsed
			}
		}
	}
	var running *state.ConfigurationOperating
	if current := s.currentNode(); current != nil {
		config := current.Config()
		running = &config
	}
	var effective *state.ConfigurationOperating
	if fileConfig != nil {
		config := s.effectiveConfig(*fileConfig)
		effective = &config
	}
	view.Fields = configFieldViews(fileConfig, running, effective)
	for _, field := range view.Fields {
		view.RestartRequired = view.RestartRequired || field.Pending
	}
	writeJSONResponse(w, http.StatusOK, view)
}

// configFieldViews renders the schema. value comes from fileConfig, falling
// back to running when the file is unavailable; pending compares the file
// configuration with command-line overrides applied against running.
func configFieldViews(fileConfig, running, effective *state.ConfigurationOperating) []configFieldView {
	views := make([]configFieldView, 0, len(configFields))
	for _, field := range configFields {
		minimum, maximum, options := field.bounds()
		view := configFieldView{
			Key: field.key, Group: field.group, Label: field.label, Description: field.description,
			Type: field.kind, Min: minimum, Max: maximum, Options: options, Unit: field.unit,
			Apply: field.apply(), Requires: append([]string{}, field.requires...),
		}
		if running != nil {
			view.Running = field.get(*running)
		}
		switch {
		case fileConfig != nil:
			view.Value = field.get(*fileConfig)
		case running != nil:
			view.Value = view.Running
		}
		if !field.live && effective != nil && running != nil {
			view.Pending = !configValuesEqual(field.get(*effective), view.Running)
		}
		views = append(views, view)
	}
	return views
}

// decodeConfigRequest reads one JSON object with no unknown fields.
func decodeConfigRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, configRequestBodyLimit))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, configErrorResponse{Error: configInvalidPayloadError + ": " + err.Error()})
		return false
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeJSONResponse(w, http.StatusBadRequest, configErrorResponse{Error: "configuration payload must contain one JSON value"})
		return false
	}
	return true
}

// authorizeConfigWrite applies the write policy and memory-mode rule shared by
// PATCH and rollback.
func (s *WebUIServer) authorizeConfigWrite(w http.ResponseWriter, r *http.Request) bool {
	if !s.remoteWriteAllowed(r) {
		writeAPIError(w, http.StatusForbidden, configRemoteWriteReason)
		return false
	}
	if s.config.ConfigPath == "" {
		writeAPIError(w, http.StatusConflict, configPathUnavailable)
		return false
	}
	return true
}

// readConfigForWrite reads the configuration file and verifies the client
// revision. The caller must hold configMu.
func (s *WebUIServer) readConfigForWrite(w http.ResponseWriter, revision string) ([]byte, bool) {
	content, err := os.ReadFile(s.config.ConfigPath)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "cannot read configuration")
		return nil, false
	}
	if current := configRevision(content); current != revision {
		writeJSONResponse(w, http.StatusConflict, configConflictResponse{Error: configChangedOnDisk, Revision: current})
		return nil, false
	}
	return content, true
}

func (s *WebUIServer) patchConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeConfigWrite(w, r) {
		return
	}
	var request configPatchRequest
	if !decodeConfigRequest(w, r, &request) {
		return
	}
	for key := range request.Changes {
		if _, ok := lookupConfigField(key); !ok {
			writeJSONResponse(w, http.StatusBadRequest, configErrorResponse{Error: configUnknownKeyMessage, Key: key})
			return
		}
	}

	s.configMu.Lock()
	defer s.configMu.Unlock()
	current, ok := s.readConfigForWrite(w, request.Revision)
	if !ok {
		return
	}
	previous, previousErr := state.ConfigurationParseOperating(string(current), s.config.ConfigPath)
	updates := make([]iniUpdate, 0, len(request.Changes)+1)
	for _, field := range configFields {
		raw, requested := request.Changes[field.key]
		if !requested {
			continue
		}
		value, remove, err := field.encode(raw)
		if err != nil {
			writeJSONResponse(w, http.StatusBadRequest, configErrorResponse{Error: err.Error(), Key: field.key})
			return
		}
		updates = append(updates, iniUpdate{section: field.section(), key: field.name(), value: value, remove: remove})
		// listen_port is valid only beside listen_host; pin the host already in effect.
		if field.name() == "listen_port" && !iniHasKey(string(current), field.section(), "listen_host") {
			base := previous
			if previousErr != nil {
				base = state.ConfigurationDefaultOperating()
			}
			updates = append(updates, iniUpdate{section: field.section(), key: "listen_host", value: listenHost(base, field.section())})
		}
	}
	nextText := updateINI(string(current), updates)
	next, err := state.ConfigurationParseOperating(nextText, s.config.ConfigPath)
	if err != nil {
		s.recordAction(actionConfig, err, "")
		writeJSONResponse(w, http.StatusBadRequest, configErrorResponse{Error: err.Error(), Key: configValidationKey(err)})
		return
	}
	var previousConfig *state.ConfigurationOperating
	if previousErr == nil {
		previousConfig = &previous
	}
	applied, restartRequired := changedConfigKeys(previousConfig, next, request.Changes)
	s.commitConfig(w, r, actionConfig, current, []byte(nextText), next, applied, restartRequired)
}

func (s *WebUIServer) handleConfigRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !s.authorizeConfigWrite(w, r) {
		return
	}
	var request configRollbackRequest
	if !decodeConfigRequest(w, r, &request) {
		return
	}

	s.configMu.Lock()
	defer s.configMu.Unlock()
	current, ok := s.readConfigForWrite(w, request.Revision)
	if !ok {
		return
	}
	backup, err := os.ReadFile(s.configBackupPath())
	if errors.Is(err, os.ErrNotExist) {
		writeAPIError(w, http.StatusNotFound, configBackupMissing)
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "cannot read configuration backup")
		return
	}
	restored, err := state.ConfigurationParseOperating(string(backup), s.config.ConfigPath)
	if err != nil {
		s.recordAction(actionRollback, err, "")
		writeJSONResponse(w, http.StatusBadRequest, configErrorResponse{Error: "configuration backup is invalid: " + err.Error(), Key: configValidationKey(err)})
		return
	}
	var previousConfig *state.ConfigurationOperating
	if previous, previousErr := state.ConfigurationParseOperating(string(current), s.config.ConfigPath); previousErr == nil {
		previousConfig = &previous
	}
	applied, restartRequired := changedConfigKeys(previousConfig, restored, nil)
	s.commitConfig(w, r, actionRollback, current, backup, restored, applied, restartRequired)
}

// commitConfig writes the replaced bytes to the backup file, installs next,
// applies live settings, and writes the PATCH-shaped response. The caller
// must hold configMu.
func (s *WebUIServer) commitConfig(w http.ResponseWriter, r *http.Request, action string, current, next []byte, nextConfig state.ConfigurationOperating, applied, restartRequired []string) {
	if bytes.Equal(current, next) || len(applied)+len(restartRequired) == 0 {
		writeJSONResponse(w, http.StatusOK, configUpdateResult{
			Status: configStatusUnchanged, Revision: configRevision(current), Applied: []string{}, RestartRequired: []string{},
		})
		return
	}
	if err := writePrivateFileAtomic(s.configBackupPath(), current); err != nil {
		s.recordAction(action, err, "")
		writeAPIError(w, http.StatusInternalServerError, "cannot write configuration backup")
		return
	}
	if err := writePrivateFileAtomic(s.config.ConfigPath, next); err != nil {
		s.recordAction(action, err, "")
		writeAPIError(w, http.StatusInternalServerError, "cannot save configuration")
		return
	}
	if contains(applied, "log.level") && s.logLevel != nil {
		setSlogLevel(s.logLevel, s.effectiveConfig(nextConfig).Log.Level)
	}
	keys := append(append([]string{}, applied...), restartRequired...)
	message := "webui configuration saved"
	if action == actionRollback {
		message = "webui configuration rolled back"
	}
	s.logger.Info(message, "remote", r.RemoteAddr, "keys", keys)
	s.recordAction(action, nil, fmt.Sprintf("%s: %s", strings.TrimPrefix(message, "webui configuration "), strings.Join(keys, ", ")))
	writeJSONResponse(w, http.StatusOK, configUpdateResult{
		Status: configStatusSaved, Revision: configRevision(next), Applied: applied, RestartRequired: restartRequired,
	})
}

// changedConfigKeys lists schema keys whose value differs between previous
// and next, split by apply mode in schema order. When requested is non-nil
// only those keys are considered. An unparseable previous file treats every
// considered key as changed.
func changedConfigKeys(previous *state.ConfigurationOperating, next state.ConfigurationOperating, requested map[string]json.RawMessage) (applied, restartRequired []string) {
	applied, restartRequired = []string{}, []string{}
	for _, field := range configFields {
		if requested != nil {
			if _, ok := requested[field.key]; !ok {
				continue
			}
		}
		if previous != nil && configValuesEqual(field.get(*previous), field.get(next)) {
			continue
		}
		if field.live {
			applied = append(applied, field.key)
		} else {
			restartRequired = append(restartRequired, field.key)
		}
	}
	return applied, restartRequired
}

// configValidationKey maps a configuration validation error to the schema key
// it names, or returns an empty string when no editable key matches.
func configValidationKey(err error) string {
	if !errors.Is(err, state.ConfigurationErrInvalidOperating) {
		return ""
	}
	detail := strings.TrimPrefix(err.Error(), state.ConfigurationErrInvalidOperating.Error()+": ")
	if _, ok := lookupConfigField(detail); ok {
		return detail
	}
	section, name, _ := strings.Cut(detail, ".")
	candidates := map[string]string{
		"listen_endpoint": section + ".listen_port",
		"listen":          section + ".listen_port",
		"listen_host":     section + ".listen_port",
		"bearer_token":    section + ".enabled",
	}
	if candidate, ok := candidates[name]; ok {
		if _, known := lookupConfigField(candidate); known {
			return candidate
		}
	}
	return ""
}

func listenHost(config state.ConfigurationOperating, section string) string {
	switch section {
	case "http_proxy":
		return config.HTTPProxy.Address.Host
	case "socks5":
		return config.SOCKS5.Address.Host
	case "sam":
		return config.SAM.Address.Host
	case "control":
		return config.Control.Address.Host
	case "metrics":
		return config.Metrics.Address.Host
	}
	return ""
}

// iniHasKey reports whether text assigns key inside section.
func iniHasKey(text, section, key string) bool {
	currentSection := ""
	for line := range strings.SplitSeq(text, "\n") {
		if name, ok := iniSection(line); ok {
			currentSection = name
			continue
		}
		trimmed := strings.TrimSpace(line)
		if currentSection != section || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if name, _, assignment := strings.Cut(trimmed, "="); assignment && strings.TrimSpace(name) == key {
			return true
		}
	}
	return false
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
