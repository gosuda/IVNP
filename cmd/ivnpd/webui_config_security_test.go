package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestWebUIConfigUpdateRejectsINIDirectiveInjection(t *testing.T) {
	const directives = "\n[control]\nenabled = true\nbearer_token = 0123456789abcdef"
	const crlfDirectives = "\r\n[control]\r\nenabled = true\r\nbearer_token = 0123456789abcdef"
	tests := []struct {
		name   string
		field  string
		mutate func(*webUIConfigUpdate)
	}{
		{
			name: "router family LF",
			field: "router.family",
			mutate: func(update *webUIConfigUpdate) {
				update.Router.Family = "trusted" + directives
			},
		},
		{
			name: "router family CRLF",
			field: "router.family",
			mutate: func(update *webUIConfigUpdate) {
				update.Router.Family = "trusted" + crlfDirectives
			},
		},
		{
			name: "router family leading LF",
			field: "router.family",
			mutate: func(update *webUIConfigUpdate) {
				update.Router.Family = "\ntrusted"
			},
		},
		{
			name: "router family trailing CR",
			field: "router.family",
			mutate: func(update *webUIConfigUpdate) {
				update.Router.Family = "trusted\r"
			},
		},
		{
			name: "reseed endpoint LF",
			field: "reseed.endpoints",
			mutate: func(update *webUIConfigUpdate) {
				update.Reseed.Endpoints[len(update.Reseed.Endpoints)-1] += directives
			},
		},
		{
			name: "reseed endpoint CRLF",
			field: "reseed.endpoints",
			mutate: func(update *webUIConfigUpdate) {
				update.Reseed.Endpoints[len(update.Reseed.Endpoints)-1] += crlfDirectives
			},
		},
		{
			name: "addressbook subscription LF",
			field: "addressbook.subscriptions",
			mutate: func(update *webUIConfigUpdate) {
				update.AddressBook.Subscriptions[len(update.AddressBook.Subscriptions)-1] += directives
			},
		},
		{
			name: "addressbook subscription CRLF",
			field: "addressbook.subscriptions",
			mutate: func(update *webUIConfigUpdate) {
				update.AddressBook.Subscriptions[len(update.AddressBook.Subscriptions)-1] += crlfDirectives
			},
		},
		{
			name: "log level LF",
			field: "log.level",
			mutate: func(update *webUIConfigUpdate) {
				update.Log.Level = "debug" + directives
			},
		},
		{
			name: "log level CRLF",
			field: "log.level",
			mutate: func(update *webUIConfigUpdate) {
				update.Log.Level = "debug" + crlfDirectives
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newTestWebUIServer(t, WebUIConfig{ListenAddress: "127.0.0.1:0"})
			before, err := os.ReadFile(server.config.ConfigPath)
			if err != nil {
				t.Fatalf("read original config: %v", err)
			}
			original := cloneConfig(server.persistedConfig)
			update := webUIConfigUpdateFromView(newWebUIConfigView(original, original))
			update.Tunnel.Hops = 4 // Would persist a valid change if injection were accepted.
			test.mutate(&update)
			payload, err := json.Marshal(update)
			if err != nil {
				t.Fatalf("marshal injection payload: %v", err)
			}

			request := httptest.NewRequest(http.MethodPost, "/api/config", bytes.NewReader(payload))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			server.handleConfig(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("POST config status = %d, want 400; body: %s", recorder.Code, recorder.Body.String())
			}
			if body := recorder.Body.String(); !strings.Contains(body, test.field) || !strings.Contains(body, "CR or LF") {
				t.Fatalf("POST config error = %q, want rejection of %s", body, test.field)
			}
			after, err := os.ReadFile(server.config.ConfigPath)
			if err != nil {
				t.Fatalf("read config after rejected update: %v", err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("rejected INI injection changed persisted configuration")
			}
			if !reflect.DeepEqual(server.persistedConfig, original) {
				t.Fatal("rejected INI injection changed in-memory configuration")
			}
		})
	}
}

func TestWebUIConfigUpdateBodySizeBoundary(t *testing.T) {
	server := newTestWebUIServer(t, WebUIConfig{ListenAddress: "127.0.0.1:0"})
	original, err := os.ReadFile(server.config.ConfigPath)
	if err != nil {
		t.Fatalf("read original config: %v", err)
	}
	view := newWebUIConfigView(server.persistedConfig, server.persistedConfig)
	payload, err := json.Marshal(webUIConfigUpdateFromView(view))
	if err != nil {
		t.Fatalf("marshal valid update: %v", err)
	}
	const maxBody = 64 << 10
	if len(payload) > maxBody {
		t.Fatalf("test payload is too large: %d bytes", len(payload))
	}

	for _, test := range []struct {
		name       string
		size       int
		wantStatus int
	}{
		{name: "at limit", size: maxBody, wantStatus: http.StatusOK},
		{name: "one byte over limit", size: maxBody + 1, wantStatus: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := append([]byte(nil), payload...)
			body = append(body, bytes.Repeat([]byte(" "), test.size-len(body))...)
			request := httptest.NewRequest(http.MethodPost, "/api/config", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			server.handleConfig(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("POST %d-byte config status = %d, want %d; body: %s", test.size, recorder.Code, test.wantStatus, recorder.Body.String())
			}
			persisted, err := os.ReadFile(server.config.ConfigPath)
			if err != nil {
				t.Fatalf("read config after bounded update: %v", err)
			}
			if !bytes.Equal(persisted, original) {
				t.Fatal("body boundary test changed persisted configuration")
			}
		})
	}
}
