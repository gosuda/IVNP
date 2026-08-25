package reseed

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/pool"
	"gosuda.org/ivnp/networking/internal/network_database"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func zipArchiveBytes(t *testing.T, name string, payload []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), archive.Bytes()...)
}

func zipFile(t *testing.T, name string, payload []byte) *zip.File {
	t.Helper()
	archive := zipArchiveBytes(t, name, payload)
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	return reader.File[0]
}

func TestReadRouterInfoUsesBoundedPoolBuffer(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 1024)
	data, err := readRouterInfo(zipFile(t, "routerInfo-test.dat", payload))
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatalf("readRouterInfo() = %d bytes, %v", len(data), err)
	}
	pool.Release(data)
}

func TestClientRejectsInsecureEndpointBeforeNetwork(t *testing.T) {
	client := Client{}
	database := networkdatabase.NewDatabase(foundation.Hash{}, networkdatabase.DefaultBucketCapacity)
	if _, err := client.FetchInto(context.Background(), "http://example.invalid/reseed.zip?netid=2", database, 0); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("FetchInto() error = %v, want ErrInsecureURL", err)
	}
}

func TestClientRequiresExactNetworkQueryAndNoCredentials(t *testing.T) {
	client := Client{}
	database := networkdatabase.NewDatabase(foundation.Hash{}, networkdatabase.DefaultBucketCapacity)
	for _, endpoint := range []string{
		"https://reseed.example/i2pseeds.su3",
		"https://reseed.example/i2pseeds.su3?netid=3",
		"https://reseed.example/i2pseeds.su3?netid=2&other=1",
		"https://user:password@reseed.example/i2pseeds.su3?netid=2",
		"https://reseed.example/i2pseeds.su3?netid=2#fragment",
	} {
		if _, err := client.FetchInto(context.Background(), endpoint, database, 0); !errors.Is(err, ErrInvalidURL) {
			t.Fatalf("FetchInto(%q) error = %v, want ErrInvalidURL", endpoint, err)
		}
	}
}
func TestClientRejectsPlainZIPWithoutTestFixtureOption(t *testing.T) {
	archive := zipArchiveBytes(t, "routerInfo-fixture.dat", []byte("fixture"))
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/zip")
		_, _ = writer.Write(archive)
	}))
	defer server.Close()

	database := networkdatabase.NewDatabase(foundation.Hash{}, networkdatabase.DefaultBucketCapacity)
	client := Client{HTTPClient: server.Client()}
	endpoint := server.URL + "/i2pseeds.su3?netid=2"
	if _, err := client.FetchInto(context.Background(), endpoint, database, 1); !errors.Is(err, ErrUnsignedArchive) {
		t.Fatalf("production FetchInto() error = %v, want ErrUnsignedArchive", err)
	}

	client.allowUnsignedZIP = true
	if _, err := client.FetchInto(context.Background(), endpoint, database, 1); !errors.Is(err, ErrNoRouterInfos) {
		t.Fatalf("fixture FetchInto() error = %v, want parsed ZIP with no admissible RouterInfos", err)
	}
}

func TestClientSendsStandardReseedUserAgent(t *testing.T) {
	var gotAgent, gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gotAgent, gotQuery = request.UserAgent(), request.URL.RawQuery
		http.Error(writer, "expected test response", http.StatusForbidden)
	}))
	defer server.Close()
	client := Client{HTTPClient: server.Client(), AllowHTTP: true}
	database := networkdatabase.NewDatabase(foundation.Hash{}, networkdatabase.DefaultBucketCapacity)
	_, _ = client.FetchInto(context.Background(), server.URL+"/i2pseeds.su3?netid=2", database, 0)
	if gotAgent != ReseedUserAgent || gotQuery != "netid=2" {
		t.Fatalf("request User-Agent/query = %q/%q", gotAgent, gotQuery)
	}
}

func TestClientRejectsUnsafeRedirects(t *testing.T) {
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("cross-origin redirect destination was requested")
	}))
	defer destination.Close()

	tests := map[string]func(*httptest.Server) string{
		"cross origin": func(*httptest.Server) string {
			return destination.URL + "/i2pseeds.su3?netid=2"
		},
		"network query changed": func(server *httptest.Server) string {
			return server.URL + "/redirected?netid=3"
		},
		"HTTPS downgrade": func(server *httptest.Server) string {
			return "http" + strings.TrimPrefix(server.URL, "https") + "/redirected?netid=2"
		},
	}
	for name, location := range tests {
		t.Run(name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				http.Redirect(writer, request, location(server), http.StatusFound)
			}))
			defer server.Close()
			client := Client{HTTPClient: server.Client()}
			database := networkdatabase.NewDatabase(foundation.Hash{}, networkdatabase.DefaultBucketCapacity)
			_, err := client.FetchInto(context.Background(), server.URL+"/i2pseeds.su3?netid=2", database, 0)
			if !errors.Is(err, ErrUnsafeRedirect) {
				t.Fatalf("FetchInto() error = %v, want ErrUnsafeRedirect", err)
			}
		})
	}
}

func TestLiveReseedIntegration(t *testing.T) {
	if os.Getenv("IVNP_RESEED_INTEGRATION") != "1" {
		t.Skip("set IVNP_RESEED_INTEGRATION=1 to fetch and verify live reseeds")
	}
	endpoints := []string{
		"https://waw01.i2p-reseed.hosted-by.skhron.eu/i2pseeds.su3?netid=2",
		"https://sto01.i2p-reseed.hosted-by.skhron.eu/i2pseeds.su3?netid=2",
		"https://i2p.ntp.poweredbyberlin.de/i2pseeds.su3?netid=2",
		"https://spiral.likogan.dev/i2pseeds.su3?netid=2",
		"https://reseed.stormycloud.org/i2pseeds.su3?netid=2",
	}
	database := networkdatabase.NewDatabase(foundation.Hash{}, networkdatabase.DefaultBucketCapacity)
	client := Client{HTTPClient: &http.Client{Timeout: 30 * time.Second}}
	now := time.Now()
	successes := 0
	var failures []error
	for _, endpoint := range endpoints {
		context, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		count, err := client.FetchInto(context, endpoint, database, uint64(now.UnixMilli()))
		cancel()
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", endpoint, err))
			continue
		}
		t.Logf("verified %d current RouterInfos from %s", count, endpoint)
		successes++
		if successes == 2 {
			break
		}
	}
	if successes < 2 {
		t.Fatalf("verified %d live endpoints, want at least 2: %v", successes, errors.Join(failures...))
	}
	if count := database.Routers().Len(); count < 50 {
		t.Fatalf("admitted live RouterInfos = %d, want at least 50", count)
	}
	t.Logf("admitted %d distinct current RouterInfos from %d live endpoints", database.Routers().Len(), successes)
}
