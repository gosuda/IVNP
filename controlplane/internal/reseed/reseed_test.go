package reseed

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/foundation"
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
	data, lease, err := readRouterInfo(zipFile(t, "routerInfo-test.dat", payload))
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatalf("readRouterInfo() = %d bytes, %v", len(data), err)
	}
	lease.Release()
}

func TestClientRejectsInsecureEndpointBeforeNetwork(t *testing.T) {
	client := Client{NetworkID: 2}
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	if _, err := client.FetchInto(context.Background(), "http://example.invalid/reseed.zip?netid=2", database, 0); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("FetchInto() error = %v, want ErrInsecureURL", err)
	}
}

func TestClientRequiresExactNetworkQueryAndNoCredentials(t *testing.T) {
	client := Client{NetworkID: 2}
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
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

	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	client := Client{NetworkID: 2, HTTPClient: server.Client()}
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
	client := Client{NetworkID: 2, HTTPClient: server.Client(), AllowHTTP: true}
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
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
			client := Client{NetworkID: 2, HTTPClient: server.Client()}
			database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
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
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	client := Client{NetworkID: 2, HTTPClient: &http.Client{Timeout: 30 * time.Second}}
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

func TestClientImportsOnlySelectedNetwork(t *testing.T) {
	for _, networkID := range []uint8{0, 3, 255} {
		t.Run(fmt.Sprint(networkID), func(t *testing.T) {
			local, err := foundation.GenerateLocalAddress()
			if err != nil {
				t.Fatal(err)
			}
			owner, err := controlplanenetdb.NewLocalRouterInfo(controlplanenetdb.LocalRouterInfoConfig{
				Local: local,
				Contacts: controlplanenetdb.RouterInfoContacts{Options: []foundation.MappingEntry{
					{Key: []byte("netId"), Value: []byte(fmt.Sprint(networkID))},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			info, err := owner.Publish(1000)
			if err != nil {
				t.Fatal(err)
			}
			archive := zipArchiveBytes(t, "routerInfo-test.dat", info.Bytes())
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(archive)
			}))
			defer server.Close()
			for _, selected := range []uint8{networkID, 2} {
				client := Client{NetworkID: selected, HTTPClient: server.Client(), allowUnsignedZIP: true}
				database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
				count, err := client.FetchInto(context.Background(), server.URL+"?netid="+fmt.Sprint(selected), database, 1000)
				if selected == networkID {
					if err != nil || count != 1 || database.Routers().Len() != 1 {
						t.Fatalf("matching network import = %d, %v", count, err)
					}
				} else if !errors.Is(err, ErrNoRouterInfos) || database.Routers().Len() != 0 {
					t.Fatalf("wrong network import = %d, %v", count, err)
				}
			}
		})
	}
}

func TestFetchAnyParallelAccumulation(t *testing.T) {
	var archives [][]byte
	for i := range 3 {
		local, err := foundation.GenerateLocalAddress()
		if err != nil {
			t.Fatal(err)
		}
		owner, err := controlplanenetdb.NewLocalRouterInfo(controlplanenetdb.LocalRouterInfoConfig{
			Local: local,
			Contacts: controlplanenetdb.RouterInfoContacts{Options: []foundation.MappingEntry{
				{Key: []byte("netId"), Value: []byte("2")},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		info, err := owner.Publish(1000)
		if err != nil {
			t.Fatal(err)
		}
		archives = append(archives, zipArchiveBytes(t, fmt.Sprintf("routerInfo-%d.dat", i), info.Bytes()))
	}
	var servers []*httptest.Server
	var endpoints []string
	for i := range 3 {
		data := archives[i]
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(data)
		}))
		defer srv.Close()
		servers = append(servers, srv)
		endpoints = append(endpoints, srv.URL+"?netid=2")
	}

	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	client := Client{
		NetworkID:         2,
		HTTPClient:        servers[0].Client(),
		allowUnsignedZIP:  true,
		TargetRouterInfos: 2,
	}

	count, err := client.FetchAny(context.Background(), endpoints, database, 1000)
	if err != nil {
		t.Fatalf("FetchAny() error = %v", err)
	}
	if count < 2 {
		t.Fatalf("FetchAny() count = %d, want at least 2", count)
	}
	if database.Routers().Len() < 2 {
		t.Fatalf("database router count = %d, want at least 2", database.Routers().Len())
	}
}

func TestFetchAnyAllFailures(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	client := Client{
		NetworkID:        2,
		HTTPClient:       srv.Client(),
		allowUnsignedZIP: true,
	}

	endpoints := []string{srv.URL + "?netid=2"}
	_, err := client.FetchAny(context.Background(), endpoints, database, 1000)
	if err == nil {
		t.Fatal("FetchAny() expected error when all endpoints fail")
	}
}

func buildSU3Container(t *testing.T, signerID string, content []byte) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	version := bytes.Repeat([]byte{'1'}, su3MinimumVersion)
	header := make([]byte, su3HeaderLen)
	copy(header[:7], []byte{'I', '2', 'P', 's', 'u', '3', 0})
	binary.BigEndian.PutUint16(header[8:10], uint16(foundation.SigningRSASHA512_4096))
	binary.BigEndian.PutUint16(header[10:12], su3RSASignatureLen)
	header[13], header[15] = byte(len(version)), byte(len(signerID))
	binary.BigEndian.PutUint64(header[16:24], uint64(len(content)))
	header[25], header[27] = su3FileTypeZIP, su3ContentTypeReseed
	signed := append(append(append([]byte{}, header...), version...), []byte(signerID)...)
	signed = append(signed, content...)
	digest := sha512.Sum512(signed)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.Hash(0), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte(nil), signed...), sig...)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestTLSTrustedReseedHostAllowsUntrustedSU3Signer(t *testing.T) {
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := controlplanenetdb.NewLocalRouterInfo(controlplanenetdb.LocalRouterInfoConfig{
		Local: local,
		Contacts: controlplanenetdb.RouterInfoContacts{Options: []foundation.MappingEntry{
			{Key: []byte("netId"), Value: []byte("2")},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := owner.Publish(1000)
	if err != nil {
		t.Fatal(err)
	}
	zipBytes := zipArchiveBytes(t, "routerInfo-test.dat", info.Bytes())
	su3Bytes := buildSU3Container(t, "reseed@ivnp.network", zipBytes)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(su3Bytes)
	}))
	defer srv.Close()

	srvURL, _ := url.Parse(srv.URL)
	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			clone := req.Clone(req.Context())
			clone.URL.Scheme = srvURL.Scheme
			clone.URL.Host = srvURL.Host
			return srv.Client().Transport.RoundTrip(clone)
		}),
	}

	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	client := Client{
		NetworkID:  2,
		HTTPClient: httpClient,
	}

	// Hotseed over HTTPS succeeds even though reseed@ivnp.network is not in default signers
	count, err := client.FetchInto(context.Background(), "https://hotseed.gosuda.org/i2pseeds.su3?netid=2", database, 1000)
	if err != nil {
		t.Fatalf("FetchInto(hotseed.gosuda.org) error = %v, want success via TLS verification", err)
	}
	if count != 1 || database.Routers().Len() != 1 {
		t.Fatalf("admitted count = %d, database routers = %d", count, database.Routers().Len())
	}

	// Other untrusted host fails with ErrSU3Signer
	database2 := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	_, err = client.FetchInto(context.Background(), "https://untrusted.example.org/i2pseeds.su3?netid=2", database2, 1000)
	if !errors.Is(err, ErrSU3Signer) {
		t.Fatalf("FetchInto(untrusted.example.org) error = %v, want ErrSU3Signer", err)
	}
}

func TestFetchAnyPrioritizesHotseedWithHeadStart(t *testing.T) {
	var requestOrder []string
	var mu sync.Mutex

	hotseedSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestOrder = append(requestOrder, "hotseed")
		mu.Unlock()
		local, _ := foundation.GenerateLocalAddress()
		owner, _ := controlplanenetdb.NewLocalRouterInfo(controlplanenetdb.LocalRouterInfoConfig{
			Local: local,
			Contacts: controlplanenetdb.RouterInfoContacts{Options: []foundation.MappingEntry{
				{Key: []byte("netId"), Value: []byte("2")},
			}},
		})
		info, _ := owner.Publish(1000)
		_, _ = w.Write(zipArchiveBytes(t, "routerInfo-hotseed.dat", info.Bytes()))
	}))
	defer hotseedSrv.Close()

	fallbackSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestOrder = append(requestOrder, "fallback")
		mu.Unlock()
		_, _ = w.Write([]byte{})
	}))
	defer fallbackSrv.Close()

	hotseedURL, _ := url.Parse(hotseedSrv.URL)
	fallbackURL, _ := url.Parse(fallbackSrv.URL)

	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			clone := req.Clone(req.Context())
			if req.URL.Hostname() == "hotseed.gosuda.org" {
				clone.URL.Scheme = hotseedURL.Scheme
				clone.URL.Host = hotseedURL.Host
				return hotseedSrv.Client().Transport.RoundTrip(clone)
			}
			clone.URL.Scheme = fallbackURL.Scheme
			clone.URL.Host = fallbackURL.Host
			return fallbackSrv.Client().Transport.RoundTrip(clone)
		}),
	}

	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	client := Client{
		NetworkID:         2,
		HTTPClient:        httpClient,
		allowUnsignedZIP:  true,
		TargetRouterInfos: 1,
	}

	endpoints := []string{
		"https://fallback.example.org/i2pseeds.su3?netid=2",
		"https://hotseed.gosuda.org/i2pseeds.su3?netid=2",
		"https://fallback2.example.org/i2pseeds.su3?netid=2",
	}

	count, err := client.FetchAny(context.Background(), endpoints, database, 1000)
	if err != nil {
		t.Fatalf("FetchAny() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("FetchAny() count = %d, want 1", count)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requestOrder) != 1 || requestOrder[0] != "hotseed" {
		t.Fatalf("requestOrder = %v, want only [hotseed] (fallback should not be queried when hotseed succeeds)", requestOrder)
	}
}
