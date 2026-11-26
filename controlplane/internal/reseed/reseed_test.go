package reseed

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
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

	result, err := client.FetchAny(context.Background(), endpoints, database, 1000)
	if err != nil {
		t.Fatalf("FetchAny() error = %v", err)
	}
	if result.Admitted < 2 {
		t.Fatalf("FetchAny() admitted = %d, want at least 2", result.Admitted)
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
	return buildSU3ContainerWithKey(t, priv, signerID, content)
}

func buildSU3ContainerWithKey(t *testing.T, priv *rsa.PrivateKey, signerID string, content []byte) []byte {
	t.Helper()
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

func TestUntrustedSU3SignerRejectedOnAnyHost(t *testing.T) {
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

	client := Client{
		NetworkID:  2,
		HTTPClient: httpClient,
	}

	// Archives signed by non-embedded signers are rejected everywhere, including
	// on the prioritized hotseed host; TLS channel trust never substitutes for
	// SU3 signature verification.
	for _, host := range []string{"hotseed.gosuda.org", "untrusted.example.org"} {
		database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
		_, err := client.FetchInto(context.Background(), "https://"+host+"/i2pseeds.su3?netid=2", database, 1000)
		if !errors.Is(err, ErrSU3Signer) {
			t.Fatalf("FetchInto(%s) error = %v, want ErrSU3Signer", host, err)
		}
		if database.Routers().Len() != 0 {
			t.Fatalf("FetchInto(%s) admitted %d routers, want 0", host, database.Routers().Len())
		}
	}
}

// A signer admitted while its certificate was valid must stop being trusted
// once the certificate expires, without restarting the client.
func TestClientRejectsSignerExpiredAtFetchTime(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expiring-reseed@internal.example"},
		NotBefore:    start.Add(-time.Hour),
		NotAfter:     start.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	signers, err := MergeSU3Signers(nil, [][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, start)
	if err != nil {
		t.Fatal(err)
	}
	su3Bytes := buildSU3ContainerWithKey(t, private, template.Subject.CommonName,
		zipArchiveBytes(t, "routerInfo-test.dat", testRouterInfoWithHost(t, "198.51.100.20")))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(su3Bytes)
	}))
	defer srv.Close()
	srvURL, _ := url.Parse(srv.URL)
	var clock struct {
		sync.Mutex
		now time.Time
	}
	clock.now = start
	client := Client{
		NetworkID: 2,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			clone := req.Clone(req.Context())
			clone.URL.Scheme, clone.URL.Host = srvURL.Scheme, srvURL.Host
			return srv.Client().Transport.RoundTrip(clone)
		})},
		SU3Signers: signers,
		Now: func() time.Time {
			clock.Lock()
			defer clock.Unlock()
			return clock.now
		},
	}
	const endpoint = "https://reseed.example.org/i2pseeds.su3?netid=2"

	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	if admitted, err := client.FetchInto(context.Background(), endpoint, database, 1000); err != nil || admitted != 1 {
		t.Fatalf("FetchInto(valid signer) = %d, %v; want 1, nil", admitted, err)
	}

	clock.Lock()
	clock.now = template.NotAfter.Add(time.Second)
	clock.Unlock()
	database = controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	if _, err := client.FetchInto(context.Background(), endpoint, database, 1000); !errors.Is(err, ErrSU3Signer) {
		t.Fatalf("FetchInto(expired signer) error = %v, want ErrSU3Signer", err)
	}
	if database.Routers().Len() != 0 {
		t.Fatalf("FetchInto(expired signer) admitted %d routers, want 0", database.Routers().Len())
	}
}

func testRouterInfoWithHost(t *testing.T, host string) []byte {
	t.Helper()
	return testRouterInfoInBucket(t, host, -1)
}

// testRouterInfoInBucket creates a RouterInfo whose hash lands in the given
// local K-bucket relative to the all-zero local hash (-1 accepts any bucket).
func testRouterInfoInBucket(t *testing.T, host string, bucket int) []byte {
	t.Helper()
	for {
		local, err := foundation.GenerateLocalAddress()
		if err != nil {
			t.Fatal(err)
		}
		owner, err := controlplanenetdb.NewLocalRouterInfo(controlplanenetdb.LocalRouterInfoConfig{
			Local: local,
			Contacts: controlplanenetdb.RouterInfoContacts{
				Addresses: []controlplanenetdb.LocalRouterAddress{{
					TransportStyle: []byte("NTCP2"),
					Options: []foundation.MappingEntry{
						{Key: []byte("host"), Value: []byte(host)},
						{Key: []byte("port"), Value: []byte("12345")},
					},
				}},
				Options: []foundation.MappingEntry{
					{Key: []byte("netId"), Value: []byte("2")},
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		info, err := owner.Publish(1000)
		if err != nil {
			t.Fatal(err)
		}
		if bucket < 0 || leadingZerosXOR(foundation.Hash{}, info.Hash()) == bucket {
			return info.Bytes()
		}
	}
}

func zipMultiArchiveBytes(t *testing.T, payloads [][]byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for i, payload := range payloads {
		entry, err := writer.Create(fmt.Sprintf("routerInfo-%d.dat", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), archive.Bytes()...)
}

func TestFetchIntoDedupesIPv4Subnet16(t *testing.T) {
	// All candidates land in local bucket 0 so the per-bucket subnet quota
	// applies: M=2 per /16 (IPv4) and /48 (IPv6), plus one peer each on
	// uncontested subnets.
	archive := zipMultiArchiveBytes(t, [][]byte{
		testRouterInfoInBucket(t, "10.1.2.3", 0),
		testRouterInfoInBucket(t, "10.1.9.9", 0),
		testRouterInfoInBucket(t, "10.1.5.5", 0), // third 10.1/16 in bucket 0: dropped
		testRouterInfoInBucket(t, "10.2.0.1", 0),
		testRouterInfoInBucket(t, "2001:db8::1", 0),
		testRouterInfoInBucket(t, "2001:db8::2", 0),
		testRouterInfoInBucket(t, "2001:db8::3", 0), // third 2001:db8::/48: dropped
		testRouterInfoInBucket(t, "192.168.50.7", 0),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	client := Client{
		NetworkID:        2,
		HTTPClient:       srv.Client(),
		AllowHTTP:        true,
		allowUnsignedZIP: true,
	}

	count, err := client.FetchInto(context.Background(), srv.URL+"/i2pseeds.su3?netid=2", database, 1000)
	if err != nil {
		t.Fatalf("FetchInto() error = %v", err)
	}
	if count != 6 || database.Routers().Len() != 6 {
		t.Fatalf("admitted count = %d, database routers = %d, want 6", count, database.Routers().Len())
	}
}

func TestIngressGuardBucketSubnetQuota(t *testing.T) {
	guard := newIngressGuard(2, 20, 0)
	subnetA := ingressSubnet{1, 10, 1}
	subnetB := ingressSubnet{2, 0x20, 0x01, 0x0d, 0xb8, 0, 0}
	if !guard.claim(0, 0, []ingressSubnet{subnetA}) || !guard.claim(0, 0, []ingressSubnet{subnetA}) {
		t.Fatal("first two claims on the same subnet must pass (quota=2)")
	}
	if guard.claim(0, 0, []ingressSubnet{subnetA}) {
		t.Fatal("third claim on the same subnet in the same bucket must fail")
	}
	if !guard.claim(1, 0, []ingressSubnet{subnetA}) {
		t.Fatal("same subnet in a different bucket has its own quota")
	}
	if !guard.claim(0, 0, []ingressSubnet{subnetB}) || !guard.claim(0, 0, []ingressSubnet{subnetB}) {
		t.Fatal("IPv6 /48 claims follow the same quota")
	}
	if guard.claim(0, 0, []ingressSubnet{subnetB}) {
		t.Fatal("third IPv6 /48 claim must fail")
	}
}

func TestIngressGuardBucketCapacity(t *testing.T) {
	guard := newIngressGuard(2, 3, 0)
	for i := 0; i < 3; i++ {
		if !guard.claim(5, 0, []ingressSubnet{{1, byte(i), 0}}) {
			t.Fatalf("claim %d under bucket capacity must pass", i)
		}
	}
	if guard.claim(5, 0, []ingressSubnet{{1, 9, 9}}) {
		t.Fatal("bucket capacity reached: further claims must fail")
	}
	if !guard.claim(6, 0, []ingressSubnet{{1, 9, 9}}) {
		t.Fatal("other buckets keep their own capacity")
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

	result, err := client.FetchAny(context.Background(), endpoints, database, 1000)
	if err != nil {
		t.Fatalf("FetchAny() error = %v", err)
	}
	if result.Admitted != 1 {
		t.Fatalf("FetchAny() admitted = %d, want 1", result.Admitted)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requestOrder) != 3 || requestOrder[0] != "hotseed" {
		t.Fatalf("requestOrder = %v, want hotseed first, then the fallbacks for a second independent source", requestOrder)
	}
}

func TestFetchAnyPriorityFailureFallsBack(t *testing.T) {
	var requested []string
	var mu sync.Mutex

	hotseedSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, "hotseed")
		mu.Unlock()
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer hotseedSrv.Close()

	fallbackSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, "fallback")
		mu.Unlock()
		local, _ := foundation.GenerateLocalAddress()
		owner, _ := controlplanenetdb.NewLocalRouterInfo(controlplanenetdb.LocalRouterInfoConfig{
			Local: local,
			Contacts: controlplanenetdb.RouterInfoContacts{Options: []foundation.MappingEntry{
				{Key: []byte("netId"), Value: []byte("2")},
			}},
		})
		info, _ := owner.Publish(1000)
		_, _ = w.Write(zipArchiveBytes(t, "routerInfo-fallback.dat", info.Bytes()))
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
		NetworkID:        2,
		HTTPClient:       httpClient,
		allowUnsignedZIP: true,
	}

	endpoints := []string{
		"https://hotseed.gosuda.org/i2pseeds.su3?netid=2",
		"https://fallback.example.org/i2pseeds.su3?netid=2",
	}

	result, err := client.FetchAny(context.Background(), endpoints, database, 1000)
	if err != nil {
		t.Fatalf("FetchAny() error = %v", err)
	}
	if result.Admitted != 1 {
		t.Fatalf("FetchAny() admitted = %d, want 1", result.Admitted)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requested) != 2 || requested[0] != "hotseed" || requested[1] != "fallback" {
		t.Fatalf("requested = %v, want [hotseed, fallback]", requested)
	}
}

// priorityMux routes hotseed.gosuda.org hostnames to test servers by
// subdomain label: "hotseed.gosuda.org" hits servers[""], and
// "<label>.hotseed.gosuda.org" hits servers[label].
func priorityMux(t *testing.T, servers map[string]*httptest.Server) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		host := req.URL.Hostname()
		label := ""
		if host != "hotseed.gosuda.org" {
			label, _, _ = strings.Cut(host, ".hotseed.gosuda.org")
		}
		srv := servers[label]
		if srv == nil {
			return nil, fmt.Errorf("unexpected host %s", host)
		}
		srvURL, _ := url.Parse(srv.URL)
		clone := req.Clone(req.Context())
		clone.URL.Scheme = srvURL.Scheme
		clone.URL.Host = srvURL.Host
		return srv.Client().Transport.RoundTrip(clone)
	})}
}

func testRouterInfoBytes(t *testing.T) []byte {
	t.Helper()
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
	return info.Bytes()
}

func TestFetchAnyMergesPrioritySources(t *testing.T) {
	var hits []string
	var mu sync.Mutex
	newServer := func(name, entry string) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits = append(hits, name)
			mu.Unlock()
			_, _ = w.Write(zipArchiveBytes(t, entry, testRouterInfoBytes(t)))
		}))
	}
	srvA := newServer("a", "routerInfo-a.dat")
	defer srvA.Close()
	srvB := newServer("b", "routerInfo-b.dat")
	defer srvB.Close()

	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	client := Client{
		NetworkID:        2,
		HTTPClient:       priorityMux(t, map[string]*httptest.Server{"": srvA, "b": srvB}),
		allowUnsignedZIP: true,
		MergeWait:        2 * time.Second,
	}

	result, err := client.FetchAny(context.Background(), []string{
		"https://hotseed.gosuda.org/i2pseeds.su3?netid=2",
		"https://b.hotseed.gosuda.org/i2pseeds.su3?netid=2",
	}, database, 1000)
	if err != nil {
		t.Fatalf("FetchAny() error = %v", err)
	}
	if result.Admitted != 2 || database.Routers().Len() != 2 {
		t.Fatalf("FetchAny() admitted = %d, routers = %d, want 2", result.Admitted, database.Routers().Len())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hits) != 2 {
		t.Fatalf("priority hits = %v, want both servers queried for the merge", hits)
	}
}

func TestFetchAnyMergeDisabledUsesFirstResponse(t *testing.T) {
	aServed := make(chan struct{})
	srvA := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipArchiveBytes(t, "routerInfo-a.dat", testRouterInfoBytes(t)))
		close(aServed)
	}))
	defer srvA.Close()
	srvB := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-aServed
		_, _ = w.Write(zipArchiveBytes(t, "routerInfo-b.dat", testRouterInfoBytes(t)))
	}))
	defer srvB.Close()

	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	client := Client{
		NetworkID:        2,
		HTTPClient:       priorityMux(t, map[string]*httptest.Server{"": srvA, "b": srvB}),
		allowUnsignedZIP: true,
		MergeWait:        -1,
	}

	result, err := client.FetchAny(context.Background(), []string{
		"https://hotseed.gosuda.org/i2pseeds.su3?netid=2",
		"https://b.hotseed.gosuda.org/i2pseeds.su3?netid=2",
	}, database, 1000)
	if err != nil {
		t.Fatalf("FetchAny() error = %v", err)
	}
	if result.Admitted != 1 {
		t.Fatalf("FetchAny() admitted = %d, want 1 from the first priority response", result.Admitted)
	}
}

func TestFetchAnyMergeIngestsPartialOnDeadline(t *testing.T) {
	srvA := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipArchiveBytes(t, "routerInfo-a.dat", testRouterInfoBytes(t)))
	}))
	defer srvA.Close()
	srvB := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srvB.Close()

	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	client := Client{
		NetworkID:        2,
		HTTPClient:       priorityMux(t, map[string]*httptest.Server{"": srvA, "b": srvB}),
		allowUnsignedZIP: true,
		MergeWait:        2 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	result, err := client.FetchAny(ctx, []string{
		"https://hotseed.gosuda.org/i2pseeds.su3?netid=2",
		"https://b.hotseed.gosuda.org/i2pseeds.su3?netid=2",
	}, database, 1000)
	if err != nil {
		t.Fatalf("FetchAny() error = %v, want partial ingest instead of deadline error", err)
	}
	if result.Admitted != 1 {
		t.Fatalf("FetchAny() admitted = %d, want 1 from the responsive priority source", result.Admitted)
	}
}

func TestFpsOrderBucketSpreadsPicks(t *testing.T) {
	mk := func(first, last byte, floodfill bool, src int) bucketCandidate {
		var h foundation.Hash
		h[0] = first
		h[31] = last
		return bucketCandidate{candidate: reseedCandidate{source: src}, hash: h, floodfill: floodfill}
	}
	cands := []bucketCandidate{
		mk(0x80, 0, false, 0),
		mk(0x80, 1, true, 1), // floodfill anchor
		mk(0xFF, 2, false, 2),
		mk(0xC0, 3, false, 3),
	}
	out := fpsOrderBucket(cands, 4, nil)
	if len(out) != 4 {
		t.Fatalf("fpsOrderBucket returned %d candidates, want 4", len(out))
	}
	got := []int{out[0].source, out[1].source, out[2].source, out[3].source}
	want := []int{1, 3, 2, 0}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pick order = %v, want %v", got, want)
		}
	}
}

func TestInsertAnchorKeepsClosest(t *testing.T) {
	var local foundation.Hash
	mk := func(lz int, salt byte) foundation.Hash {
		var h foundation.Hash
		h[lz/8] |= 0x80 >> (lz % 8)
		h[31] = salt
		return h
	}
	var anchors []foundation.Hash
	for i, lz := range []int{5, 9, 20, 2, 12} {
		anchors = insertAnchor(anchors, local, mk(lz, byte(i)), 3)
	}
	if len(anchors) != 3 {
		t.Fatalf("anchors = %d, want 3", len(anchors))
	}
	wantLZ := []int{20, 12, 9}
	for i, anchor := range anchors {
		if got := leadingZerosXOR(local, anchor); got != wantLZ[i] {
			t.Fatalf("anchors[%d] lz = %d, want %d (closest-first)", i, got, wantLZ[i])
		}
	}
}

func TestFpsOrderBucketHonorsPickLimit(t *testing.T) {
	mk := func(b byte, src int) bucketCandidate {
		var h foundation.Hash
		h[0] = 0x80
		h[1] = b
		return bucketCandidate{candidate: reseedCandidate{source: src}, hash: h}
	}
	cands := []bucketCandidate{mk(0, 0), mk(1, 1), mk(2, 2), mk(3, 3), mk(4, 4)}
	out := fpsOrderBucket(cands, 2, nil)
	if len(out) != len(cands) {
		t.Fatalf("fpsOrderBucket returned %d candidates, want %d", len(out), len(cands))
	}
	seen := map[int]bool{out[0].source: true, out[1].source: true}
	for i := 2; i < len(out); i++ {
		if seen[out[i].source] {
			t.Fatalf("unordered tail contains a picked candidate: %v", out)
		}
	}
}

// forgedRouterInfo returns a copy of genuine with its Published field moved
// forward. The router hash is unchanged and the signature no longer verifies.
func forgedRouterInfo(t *testing.T, genuine []byte, delta uint64) foundation.NetworkDatabaseRouterInfo {
	t.Helper()
	info, err := foundation.NetworkDatabaseParseRouterInfo(genuine)
	if err != nil {
		t.Fatal(err)
	}
	var published [8]byte
	binary.BigEndian.PutUint64(published[:], info.Published)
	index := bytes.Index(genuine[384:], published[:])
	if index < 0 {
		t.Fatal("published field not found")
	}
	forged := bytes.Clone(genuine)
	binary.BigEndian.PutUint64(forged[384+index:], info.Published+delta)
	out, err := foundation.NetworkDatabaseParseRouterInfo(forged)
	if err != nil {
		t.Fatal(err)
	}
	if out.Hash() != info.Hash() {
		t.Fatal("forged copy must keep the router hash")
	}
	if ok, _ := out.Verify(); ok {
		t.Fatal("forged copy must not verify")
	}
	return out
}

func TestIngestForgedDuplicatesDoNotSuppressHonestRouter(t *testing.T) {
	raw := testRouterInfoWithHost(t, "198.51.100.10")
	genuine, err := foundation.NetworkDatabaseParseRouterInfo(raw)
	if err != nil {
		t.Fatal(err)
	}
	forgedA := forgedRouterInfo(t, raw, 10)
	forgedB := forgedRouterInfo(t, raw, 20)
	forgedC := forgedRouterInfo(t, raw, 30)
	cases := map[string][]reseedCandidate{
		"two forged copies from one source": {
			{info: genuine, source: 1},
			{info: forgedA, source: 0},
			{info: forgedB, source: 0},
		},
		"honest copy arrives last": {
			{info: forgedA, source: 0},
			{info: forgedB, source: 0},
			{info: genuine, source: 1},
		},
		"forged copies from several sources": {
			{info: forgedA, source: 0},
			{info: genuine, source: 1},
			{info: forgedB, source: 2},
			{info: forgedC, source: 3},
		},
	}
	for name, candidates := range cases {
		t.Run(name, func(t *testing.T) {
			slots := make(map[foundation.Hash]*dedupSlot)
			for _, candidate := range candidates {
				addCandidate(slots, candidate)
			}
			database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
			result := (Client{NetworkID: 2}).ingestCandidates(slots, database, 1000)
			if result.Admitted != 1 {
				t.Fatalf("admitted = %d, want the honest RouterInfo", result.Admitted)
			}
			stored, ok := database.Routers().Get(genuine.Hash())
			if !ok || stored.Info.Published != genuine.Published {
				t.Fatalf("stored RouterInfo = %v/%v, want the honest copy", ok, stored.Info.Published)
			}
		})
	}
}

func TestFetchIntoRejectsDuplicateRouterHashes(t *testing.T) {
	raw := testRouterInfoWithHost(t, "198.51.100.10")
	forged := forgedRouterInfo(t, raw, 10)
	archive := zipMultiArchiveBytes(t, [][]byte{raw, forged.Bytes()})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	client := Client{NetworkID: 2, HTTPClient: srv.Client(), AllowHTTP: true, allowUnsignedZIP: true}
	count, err := client.FetchInto(context.Background(), srv.URL+"/i2pseeds.su3?netid=2", database, 1000)
	if !errors.Is(err, ErrDuplicateRouterInfo) || count != 0 || database.Routers().Len() != 0 {
		t.Fatalf("FetchInto() = %d, %v (routers %d), want ErrDuplicateRouterInfo and no admissions", count, err, database.Routers().Len())
	}
}

func TestIngestHostlessRouterInfosShareSubnetQuota(t *testing.T) {
	slots := make(map[foundation.Hash]*dedupSlot)
	for range 6 {
		info, err := foundation.NetworkDatabaseParseRouterInfo(testRouterInfoInBucket(t, "", 0))
		if err != nil {
			t.Fatal(err)
		}
		addCandidate(slots, reseedCandidate{info: info})
	}
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	result := (Client{NetworkID: 2, BucketSubnetQuota: 1}).ingestCandidates(slots, database, 1000)
	if result.Admitted != 1 {
		t.Fatalf("admitted = %d hostless RouterInfos, want 1 under a shared quota of 1", result.Admitted)
	}
}

func TestIngressSubnetsOfHostlessAndHostnameShareKey(t *testing.T) {
	for _, host := range []string{"", "reseed.example"} {
		info, err := foundation.NetworkDatabaseParseRouterInfo(testRouterInfoWithHost(t, host))
		if err != nil {
			t.Fatal(err)
		}
		subnets := ingressSubnetsOf(info)
		if len(subnets) != 1 || subnets[0] != hostlessIngressSubnet {
			t.Fatalf("host %q subnets = %v, want the shared hostless key", host, subnets)
		}
	}
}

func TestIngestCapsPerSourceShareOfBucket(t *testing.T) {
	slots := make(map[foundation.Hash]*dedupSlot)
	var flooded, honest []foundation.Hash
	for i := range 20 {
		info, err := foundation.NetworkDatabaseParseRouterInfo(testRouterInfoInBucket(t, fmt.Sprintf("10.%d.0.1", i), 0))
		if err != nil {
			t.Fatal(err)
		}
		addCandidate(slots, reseedCandidate{info: info, source: 0})
		flooded = append(flooded, info.Hash())
	}
	for i := range 5 {
		info, err := foundation.NetworkDatabaseParseRouterInfo(testRouterInfoInBucket(t, fmt.Sprintf("172.%d.0.1", i), 0))
		if err != nil {
			t.Fatal(err)
		}
		addCandidate(slots, reseedCandidate{info: info, source: 1})
		honest = append(honest, info.Hash())
	}
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	result := (Client{NetworkID: 2, BucketAdmitLimit: 20}).ingestCandidates(slots, database, 1000)
	count := func(hashes []foundation.Hash) int {
		n := 0
		for _, hash := range hashes {
			if _, ok := database.Routers().Get(hash); ok {
				n++
			}
		}
		return n
	}
	if got := count(flooded); got != 10 {
		t.Fatalf("flooding source admitted %d of bucket limit 20, want its 10-entry share", got)
	}
	if got := count(honest); got != 5 {
		t.Fatalf("second source admitted %d, want all 5", got)
	}
	if result.Admitted != 15 {
		t.Fatalf("admitted = %d, want 15", result.Admitted)
	}
}

func TestIngestSingleSourceKeepsFullBucket(t *testing.T) {
	slots := make(map[foundation.Hash]*dedupSlot)
	for i := range 6 {
		info, err := foundation.NetworkDatabaseParseRouterInfo(testRouterInfoInBucket(t, fmt.Sprintf("10.%d.0.1", i), 0))
		if err != nil {
			t.Fatal(err)
		}
		addCandidate(slots, reseedCandidate{info: info, source: 3})
	}
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	result := (Client{NetworkID: 2, BucketAdmitLimit: 6}).ingestCandidates(slots, database, 1000)
	if result.Admitted != 6 {
		t.Fatalf("admitted = %d, want 6 when only one source answered", result.Admitted)
	}
}

func TestFetchAnyWaitsForSecondSource(t *testing.T) {
	var hashes []foundation.Hash
	archive := func(hosts ...string) []byte {
		var payloads [][]byte
		for _, host := range hosts {
			raw := testRouterInfoWithHost(t, host)
			info, err := foundation.NetworkDatabaseParseRouterInfo(raw)
			if err != nil {
				t.Fatal(err)
			}
			hashes = append(hashes, info.Hash())
			payloads = append(payloads, raw)
		}
		return zipMultiArchiveBytes(t, payloads)
	}
	first := archive("10.1.0.1", "10.2.0.1")
	second := archive("10.3.0.1", "10.4.0.1")
	newServer := func(body []byte) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(body)
		}))
	}
	firstSrv := newServer(first)
	defer firstSrv.Close()
	secondSrv := newServer(second)
	defer secondSrv.Close()

	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	client := Client{
		NetworkID:         2,
		HTTPClient:        firstSrv.Client(),
		allowUnsignedZIP:  true,
		TargetRouterInfos: 2,
	}
	result, err := client.FetchAny(context.Background(), []string{firstSrv.URL + "?netid=2", secondSrv.URL + "?netid=2"}, database, 1000)
	if err != nil {
		t.Fatalf("FetchAny() error = %v", err)
	}
	for _, hash := range hashes {
		if _, ok := database.Routers().Get(hash); !ok {
			t.Fatalf("admitted = %d, router %x missing; want both sources merged before ingest", result.Admitted, hash[:4])
		}
	}
}
