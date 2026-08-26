package ivnp_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestEepsiteAccessThroughRunningProxy(t *testing.T) {
	proxyAddress := os.Getenv("IVNP_EEPSITE_PROXY")
	if proxyAddress == "" {
		t.Skip("set IVNP_EEPSITE_PROXY to a running IVNP HTTP proxy URL")
	}
	proxyURL, err := url.Parse(proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   2 * time.Minute,
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://stats.i2p/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<10))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || len(body) == 0 {
		t.Fatalf("stats.i2p was not reached: status=%s body=%q", response.Status, body)
	}
}
