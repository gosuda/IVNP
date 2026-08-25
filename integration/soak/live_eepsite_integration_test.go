//go:build integration

package main

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
)

func TestLiveTargetedEepsites(t *testing.T) {
	if os.Getenv("IVNP_EEPSITE_INTEGRATION") != "1" {
		t.Skip("set IVNP_EEPSITE_INTEGRATION=1 with live Java and IVNP SAM endpoints")
	}
	javaSAM := os.Getenv("IVNP_JAVA_SAM")
	ivnpSAM := os.Getenv("IVNP_SAM")
	if javaSAM == "" || ivnpSAM == "" {
		t.Fatal("IVNP_JAVA_SAM and IVNP_SAM are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	specs := []struct {
		name    string
		address string
	}{
		{name: "java", address: javaSAM},
		{name: "ivnp-client", address: ivnpSAM},
		{name: "ivnp-site", address: ivnpSAM},
	}
	results := make([]struct {
		endpoint *trafficEndpoint
		err      error
	}, len(specs))
	var group sync.WaitGroup
	for index, spec := range specs {
		group.Add(1)
		go func() {
			defer group.Done()
			results[index].endpoint, results[index].err = startTrafficEndpoint(ctx, "targeted-live-eepsite", spec.name, spec.address)
		}()
	}
	group.Wait()
	endpoints := make(map[string]*trafficEndpoint, len(specs))
	for index, result := range results {
		if result.endpoint != nil {
			endpoints[specs[index].name] = result.endpoint
		}
	}
	t.Cleanup(func() {
		for _, endpoint := range endpoints {
			endpoint.Close()
		}
	})
	for index, result := range results {
		if result.err != nil {
			t.Fatalf("start %s: %v", specs[index].name, result.err)
		}
	}
	for _, spec := range specs {
		t.Logf("%s destination: %s", spec.name, endpoints[spec.name].network.B32())
	}

	runner := &trafficRunner{runID: "targeted-live-eepsite", endpoints: endpoints, sequence: make(map[string]uint64)}
	for _, route := range requiredDirections {
		var last error
		for attempt := 1; attempt <= 3; attempt++ {
			probeCtx, probeCancel := context.WithTimeout(ctx, probeTimeout)
			last = runner.probeStream(probeCtx, route, uint64(attempt), 1024)
			probeCancel()
			if last == nil {
				t.Logf("%s: HTTP 200 and expected body", route.name)
				break
			}
			t.Logf("%s attempt %d: %v", route.name, attempt, last)
			select {
			case <-ctx.Done():
				t.Fatalf("%s: %v", route.name, last)
			case <-time.After(time.Second):
			}
		}
		if last != nil {
			t.Fatalf("%s: %v", route.name, last)
		}
	}
}
