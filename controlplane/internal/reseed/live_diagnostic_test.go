package reseed

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/foundation"
)

// TestLivePriorityReseedDiagnostic fetches the production priority reseed
// bundle and tallies per-stage admission outcomes, so operators can see why
// entries are accepted or rejected by the two-phase pipeline.
func TestLivePriorityReseedDiagnostic(t *testing.T) {
	if os.Getenv("IVNP_RESEED_INTEGRATION") != "1" {
		t.Skip("set IVNP_RESEED_INTEGRATION=1 to fetch and verify the live priority reseed")
	}
	endpoint := "https://hotseed.gosuda.org/i2pseeds.su3?netid=2"
	seenAt := uint64(time.Now().UnixMilli())

	httpClient := &http.Client{Timeout: 30 * time.Second}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("User-Agent", ReseedUserAgent)
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatalf("fetch %s: %v", endpoint, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("fetch %s: HTTP %s", endpoint, response.Status)
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, DefaultMaxArchiveBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("archive: %d bytes, Content-Length=%d, ETag=%s", len(archive), response.ContentLength, response.Header.Get("ETag"))

	signers, err := DefaultSU3SignersAt(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := VerifySU3(archive, signers, DefaultMaxArchiveBytes)
	if err != nil {
		t.Fatalf("SU3 verification failed: %v", err)
	}
	t.Logf("SU3 signature verified: %d bytes payload", len(payload))

	reader, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}

	var parseFailed, netIDMismatch, stale, future int
	var candidates []reseedCandidate
	entries := 0
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || !strings.HasPrefix(path.Base(file.Name), "routerInfo-") {
			continue
		}
		entries++
		data, lease, readErr := readRouterInfo(file)
		if readErr != nil {
			parseFailed++
			continue
		}
		owned := make([]byte, len(data))
		copy(owned, data)
		lease.Release()
		info, parseErr := foundation.NetworkDatabaseParseRouterInfo(owned)
		if parseErr != nil {
			parseFailed++
			continue
		}
		if !routerInfoMatchesNetwork(info, 2) {
			netIDMismatch++
			continue
		}
		if freshErr := controlplanenetdb.ReseedRouterInfoFresh(info, seenAt); freshErr != nil {
			if info.Published > seenAt {
				future++
			} else {
				stale++
			}
			continue
		}
		candidates = append(candidates, reseedCandidate{info: info})
	}
	t.Logf("collection: %d routerInfo entries -> %d candidates (parse-failed=%d, netid-mismatch=%d, stale=%d, future=%d)",
		entries, len(candidates), parseFailed, netIDMismatch, stale, future)

	slots := make(map[foundation.Hash]*dedupSlot, len(candidates))
	duplicates := 0
	for _, candidate := range candidates {
		hash := candidate.info.Hash()
		if _, ok := slots[hash]; ok {
			duplicates++
		}
		addCandidate(slots, candidate)
	}
	t.Logf("dedup: %d candidates -> %d unique hashes (%d duplicates)", len(candidates), len(slots), duplicates)

	var local foundation.Hash
	_, _ = rand.Read(local[:])
	database := controlplanenetdb.NewDatabase(local, controlplanenetdb.DefaultBucketCapacity)
	client := Client{NetworkID: 2}

	sigFailed, noSigFallback, quotaRejected, admitFailed := 0, 0, 0, 0
	bucketFull, subnetQuota := 0, 0
	floodfills, v2Only, noV2 := 0, 0, 0
	guard := newIngressGuard(client.bucketSubnetQuota(), client.bucketAdmitLimit())
	for _, slot := range slots {
		candidate := slot.best
		if ok, _ := candidate.info.Verify(); !ok {
			if slot.count < 2 {
				sigFailed++
				noSigFallback++
				continue
			}
			candidate = slot.fallback
			if ok, _ := candidate.info.Verify(); !ok {
				sigFailed++
				continue
			}
			sigFailed++
		}
		if foundation.NetworkDatabaseIsFloodfill(candidate.info) {
			floodfills++
		}
		if hasV2Transport(candidate.info) {
			v2Only++
		} else {
			noV2++
		}
		bucket := leadingZerosXOR(local, candidate.info.Hash())
		subnets := ingressSubnetsOf(candidate.info)
		if !guard.claim(bucket, subnets) {
			quotaRejected++
			if guard.bucketUse[bucket] >= guard.bucketLimit {
				bucketFull++
			} else {
				subnetQuota++
			}
			continue
		}
		if database.AdmitVerifiedReseedRouterInfo(candidate.info, seenAt) != nil {
			admitFailed++
		}
	}
	t.Logf("admission: sig-failed=%d (no-fallback=%d), quota-rejected=%d (bucket-full=%d, subnet-quota=%d), admit-failed=%d",
		sigFailed, noSigFallback, quotaRejected, bucketFull, subnetQuota, admitFailed)
	t.Logf("candidate profile: floodfills=%d, with-v2-transport=%d, no-v2-transport=%d", floodfills, v2Only, noV2)
	t.Logf("admitted=%d / %d unique", database.Routers().Len(), len(slots))

	result := client.ingestCandidates(slots, database, seenAt)
	t.Logf("ingestCandidates: admitted=%d (delta vs manual pass: already stored), anchors=%d", result.Admitted, len(result.Anchors))

	// Re-run against a fresh database for the authoritative end-to-end count.
	database2 := controlplanenetdb.NewDatabase(local, controlplanenetdb.DefaultBucketCapacity)
	result2 := client.ingestCandidates(slots, database2, seenAt)
	fmt.Printf("RESULT admitted=%d unique=%d entries=%d floodfills=%d anchors=%d\n",
		result2.Admitted, len(slots), entries, floodfills, len(result2.Anchors))
	if result2.Admitted == 0 {
		t.Fatal("priority reseed bundle admitted zero RouterInfos")
	}
}
