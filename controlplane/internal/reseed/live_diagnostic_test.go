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

	var candidates []reseedCandidate
	rejections := map[string]int{}
	entries := 0
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || !strings.HasPrefix(path.Base(file.Name), "routerInfo-") {
			continue
		}
		entries++
		candidate, reason := collectZipCandidate(file, 2, seenAt)
		if reason == "" {
			candidates = append(candidates, candidate)
			continue
		}
		rejections[reason]++
	}
	t.Logf("collection: %d routerInfo entries -> %d candidates (parse-failed=%d, netid-mismatch=%d, stale=%d, future=%d)",
		entries, len(candidates), rejections["parse"], rejections["netid"], rejections["stale"], rejections["future"])

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

	outcomes := map[string]int{}
	sigFailures, floodfills, v2Only, noV2 := 0, 0, 0, 0
	guard := newIngressGuard(client.bucketSubnetQuota(), client.bucketAdmitLimit())
	for _, slot := range slots {
		category, sigFailed, isFF, hasV2 := classifySlotAdmission(slot, guard, database, local, seenAt)
		outcomes[category]++
		if sigFailed {
			sigFailures++
		}
		if isFF {
			floodfills++
		}
		if hasV2 {
			v2Only++
		} else {
			noV2++
		}
	}
	t.Logf("admission: sig-failed=%d (no-fallback=%d), quota-rejected=%d (bucket-full=%d, subnet-quota=%d), admit-failed=%d",
		sigFailures, outcomes["sig-failed-no-fallback"],
		outcomes["bucket-full"]+outcomes["subnet-quota"], outcomes["bucket-full"], outcomes["subnet-quota"],
		outcomes["admit-failed"])
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

// collectZipCandidate runs the collection-stage pre-cut on a single ZIP entry:
// read, parse, netID match, freshness. It returns the candidate on success, or
// a short rejection reason ("parse", "netid", "stale", "future").
func collectZipCandidate(file *zip.File, netID uint8, seenAt uint64) (reseedCandidate, string) {
	data, lease, err := readRouterInfo(file)
	if err != nil {
		return reseedCandidate{}, "parse"
	}
	owned := make([]byte, len(data))
	copy(owned, data)
	lease.Release()
	info, err := foundation.NetworkDatabaseParseRouterInfo(owned)
	if err != nil {
		return reseedCandidate{}, "parse"
	}
	if !routerInfoMatchesNetwork(info, netID) {
		return reseedCandidate{}, "netid"
	}
	if err := controlplanenetdb.ReseedRouterInfoFresh(info, seenAt); err != nil {
		if info.Published > seenAt {
			return reseedCandidate{}, "future"
		}
		return reseedCandidate{}, "stale"
	}
	return reseedCandidate{info: info}, ""
}

// classifySlotAdmission replays the ingestion pipeline against a single dedup
// slot. It returns a rejection category ("", "sig-failed",
// "sig-failed-no-fallback", "bucket-full", "subnet-quota", "admit-failed"),
// whether any signature verification failed, and the admitted candidate's
// floodfill and v2-transport flags.
func classifySlotAdmission(slot *dedupSlot, guard *ingressGuard, database *controlplanenetdb.Database, local foundation.Hash, seenAt uint64) (string, bool, bool, bool) {
	candidate := slot.best
	sigFailed := false
	if ok, _ := candidate.info.Verify(); !ok {
		sigFailed = true
		if slot.count < 2 {
			return "sig-failed-no-fallback", true, false, false
		}
		candidate = slot.fallback
		if ok, _ := candidate.info.Verify(); !ok {
			return "sig-failed", true, false, false
		}
	}
	isFF := foundation.NetworkDatabaseIsFloodfill(candidate.info)
	hasV2 := hasV2Transport(candidate.info)
	bucket := leadingZerosXOR(local, candidate.info.Hash())
	if !guard.claim(bucket, ingressSubnetsOf(candidate.info)) {
		if guard.bucketUse[bucket] >= guard.bucketLimit {
			return "bucket-full", sigFailed, isFF, hasV2
		}
		return "subnet-quota", sigFailed, isFF, hasV2
	}
	if database.AdmitVerifiedReseedRouterInfo(candidate.info, seenAt) != nil {
		return "admit-failed", sigFailed, isFF, hasV2
	}
	return "", sigFailed, isFF, hasV2
}
