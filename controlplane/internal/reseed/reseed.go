// Package reseed downloads, verifies, and imports bootstrap RouterInfos from SU3/ZIP reseed archives.
package reseed

import (
	"archive/zip"
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
	"gosuda.org/ivnp/internal/pool"
)

const (
	DefaultMaxArchiveBytes     = 1 << 20
	DefaultMaxRouterInfos      = 4_000
	DefaultMaxTotalRouterBytes = 64 << 20
	DefaultTargetRouterInfos   = 150
	DefaultParallelFetches     = 3
	DefaultMaxSuccessfulReseed = 3
	DefaultBucketSubnetQuota   = 2
	DefaultBucketAdmitLimit    = 20
	DefaultVerifyAnchorCount   = 16
	DefaultMergeWait           = 5 * time.Second
	ReseedUserAgent            = "Wget/1.11.4"
)

var (
	ErrInsecureURL     = errors.New("reseed: HTTPS endpoint required")
	ErrInvalidURL      = errors.New("reseed: endpoint must have exactly the selected netid query and no credentials or fragment")
	ErrNetwork         = errors.New("reseed: RouterInfo network does not match selected network")
	ErrUnsafeRedirect  = errors.New("reseed: unsafe redirect")
	ErrArchiveTooLarge = errors.New("reseed: archive exceeds configured limit")
	ErrTooManyEntries  = errors.New("reseed: router info count exceeds configured limit")
	ErrNoRouterInfos   = errors.New("reseed: archive contained no admissible router infos")
	ErrUnsignedArchive = errors.New("reseed: authenticated SU3 archive required")
	errRedirectLimit   = errors.New("stopped after 10 redirects")
	errNilDatabase     = errors.New("reseed: nil database")
)

// Client fetches and processes reseed archives.
type Client struct {
	HTTPClient          *http.Client
	NetworkID           uint8
	MaxArchiveBytes     int64
	MaxRouterInfos      int
	MaxTotalRouterBytes int64
	TargetRouterInfos   int
	// BucketSubnetQuota caps admissions per local K-bucket per subnet
	// (IPv4 /16 or IPv6 /48). BucketAdmitLimit caps admissions per bucket.
	// VerifyAnchorCount bounds the floodfill anchors returned for post-reseed
	// connectivity checks.
	BucketSubnetQuota int
	BucketAdmitLimit  int
	VerifyAnchorCount int
	// MergeWait bounds how long FetchAny waits for outstanding priority-source
	// responses before ingesting the merged candidate set. Zero selects
	// DefaultMergeWait; a negative value disables merging and finishes on the
	// first successful priority response.
	MergeWait        time.Duration
	SU3Signers       map[string]SU3Signer
	Now              func() time.Time
	AllowHTTP        bool // only for controlled tests or explicit local deployments
	allowUnsignedZIP bool
}

// ReseedResult reports the admission outcome plus floodfill anchors chosen
// closest to the local router for post-reseed connectivity verification.
type ReseedResult struct {
	Admitted int
	Anchors  []foundation.Hash
}

func (c Client) limits() (archive int64, infos int, total int64) {
	archive, infos, total = c.MaxArchiveBytes, c.MaxRouterInfos, c.MaxTotalRouterBytes
	if archive <= 0 {
		archive = DefaultMaxArchiveBytes
	}
	if infos <= 0 {
		infos = DefaultMaxRouterInfos
	}
	if total <= 0 {
		total = DefaultMaxTotalRouterBytes
	}
	return archive, infos, total
}

func (c Client) targetRouterInfos() int {
	if c.TargetRouterInfos > 0 {
		return c.TargetRouterInfos
	}
	return DefaultTargetRouterInfos
}

func (c Client) bucketSubnetQuota() int {
	if c.BucketSubnetQuota > 0 {
		return c.BucketSubnetQuota
	}
	return DefaultBucketSubnetQuota
}

func (c Client) bucketAdmitLimit() int {
	if c.BucketAdmitLimit > 0 {
		return c.BucketAdmitLimit
	}
	return DefaultBucketAdmitLimit
}

func (c Client) verifyAnchorCount() int {
	if c.VerifyAnchorCount > 0 {
		return c.VerifyAnchorCount
	}
	return DefaultVerifyAnchorCount
}

func (c Client) mergeWait() time.Duration {
	if c.MergeWait == 0 {
		return DefaultMergeWait
	}
	return c.MergeWait
}

func validateEndpoint(endpoint *url.URL, allowHTTP bool, networkID uint8) error {
	validateEndpointRejected := endpoint == nil || endpoint.Hostname() == "" || endpoint.User != nil ||
		endpoint.Fragment != "" || endpoint.RawQuery != "netid="+strconv.FormatUint(uint64(networkID), 10)
	if !validateEndpointRejected {
		validateEndpointRejected = endpoint.ForceQuery
	}
	if validateEndpointRejected {
		return ErrInvalidURL
	}
	if endpoint.Scheme == "https" {
		return nil
	}
	if endpoint.Scheme == "http" && allowHTTP {
		return nil
	}
	return ErrInsecureURL
}

func endpointOrigin(endpoint *url.URL) (scheme, host, port string) {
	scheme, host, port = endpoint.Scheme, strings.ToLower(endpoint.Hostname()), endpoint.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return
}

func sameOrigin(first, next *url.URL) bool {
	firstScheme, firstHost, firstPort := endpointOrigin(first)
	nextScheme, nextHost, nextPort := endpointOrigin(next)
	return firstScheme == nextScheme && firstHost == nextHost && firstPort == nextPort
}

func (c Client) httpClientFor(endpoint *url.URL) *http.Client {
	base := c.HTTPClient
	if base == nil {
		base = http.DefaultClient

	}

	client := *base
	previous := base.CheckRedirect
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) == 0 || !sameOrigin(endpoint, request.URL) {
			return ErrUnsafeRedirect
		}
		if err := validateEndpoint(request.URL, c.AllowHTTP, c.NetworkID); err != nil {
			return fmt.Errorf("%w: %v", ErrUnsafeRedirect, err)
		}
		if previous != nil {
			return previous(request, via)
		}
		if len(via) >= 10 {
			return errRedirectLimit
		}
		return nil
	}
	return &client
}

// FetchInto downloads a reseed archive, parses verified RouterInfos, and stores them in database.
func (c Client) FetchInto(ctx context.Context, endpoint string, database *controlplanenetdb.Database, seenAt uint64) (int, error) {
	if database == nil {
		return 0, errNilDatabase
	}
	candidates, err := c.fetchCandidates(ctx, endpoint, seenAt)
	if err != nil {
		return 0, err
	}
	slots := make(map[foundation.Hash]*dedupSlot, len(candidates))
	for _, candidate := range candidates {
		addCandidate(slots, candidate)
	}
	result := c.ingestCandidates(slots, database, seenAt)
	if result.Admitted == 0 {
		return 0, ErrNoRouterInfos
	}
	return result.Admitted, nil
}

// reseedCandidate is a parsed but signature-unverified RouterInfo collected
// from one authenticated archive. info.Bytes() points to an owned copy so the
// candidate outlives archive processing.
type reseedCandidate struct {
	info   foundation.NetworkDatabaseRouterInfo
	source int
}

// fetchCandidates downloads one reseed archive, authenticates the SU3/ZIP
// container, and returns candidates that pass the cheap pre-signature cuts:
// netId match and reseed freshness. RouterInfo signatures stay unverified until
// cross-archive deduplication selects the newest candidates per hash.
func (c Client) fetchCandidates(ctx context.Context, endpoint string, seenAt uint64) ([]reseedCandidate, error) {
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if err := validateEndpoint(parsedURL, c.AllowHTTP, c.NetworkID); err != nil {
		return nil, err
	}
	client := c.httpClientFor(parsedURL)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", ReseedUserAgent)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reseed: unexpected HTTP status %s", response.Status)
	}
	maxArchive, maxInfos, maxTotal := c.limits()
	if response.ContentLength > maxArchive {
		return nil, ErrArchiveTooLarge
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, maxArchive+1))
	if err != nil {
		return nil, err
	}
	if int64(len(archive)) > maxArchive {
		return nil, ErrArchiveTooLarge
	}
	payload := archive
	if len(archive) >= 7 && bytes.Equal(archive[:7], []byte{'I', '2', 'P', 's', 'u', '3', 0}) {
		signers := c.SU3Signers
		if signers == nil {
			now := time.Now()
			if c.Now != nil {
				now = c.Now()
			}
			signers, err = DefaultSU3SignersAt(now)
			if err != nil {
				return nil, err
			}
		}
		payload, err = VerifySU3(archive, signers, maxArchive)
		if err != nil {
			return nil, err
		}
	} else if !c.allowUnsignedZIP {
		return nil, ErrUnsignedArchive
	}
	reader, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return nil, err
	}

	files := make([]*zip.File, 0, min(len(reader.File), maxInfos))
	var total uint64
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || !strings.HasPrefix(path.Base(file.Name), "routerInfo-") {
			continue
		}
		if len(files) == maxInfos {
			return nil, ErrTooManyEntries
		}
		files = append(files, file)
		if file.UncompressedSize64 == 0 || file.UncompressedSize64 > uint64(foundation.NetworkDatabaseMaxRouterInfoBytes) {
			continue
		}
		total += file.UncompressedSize64
		if total > uint64(maxTotal) {
			return nil, ErrArchiveTooLarge
		}
	}
	var candidates []reseedCandidate
	for _, file := range files {
		if file.UncompressedSize64 == 0 || file.UncompressedSize64 > uint64(foundation.NetworkDatabaseMaxRouterInfoBytes) {
			continue
		}
		data, lease, readErr := readRouterInfo(file)
		if readErr != nil {
			continue
		}
		owned := make([]byte, len(data))
		copy(owned, data)
		lease.Release()
		info, parseErr := foundation.NetworkDatabaseParseRouterInfo(owned)
		if parseErr == nil && !routerInfoMatchesNetwork(info, c.NetworkID) {
			continue
		}
		if parseErr == nil && controlplanenetdb.ReseedRouterInfoFresh(info, seenAt) != nil {
			continue
		}
		if parseErr == nil {
			candidates = append(candidates, reseedCandidate{info: info})
		}
	}
	if len(candidates) == 0 {
		return nil, ErrNoRouterInfos
	}
	return candidates, nil
}

// dedupSlot retains the two most recent candidates for one router hash. The
// runner-up survives a forged-newest attack: if the freshest candidate fails
// signature verification, the second falls back instead of losing the router.
type dedupSlot struct {
	best     reseedCandidate
	fallback reseedCandidate
	count    int
}

func addCandidate(slots map[foundation.Hash]*dedupSlot, candidate reseedCandidate) {
	hash := candidate.info.Hash()
	slot, ok := slots[hash]
	if !ok {
		slots[hash] = &dedupSlot{best: candidate, count: 1}
		return
	}
	slot.count++
	if candidate.info.Published >= slot.best.info.Published {
		slot.fallback = slot.best
		slot.best = candidate
	} else if slot.count == 2 || candidate.info.Published > slot.fallback.info.Published {
		slot.fallback = candidate
	}
}

// leadingZerosXOR mirrors distanceBucket: the number of shared leading bits
// between two router hashes, i.e. the local K-bucket index of the candidate.
func leadingZerosXOR(a, b foundation.Hash) int {
	lz := 0
	for i := 0; i < len(a); i++ {
		delta := a[i] ^ b[i]
		if delta != 0 {
			return lz + bits.LeadingZeros8(delta)
		}
		lz += 8
	}
	return controlplanenetdb.BucketCount - 1
}

// ingressSubnet identifies one claimed subnet slot inside a local K-bucket.
// The first byte tags the address family so a /16 and a /48 can never alias.
type ingressSubnet [8]byte

// ingressKey is a (local bucket, subnet) quota slot.
type ingressKey struct {
	bucket uint16
	subnet ingressSubnet
}

// ingressGuard enforces per-local-bucket admission quotas: at most M routers
// per subnet per bucket and at most the bucket capacity overall. Unlike the
// retired per-archive guard, the quota follows the local router's own distance
// bands, which is where an eclipse attacker would concentrate keys.
type ingressGuard struct {
	subnetQuota int
	bucketLimit int
	subnetUse   map[ingressKey]int
	bucketUse   [256]int
}

func newIngressGuard(subnetQuota, bucketLimit int) *ingressGuard {
	return &ingressGuard{subnetQuota: subnetQuota, bucketLimit: bucketLimit, subnetUse: make(map[ingressKey]int)}
}

func (g *ingressGuard) claim(bucket int, subnets []ingressSubnet) bool {
	if bucket < 0 || bucket >= len(g.bucketUse) || g.bucketUse[bucket] >= g.bucketLimit {
		return false
	}
	for _, subnet := range subnets {
		if g.subnetUse[ingressKey{bucket: uint16(bucket), subnet: subnet}] >= g.subnetQuota {
			return false
		}
	}
	for _, subnet := range subnets {
		g.subnetUse[ingressKey{bucket: uint16(bucket), subnet: subnet}]++
	}
	g.bucketUse[bucket]++
	return true
}

// ingressSubnetsOf returns the distinct subnet claims of a RouterInfo's
// contact addresses: IPv4 /16 and IPv6 /48 prefixes.
func ingressSubnetsOf(info foundation.NetworkDatabaseRouterInfo) []ingressSubnet {
	seen := make(map[ingressSubnet]struct{}, 4)
	var subnets []ingressSubnet
	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil || !ok {
			break
		}
		var host []byte
		options := address.Options.Iterator()
		for {
			key, value, ok, err := options.Next()
			if err != nil || !ok {
				break
			}
			if bytes.Equal(key, []byte("host")) {
				host = value
				break
			}
		}
		ip, err := netip.ParseAddr(string(host))
		if err != nil {
			continue
		}
		var subnet ingressSubnet
		if ip.Is4() {
			octets := ip.As4()
			subnet = ingressSubnet{1, octets[0], octets[1]}
		} else if ip.Is6() {
			octets := ip.As16()
			subnet = ingressSubnet{2, octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]}
		} else {
			continue
		}
		if _, dup := seen[subnet]; !dup {
			seen[subnet] = struct{}{}
			subnets = append(subnets, subnet)
		}
	}
	return subnets
}

// hasV2Transport reports whether the RouterInfo publishes at least one
// dialable NTCP2 or SSU2 address (transport style plus host/port options).
func hasV2Transport(info foundation.NetworkDatabaseRouterInfo) bool {
	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil || !ok {
			return false
		}
		style := string(address.TransportStyle)
		if style != "NTCP2" && style != "SSU2" {
			continue
		}
		var host, port bool
		options := address.Options.Iterator()
		for {
			key, _, ok, err := options.Next()
			if err != nil || !ok {
				break
			}
			switch string(key) {
			case "host":
				host = true
			case "port":
				port = true
			}
		}
		if host && port {
			return true
		}
	}
}

// bucketCandidate pairs a candidate with its precomputed identity hash and
// admission-priority flags so ordering never reparses RouterInfo bytes.
type bucketCandidate struct {
	candidate reseedCandidate
	hash      foundation.Hash
	floodfill bool
	v2        bool
}

// candidatePriority orders candidates by admission preference: floodfills
// first, then v2 transports, then newest published, then hash.
func candidatePriority(a, b bucketCandidate) int {
	if a.floodfill != b.floodfill {
		if a.floodfill {
			return -1
		}
		return 1
	}
	if a.v2 != b.v2 {
		if a.v2 {
			return -1
		}
		return 1
	}
	if a.candidate.info.Published != b.candidate.info.Published {
		return cmp.Compare(b.candidate.info.Published, a.candidate.info.Published)
	}
	return bytes.Compare(a.hash[:], b.hash[:])
}

// fpsOrderBucket greedily orders one local bucket's candidates so each pick
// maximizes XOR distance to the already-picked set, spreading admissions
// evenly across the bucket's subspace. Distance ties break on admission
// priority. At most picks entries are ordered; the rest append unordered.
func fpsOrderBucket(cands []bucketCandidate, picks int, out []reseedCandidate) []reseedCandidate {
	n := len(cands)
	if n == 0 {
		return out
	}
	if picks > n {
		picks = n
	}
	maxLZ := make([]int, n)
	for i := range maxLZ {
		maxLZ[i] = -1
	}
	used := make([]bool, n)

	anchor := 0
	for i := 1; i < n; i++ {
		if candidatePriority(cands[i], cands[anchor]) < 0 {
			anchor = i
		}
	}
	commit := func(i int) {
		out = append(out, cands[i].candidate)
		used[i] = true
		for j := 0; j < n; j++ {
			if used[j] {
				continue
			}
			if lz := leadingZerosXOR(cands[j].hash, cands[i].hash); lz > maxLZ[j] {
				maxLZ[j] = lz
			}
		}
	}
	commit(anchor)
	betterPick := func(i, j int) bool {
		if maxLZ[i] != maxLZ[j] {
			return maxLZ[i] < maxLZ[j]
		}
		return candidatePriority(cands[i], cands[j]) < 0
	}
	for picked := 1; picked < picks; picked++ {
		best := -1
		for i := 0; i < n; i++ {
			if used[i] {
				continue
			}
			if best == -1 || betterPick(i, best) {
				best = i
			}
		}
		if best < 0 {
			break
		}
		commit(best)
	}
	for i := 0; i < n; i++ {
		if !used[i] {
			out = append(out, cands[i].candidate)
		}
	}
	return out
}

// orderByLocalBuckets groups deduplicated candidates by their local K-bucket
// index and emits each bucket in max-min XOR spread order, so the admission
// pass fills every bucket's subspace evenly rather than clustering picks in
// populated hash ranges. Bucket quotas make cross-bucket order irrelevant, so
// buckets emit sequentially.
func orderByLocalBuckets(slots map[foundation.Hash]*dedupSlot, local foundation.Hash, pickLimit int) []reseedCandidate {
	var buckets [256][]bucketCandidate
	for hash, slot := range slots {
		info := slot.best.info
		b := leadingZerosXOR(local, hash)
		buckets[b] = append(buckets[b], bucketCandidate{
			candidate: slot.best,
			hash:      hash,
			floodfill: foundation.NetworkDatabaseIsFloodfill(info),
			v2:        hasV2Transport(info),
		})
	}
	ordered := make([]reseedCandidate, 0, len(slots))
	picks := max(1, pickLimit) * 4 // order a margin past the quota for rejections
	for b := range buckets {
		ordered = fpsOrderBucket(buckets[b], picks, ordered)
	}
	return ordered
}

// ingestCandidates is phase two of reseed admission: deduplicated candidates
// are ordered by per-local-bucket farthest-point spread, signature-verified
// once, gated on per-local-bucket subnet quotas, then stored. Floodfill
// anchors closest to the local hash are retained for post-reseed connectivity
// checks.
func (c Client) ingestCandidates(slots map[foundation.Hash]*dedupSlot, database *controlplanenetdb.Database, seenAt uint64) ReseedResult {
	local := database.Routers().Local()
	ordered := orderByLocalBuckets(slots, local, c.bucketAdmitLimit())
	guard := newIngressGuard(c.bucketSubnetQuota(), c.bucketAdmitLimit())
	anchorLimit := c.verifyAnchorCount()
	var anchors []foundation.Hash
	admitted := 0
	for _, candidate := range ordered {
		hash := candidate.info.Hash()
		bucket := leadingZerosXOR(local, hash)
		if guard.bucketUse[bucket] >= guard.bucketLimit {
			continue // bucket already full: skip signature verification
		}
		if ok, _ := candidate.info.Verify(); !ok {
			slot := slots[hash]
			if slot == nil || slot.count < 2 {
				continue
			}
			candidate = slot.fallback
			if ok, _ := candidate.info.Verify(); !ok {
				continue
			}
		}
		if !guard.claim(bucket, ingressSubnetsOf(candidate.info)) {
			continue
		}
		if database.AdmitVerifiedReseedRouterInfo(candidate.info, seenAt) != nil {
			continue
		}
		admitted++
		if foundation.NetworkDatabaseIsFloodfill(candidate.info) {
			anchors = insertAnchor(anchors, local, hash, anchorLimit)
		}
	}
	return ReseedResult{Admitted: admitted, Anchors: anchors}
}

// insertAnchor keeps anchors sorted by XOR distance to the local hash,
// retaining at most limit entries.
func insertAnchor(anchors []foundation.Hash, local, hash foundation.Hash, limit int) []foundation.Hash {
	dist := leadingZerosXOR(local, hash)
	index := len(anchors)
	for i, anchor := range anchors {
		if leadingZerosXOR(local, anchor) > dist {
			index = i
			break
		}
	}
	anchors = append(anchors, foundation.Hash{})
	copy(anchors[index+1:], anchors[index:])
	anchors[index] = hash
	if len(anchors) > limit {
		anchors = anchors[:limit]
	}
	return anchors
}

func routerInfoMatchesNetwork(info foundation.NetworkDatabaseRouterInfo, networkID uint8) bool {
	iterator := info.Options.Iterator()
	for {
		key, value, ok, err := iterator.Next()
		if err != nil || !ok {
			return false
		}
		if string(key) == "netId" {
			id, err := strconv.ParseUint(string(value), 10, 8)
			return err == nil && uint8(id) == networkID
		}
	}
}

type fetchResult struct {
	index      int
	candidates []reseedCandidate
	err        error
}

type fetchAnyState struct {
	client          Client
	ctx             context.Context
	endpoints       []string
	seenAt          uint64
	results         chan fetchResult
	failures        []error
	slots           map[foundation.Hash]*dedupSlot
	next            int
	active          int
	limit           int
	target          int
	successes       int
	priorityPending int
	mergeExpired    bool
}

func (state *fetchAnyState) launch() {
	index := state.next
	state.next++
	state.active++
	go func() {
		candidates, err := state.client.fetchCandidates(state.ctx, state.endpoints[index], state.seenAt)
		for i := range candidates {
			candidates[i].source = index
		}
		state.results <- fetchResult{index: index, candidates: candidates, err: err}
	}()
}

func (state *fetchAnyState) drain() {
	for state.active != 0 {
		<-state.results
		state.active--
	}
}

func (state *fetchAnyState) launchNext(timer *time.Timer, delay time.Duration) {
	if state.next >= len(state.endpoints) || state.active >= state.limit {
		return
	}
	state.launch()
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(delay)
}

func isPriorityReseedHost(host string) bool {
	h := strings.ToLower(host)
	return h == "hotseed.gosuda.org" || strings.HasSuffix(h, ".hotseed.gosuda.org")
}

func isPriorityReseedEndpoint(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	return isPriorityReseedHost(parsed.Hostname())
}

// FetchAny fetches reseed archives across multiple endpoints until enough
// unique candidates are collected or sufficient independent sources succeed,
// then runs one deduplicated, quota-gated admission pass. Prioritized
// endpoints (such as hotseed.gosuda.org) are all queried in parallel and
// their archives are merged — ingestion waits for every priority response so
// a slow source still contributes coverage, bounded by Client.MergeWait —
// before hedging against the remaining random endpoints. When MergeWait is
// negative, the first successful priority response finishes the fetch.
func (c Client) FetchAny(ctx context.Context, endpoints []string, database *controlplanenetdb.Database, seenAt uint64) (ReseedResult, error) {
	if database == nil {
		return ReseedResult{}, errNilDatabase
	}
	if len(endpoints) == 0 {
		return ReseedResult{}, ErrNoRouterInfos
	}

	var priority []string
	var fallbacks []string
	for _, ep := range endpoints {
		if isPriorityReseedEndpoint(ep) {
			priority = append(priority, ep)
		} else {
			fallbacks = append(fallbacks, ep)
		}
	}
	if len(fallbacks) > 1 {
		rand.Shuffle(len(fallbacks), func(i, j int) {
			fallbacks[i], fallbacks[j] = fallbacks[j], fallbacks[i]
		})
	}
	ordered := append(priority, fallbacks...)

	child, cancel := context.WithCancel(ctx)
	defer cancel()
	target := c.targetRouterInfos()
	limit := max(DefaultParallelFetches, parallelism.Workers(len(ordered)))
	state := fetchAnyState{
		client:          c,
		ctx:             child,
		endpoints:       ordered,
		seenAt:          seenAt,
		results:         make(chan fetchResult, len(ordered)),
		failures:        make([]error, len(ordered)),
		slots:           make(map[foundation.Hash]*dedupSlot),
		limit:           limit,
		target:          target,
		priorityPending: len(priority),
	}

	finish := func() ReseedResult {
		cancel()
		state.drain()
		return c.ingestCandidates(state.slots, database, seenAt)
	}
	done := func() bool {
		return len(state.slots) >= state.target ||
			state.successes >= DefaultMaxSuccessfulReseed ||
			(state.next >= len(state.endpoints) && state.active == 0)
	}

	hasPriority := len(priority) > 0
	initialParallel := min(DefaultParallelFetches, len(ordered))
	if hasPriority {
		initialParallel = len(priority)
	}
	for range initialParallel {
		state.launch()
	}
	hedgeDelay := time.Second
	if hasPriority {
		hedgeDelay = 2 * time.Second
	} else if c.HTTPClient != nil && c.HTTPClient.Timeout > 0 {
		hedgeDelay = max(time.Millisecond, c.HTTPClient.Timeout/time.Duration(len(ordered)))
	}
	timer := time.NewTimer(hedgeDelay)
	defer timer.Stop()

	mergeWait := c.mergeWait()
	var mergeC <-chan time.Time
	if hasPriority && mergeWait > 0 {
		mergeTimer := time.NewTimer(mergeWait)
		defer mergeTimer.Stop()
		mergeC = mergeTimer.C
	}

	for state.active != 0 || state.next < len(ordered) {
		select {
		case outcome := <-state.results:
			state.active--
			if outcome.index < len(priority) {
				state.priorityPending--
			}
			if outcome.err != nil {
				state.failures[outcome.index] = outcome.err
				state.launchNext(timer, hedgeDelay)
				continue
			}
			state.successes++
			for _, candidate := range outcome.candidates {
				addCandidate(state.slots, candidate)
			}
			if mergeWait < 0 && outcome.index < len(priority) && len(state.slots) > 0 {
				return finish(), nil
			}
			waitingPriority := mergeWait > 0 && hasPriority && state.priorityPending > 0 && !state.mergeExpired
			if !waitingPriority && done() {
				return finish(), nil
			}
			state.launchNext(timer, hedgeDelay)
		case <-mergeC:
			state.mergeExpired = true
			if done() {
				return finish(), nil
			}
		case <-timer.C:
			if state.next < len(ordered) && state.active < state.limit {
				state.launch()
			}
			timer.Reset(hedgeDelay)
		case <-ctx.Done():
			cancel()
			state.drain()
			if len(state.slots) > 0 {
				return c.ingestCandidates(state.slots, database, seenAt), nil
			}
			return ReseedResult{}, ctx.Err()
		}
	}
	if len(state.slots) > 0 {
		return c.ingestCandidates(state.slots, database, seenAt), nil
	}
	compacted := state.failures[:0]
	for _, failure := range state.failures {
		if failure != nil {
			compacted = append(compacted, failure)
		}
	}
	return ReseedResult{}, errors.Join(compacted...)
}

func readRouterInfo(file *zip.File) ([]byte, *pool.Lease, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, nil, err
	}
	defer reader.Close()
	size := int(file.UncompressedSize64)
	lease, ok := pool.AcquireLease(size + 1)
	if !ok {
		return nil, nil, ErrArchiveTooLarge
	}
	data, _ := lease.Bytes(size + 1)
	read, err := io.ReadFull(reader, data[:size])
	if err != nil || read != size {
		lease.Release()
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, nil, err
	}
	one, err := reader.Read(data[size:])
	if one != 0 || (err != nil && err != io.EOF) {
		lease.Release()
		if err == nil {
			err = ErrArchiveTooLarge
		}
		return nil, nil, err
	}
	return data[:size], lease, nil
}
