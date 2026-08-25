// Package reseed imports verified RouterInfos from standard I2P reseed ZIPs.
package reseed

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"gosuda.org/ivnp/internal/parallelism"
	"gosuda.org/ivnp/internal/pool"
	"gosuda.org/ivnp/protocol/netdb"
)

const (
	DefaultMaxArchiveBytes     = 1 << 20
	DefaultMaxRouterInfos      = 4_000
	DefaultMaxTotalRouterBytes = 64 << 20
	ReseedUserAgent            = "Wget/1.11.4"
)

var (
	ErrInsecureURL     = errors.New("reseed: HTTPS endpoint required")
	ErrInvalidURL      = errors.New("reseed: endpoint must have exactly the netid=2 query and no credentials or fragment")
	ErrUnsafeRedirect  = errors.New("reseed: unsafe redirect")
	ErrArchiveTooLarge = errors.New("reseed: archive exceeds configured limit")
	ErrTooManyEntries  = errors.New("reseed: router info count exceeds configured limit")
	ErrNoRouterInfos   = errors.New("reseed: archive contained no admissible router infos")
	ErrUnsignedArchive = errors.New("reseed: authenticated SU3 archive required")
)

// Client fetches one reseed archive at a time. Limits are enforced before
// decompression, and each ZIP entry has an independent I2NP-size bound.
type Client struct {
	HTTPClient          *http.Client
	MaxArchiveBytes     int64
	MaxRouterInfos      int
	MaxTotalRouterBytes int64
	SU3Signers          map[string]SU3Signer
	Now                 func() time.Time
	AllowHTTP           bool // only for controlled tests or explicit local deployments
	// allowUnsignedZIP is deliberately package-private. Tests may enable it for
	// hand-built RouterInfo fixtures; daemon and external production callers
	// cannot bypass the SU3 authorization boundary.
	allowUnsignedZIP bool
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

func validateEndpoint(endpoint *url.URL, allowHTTP bool) error {
	if endpoint == nil || endpoint.Hostname() == "" || endpoint.User != nil ||
		endpoint.Fragment != "" || endpoint.RawQuery != "netid=2" || endpoint.ForceQuery {
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
		if err := validateEndpoint(request.URL, c.AllowHTTP); err != nil {
			return fmt.Errorf("%w: %v", ErrUnsafeRedirect, err)
		}
		if previous != nil {
			return previous(request, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &client
}

// FetchInto downloads endpoint, verifies each RouterInfo, and retains valid
// entries in database. Invalid peers are skipped; archive-level violations fail
// the whole fetch because they indicate a malformed or hostile source.
func (c Client) FetchInto(ctx context.Context, endpoint string, database *netdb.Database, seenAt uint64) (int, error) {
	if database == nil {
		return 0, errors.New("reseed: nil database")
	}
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return 0, err
	}
	if err := validateEndpoint(parsedURL, c.AllowHTTP); err != nil {
		return 0, err
	}
	client := c.httpClientFor(parsedURL)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("User-Agent", ReseedUserAgent)
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("reseed: unexpected HTTP status %s", response.Status)
	}
	maxArchive, maxInfos, maxTotal := c.limits()
	if response.ContentLength > maxArchive {
		return 0, ErrArchiveTooLarge
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, maxArchive+1))
	if err != nil {
		return 0, err
	}
	if int64(len(archive)) > maxArchive {
		return 0, ErrArchiveTooLarge
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
				return 0, err
			}
		}
		payload, err = VerifySU3(archive, signers, maxArchive)
		if err != nil {
			return 0, err
		}
	} else if !c.allowUnsignedZIP {
		return 0, ErrUnsignedArchive
	}
	reader, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return 0, err
	}

	candidates := make([]*zip.File, 0, min(len(reader.File), maxInfos))
	var total uint64
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || !strings.HasPrefix(path.Base(file.Name), "routerInfo-") {
			continue
		}
		if len(candidates) == maxInfos {
			return 0, ErrTooManyEntries
		}
		candidates = append(candidates, file)
		if file.UncompressedSize64 == 0 || file.UncompressedSize64 > uint64(netdb.MaxRouterInfoBytes) {
			continue
		}
		total += file.UncompressedSize64
		if total > uint64(maxTotal) {
			return 0, ErrArchiveTooLarge
		}
	}
	results := make([]bool, len(candidates))
	jobs := make(chan int)
	workers := parallelism.Workers(len(candidates))
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for index := range jobs {
				file := candidates[index]
				if file.UncompressedSize64 == 0 || file.UncompressedSize64 > uint64(netdb.MaxRouterInfoBytes) {
					continue
				}
				data, readErr := readRouterInfo(file)
				if readErr != nil {
					continue
				}
				info, parseErr := netdb.ParseRouterInfo(data)
				if parseErr == nil {
					parseErr = database.AdmitReseedRouterInfo(info, seenAt)
				}
				pool.Release(data)
				results[index] = parseErr == nil
			}
		}()
	}
	for index := range candidates {
		jobs <- index
	}
	close(jobs)
	group.Wait()
	accepted := 0
	for _, admitted := range results {
		if admitted {
			accepted++
		}
	}
	if accepted == 0 {
		return 0, ErrNoRouterInfos
	}
	return accepted, nil
}

// FetchAny hedges slow reseed endpoints while bounding active requests by the
// current CPU budget and endpoint backpressure. The first success cancels the
// remaining HTTP work.
func (c Client) FetchAny(ctx context.Context, endpoints []string, database *netdb.Database, seenAt uint64) (int, error) {
	if len(endpoints) == 0 {
		return 0, ErrNoRouterInfos
	}
	type result struct {
		index int
		count int
		err   error
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, len(endpoints))
	activeLimit := parallelism.Workers(len(endpoints))
	next, active := 0, 0
	launch := func() {
		index := next
		next++
		active++
		go func() {
			count, err := c.FetchInto(child, endpoints[index], database, seenAt)
			results <- result{index: index, count: count, err: err}
		}()
	}
	drain := func() {
		for active != 0 {
			<-results
			active--
		}
	}
	launch()
	failures := make([]error, len(endpoints))
	hedgeDelay := time.Second
	if c.HTTPClient != nil && c.HTTPClient.Timeout > 0 {
		hedgeDelay = max(time.Millisecond, c.HTTPClient.Timeout/time.Duration(len(endpoints)))
	}
	timer := time.NewTimer(hedgeDelay)
	defer timer.Stop()
	for active != 0 || next < len(endpoints) {
		select {
		case outcome := <-results:
			active--
			if outcome.err == nil {
				cancel()
				drain()
				return outcome.count, nil
			}
			failures[outcome.index] = outcome.err
			if next < len(endpoints) && active < activeLimit {
				launch()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(hedgeDelay)
			}
		case <-timer.C:
			if next < len(endpoints) && active < activeLimit {
				launch()
			}
			timer.Reset(hedgeDelay)
		case <-ctx.Done():
			cancel()
			drain()
			return 0, ctx.Err()
		}
	}
	compacted := failures[:0]
	for _, failure := range failures {
		if failure != nil {
			compacted = append(compacted, failure)
		}
	}
	return 0, errors.Join(compacted...)
}

func readRouterInfo(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	size := int(file.UncompressedSize64)
	data, ok := pool.Acquire(size + 1)
	if !ok {
		return nil, ErrArchiveTooLarge
	}
	read, err := io.ReadFull(reader, data[:size])
	if err != nil || read != size {
		pool.Release(data)
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	one, err := reader.Read(data[size:])
	if one != 0 || (err != nil && err != io.EOF) {
		pool.Release(data)
		if err == nil {
			err = ErrArchiveTooLarge
		}
		return nil, err
	}
	return data[:size], nil
}
