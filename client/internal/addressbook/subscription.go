package addressbook

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"gosuda.org/ivnp/internal/parallelism"
)

var (
	errTooManyRedirects           = errors.New("addressbook: too many redirects")
	errCrossOriginRedirect        = errors.New("addressbook: cross-origin redirect")
	errNotModifiedWithoutSnapshot = errors.New("addressbook: 304 without source snapshot")
)

func subscriptionURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || u.Host == "" {
		return nil, ErrConfig
	}
	if strings.EqualFold(u.Scheme, "https") {
		return u, nil
	}
	if strings.EqualFold(u.Scheme, "http") {
		host := u.Hostname()
		if strings.HasSuffix(strings.ToLower(host), ".i2p") || strings.EqualFold(host, "localhost") || host == "127.0.0.1" || host == "::1" {
			return u, nil
		}
	}
	return nil, ErrConfig
}

func (s *Service) refresh(parent context.Context) error {
	client := s.config.HTTPClient
	if client == nil {
		client = &http.Client{Transport: &http.Transport{Proxy: nil, DisableCompression: false, ForceAttemptHTTP2: true}}
	} else {
		copyClient := *client
		client = &copyClient
	}
	client.Timeout = s.config.RequestTimeout
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > s.config.MaxRedirects {
			return errTooManyRedirects
		}
		if _, err := subscriptionURL(request.URL.String()); err != nil {
			return err
		}
		if len(via) != 0 && (!strings.EqualFold(request.URL.Scheme, via[0].URL.Scheme) || !strings.EqualFold(request.URL.Host, via[0].URL.Host)) {
			return errCrossOriginRedirect
		}
		return nil
	}

	s.mu.Lock()
	previous := cloneEntries(s.remote)
	previousOwners := cloneEntries(s.owners)
	sources := cloneSources(s.sources)
	etags := cloneEntries(s.etag)
	modified := cloneEntries(s.modified)
	s.mu.Unlock()
	type fetchJob struct {
		raw          string
		haveSnapshot bool
		etag         string
		modified     string
	}
	type fetchResult struct {
		entries   map[string]string
		etag      string
		modified  string
		unchanged bool
		err       error
	}
	jobs := make(chan int)
	fetches := make([]fetchJob, len(s.config.Subscriptions))
	results := make([]fetchResult, len(fetches))
	for index, raw := range s.config.Subscriptions {
		_, haveSnapshot := sources[raw]
		fetches[index] = fetchJob{raw: raw, haveSnapshot: haveSnapshot, etag: etags[raw], modified: modified[raw]}
	}
	workers := parallelism.Workers(len(fetches))
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for index := range jobs {
				job := fetches[index]
				entries, etag, lastModified, unchanged, err := s.fetchSubscription(parent, client, job.raw, job.haveSnapshot, job.etag, job.modified)
				results[index] = fetchResult{entries: entries, etag: etag, modified: lastModified, unchanged: unchanged, err: err}
			}
		}()
	}
	for index := range fetches {
		jobs <- index
	}
	close(jobs)
	group.Wait()
	// A failed subscription keeps its last good snapshot and does not hold
	// back the others; its error still schedules an early retry.
	var fetchErrs []error
	for index, result := range results {
		raw := fetches[index].raw
		if result.err != nil {
			fetchErrs = append(fetchErrs, result.err)
			continue
		}
		if result.unchanged {
			continue
		}
		sources[raw] = result.entries
		if result.etag != "" {
			etags[raw] = result.etag
		} else {
			delete(etags, raw)
		}
		if result.modified != "" {
			modified[raw] = result.modified
		} else {
			delete(modified, raw)
		}
	}
	if len(fetchErrs) == len(results) || parent.Err() != nil {
		return errors.Join(append(fetchErrs, parent.Err())...)
	}
	remote, owners, err := s.mergeBindings(previous, previousOwners, sources)
	if err != nil {
		return err
	}
	if err = saveState(s.config.StatePath, persistedState{Entries: remote, Owners: owners, Sources: sources, ETag: etags, Modified: modified}, s.config.MaxFileBytes); err != nil {
		return err
	}
	s.mu.Lock()
	s.remote, s.owners, s.sources, s.etag, s.modified = remote, owners, sources, etags, modified
	s.publish()
	s.mu.Unlock()
	return errors.Join(fetchErrs...)
}

// maxLoggedConflicts bounds the names listed in one conflict report, so a
// hostile feed cannot flood the log.
const maxLoggedConflicts = 8

// mergeBindings builds the remote address book the way the Java I2P
// addressbook does: a name bound by a subscription keeps its first
// destination for as long as that subscription stays configured, even if the
// feed later drops or re-points it. Names nobody has bound yet go to the first
// configured subscription that lists them. A feed entry that disagrees with an
// existing binding is ignored and reported. IVNP does not accept signed
// changedest records, so only local hosts files or unsubscribing can change a
// bound name.
func (s *Service) mergeBindings(previous, previousOwners map[string]string, sources map[string]map[string]string) (map[string]string, map[string]string, error) {
	configured := make(map[string]struct{}, len(s.config.Subscriptions))
	for _, raw := range s.config.Subscriptions {
		configured[raw] = struct{}{}
	}
	remote := make(map[string]string, len(previous))
	owners := make(map[string]string, len(previous))
	for name, destination := range previous {
		owner := previousOwners[name]
		if _, ok := configured[owner]; !ok {
			continue
		}
		if _, local := s.local[name]; local {
			continue
		}
		remote[name], owners[name] = destination, owner
	}
	for _, raw := range s.config.Subscriptions {
		if err := s.bindSource(raw, sources[raw], remote, owners); err != nil {
			return nil, nil, err
		}
	}
	return remote, owners, nil
}

// bindSource adds the unbound names of one subscription snapshot to remote
// and reports entries that disagree with an existing binding.
func (s *Service) bindSource(raw string, entries, remote, owners map[string]string) error {
	conflicts := 0
	var sample []string
	for name, destination := range entries {
		if _, local := s.local[name]; local {
			continue
		}
		bound, exists := remote[name]
		if !exists {
			if len(remote) >= s.config.MaxEntries {
				return ErrConfig
			}
			remote[name], owners[name] = destination, raw
			continue
		}
		if bound == destination {
			continue
		}
		conflicts++
		if len(sample) < maxLoggedConflicts {
			sample = append(sample, name)
		}
	}
	if conflicts != 0 {
		s.logger.Warn("addressbook: subscription conflicts with existing bindings ignored", "subscription", raw, "conflicts", conflicts, "names", sample)
	}
	return nil
}

func (s *Service) fetchSubscription(parent context.Context, client *http.Client, raw string, haveSnapshot bool, etag, modified string) (map[string]string, string, string, bool, error) {
	u, err := subscriptionURL(raw)
	if err != nil {
		return nil, "", "", false, err
	}
	ctx, cancel := context.WithTimeout(parent, s.config.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", "", false, err
	}
	request.Header.Set("Accept", "text/plain")
	if haveSnapshot {
		if etag != "" {
			request.Header.Set("If-None-Match", etag)
		}
		if modified != "" {
			request.Header.Set("If-Modified-Since", modified)
		}
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, "", "", false, err
	}
	if response.StatusCode == http.StatusNotModified {
		_ = response.Body.Close()
		if !haveSnapshot {
			return nil, "", "", false, errNotModifiedWithoutSnapshot
		}
		return nil, "", "", true, nil
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, "", "", false, fmt.Errorf("addressbook: subscription HTTP status %d", response.StatusCode)
	}
	limited := io.LimitReader(response.Body, s.config.MaxResponseBytes+1)
	data, readErr := io.ReadAll(limited)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		return nil, "", "", false, errors.Join(readErr, closeErr)
	}
	defer clear(data)
	if int64(len(data)) > s.config.MaxResponseBytes {
		return nil, "", "", false, ErrConfig
	}
	entries, err := parseSubscriptionHosts(strings.NewReader(string(data)), s.config.MaxResponseBytes, s.config.MaxEntries)
	if err != nil {
		return nil, "", "", false, err
	}
	return entries, response.Header.Get("ETag"), response.Header.Get("Last-Modified"), false, nil
}

func cloneEntries(source map[string]string) map[string]string {
	cloned := make(map[string]string, len(source))
	maps.Copy(cloned, source)
	return cloned
}

func cloneSources(source map[string]map[string]string) map[string]map[string]string {
	cloned := make(map[string]map[string]string, len(source))
	for key, entries := range source {
		cloned[key] = cloneEntries(entries)
	}
	return cloned
}
