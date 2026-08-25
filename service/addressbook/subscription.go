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

func subscriptionURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || u.Host == "" {
		return nil, ErrConfig
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, ErrConfig
	}
	return u, nil
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
			return errors.New("addressbook: too many redirects")
		}
		if _, err := subscriptionURL(request.URL.String()); err != nil {
			return err
		}
		if len(via) != 0 && (!strings.EqualFold(request.URL.Scheme, via[0].URL.Scheme) || !strings.EqualFold(request.URL.Host, via[0].URL.Host)) {
			return errors.New("addressbook: cross-origin redirect")
		}
		return nil
	}

	sources := cloneSources(s.sources)
	etags := cloneEntries(s.etag)
	modified := cloneEntries(s.modified)
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
	for index, result := range results {
		if result.err != nil {
			return result.err
		}
		raw := fetches[index].raw
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
	remote := make(map[string]string)
	for _, raw := range s.config.Subscriptions {
		for name, destination := range sources[raw] {
			if _, local := s.local[name]; local {
				continue
			}
			if _, exists := remote[name]; !exists {
				if len(remote) >= s.config.MaxEntries {
					return ErrConfig
				}
				remote[name] = destination
			}
		}
	}
	if err := saveState(s.config.StatePath, remote, sources, etags, modified, s.config.MaxFileBytes); err != nil {
		return err
	}
	s.mu.Lock()
	s.remote, s.sources, s.etag, s.modified = remote, sources, etags, modified
	s.publish()
	s.mu.Unlock()
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
			return nil, "", "", false, errors.New("addressbook: 304 without source snapshot")
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
	entries, err := parseHosts(strings.NewReader(string(data)), s.config.MaxResponseBytes, s.config.MaxEntries)
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
