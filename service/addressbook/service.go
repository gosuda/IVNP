// Package addressbook provides the daemon-owned I2P hosts resolver.
package addressbook

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"gosuda.org/ivnp/service/clientapi"
)

var (
	ErrName        = errors.New("addressbook: invalid I2P name")
	ErrDestination = errors.New("addressbook: invalid Destination")
	ErrNotFound    = errors.New("addressbook: name not found")
	ErrConfig      = errors.New("addressbook: invalid configuration")
	ErrMutation    = errors.New("addressbook: signed mutation commands unsupported")
)

// Config bounds local loading, persisted remote state, and subscription work.
type Config struct {
	PrivateHostsPath string
	UserHostsPath    string
	HostsPath        string
	StatePath        string
	Subscriptions    []string
	RefreshInterval  time.Duration
	RetryInterval    time.Duration
	RequestTimeout   time.Duration
	MaxEntries       int
	MaxFileBytes     int64
	MaxResponseBytes int64
	MaxRedirects     int
	HTTPClient       *http.Client
}

type snapshot struct{ entries map[string]string }

// Service resolves from immutable snapshots; ordinary lookups never do I/O.
type Service struct {
	config   Config
	local    map[string]string
	remote   map[string]string
	sources  map[string]map[string]string
	current  atomic.Pointer[snapshot]
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	started  bool
	closed   bool
	etag     map[string]string
	modified map[string]string
}

func NewService(config Config) (*Service, error) {
	if config.MaxEntries <= 0 {
		config.MaxEntries = 100_000
	}
	if config.MaxFileBytes <= 0 {
		config.MaxFileBytes = 8 << 20
	}
	if config.MaxResponseBytes <= 0 {
		config.MaxResponseBytes = 16 << 20
	}
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = 12 * time.Hour
	}
	if config.RetryInterval <= 0 {
		config.RetryInterval = 5 * time.Minute
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 30 * time.Second
	}
	if config.MaxRedirects < 0 || config.MaxRedirects > 16 || len(config.Subscriptions) > 32 {
		return nil, ErrConfig
	}
	if config.MaxRedirects == 0 {
		config.MaxRedirects = 3
	}
	s := &Service{config: config, local: make(map[string]string), remote: make(map[string]string), sources: make(map[string]map[string]string), done: make(chan struct{}), etag: make(map[string]string), modified: make(map[string]string)}
	configured := make(map[string]struct{}, len(config.Subscriptions))
	for _, raw := range config.Subscriptions {
		u, err := subscriptionURL(raw)
		if err != nil || u.String() != raw {
			return nil, ErrConfig
		}
		if _, duplicate := configured[raw]; duplicate {
			return nil, ErrConfig
		}
		configured[raw] = struct{}{}
	}
	for _, path := range []string{config.PrivateHostsPath, config.UserHostsPath, config.HostsPath} {
		entries, err := loadHostsFile(path, config.MaxFileBytes, config.MaxEntries)
		if err != nil {
			return nil, err
		}
		for name, destination := range entries {
			if _, exists := s.local[name]; !exists {
				s.local[name] = destination
			}
		}
	}
	if config.StatePath != "" {
		_, sources, etags, modified, err := loadState(config.StatePath, config.MaxFileBytes, config.MaxEntries)
		if err == nil {
			for _, raw := range config.Subscriptions {
				source, present := sources[raw]
				if !present {
					continue
				}
				s.sources[raw] = cloneEntries(source)
				if value := etags[raw]; value != "" {
					s.etag[raw] = value
				}
				if value := modified[raw]; value != "" {
					s.modified[raw] = value
				}
				for name, destination := range source {
					if _, local := s.local[name]; local {
						continue
					}
					if _, exists := s.remote[name]; !exists {
						if len(s.remote) >= config.MaxEntries {
							return nil, ErrConfig
						}
						s.remote[name] = destination
					}
				}
			}
			// Rewrite the cache immediately so removed sources cannot become
			// authoritative again merely by being re-added before a verified
			// refresh. With no subscriptions this durably discards all remote
			// snapshots and conditional validators.
			if err = saveState(config.StatePath, s.remote, s.sources, s.etag, s.modified, config.MaxFileBytes); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			// A corrupt or obsolete cache is never authoritative. Local
			// sources remain available and verified refresh starts clean.
			s.remote = make(map[string]string)
			s.sources = make(map[string]map[string]string)
		}
	}
	s.publish()
	return s, nil
}

func (s *Service) publish() {
	entries := make(map[string]string, len(s.remote)+len(s.local))
	for name, destination := range s.remote {
		entries[name] = destination
	}
	for name, destination := range s.local {
		entries[name] = destination
	}
	s.current.Store(&snapshot{entries: entries})
}

func (s *Service) ResolveDestination(ctx context.Context, value string) (string, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return "", err
		}
	}
	if destination, ok := canonicalDestination(value); ok {
		return destination, nil
	}
	name, err := normalizeName(value)
	if err != nil {
		return "", err
	}
	book := s.current.Load()
	if book == nil {
		return "", ErrNotFound
	}
	destination, ok := book.entries[name]
	if !ok {
		return "", ErrNotFound
	}
	return destination, nil
}

func (s *Service) Start(parent context.Context) error {
	if parent == nil {
		parent = context.Background()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.started {
		return nil
	}
	s.started = true
	s.ctx, s.cancel = context.WithCancel(parent)
	go s.run()
	return nil
}

func (s *Service) run() {
	defer close(s.done)
	if len(s.config.Subscriptions) == 0 {
		<-s.ctx.Done()
		return
	}
	delay := time.Duration(0)
	for {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-s.ctx.Done():
				timer.Stop()
				return
			}
		}
		err := s.refresh(s.ctx)
		if err != nil {
			delay = s.config.RetryInterval
		} else {
			delay = s.config.RefreshInterval
		}
	}
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	} else {
		close(s.done)
	}
	s.mu.Unlock()
	return nil
}

func (s *Service) Wait() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	started := s.started
	done := s.done
	s.mu.Unlock()
	if started {
		<-done
	}
	return nil
}

func ensureStateDir(path string) error {
	if path == "" {
		return nil
	}
	return os.MkdirAll(filepath.Dir(path), 0700)
}

var _ clientapi.DestinationResolver = (*Service)(nil)
