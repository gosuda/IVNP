package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gosuda.org/ivnp/foundation"
)

// Crawler discovers and parses RouterInfos from local NetDB filesystem stores.
type Crawler struct {
	store *PeerStore
}

func NewCrawler(store *PeerStore) *Crawler {
	return &Crawler{store: store}
}

// CrawlDirectory scans a directory recursively for routerInfo files and imports valid ones.
func (c *Crawler) CrawlDirectory(dirPath string) (int, error) {
	if _, err := os.Stat(dirPath); err != nil {
		return 0, err
	}

	imported := 0
	err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasPrefix(name, "routerInfo-") && !strings.HasSuffix(name, ".dat") {
			return nil
		}

		if c.parseAndAdmit(path) {
			imported++
		}
		return nil
	})

	return imported, err
}

func (c *Crawler) parseAndAdmit(path string) bool {
	data, readErr := os.ReadFile(path)
	if readErr != nil || len(data) == 0 || len(data) > foundation.NetworkDatabaseMaxRouterInfoBytes {
		return false
	}

	info, parseErr := foundation.NetworkDatabaseParseRouterInfo(data)
	if parseErr != nil {
		return false
	}

	if ok, verifyErr := info.Verify(); !ok || verifyErr != nil {
		return false
	}

	c.store.AddOrUpdate(info, data)
	return true
}
