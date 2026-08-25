package networkdatabase

import "gosuda.org/ivnp/state"

import (
	"fmt"
	"gosuda.org/ivnp/foundation"
)

// LoadStaticRouterInfos loads exact signed RouterInfo files into database. Every
// configured file is required to parse, verify, and satisfy the live transport
// freshness window; callers should invoke it after durable NetDB restoration
// and before starting network reseed.
func LoadStaticRouterInfos(paths []string, database *Database, nowMillis uint64) ([]foundation.Hash, error) {
	if database == nil {
		return nil, fmt.Errorf("netdb: static bootstrap database is nil")
	}
	hashes := make([]foundation.Hash, 0, len(paths))
	for _, path := range paths {
		file, _, err := state.FilesystemStoreOpenRegular(path)
		if err != nil {
			return hashes, fmt.Errorf("netdb: open static RouterInfo %q: %w", path, err)
		}
		wire, readErr := state.FilesystemStoreReadBoundedFile(file, int64(MaxRouterInfoBytes))
		closeErr := file.Close()
		if readErr != nil {
			return hashes, fmt.Errorf("netdb: read static RouterInfo %q: %w", path, readErr)
		}
		if closeErr != nil {
			return hashes, fmt.Errorf("netdb: close static RouterInfo %q: %w", path, closeErr)
		}
		info, err := ParseRouterInfo(wire)
		if err != nil {
			return hashes, fmt.Errorf("netdb: parse static RouterInfo %q: %w", path, err)
		}
		if err = database.AdmitRouterInfo(info, false, nowMillis); err != nil {
			return hashes, fmt.Errorf("netdb: verify static RouterInfo %q: %w", path, err)
		}
		hashes = append(hashes, info.Hash())
	}
	return hashes, nil
}
