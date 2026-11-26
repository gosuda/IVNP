package addressbook

import (
	"encoding/json"
	"errors"
	"io"
	"os"

	"gosuda.org/ivnp/state"
)

var errStateSizeOverflow = errors.New("addressbook: state size limit overflows int")

// persistedState is the address book cache. Entries holds the merged remote
// bindings and Owners names the subscription that first bound each entry.
// Version 3 added Owners; older files have their owners inferred on load.
type persistedState struct {
	Version  int                          `json:"version"`
	Entries  map[string]string            `json:"entries"`
	Owners   map[string]string            `json:"owners,omitempty"`
	Sources  map[string]map[string]string `json:"sources,omitempty"`
	ETag     map[string]string            `json:"etag,omitempty"`
	Modified map[string]string            `json:"modified,omitempty"`
}

const persistedStateVersion = 3

func loadState(path string, maxBytes int64, maxEntries int) (persistedState, error) {
	file, err := os.Open(path)
	if err != nil {
		return persistedState{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBytes {
		return persistedState{}, ErrConfig
	}
	data := make([]byte, info.Size())
	if _, err = io.ReadFull(file, data); err != nil {
		return persistedState{}, err
	}
	var state persistedState
	err = json.Unmarshal(data, &state)
	invalidState := err != nil
	if !invalidState {
		invalidState = state.Version < 1 || state.Version > persistedStateVersion || len(state.Entries) > maxEntries
	}
	if invalidState {
		return persistedState{}, ErrConfig
	}
	validate := func(entries map[string]string) error {
		for name, destination := range entries {
			normalized, nameErr := normalizeName(name)
			canonical, ok := canonicalDestination(destination)
			if nameErr != nil || normalized != name || !ok || canonical != destination {
				return ErrConfig
			}
		}
		return nil
	}
	if validate(state.Entries) != nil {
		return persistedState{}, ErrConfig
	}
	for _, owner := range state.Owners {
		if u, ownerErr := subscriptionURL(owner); ownerErr != nil || u.String() != owner {
			return persistedState{}, ErrConfig
		}
	}
	total := 0
	for source, entries := range state.Sources {
		u, sourceErr := subscriptionURL(source)
		if sourceErr != nil || u.String() != source || len(entries) > maxEntries || validate(entries) != nil {
			return persistedState{}, ErrConfig
		}
		total += len(entries)
		if total > maxEntries*32 {
			return persistedState{}, ErrConfig
		}
	}
	if state.Entries == nil {
		state.Entries = make(map[string]string)
	}
	if state.Owners == nil {
		state.Owners = make(map[string]string)
	}
	if state.Sources == nil {
		state.Sources = make(map[string]map[string]string)
	}
	if state.ETag == nil {
		state.ETag = make(map[string]string)
	}
	if state.Modified == nil {
		state.Modified = make(map[string]string)
	}
	return state, nil
}

func saveState(path string, persisted persistedState, max int64) error {
	if path == "" {
		return nil
	}
	if err := ensureStateDir(path); err != nil {
		return err
	}
	persisted.Version = persistedStateVersion
	data, err := json.Marshal(persisted)
	if err != nil {
		return err
	}
	if max > int64(^uint(0)>>1) {
		return errStateSizeOverflow
	}
	return state.FilesystemStoreWriteAtomic(path, data, 0600, int(max))
}
