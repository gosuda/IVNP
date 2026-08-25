package addressbook

import (
	"encoding/json"
	"errors"
	"io"
	"os"

	"gosuda.org/ivnp/support/fsstore"
)

type persistedState struct {
	Version  int                          `json:"version"`
	Entries  map[string]string            `json:"entries"`
	Sources  map[string]map[string]string `json:"sources,omitempty"`
	ETag     map[string]string            `json:"etag,omitempty"`
	Modified map[string]string            `json:"modified,omitempty"`
}

func loadState(path string, maxBytes int64, maxEntries int) (map[string]string, map[string]map[string]string, map[string]string, map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, nil, nil, nil, ErrConfig
	}
	data := make([]byte, info.Size())
	if _, err = io.ReadFull(file, data); err != nil {
		return nil, nil, nil, nil, err
	}
	var state persistedState
	if err = json.Unmarshal(data, &state); err != nil || (state.Version != 1 && state.Version != 2) || len(state.Entries) > maxEntries {
		return nil, nil, nil, nil, ErrConfig
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
		return nil, nil, nil, nil, ErrConfig
	}
	total := 0
	for source, entries := range state.Sources {
		u, sourceErr := subscriptionURL(source)
		if sourceErr != nil || u.String() != source || len(entries) > maxEntries || validate(entries) != nil {
			return nil, nil, nil, nil, ErrConfig
		}
		total += len(entries)
		if total > maxEntries*32 {
			return nil, nil, nil, nil, ErrConfig
		}
	}
	if state.Entries == nil {
		state.Entries = make(map[string]string)
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
	return state.Entries, state.Sources, state.ETag, state.Modified, nil
}

func saveState(path string, entries map[string]string, sources map[string]map[string]string, etags, modified map[string]string, max int64) error {
	if path == "" {
		return nil
	}
	if err := ensureStateDir(path); err != nil {
		return err
	}
	data, err := json.Marshal(persistedState{Version: 2, Entries: entries, Sources: sources, ETag: etags, Modified: modified})
	if err != nil {
		return err
	}
	if max > int64(^uint(0)>>1) {
		return errors.New("addressbook: state size limit overflows int")
	}
	return fsstore.WriteAtomic(path, data, 0600, int(max))
}
