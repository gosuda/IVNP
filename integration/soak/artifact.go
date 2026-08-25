package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const artifactSchema = "ivnp.soak/v1"

type manifest struct {
	Schema              string            `json:"schema"`
	RunID               string            `json:"run_id"`
	Mode                string            `json:"mode"`
	Scope               string            `json:"scope"`
	Policy              string            `json:"policy"`
	GitRevision         string            `json:"git_revision"`
	GitDirty            bool              `json:"git_dirty"`
	BinarySHA256        string            `json:"binary_sha256"`
	Images              map[string]string `json:"images"`
	ConfigSHA256        string            `json:"config_sha256"`
	GoVersion           string            `json:"go_version"`
	GOOS                string            `json:"goos"`
	GOARCH              string            `json:"goarch"`
	Kernel              string            `json:"kernel"`
	CPUs                int               `json:"cpus"`
	GOMAXPROCS          int               `json:"gomaxprocs"`
	Seed                int64             `json:"seed"`
	Endpoints           map[string]string `json:"endpoints"`
	RequestedSeconds    int64             `json:"requested_seconds"`
	StartedUTC          time.Time         `json:"started_utc"`
	MeasurementStartUTC time.Time         `json:"measurement_start_utc,omitempty"`
	MeasurementEndUTC   time.Time         `json:"measurement_end_utc,omitempty"`
	MeasuredSeconds     float64           `json:"measured_monotonic_seconds"`
	RestartVerified     bool              `json:"restart_verified"`
}

type event struct {
	At      time.Time      `json:"at"`
	Elapsed float64        `json:"elapsed_seconds,omitempty"`
	Type    string         `json:"type"`
	Fields  map[string]any `json:"fields,omitempty"`
}

type criterion struct {
	ID          string         `json:"id"`
	Status      string         `json:"status"`
	Scope       string         `json:"scope"`
	Assertion   string         `json:"assertion"`
	Observed    map[string]any `json:"observed"`
	Policy      string         `json:"policy"`
	Evidence    []string       `json:"evidence"`
	Limitations []string       `json:"limitations"`
}

type summary struct {
	Schema    string      `json:"schema"`
	RunID     string      `json:"run_id"`
	Mode      string      `json:"mode"`
	Scope     string      `json:"scope"`
	Verdict   string      `json:"verdict"`
	E5OneHour string      `json:"E5_ONE_HOUR"`
	Reason    string      `json:"reason,omitempty"`
	Criteria  []criterion `json:"criteria"`
}

type artifactRecorder struct {
	dir     string
	mu      sync.Mutex
	events  *os.File
	eventW  *bufio.Writer
	samples *os.File
	sampleW *bufio.Writer
}

func newArtifactRecorder(dir string) (*artifactRecorder, error) {
	if dir == "" {
		return nil, errors.New("artifact directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	events, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	samples, err := os.OpenFile(filepath.Join(dir, "samples.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		events.Close()
		return nil, err
	}
	return &artifactRecorder{dir: dir, events: events, eventW: bufio.NewWriterSize(events, 32<<10), samples: samples, sampleW: bufio.NewWriterSize(samples, 64<<10)}, nil
}

func (r *artifactRecorder) writeEvent(value event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := json.NewEncoder(r.eventW).Encode(value); err != nil {
		return err
	}
	return r.flushLocked(r.eventW, r.events)
}

func (r *artifactRecorder) writeSample(value any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := json.NewEncoder(r.sampleW).Encode(value); err != nil {
		return err
	}
	return r.flushLocked(r.sampleW, r.samples)
}

func (r *artifactRecorder) flushLocked(writer *bufio.Writer, file *os.File) error {
	if err := writer.Flush(); err != nil {
		return err
	}
	return file.Sync()
}

func (r *artifactRecorder) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result error
	if err := r.eventW.Flush(); err != nil {
		result = err
	}
	if err := r.sampleW.Flush(); result == nil && err != nil {
		result = err
	}
	if err := r.events.Close(); result == nil && err != nil {
		result = err
	}
	if err := r.samples.Close(); result == nil && err != nil {
		result = err
	}
	return result
}

func writeAtomicJSON(path string, value any) error {
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(value); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(temporary)
		return err
	}
	return os.Rename(temporary, path)
}

func writeChecksums(dir string) error {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() == "checksums.sha256" || strings.HasSuffix(entry.Name(), ".tmp") {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(paths)
	file, err := os.OpenFile(filepath.Join(dir, "checksums.sha256"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, path := range paths {
		digest, digestErr := sha256File(path)
		if digestErr != nil {
			return digestErr
		}
		relative, relativeErr := filepath.Rel(dir, path)
		if relativeErr != nil {
			return relativeErr
		}
		if _, err = fmt.Fprintf(file, "%s  %s\n", digest, filepath.ToSlash(relative)); err != nil {
			return err
		}
	}
	return file.Sync()
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err = io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
