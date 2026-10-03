// Command dstoverlay generates the -overlay file used by the dst test suite.
//
// Go's sync primitives park on runtime semaphores whose wait reason is not
// considered "idle" by testing/synctest, so a goroutine blocked on a lock
// freezes the bubble's virtual clock. The patch below routes lock waits
// through runtime_SemacquireWaitGroup(addr, true) while the caller is inside a
// bubble, which parks with waitReasonSynctestWaitGroupWait and lets virtual
// time advance. Outside a bubble every patched call keeps its stock behavior.
//
// Patches are applied to the *current* GOROOT's sources, so the tool is
// portable across platforms and Go versions. Every anchor must match exactly
// once: a Go toolchain update that moves the code fails the tool loudly
// instead of silently producing a stock (non-durable) test binary.
//
// The overlay also adds sync.DurableMutexOverlay, a marker constant that dst
// test mains reference, so running dst tests without -overlay fails at
// compile time instead of hanging on a frozen virtual clock.
//
// The generated overlay is only ever passed to `go test -overlay=...` in dst
// runs; production builds are unaffected.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// patch describes one GOROOT file to rewrite.
type patch struct {
	// file is the path relative to GOROOT/src.
	file string
	// edits are applied in order; each anchor must occur exactly once.
	edits []edit
}

// edit replaces one occurrence of anchor with replacement.
type edit struct {
	anchor      string
	replacement string
}

// addition is a file the overlay adds to a GOROOT package.
type addition struct {
	// file is the path relative to GOROOT/src; it must not already exist.
	file    string
	content string
}

const (
	durableDecl = `// runtime_SemacquireWaitGroup is runtime_SemacquireMutex with the synctest
// durability flag: when synctestDurable is true the goroutine parks with
// waitReasonSynctestWaitGroupWait, which testing/synctest treats as idle, so
// the simulated clock can advance while a goroutine waits for a lock.
//
//go:linkname runtime_SemacquireWaitGroup
func runtime_SemacquireWaitGroup(s *uint32, synctestDurable bool)
`

	// The runtime pushes symbols into internal/sync; the reverse direction is
	// rejected by the linker ("invalid reference"), so the bridge must live in
	// package runtime.
	runtimeBridge = `//go:linkname internal_sync_runtime_SemacquireWaitGroup internal/sync.runtime_SemacquireWaitGroup
func internal_sync_runtime_SemacquireWaitGroup(addr *uint32, synctestDurable bool) {
	reason := waitReasonSyncMutexLock
	if synctestDurable {
		reason = waitReasonSynctestWaitGroupWait
	}
	semacquire1(addr, false, semaBlockProfile|semaMutexProfile, 0, reason)
}

`

	markerFile = `package sync

// DurableMutexOverlay is present only when the dst durable-semaphore overlay
// patched this toolchain. Dst test mains reference it so that running dst
// tests without -overlay fails at compile time instead of freezing the
// synctest virtual clock on a non-durable lock wait.
const DurableMutexOverlay = true
`
)

func patches() []patch {
	return []patch{
		{
			file: "runtime/sema.go",
			edits: []edit{{
				anchor:      "//go:linkname poll_runtime_Semrelease internal/poll.runtime_Semrelease",
				replacement: runtimeBridge + "//go:linkname poll_runtime_Semrelease internal/poll.runtime_Semrelease",
			}},
		},
		{
			file: "internal/sync/mutex.go",
			edits: []edit{
				{
					anchor:      "\t\"internal/race\"\n",
					replacement: "\t\"internal/race\"\n\t\"internal/synctest\"\n",
				},
				{
					anchor:      "// A Mutex is a mutual exclusion lock.",
					replacement: durableDecl + "\n// A Mutex is a mutual exclusion lock.",
				},
				{
					anchor: "\told := m.state\n\tfor {\n",
					replacement: "\told := m.state\n" +
						"\t// durableWait is true inside a synctest bubble: park with a wait reason\n" +
						"\t// that lets the bubble's virtual clock advance while this goroutine waits.\n" +
						"\tdurableWait := synctest.IsInBubble()\n\tfor {\n",
				},
				{
					anchor: "\t\t\truntime_SemacquireMutex(&m.sema, queueLifo, 2)\n",
					replacement: "\t\t\tif durableWait {\n" +
						"\t\t\t\t// queueLifo has no durable variant; the state machine does not\n" +
						"\t\t\t\t// depend on queue position, only on the woken/starving flags.\n" +
						"\t\t\t\truntime_SemacquireWaitGroup(&m.sema, true)\n" +
						"\t\t\t} else {\n" +
						"\t\t\t\truntime_SemacquireMutex(&m.sema, queueLifo, 2)\n" +
						"\t\t\t}\n",
				},
			},
		},
		{
			file: "sync/rwmutex.go",
			edits: []edit{
				{
					anchor:      "\t\"internal/race\"\n",
					replacement: "\t\"internal/race\"\n\t\"internal/synctest\"\n",
				},
				{
					anchor: "\t\truntime_SemacquireRWMutexR(&rw.readerSem, false, 0)\n",
					replacement: "\t\tif synctest.IsInBubble() {\n" +
						"\t\t\truntime_SemacquireWaitGroup(&rw.readerSem, true)\n" +
						"\t\t} else {\n" +
						"\t\t\truntime_SemacquireRWMutexR(&rw.readerSem, false, 0)\n" +
						"\t\t}\n",
				},
				{
					anchor: "\t\truntime_SemacquireRWMutex(&rw.writerSem, false, 0)\n",
					replacement: "\t\tif synctest.IsInBubble() {\n" +
						"\t\t\truntime_SemacquireWaitGroup(&rw.writerSem, true)\n" +
						"\t\t} else {\n" +
						"\t\t\truntime_SemacquireRWMutex(&rw.writerSem, false, 0)\n" +
						"\t\t}\n",
				},
			},
		},
	}
}

func additions() []addition {
	return []addition{{file: "sync/dst_marker.go", content: markerFile}}
}

func main() {
	var (
		write = flag.String("write", "dst_overlay.json", "overlay file to write (\"-\" for stdout)")
		dir   = flag.String("dir", "", "directory for patched sources (default: a temp dir)")
		check = flag.Bool("check", false, "only verify that every anchor still matches")
	)
	flag.Parse()

	goroot, err := gorootDir()
	if err != nil {
		fatal(err)
	}
	if *dir == "" {
		*dir, err = os.MkdirTemp("", "ivnp-dst-overlay-")
		if err != nil {
			fatal(err)
		}
	} else if err := os.MkdirAll(*dir, 0o755); err != nil {
		fatal(err)
	}

	replace := make(map[string]string)
	for _, p := range patches() {
		target := filepath.Join(goroot, "src", filepath.FromSlash(p.file))
		src, err := os.ReadFile(target)
		if err != nil {
			fatal(err)
		}
		patched, err := apply(p, string(src))
		if err != nil {
			fatal(fmt.Errorf("%s: %w (GOROOT %s)", p.file, err, goroot))
		}
		if *check {
			continue
		}
		out := filepath.Join(*dir, strings.ReplaceAll(p.file, "/", "_"))
		if err := os.WriteFile(out, []byte(patched), 0o644); err != nil {
			fatal(err)
		}
		replace[target] = out
	}
	for _, a := range additions() {
		target := filepath.Join(goroot, "src", filepath.FromSlash(a.file))
		if _, err := os.Stat(target); err == nil {
			fatal(fmt.Errorf("%s already exists in GOROOT %s; rename the overlay file", a.file, goroot))
		}
		if *check {
			continue
		}
		out := filepath.Join(*dir, strings.ReplaceAll(a.file, "/", "_"))
		if err := os.WriteFile(out, []byte(a.content), 0o644); err != nil {
			fatal(err)
		}
		replace[target] = out
	}
	if *check {
		fmt.Println("dstoverlay: all anchors match")
		return
	}

	blob, err := json.MarshalIndent(map[string]any{"Replace": replace}, "", "\t")
	if err != nil {
		fatal(err)
	}
	if *write == "-" {
		fmt.Println(string(blob))
		return
	}
	if err := os.WriteFile(*write, append(blob, '\n'), 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("dstoverlay: wrote %s (%d files, sources in %s)\n", *write, len(replace), *dir)
}

// apply rewrites src according to p, requiring each anchor to occur once.
func apply(p patch, src string) (string, error) {
	for i, e := range p.edits {
		n := strings.Count(src, e.anchor)
		if n != 1 {
			return "", fmt.Errorf("edit %d: anchor %q occurs %d times, want 1", i, e.anchor, n)
		}
		src = strings.Replace(src, e.anchor, e.replacement, 1)
	}
	return src, nil
}

func gorootDir() (string, error) {
	if g := os.Getenv("GOROOT"); g != "" {
		return g, nil
	}
	// runtime.GOROOT reports the toolchain that built this binary, which is the
	// toolchain `go run`/`go test -overlay` will compile against.
	if g := runtime.GOROOT(); g != "" {
		return g, nil
	}
	return "", errNoGOROOT
}

var errNoGOROOT = errors.New("cannot locate GOROOT; set the GOROOT environment variable")

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "dstoverlay:", err)
	os.Exit(1)
}
