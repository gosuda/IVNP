// Command dstoverlay generates the -overlay file used by the dst test suite.
//
// Go's sync primitives park on runtime semaphores whose wait reason is not
// considered "idle" by testing/synctest, so a goroutine blocked on a lock
// freezes the bubble's virtual clock. The patch below routes lock waits
// through runtime_SemacquireWaitGroup(addr, true) while the caller is inside a
// bubble, which parks with waitReasonSynctestWaitGroupWait and lets virtual
// time advance. Outside a bubble every patched call keeps its stock behavior.
//
// Two further patches remove wall-clock and cross-bubble inputs to a
// GOMAXPROCS=1 dst run: runtime/rand.go, runtime/select.go, runtime/sema.go,
// runtime/time.go, and runtime/synctest.go seed the global PRNG from a fixed
// constant and reset dedicated bubble-scoped PRNG streams, sync.Pool caches,
// and pp.schedtick at the start of every synctest bubble; runtime/proc.go and
// runtime/mgcscavenge.go disable sysmon and background heap scavenger wakes so
// wall-clock timers never retake a P or inject system goroutines. Matched runs
// also need GODEBUG=cryptocustomrand=1 (without it Go 1.27's crypto packages
// bypass a swapped crypto/rand.Reader for the internal DRBG) and GOGC=off to
// keep GC marker goroutines out of the single P's run queue. Finally,
// crypto/internal/randutil.MaybeReadByte is neutralized: it steals a byte
// from custom readers with 50% probability under cryptocustomrand=1, while
// dst fixtures pass exactly-sized readers that must observe exact
// consumption.
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

	// randSeedAnchor is the stock randinit seeding block that randSeedPatch
	// replaces, and randSeedConstDecl declares the fixed seed it references.
	randSeedAnchor = "\tseed := &globalRand.seed\n" +
		"\tif len(startupRand) >= 16 &&\n" +
		"\t\t// Check that at least the first two words of startupRand weren't\n" +
		"\t\t// cleared by any libc initialization.\n" +
		"\t\t!allZero(startupRand[:8]) && !allZero(startupRand[8:16]) {\n" +
		"\t\tfor i, c := range startupRand {\n" +
		"\t\t\tseed[i%len(seed)] ^= c\n" +
		"\t\t}\n" +
		"\t} else {\n" +
		"\t\tif readRandom(seed[:]) != len(seed) || allZero(seed[:]) {\n" +
		"\t\t\t// readRandom should never fail, but if it does we'd rather\n" +
		"\t\t\t// not make Go binaries completely unusable, so make up\n" +
		"\t\t\t// some random data based on the current time.\n" +
		"\t\t\treadRandomFailed = true\n" +
		"\t\t\treadTimeRandom(seed[:])\n" +
		"\t\t}\n" +
		"\t}\n"

	randSeedPatch = "\tseed := &globalRand.seed\n" +
		"\t// IVNP dst overlay: pin the runtime PRNG seed so select pollorder\n" +
		"\t// shuffles (selectgo), map iteration starts (maps_rand), and per-m\n" +
		"\t// rand state (mrandinit) are identical across processes.\n" +
		"\tfor i := range seed {\n" +
		"\t\tseed[i] = ivnpDstRandSeed[i%len(ivnpDstRandSeed)]\n" +
		"\t}\n"

	randSeedConstDecl = "\n// ivnpDstRandSeed keys the fixed runtime PRNG used by dst overlay builds.\n" +
		"const ivnpDstRandSeed = \"ivnp-dst-replay-v1\"\n\n" +
		"var ivnpBubbleRand struct {\n" +
		"\tchacha8    chacha8rand.State\n" +
		"\tselectRand uint32\n" +
		"\tsemaRand   uint32\n" +
		"\ttimerRand  uint32\n" +
		"}\n\n" +
		"func ivnpResetBubbleRand() {\n" +
		"\tif poolcleanup != nil {\n" +
		"\t\tpoolcleanup()\n" +
		"\t\tpoolcleanup()\n" +
		"\t}\n" +
		"\tvar seed [32]byte\n" +
		"\tfor i := range seed {\n" +
		"\t\tseed[i] = ivnpDstRandSeed[i%len(ivnpDstRandSeed)]\n" +
		"\t}\n" +
		"\tivnpBubbleRand.chacha8.Init(seed)\n" +
		"\tivnpBubbleRand.selectRand = 0x64737431\n" +
		"\tivnpBubbleRand.semaRand = 0x64737432\n" +
		"\tivnpBubbleRand.timerRand = 0x64737433\n" +
		"}\n\n" +
		"//go:nosplit\n" +
		"func ivnpTimerRand() uint32 {\n" +
		"\tivnpBubbleRand.timerRand += 0x53c5ca59\n" +
		"\thi, lo := bits.Mul32(ivnpBubbleRand.timerRand, ivnpBubbleRand.timerRand^0x74743c1b)\n" +
		"\treturn hi ^ lo\n" +
		"}\n\n" +
		"//go:nosplit\n" +
		"func ivnpSelectRandn(n uint32) uint32 {\n" +
		"\tif getg().bubble != nil {\n" +
		"\t\tivnpBubbleRand.selectRand += 0x53c5ca59\n" +
		"\t\thi, lo := bits.Mul32(ivnpBubbleRand.selectRand, ivnpBubbleRand.selectRand^0x74743c1b)\n" +
		"\t\treturn uint32((uint64(hi^lo) * uint64(n)) >> 32)\n" +
		"\t}\n" +
		"\treturn cheaprandn(n)\n" +
		"}\n\n" +
		"//go:nosplit\n" +
		"func ivnpSemaRand() uint32 {\n" +
		"\tif getg().bubble != nil {\n" +
		"\t\tivnpBubbleRand.semaRand += 0x53c5ca59\n" +
		"\t\thi, lo := bits.Mul32(ivnpBubbleRand.semaRand, ivnpBubbleRand.semaRand^0x74743c1b)\n" +
		"\t\treturn hi ^ lo\n" +
		"\t}\n" +
		"\treturn cheaprand()\n" +
		"}\n"

	randPerMAnchor = "\tmp := getg().m\n\tc := &mp.chacha8\n"

	randPerMPatch = "\tmp := getg().m\n\tc := &mp.chacha8\n" +
		"\tif getg().bubble != nil {\n" +
		"\t\tc = &ivnpBubbleRand.chacha8\n" +
		"\t}\n"

	readTimeRandomComment = "// readTimeRandom stretches any entropy in the current time"

	sysmonSpawnAnchor = "\tif haveSysmon {\n" +
		"\t\tsystemstack(func() {\n" +
		"\t\t\tnewm(sysmon, nil, -1)\n" +
		"\t\t})\n" +
		"\t}\n"

	sysmonSpawnGuard = "\t// IVNP dst overlay: do not spawn sysmon. A background OS thread\n" +
		"\t// polling netpoll, waking the scavenger, or retaking Ps introduces\n" +
		"\t// wall-clock scheduling jitter into GOMAXPROCS=1 simulations.\n" +
		"\tif false && haveSysmon {\n" +
		"\t\tsystemstack(func() {\n" +
		"\t\t\tnewm(sysmon, nil, -1)\n" +
		"\t\t})\n" +
		"\t}\n"

	retakeAnchor = "func retake(now int64) uint32 {\n\tn := 0\n"

	retakeGuard = "func retake(now int64) uint32 {\n" +
		"\t// IVNP dst overlay: sysmon never retakes a P. A P handed off\n" +
		"\t// mid-syscall requeues the returning goroutine onto the global run\n" +
		"\t// queue, reordering it relative to the local run queue: a\n" +
		"\t// wall-clock-dependent input under GOMAXPROCS=1. The remainder of\n" +
		"\t// this function is unreachable.\n" +
		"\treturn 0\n" +
		"\tn := 0\n"

	scavengerWakeAnchor = "func (s *scavengerState) wake() {\n\tlock(&s.lock)\n"

	scavengerWakeGuard = "func (s *scavengerState) wake() {\n" +
		"\t// IVNP dst overlay: keep the background heap scavenger parked so\n" +
		"\t// wall-clock timer wakes never inject system goroutines or advance\n" +
		"\t// pp.schedtick during a simulation.\n" +
		"\tif true {\n" +
		"\t\treturn\n" +
		"\t}\n" +
		"\tlock(&s.lock)\n"

	synctestStartAnchor = "\t// This is newproc, but also records the new g in bubble.main.\n" +
		"\tpc := sys.GetCallerPC()\n" +
		"\tsystemstack(func() {\n" +
		"\t\tfv := *(**funcval)(unsafe.Pointer(&f))\n" +
		"\t\tbubble.main = newproc1(fv, gp, pc, false, waitReasonZero)\n" +
		"\t\tpp := getg().m.p.ptr()\n" +
		"\t\trunqput(pp, bubble.main, true)\n" +
		"\t\twakep()\n" +
		"\t})\n"

	synctestStartPatch = "\t// This is newproc, but also records the new g in bubble.main.\n" +
		"\tpc := sys.GetCallerPC()\n" +
		"\tsystemstack(func() {\n" +
		"\t\tivnpResetBubbleRand()\n" +
		"\t\tfv := *(**funcval)(unsafe.Pointer(&f))\n" +
		"\t\tbubble.main = newproc1(fv, gp, pc, false, waitReasonZero)\n" +
		"\t\tpp := getg().m.p.ptr()\n" +
		"\t\tpp.schedtick = 0\n" +
		"\t\trunqput(pp, bubble.main, true)\n" +
		"\t\twakep()\n" +
		"\t})\n"

	// randutilMaybeReadByte is the stock body of MaybeReadByte; the
	// replacement makes it a no-op so pinned test readers see exact
	// consumption.
	randutilBody = "\tif rand.Uint64()&1 == 1 {\n" +
		"\t\treturn\n" +
		"\t}\n" +
		"\tvar buf [1]byte\n" +
		"\tr.Read(buf[:])\n"

	randutilNoOp = "\t// IVNP dst overlay: never steal a byte from custom readers. dst\n" +
		"\t// fixtures pin entropy to exactly-sized readers; the 50% skip is\n" +
		"\t// itself nondeterministic consumption.\n"

	randutilImport = "\t\"io\"\n\t\"math/rand/v2\"\n"

	randutilImportPatched = "\t\"io\"\n"

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
			edits: []edit{
				{
					anchor:      "//go:linkname poll_runtime_Semrelease internal/poll.runtime_Semrelease",
					replacement: runtimeBridge + "//go:linkname poll_runtime_Semrelease internal/poll.runtime_Semrelease",
				},
				{
					anchor:      "\ts.ticket = cheaprand() | 1\n",
					replacement: "\ts.ticket = ivnpSemaRand() | 1\n",
				},
			},
		},
		{
			file: "runtime/select.go",
			edits: []edit{{
				anchor:      "\t\tj := cheaprandn(uint32(norder + 1))\n",
				replacement: "\t\tj := ivnpSelectRandn(uint32(norder + 1))\n",
			}},
		},
		{
			file: "runtime/time.go",
			edits: []edit{{
				anchor:      "\t\t\tt.rand = cheaprand()\n",
				replacement: "\t\t\tt.rand = ivnpTimerRand()\n",
			}},
		},
		{
			file: "runtime/synctest.go",
			edits: []edit{{
				anchor:      synctestStartAnchor,
				replacement: synctestStartPatch,
			}},
		},
		{
			file: "runtime/mgcscavenge.go",
			edits: []edit{{
				anchor:      scavengerWakeAnchor,
				replacement: scavengerWakeGuard,
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
				{
					anchor: "\t\t\tstarving = starving || runtime_nanotime()-waitStartTime > starvationThresholdNs\n",
					replacement: "\t\t\tif durableWait {\n" +
						"\t\t\t\t// Starvation mode keys off real nanotime, a wall-clock\n" +
						"\t\t\t\t// input; stay in normal mode inside bubbles so lock handoff\n" +
						"\t\t\t\t// order is a pure function of the event schedule.\n" +
						"\t\t\t\tstarving = false\n" +
						"\t\t\t} else {\n" +
						"\t\t\t\tstarving = starving || runtime_nanotime()-waitStartTime > starvationThresholdNs\n" +
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
		{
			file: "runtime/rand.go",
			edits: []edit{
				{
					anchor:      randSeedAnchor,
					replacement: randSeedPatch,
				},
				{
					anchor:      readTimeRandomComment,
					replacement: randSeedConstDecl + "\n" + readTimeRandomComment,
				},
				{
					anchor:      randPerMAnchor,
					replacement: randPerMPatch,
				},
			},
		},
		{
			file: "runtime/proc.go",
			edits: []edit{
				{
					anchor:      sysmonSpawnAnchor,
					replacement: sysmonSpawnGuard,
				},
				{
					anchor:      retakeAnchor,
					replacement: retakeGuard,
				},
			},
		},
		{
			file: "crypto/internal/randutil/randutil.go",
			edits: []edit{
				{
					anchor:      randutilImport,
					replacement: randutilImportPatched,
				},
				{
					anchor:      randutilBody,
					replacement: randutilNoOp,
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
