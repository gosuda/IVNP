# Verification, Simulation & Tooling

This document specifies the verification gates, static analysis tools, deterministic simulation testing (DST) infrastructure, and live-network integration suites used across **IVNP** (`gosuda.org/ivnp`).

---

## 1. Standard Test Suite, Race Detection & Static Analysis

Run the unit test suite, race detector, canonical import formatter, lock analyzer, and static linter from the repository root:

```sh
go test ./...
go test -race ./...
go run gosuda.org/ivnp/tools/importformatter -write
go vet ./...
go vet -vettool="$(go env GOPATH)/bin/checklocks" -inferred=false ./...
gojgp lint ./...
```

### 1.1 Architectural Boundary Verification (`architecture/architecture_test.go`)

`go test ./architecture/...` runs three structural enforcement tests over the module AST and package graph:

1. **`TestImportLayersAreAcyclic`**: Executes `go list -test -json ./...` and verifies that every internal import satisfies the 10-layer unidirectional DAG (`L0` through `L9`):
   - Lower layers never import higher layers (`importedLayer <= importerLayer`).
   - Cross-subsystem imports pass exclusively through each subsystem's root facade package (`controlplane`, `dataplane`, `client`, `node`, `foundation`, `observability`, `state`, `cryptography`).
   - `dataplane` (`L4`) never imports persistent control state (`state`, `L3`).
2. **`TestPublicImportsUseCanonicalPathsWithoutAliases`**: Parses every `.go` file in the repository and rejects package import aliases on canonical subsystem root paths.
3. **`TestUnsafeImportsAreRestrictedAndABIStructsUseHostLayout`**: Rejects `"unsafe"` imports in non-test files outside the explicit OS-boundary allowlist (`dataplane/internal/transport/ssu2/batch_linux_vector.go` and `state/internal/filesystem_store/secure_windows.go`), and verifies that fixed-size kernel ABI structs declared in unsafe files (`mmsghdr`) embed `structs.HostLayout` as their first field.

### 1.2 Static Lock & Atomic Verification (`checklocks`)

`go vet -vettool="$(go env GOPATH)/bin/checklocks" -inferred=false ./...` runs gVisor's SSA lock and atomic analyzer across every package. It verifies lock acquisition/release balance across all control-flow paths and enforces `// +checklocks:`, `// +checklocksread:`, and `// +checklocksreadany` field/method guards on concurrent state machines (`SSU2Manager`, `ssu2TransportSession`, `NTCP2Manager`, `PreparedRouteSender`, `TagStore`, `Reassembler`, `Conn`, `tunnelConn`, `BuildManager`, `CreatorBudget`, `Health`, `PairedPoolMaintainer`, `destinationRuntime`, and `simnet.Network`).

### 1.3 Canonical Import Formatter (`tools/importformatter/main.go`)

`go run gosuda.org/ivnp/tools/importformatter -write` rewrites Go source files so that all imports appear in a single `import (...)` block without blank lines or comment-interrupted subgroups, sorted in standard `gofmt` order.

### 1.4 Embedded WebUI Verification (`cmd/ivnpd/webui`)

When modifying the SvelteKit frontend under `cmd/ivnpd/webui`, run type/accessibility checks and rebuild the static bundle embedded by `cmd/ivnpd/webui_server.go` (`//go:embed all:webui/build`):

```sh
npm --prefix cmd/ivnpd/webui run check
npm --prefix cmd/ivnpd/webui run build
```

---

## 2. Deterministic Simulation Testing (`internal/simnet`, `tools/dstoverlay`, `sim_*.go`)

IVNP includes a full-stack deterministic simulation suite (`//go:build dst || synctest`) that boots multi-router I2P meshes inside Go's `testing/synctest` virtual-time bubble. A 16-router mesh completes bootstrap, Kademlia NetDB discovery, 3-hop ECIES tunnel building, `LeaseSet2` publication, and end-to-end streaming / `Datagram2` transfers in seconds of wall-clock time with deterministic replay.

### 2.1 Running the Deterministic Simulation Suite

Build the Go runtime source overlay first with `tools/dstoverlay`, then run the `dst`-tagged test binary with single-processor scheduling and pinned entropy:

```sh
overlay=$(mktemp /tmp/ivnp-dst-overlay.XXXXXX.json)
go run ./tools/dstoverlay -write "$overlay"
GODEBUG=asyncpreemptoff=1,cryptocustomrand=1 GOGC=off \
  go test -tags=dst -overlay="$overlay" -run '^TestSim|^TestDeterministic' .
rm -f "$overlay"
```

### 2.2 Runtime Compiler Overlay (`tools/dstoverlay/main.go`)

Stock Go `sync.Mutex` and `sync.RWMutex` contention waits are not marked as durably blocked inside a `testing/synctest` bubble, which would stall the virtual clock whenever a background goroutine contends on a lock. `tools/dstoverlay` generates a Go compiler `-overlay` JSON patching six files in `GOROOT/src`:

| Patched `GOROOT/src` File | Runtime Modification | Purpose in `synctest` Bubble |
| :--- | :--- | :--- |
| `runtime/sema.go` | Routes `sync_runtime_SemacquireMutex` and `sync_runtime_SemacquireRWMutex*` through `semacquire1(addr, lifo, profile, skipframes, waitReasonSynctestWaitGroupWait)` when `gp.bubble != nil` and disables `runtime_canSpin` | Marks mutex contention as durably blocked so the virtual clock advances without wall-clock spinning |
| `internal/sync/mutex.go` | Disables active spinning inside bubbles (`!runtime_canSpin(0)`) | Prevents non-deterministic spin loops before semaphore acquisition |
| `sync/rwmutex.go` | Exports `const DurableMutexOverlay = true` | Referenced by `sim_main_test.go` (`var _ = sync.DurableMutexOverlay`) so compiling without `-overlay` fails at compile time |
| `runtime/rand.go` | Seeds the runtime RNG with the fixed key `"ivnp-dst-replay-v1"` | Makes `select` case pseudo-random ordering and `map` iteration order reproducible |
| `runtime/proc.go` | Turns `sysmon` into a no-op | Eliminates wall-clock background preemption noise (`GODEBUG=asyncpreemptoff=1` disables signal preemption) |
| `crypto/internal/randutil/randutil.go` | Turns `MaybeReadByte` into a no-op | Prevents non-deterministic 1-byte reads from `crypto/rand.Reader` during ECDSA/RSA/Ed25519 signing |

### 2.3 Virtual Network Engine (`internal/simnet`) & Simulation Harness (`sim_*.go`)

1. **Process & Entropy Pinning (`sim_main_test.go`, `sim_harness_test.go`)**:
   - `TestMain` verifies `GODEBUG=asyncpreemptoff=1,cryptocustomrand=1` and pins `runtime.GOMAXPROCS(1)` so runnable goroutines execute in deterministic runqueue order.
   - `simnet.PinSessionEntropy(seed)` replaces `crypto/rand.Reader` with a deterministic `ChaCha8` stream, while `foundation.SetDeterministicRandomSource` and `dataplane.SetDeterministicSeeds` seed router identities, tunnel build records, and streaming ISSNs.
2. **Min-Heap Link Scheduler (`internal/simnet/network.go`)**:
   - `simnet.Network` implements in-memory `net.Listener`, `net.Conn`, and `net.PacketConn` endpoints (`ListenStream`, `DialStreamContext`, `ListenPacket`).
   - Every TCP segment and UDP datagram is scheduled on a deterministic min-heap ordered by `(dueTime, seq)`, supporting per-link latency, jitter, uniform drop rates, Gilbert-Elliott 2-state Markov burst loss (`BurstLossConfig`), packet duplication, byte corruption, asymmetric blackholes, and abrupt router crashes.
3. **Simulation Scenarios (`sim_dst_test.go`)**:
   - `TestDeterministicRouterMesh` and `TestDeterministicRouterMesh16`: Multi-router mesh bootstrap, 3-hop tunnel formation, and end-to-end streaming and `Datagram2` delivery.
   - `TestSimChaosFailureModels`: Exercises streaming and tunnel recovery under Gilbert-Elliott burst packet loss, duplicate/corrupted UDP frames, asymmetric link partitions, and mid-transfer transit router crashes.

---

## 3. Live Network Integration Tests (`tests/integration`)

Live integration tests (`//go:build integration`) verify end-to-end interoperability against running I2P routers and public eepsites:

```sh
IVNP_EEPSITE_PROXY=http://127.0.0.1:4444 IVNP_SAM_ADDRESS=127.0.0.1:7656 \
  go test -tags=integration -run '^TestHTTPProxyCompletesI2PChallengeRoundTrip$' \
  -count=1 -timeout=12m ./tests/integration
```
