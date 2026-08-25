---
name: go-practices
description: Applies Go-specific engineering practices, standard-library APIs, deterministic tests, and the gojgp analyzer. Use when writing, changing, testing, or reviewing Go code.
license: MIT
compatibility: Requires Go 1.25 or newer. The gojgp repository selects the Go 1.27 toolchain; each target module's go directive controls its language and standard-library API baseline.
---

# Go Practices

Apply this skill only as a Go-specific supplement. Universal design, testing, health, API, and review rules remain in the general skills and are not repeated here.

## Toolchain and language selection

- The module's `go` directive declares its minimum required Go version and controls language and standard-library version diagnostics.
- The `toolchain` directive selects or suggests the compiler toolchain; it does not by itself make unguarded references to newer standard-library APIs valid for an older `go` baseline.
- Keep `go 1.25` only while ordinary source remains compatible with that baseline.
- Use a Go 1.27 API only when the target module raises its `go` directive accordingly, or isolate the implementation behind release build constraints with a compatible fallback.
- Prefer the oldest API that expresses the operation clearly when supporting multiple Go releases would otherwise require unnecessary split implementations.

Version gates relevant to this skill:

| API | Available from | Selection rule |
|---|---:|---|
| `min`, `max`, `sync.OnceValue`, `log/slog` | Go 1.21 | Prefer over local equivalents when the supported toolchain is new enough. |
| `cmp.Or`, `math/rand/v2` | Go 1.22 | Use `math/rand/v2` for non-cryptographic randomness only. |
| `testing/synctest` | Go 1.25 | Prefer for deterministic tests involving timers and durable-blocking coordination. It does not make runnable-goroutine order deterministic. |
| `bytes.CutLast` | Go 1.27 | Prefer over manual last-index slicing. |
| `testing/cryptotest.SetGlobalRandom` | Go 1.27 | Use only in non-parallel tests that need deterministic process-global cryptographic randomness. |

## Required Go practices

### 1. Parameter ordering

Put `context.Context` first in ordinary functions. In test helpers, put `testing.TB` first and `context.Context` second. This makes cancellation propagation and helper conventions predictable. Never pass a nil context; use `context.Background()` when no caller context exists.

**BAD**

```go
func fetch(limit int, ctx context.Context) error {
	return nil
}

func assertFetched(ctx context.Context, t testing.TB, limit int) {
	t.Helper()
}
```

**GOOD**

```go
func fetch(ctx context.Context, limit int) error {
	return nil
}

func assertFetched(t testing.TB, ctx context.Context, limit int) {
	t.Helper()
}
```

### 2. Time values

Use `time.Duration` for elapsed time, intervals, delays, and timeouts. Integer units hide scale at call sites and permit accidental unit conversion. Document whether zero and negative durations disable, expire, or reject an operation.

**BAD**

```go
func retry(delayMillis int) {
	time.Sleep(time.Duration(delayMillis) * time.Millisecond)
}

retry(500)
```

**GOOD**

```go
func retry(delay time.Duration) {
	time.Sleep(delay)
}

retry(500 * time.Millisecond)
```

### 3. Map lookup

Use the two-result map lookup when both presence and value matter. It performs one lookup and distinguishes an absent key from a present zero value. Reading a nil map is valid; concurrent access still requires synchronization when any goroutine may write.

**BAD**

```go
if _, ok := counts[key]; ok {
	count := counts[key]
	use(count)
}
```

**GOOD**

```go
if count, ok := counts[key]; ok {
	use(count)
}
```

### 4. Guard clauses

Handle invalid, exceptional, or terminal cases early. Do not put the remaining path in an `else` after `return`, `continue`, `break`, or `panic`; the extra nesting obscures the main flow.

**BAD**

```go
func normalize(s string) (string, error) {
	if s == "" {
		return "", errors.New("empty value")
	} else {
		return strings.ToLower(s), nil
	}
}
```

**GOOD**

```go
func normalize(s string) (string, error) {
	if s == "" {
		return "", errors.New("empty value")
	}
	return strings.ToLower(s), nil
}
```

### 5. Error causes and cleanup

Wrap operation errors with `%w` and combine independent failures with `errors.Join`. Never discard cleanup errors. `errors.Join` ignores nil operands and preserves every non-nil cause for `errors.Is` and `errors.As`.

**BAD**

```go
func writeFile(path string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %v", path, err)
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
```

**GOOD**

```go
func writeFile(path string, data []byte) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() {
		err = errors.Join(err, f.Close())
	}()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
```

### 6. Standard-library replacements

Prefer supported standard-library APIs over local helpers: `cmp.Or` for the first non-zero value, `min` and `max` for ordered bounds, `sync.OnceValue` for lazy one-time values, `log/slog` for structured logging, and `math/rand/v2` for non-security randomness. Use `crypto/rand` instead for secrets, tokens, keys, nonces, and other security-sensitive values.

**BAD**

```go
var (
	cfg     Config
	cfgOnce sync.Once
)

func config() Config {
	cfgOnce.Do(func() { cfg = loadConfig() })
	return cfg
}

func retries(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

func report(err error) {
	log.Printf("request failed: %v", err)
}
```

**GOOD**

```go
var config = sync.OnceValue(loadConfig)

func retries(n int) int {
	return max(1, n)
}

func displayName(primary, fallback string) string {
	return cmp.Or(primary, fallback)
}

func sampleBucket(n uint64) uint64 {
	return rand.Uint64N(n)
}

func report(ctx context.Context, err error) {
	slog.ErrorContext(ctx, "request failed", "error", err)
}
```

### 7. Deterministic concurrent-time tests

Use `testing/synctest` when behavior depends on timers, deadlines, or goroutine quiescence. It advances fake time when the test bubble is durably blocked, avoiding slow and flaky wall-clock sleeps. Keep external I/O outside the bubble because it cannot be made deterministic by fake time.

**BAD**

```go
func TestDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	time.Sleep(100 * time.Millisecond)
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("got %v", ctx.Err())
	}
}
```

**GOOD**

```go
func TestDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Hour)
		defer cancel()

		<-ctx.Done()
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("got %v", ctx.Err())
		}
	})
}
```

### 8. Splitting at the final byte sequence

On Go 1.27, use `bytes.CutLast` instead of combining `bytes.LastIndex` with manual slicing. It avoids repeated separator-length arithmetic and safely represents the not-found case. Remember that returned slices alias the input.

**BAD**

```go
func splitPath(b []byte) (dir, base []byte, ok bool) {
	i := bytes.LastIndex(b, []byte("/"))
	if i < 0 {
		return b, nil, false
	}
	return b[:i], b[i+1:], true
}
```

**GOOD**

```go
func splitPath(b []byte) (dir, base []byte, ok bool) {
	return bytes.CutLast(b, []byte("/"))
}
```

### 9. Deterministic cryptographic randomness in tests

On Go 1.27, `cryptotest.SetGlobalRandom(t, seed)` replaces `crypto/rand` and implicit randomness in `crypto/...` packages for the duration of the test. It affects the entire process: never call it from a parallel test or a test with a parallel ancestor. Resetting the same seed can reproduce a stream within one implementation, but cryptographic algorithms may consume randomness differently across Go releases, so do not assert a hard-coded randomized output.

**BAD**

```go
func TestToken(t *testing.T) {
	t.Parallel()
	cryptotest.SetGlobalRandom(t, 7)

	got := generateToken()
	if got != "fixed-token-from-one-go-release" {
		t.Fatalf("got %q", got)
	}
}
```

**GOOD**

```go
func TestToken(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 7)
	first := generateToken()

	cryptotest.SetGlobalRandom(t, 7)
	second := generateToken()

	if !bytes.Equal(first, second) {
		t.Fatalf("reset seed produced different streams")
	}
	if len(first) != tokenSize {
		t.Fatalf("token length = %d, want %d", len(first), tokenSize)
	}
}
```

## Edge cases and selection rules

- Propagate caller contexts; do not replace them with background contexts inside request-scoped work. Avoid storing contexts in structs unless the struct itself represents one operation with that lifetime.
- Use `time.Time` for instants and `time.Duration` for spans. Prefer monotonic comparisons carried by `time.Time`; serialization removes monotonic data.
- Distinguish absent map entries from present zero values only when the domain requires it. Use direct lookup when absence and zero are intentionally equivalent.
- A map value containing a pointer, slice, or interface may still be nil even when the key is present.
- Wrap errors at useful abstraction boundaries, not at every stack frame. Match causes with `errors.Is` or `errors.As`, not text comparison.
- Joining errors is appropriate when failures are independent. If one error is merely context for another, wrap with `%w` instead.
- `sync.OnceValue` caches a panic and repeats it on later calls. Use it only when that behavior is acceptable.
- `cmp.Or` chooses the first non-zero value; it cannot distinguish an intentionally supplied zero value from an absent value.
- `min` and `max` follow Go's ordered-value and floating-point rules. Handle NaN semantics explicitly when they matter to the domain.
- `math/rand/v2` sequences are not a stable persistence or protocol format. Tests that need reproducibility should use an explicitly seeded local generator rather than package-level randomness.
- `testing/synctest` detects durable blocking among goroutines in its bubble; it is not a substitute for race detection or synchronization.
- `bytes.CutLast` with an empty separator follows the standard byte-splitting contract. Check that this is meaningful before accepting an empty separator from input.
- `cryptotest.SetGlobalRandom` is process-global, so the test and all ancestors must be non-parallel. It is unsupported when `crypto/fips140.Version` reports the Go Cryptographic Module `v1.0.0`.
- Randomness consumption by cryptographic algorithms is not a stable cross-version contract. Assert semantic behavior or reset reproducibility, not a hard-coded randomized output.

## gojgp installation and verification

Install the analyzer with the selected toolchain:

```sh
GOTOOLCHAIN=go1.27.0 go install github.com/gosuda/JustGoodPractices/cmd/gojgp@latest
```

Pin the resolved analyzer version in reproducible automation rather than allowing it to drift. Ensure the installation directory is on `PATH`.

Run lint after every Go change:

```sh
go fmt ./...
gojgp lint ./...
```

Run the combined required check before completion; it executes `go test ./...` and `gojgp lint ./...`:

```sh
gojgp check
```

Use the selected toolchain explicitly when the environment does not already select it:

```sh
GOTOOLCHAIN=go1.27.0 gojgp check
```

If the module claims Go 1.25 compatibility, also test that minimum toolchain rather than inferring compatibility from a newer compiler:

```sh
GOTOOLCHAIN=go1.25.0 go test ./...
```

For concurrency-sensitive changes, also run:

```sh
GOTOOLCHAIN=go1.27.0 go test -race ./...
```

Treat analyzer findings as code defects. Suppress a finding only when the analyzer supports a narrow, documented suppression and the code cannot be expressed more clearly without it.
