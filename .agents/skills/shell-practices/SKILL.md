---
name: shell-practices
description: Keeps shell automation small, safe, and explicit. Use for short command orchestration scripts; move parsing, business rules, and complex state into a testable general-purpose language.
license: MIT
---

# Shell Practices

## Scope

Use shell for short, linear orchestration of existing commands: setting up an environment, connecting a few tools, managing files, and launching another program.

Keep scripts small enough to understand as one unit. Treat 50 lines as a review signal and 100 lines as a strong migration signal, not as automatic proof of quality. Move substantial parsing, data transformation, business rules, concurrency, retries, and complex state into a testable general-purpose language.

This skill is a narrow language-specific supplement. Universal design, testing, health, API, and review rules remain in the general skills and are not duplicated here.

## Selection Rules

Choose shell when all of these are true:

- The task primarily invokes existing commands.
- Control flow is short and linear.
- Inputs are simple arguments, paths, or environment variables.
- Failure can be represented by an exit status.
- Required shell and command-line tools are known in the execution environment.

Choose a general-purpose language when any of these are true:

- The script parses structured data beyond trivial field extraction.
- Correctness depends on nested conditionals, large case tables, or mutable state.
- The script implements business rules, data models, scheduling, or concurrency.
- Reliable unit tests require extensive command mocking.
- Cross-platform behavior is required across substantially different userlands.
- Quoting, escaping, serialization, or error recovery dominates the implementation.
- The script is repeatedly growing past roughly 50–100 lines.

Prefer POSIX `sh` only when portability is required and the script uses POSIX syntax exclusively. Use Bash explicitly when relying on arrays, `[[ ... ]]`, `pipefail`, `read -d`, process substitution, or other Bash features. Do not write a Bash script with a `/bin/sh` shebang.

## Core Rules

- Start Bash scripts with `#!/usr/bin/env bash` and `set -euo pipefail`.
- Quote every parameter expansion unless splitting or globbing is deliberate and documented.
- Use arrays for command arguments; do not build commands as strings.
- Use `printf` rather than `echo` for controlled output.
- Use `--` before path operands when supported.
- Create temporary files with `mktemp` and remove them with `trap`.
- Check required commands and inputs near the start of the script.
- Write diagnostics to standard error and return nonzero on failure.
- Preserve the exit status when cleanup or logging runs after a failure.
- Prefer explicit `if` statements over clever `&&` and `||` chains.
- Pass data through files or standard streams without reparsing human-oriented output.
- Keep secrets out of command-line arguments, traces, and diagnostics.

## Paired Examples

### 1. Enable strict Bash failure handling

Without strict handling, an unset variable can become an empty string, an early pipeline failure can be hidden, and execution can continue after a failed command.

**BAD**

```bash
#!/usr/bin/env bash

output=$1
build_report | gzip > $output
printf 'created %s\n' "$output"
```

**GOOD**

```bash
#!/usr/bin/env bash
set -euo pipefail

readonly output=${1:?usage: create-report OUTPUT}
build_report | gzip >"$output"
printf 'created %s\n' "$output"
```

### 2. Preserve argument boundaries with quoting and arrays

A string of command arguments loses the original argument boundaries. Unquoted expansion then performs word splitting and pathname expansion, allowing data to alter options or operand count. Generated metacharacters execute as shell syntax only when passed through another evaluator such as `eval` or `sh -c`; avoid those evaluators for data.

**BAD**

```bash
#!/usr/bin/env bash
set -euo pipefail

flags="--output $2 --label $3"
convert_image $flags $1
```

**GOOD**

```bash
#!/usr/bin/env bash
set -euo pipefail

readonly input=${1:?usage: convert-one INPUT OUTPUT LABEL}
readonly output=${2:?usage: convert-one INPUT OUTPUT LABEL}
readonly label=${3:?usage: convert-one INPUT OUTPUT LABEL}
args=(--output "$output" --label "$label")
convert_image "${args[@]}" -- "$input"
```

### 3. Create and clean up temporary resources safely

Predictable temporary paths can collide or be replaced by another process. Cleanup must run on normal exit, errors, and signals.

**BAD**

```bash
#!/usr/bin/env bash
set -euo pipefail

tmp=/tmp/current-report
render_report >"$tmp"
install -m 0644 "$tmp" "$HOME/report.txt"
rm -f "$tmp"
```

**GOOD**

```bash
#!/usr/bin/env bash
set -euo pipefail

tmp=$(mktemp "${TMPDIR:-/tmp}/current-report.XXXXXX")
cleanup() {
  status=$?
  trap - EXIT
  rm -f -- "$tmp" || true
  exit "$status"
}
trap cleanup EXIT

render_report >"$tmp"
install -m 0644 -- "$tmp" "$HOME/report.txt"
```

### 4. Make conditional execution explicit

An `&&`/`||` chain also runs its fallback when the command after `&&` fails. That compact syntax often hides which failures are expected and which exit status should be returned.

**BAD**

```bash
#!/usr/bin/env bash
set -euo pipefail

validate_release "$1" && publish_release "$1" || printf 'release failed\n' >&2
```

**GOOD**

```bash
#!/usr/bin/env bash
set -euo pipefail

readonly release=${1:?usage: publish RELEASE}
if ! validate_release "$release"; then
  printf 'invalid release: %s\n' "$release" >&2
  exit 2
fi

if ! publish_release "$release"; then
  printf 'publication failed: %s\n' "$release" >&2
  exit 1
fi
```

### 5. Handle arbitrary pathnames without word splitting

Command substitution and whitespace-delimited loops corrupt names containing spaces, tabs, newlines, or wildcard characters. Use NUL-delimited records when supported.

**BAD**

```bash
#!/usr/bin/env bash
set -euo pipefail

for file in $(find "$1" -type f -name '*.log'); do
  gzip $file
done
```

**GOOD**

```bash
#!/usr/bin/env bash
set -euo pipefail

root=${1:?usage: compress-logs ROOT}
if [[ $root == -* ]]; then
  root="./$root"
fi
find "$root" -type f -name '*.log' -print0 |
  while IFS= read -r -d '' file; do
    gzip -- "$file"
  done
```

### 6. Delegate parsing and business logic

Shell becomes fragile when it parses records, applies evolving policy, and tracks multiple states. Keep the shell layer responsible only for validating the invocation and launching a testable program.

**BAD**

```bash
#!/usr/bin/env bash
set -euo pipefail

while IFS=, read -r account region balance status; do
  if [[ $status == active && $region == north && $balance -gt 5000 ]]; then
    printf '%s,%s\n' "$account" premium
  elif [[ $status == active && $balance -gt 1000 ]]; then
    printf '%s,%s\n' "$account" standard
  else
    printf '%s,%s\n' "$account" review
  fi
done <"$1"
```

**GOOD**

```bash
#!/usr/bin/env bash
set -euo pipefail

readonly input=${1:?usage: classify-accounts INPUT OUTPUT}
readonly output=${2:?usage: classify-accounts INPUT OUTPUT}
command -v account-classifier >/dev/null 2>&1 || {
  printf 'required command not found: account-classifier\n' >&2
  exit 127
}
exec account-classifier --input "$input" --output "$output"
```

## Language-Specific Edge Cases

### Strict mode is not a complete error model

- `set -e` has context-dependent behavior in condition tests, negation, command substitutions, and compound commands. Use explicit `if ! command; then ...; fi` handling when recovery or a custom diagnostic is required.
- `pipefail` reports failure if any pipeline component fails. Some producers receive `SIGPIPE` when a consumer intentionally exits early; avoid assuming every such pipeline is erroneous.
- Commands such as `grep` use nonzero statuses for ordinary outcomes. Handle expected statuses explicitly rather than appending `|| true` broadly.

### Expansions and arithmetic

- Under `set -u`, optional values need an explicit default such as `${MODE:-safe}` or a required-value check such as `${1:?usage: tool INPUT}`.
- Quote `"$@"`; unquoted `$@` and `$*` lose argument boundaries.
- An empty Bash array expands safely with `"${args[@]}"`.
- Treat arithmetic input as untrusted. Validate numeric text before using it in arithmetic expressions, especially when values may contain signs, leading zeros, or variable-like tokens.
- Use `((count += 1))` rather than `((count++))` as a standalone command under `set -e`; post-increment returns status 1 when the previous value is zero.

### Paths and text

- Prefix operands with `--` where the command supports it so names beginning with `-` are not treated as options.
- Newlines are valid in Unix pathnames. Prefer NUL-delimited interfaces such as `find -print0` with Bash `read -d ''`.
- Shell variables cannot contain NUL bytes. Do not use shell variables for arbitrary binary data.
- Command substitution removes trailing newlines. Do not use it when trailing newlines are meaningful.
- Globs remain literal when unmatched unless shell options change that behavior. Use `nullglob` deliberately and locally when an empty match set is intended.
- Locale affects sorting, character classes, and some tool output. Set `LC_ALL=C` only when byte-oriented behavior is intentionally required.

### Processes and cleanup

- A loop fed by a pipeline may run in a subshell, so variable changes can disappear. Prefer redirection or process substitution when state must survive the loop.
- A trap can overwrite the original failure status. Capture `$?` first and return or exit with it after cleanup.
- Trapping `EXIT` does not protect against uncatchable termination or machine failure. When atomic publication is required, create the temporary output in the destination directory and rename it into place on the same filesystem.
- Background jobs require explicit PID tracking, `wait`, failure propagation, and signal cleanup. If that machinery becomes substantial, migrate the workflow.

### Portability

- `sed`, `find`, `xargs`, `date`, `stat`, and `readlink` options differ across systems. Verify every non-POSIX option against supported environments.
- `#!/usr/bin/env bash` finds Bash through `PATH`; use a fixed interpreter path only when the deployment contract guarantees it.
- Do not assume interactive aliases, shell initialization files, terminal access, or the caller's working directory.
- Resolve script-relative resources deliberately rather than assuming invocation from the script directory.

## Verification Commands

Run syntax validation first:

```bash
bash -n scripts/*.bash
```

Run static analysis when available:

```bash
shellcheck scripts/*.bash
```

Check formatting without modifying files when the formatter is available:

```bash
shfmt -d scripts/*.bash
```

Exercise strict-mode and hostile-input cases in an isolated temporary directory:

```bash
set -euo pipefail
test_dir=$(mktemp -d)
readonly test_dir
trap 'rm -rf -- "$test_dir"' EXIT
printf '%s\n' data >"$test_dir/name with spaces"
bash scripts/process-file.bash "$test_dir/name with spaces"
```

For a POSIX `sh` script, validate with the actual supported shells rather than Bash alone:

```bash
sh -n scripts/task.sh
dash -n scripts/task.sh
```

Before release, verify at minimum:

- Missing, empty, and extra arguments.
- Unset optional environment variables.
- Paths containing spaces, tabs, newlines, wildcard characters, and leading hyphens.
- Read-only destinations, missing commands, and failed pipeline stages.
- Interrupt handling and temporary-file cleanup.
- Empty input, large input, and commands producing no output.
- Execution from a different working directory with a minimal environment.
