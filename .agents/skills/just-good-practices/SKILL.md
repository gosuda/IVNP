---
name: just-good-practices
description: Helps AI agents write good code by applying reliable practices for implementation, testing, API design, refactoring, and review across programming languages. Use for software engineering tasks where correctness, clarity, or maintainability matters.
license: MIT
---

# Just Good Practices

Apply a practical, provider-neutral engineering baseline. Improve correctness first, then clarity, testability, maintainability, operability, and reviewability. Keep focused work focused; do not turn it into an unrelated rewrite.

## Role and routing

This umbrella skill classifies work, establishes cross-language defaults, and routes detailed analysis.

- Route test strategy, cases, doubles, fixtures, lifecycle, flakiness, coverage, fuzzing, performance, nondeterministic quality, and test infrastructure to `testing-practices`.
- Route readability, control flow, decomposition, dependencies, errors, logging, comments, duplication, dead code, and refactoring to `code-health`.
- Route public contracts, types, compatibility, construction, ownership, versioning, and request or response semantics to `api-design`.
- Route change structure, risk analysis, reviewer guidance, feedback, and commit quality to `code-review`.
- Route strict comment density, zero-slop policy, commit message discipline, and reviewer slop protocols to `zero-slop`.
- Route syntax, libraries, concurrency primitives, framework mechanics, build systems, and runtime idioms to the corresponding language-specific skill.
- When a deeper skill is unavailable, apply the baseline below. Do not invent language-specific mechanics from generic guidance.

## Operating workflow

1. **Understand the contract.** Identify users, observable behavior, inputs, outputs, invariants, failures, compatibility constraints, and acceptance conditions. Ask when ambiguity could change behavior; otherwise state a narrow assumption.
2. **Inspect before editing.** Read affected code, tests, interfaces, call sites, configuration, and nearby conventions. Search for an existing abstraction before adding one.
3. **Classify risk.** Consider security, data loss, concurrency, compatibility, migration, external I/O, nondeterminism, performance, rollback, and irreversible effects.
4. **Choose the smallest coherent change.** Preserve behavior unless change is requested. Separate preparatory refactoring from behavior changes when practical.
5. **Plan observable verification.** Map each acceptance condition to the cheapest stable boundary with enough fidelity, including relevant normal, boundary, invalid, partial, and failure cases.
6. **Implement incrementally.** Prefer a focused failing example, the minimum coherent implementation, and then refactoring while checks remain green.
7. **Verify progressively.** Run focused checks before broader tests, formatting, static analysis, contracts, integration checks, and builds appropriate to the repository. Inspect the diff for churn.
8. **Report evidence.** Summarize behavior, choices, checks performed, residual risks, and unverified areas. Never claim a check ran when it did not.

## Cross-cutting defaults

- Correctness, safety, explicit contracts, and compatibility outrank stylistic cleanup.
- Prefer the lowest stable public boundary that proves behavior; increase fidelity for wiring, serialization, persistence, transport, or vital journey risk.
- Prefer a real fast deterministic dependency. When substitution is required, use the weakest double that still supplies the contract: a stub for fixed answers, a fake for stateful behavior, and an interaction mock only for otherwise inaccessible observable side effects.
- Inject externally managed, side-effecting, configurable, lifecycle-sensitive, or substitutable collaborators; construct simple immutable local values directly.
- Extract shared abstractions only when repeated implementations reveal the same concept, invariants, responsibilities, and reason to change. Tolerate small local duplication first.
- Refactor nearby code only when cleanup is bounded, safe, tested, and directly helps the task. Split broad or risky cleanup.
- Preserve order when it affects behavior; otherwise impose stable order when it improves reproducibility, review, merging, or duplicate detection.
- For operator-facing destructive tools where accidental invocation is plausible, prefer preview or nondestructive defaults and require an explicit, clearly named opt-in. APIs and scheduled jobs instead need contract-appropriate authorization, idempotency, atomicity, and recovery.
- Compare meaningful design options against common named criteria; state assumptions, tradeoffs, and the selected option.
- Treat slogans, statistics, announcements, and anecdotes as context rather than engineering requirements.

## Implementation baseline

- Handle invalid input and failures first with guard clauses. Keep the main path shallow; remove redundant branches after terminating statements and use clear multi-way selection for exclusive alternatives.
- Prefer positive, intention-revealing predicates. Name compound conditions, parenthesize mixed logic, and extract complex domain rules.
- Keep functions cohesive and at one abstraction level. Separate orchestration from parsing, validation, calculation, persistence, and transport.
- Arrange statements in execution and data-flow order. For stable keyed collections whose API returns presence and value together, bind both once and reuse them; do not cache time-varying, consumptive, or side-effecting lookups.
- Separate a deterministic functional core from the imperative I/O shell.
- Avoid shared mutable state in concurrent work; otherwise coordinate every access with an appropriate mechanism. Prefer local results followed by aggregation.
- Encode units and valid states in types or named options. Avoid ambiguous primitives, positional booleans, invalid partial objects, and construct-configure-initialize sequences.
- Give long-lived collaborators to objects at construction and request-scoped commands, identifiers, or context to methods. Centralize infrastructure composition and make ownership explicit.
- Keep factories limited to object-graph construction. Avoid hidden clients, global lookup, service location, and business decisions inside factories.
- Put business concepts, transitions, and invariants behind intention-revealing domain capabilities. Avoid navigating and mutating nested object graphs from callers.
- Catch errors only to recover, add context, translate, clean up, or report at the owning boundary. Preserve causes, redact secrets, and let unexpected programming errors propagate.
- Log structured events once where the handling decision is owned. Use stable names and useful fields; prefer bounded progress and summaries over per-item noise.
- Use precise domain names and comments that explain contracts, constraints, invariants, external limitations, or rationale rather than syntax. Remove stale comments and dead code.
- Record difficult automation failures near the automation with symptom, cause, remediation, verification, and prevention.

## Testing baseline

Route detailed testing decisions to `testing-practices`; retain these release-safety defaults in every task.

- Make tests hermetic: own files, ports, databases, configuration, locale, randomness, process state, and mutable fixtures. Fail closed on accidental real external access.
- Stop every task, process, timer, stream, connection, and other resource that the test creates or explicitly owns before the test returns, including after failure. Do not close runner-owned or suite-scoped shared resources.
- Inject time, randomness, scheduling, and transport. Never synchronize with fixed sleeps; wait for an observable condition or event with a diagnostic timeout.
- Require independence from execution order. Run tests concurrently only when their owned resources permit it; serialize legitimately exclusive process-global resources while isolating and restoring their state. Retries may collect evidence but must not silently turn failures into success.
- Use many deterministic rule tests, realistic component and contract tests for wiring, and few end-to-end tests for vital user-observable journeys.
- Make each test a behavioral story with visible scenario-defining values, one meaningful action, and assertions on the public contract.
- Cover relevant behavior partitions and boundaries: normal, empty, minimum, maximum, just-inside, just-outside, malformed, partial, invalid, repeated, and failure cases.
- Assert specific results, state transitions, significant fields, or side effects. Avoid private calls, incidental formatting, whole-object equality, snapshots, and ordering unless contractual.
- Use descriptive parameterized cases only for genuinely equivalent scenarios. Do not calculate expected results with the production algorithm.
- Use property testing or fuzzing for broad parser, protocol, and state-machine spaces; preserve repaired discoveries as deterministic regressions.
- Treat coverage as a lossy diagnostic, not a target. Combine it with branch semantics, mutation results, escaped defects, flake rate, and review.
- Separate computation from I/O and wrap difficult external APIs behind small owned interfaces. Choose the weakest sufficient double and do not mock domain values.
- Verify interactions only for observable mutations or side effects, matching behaviorally significant arguments and order only when contractual.
- Give performance and nondeterministic-quality checks controlled representative inputs, explicit thresholds or invariants, reproducible diagnostics, and production monitoring where needed.
- Distinguish product, infrastructure, and test failures; retain relevant operation, trace, log, fixture, and environment context without leaking secrets.

## API and automation baseline

- Make contracts, ownership, failure semantics, units, valid states, and compatibility policy explicit.
- Expose legitimate policy and arbitrary limits as validated named options rather than hidden constants.
- Design APIs around stable capabilities and domain language, not one screen, workflow, or configuration shape.
- Keep automation focused on orchestration. Move parsing, policy, retries, complex branching, and stateful workflows into typed, testable application code.
- Extract repeated authentication, environment setup, and fixture creation into named reusable modules.
- Require explicit inputs, reject missing configuration, propagate failures, define atomicity and partial-success behavior, and produce deterministic output.

## Review and delivery baseline

- Keep changes atomic, single-purpose, independently reviewable, mergeable, revertible, and usually below roughly 200–300 changed lines when practical.
- Split large initiatives into narrow changes; do not mix formatting, dependency churn, unrelated cleanup, structural refactoring, and feature behavior.
- Prefactor separately when structure blocks a feature: preserve and verify behavior, land the preparation, then add the feature.
- Optimize diffs for comprehension, explain non-obvious boundaries, remove accidental churn, and preserve rollback points.
- Write imperative commit subjects that state the concrete outcome; use the body for motivation, constraints, assumptions, and tradeoffs.
- Give respectful, specific, actionable feedback about behavior and risk. Label optional cosmetic feedback `nit:` and distinguish it from correctness, design, and security concerns.
- Respond by acknowledging the concern, presenting evidence and tradeoffs, and changing the code or explaining a safer alternative. Treat confusion as a clarity signal.

## Paired examples

### 1. Flatten control flow and isolate a rule
**Why:** Guard clauses expose failures, while a pure rule is directly testable.

**BAD**
```python
def import_order(raw, database):
    fields = raw.split(",")
    if len(fields) == 3 and database.find(fields[0]):
        return database.save(fields[0], int(fields[1]) * float(fields[2]))
```
**GOOD**
```python
import math

def order_total(quantity: int, unit_price: float) -> float:
    if quantity <= 0 or not math.isfinite(unit_price) or unit_price < 0:
        raise ValueError("invalid order values")
    return quantity * unit_price

def import_order(request, repository):
    customer = repository.find(request.customer_id)
    if customer is None: return None
    return repository.save(customer.id, order_total(request.quantity, request.unit_price))
```

### 2. Make API intent and dependency ownership explicit
**Why:** Named, unit-bearing options prevent ambiguous calls, and construction injection prevents hidden infrastructure creation.

**BAD**
```typescript
class Reports {
  fetch(id: string, timeout: number, cached: boolean) {
    return new NetworkClient().get(id, timeout, cached);
  }
}
```
**GOOD**
```typescript
type FetchOptions = { timeoutMs: number; cache: "prefer" | "refresh" };
interface ReportSource { get(id: string, options: FetchOptions): Promise<Report>; }
class Reports {
  constructor(private readonly source: ReportSource) {}
  fetch(id: string, options: FetchOptions) { return this.source.get(id, options); }
}
```

### 3. Put domain behavior behind a stable capability
**Why:** An intention-revealing operation protects transitions and prevents callers from mutating internal structure.

**BAD**
```typescript
subscription.status = "active";
subscription.endDate = null;
subscription.account.preferences.renewal = true;
```
**GOOD**
```typescript
class Subscription {
  reactivate() {
    if (this.status !== "expired") throw new InvalidTransition("must be expired");
    this.status = "active"; this.endDate = null; this.renewalEnabled = true;
  }
}
subscription.reactivate();
```

### 4. Translate errors once and log at the owning boundary
**Why:** Preserving the cause and logging one handling decision keeps failures actionable without duplicate noise.

**BAD**
```python
def load_order(order_id):
    try: return repository.fetch(order_id)
    except Exception as error:
        print("load failed", error); raise RuntimeError("request failed")
```
**GOOD**
```python
def load_order(order_id, repository):
    try:
        return repository.fetch(order_id)
    except StorageUnavailable as error:
        raise OrderLoadFailed(f"cannot load order {order_id}") from error

try:
    order = load_order(order_id, repository)
except OrderLoadFailed:
    logger.exception("order_request_failed", extra={"order_id": order_id})
    return error_response(503)
```

### 5. Synchronize tests on observable completion
**Why:** Controlled time and event-based waiting avoid scheduler-dependent sleeps and leaked asynchronous work.

**BAD**
```text
worker.submit(Token(current_time()))
sleep(500 milliseconds)
assert store.status(token_id) equals "expired"
```
**GOOD**
```text
clock := FixedClock(1900000000000)
worker := ExpirationWorker(clock, store)
token := Token(id = "t1", expires_at = clock.now())
try:
    completion := worker.completion_for(token.id)
    worker.submit(token)
    await completion with diagnostic timeout
    assert store.status(token.id) equals "expired"
finally:
    worker.close()
```

### 6. Keep destructive automation explicit and policy testable
**Why:** Preview-by-default limits accidents, while a pure selection rule makes boundary cases easy to verify.

**BAD**
```text
for each record in load_records():
    if record.enabled and record.environment is not "production":
        delete(record)
```
**GOOD**
```text
plan := deletion_plan(load_records())
if not arguments.apply:
    print_preview(plan)
    return
within transaction:
    locked_plan := deletion_plan(load_records_for_update())
    for each record in locked_plan:
        delete(record)
```

## Edge-case checklist

Consider only applicable items:

- Empty, missing, malformed, duplicate, partial, minimum, maximum, and boundary inputs.
- Unknown values, invalid transitions, repeated requests, retries, cancellation, timeout, and partial failure.
- Concurrent access, duplicate delivery, stale reads, arbitrary test order, and cleanup after exceptions.
- Locale, time zone, clock boundaries, random seeds, unstable order, and generated identifiers.
- External unavailability, permission denial, serialization mismatch, migration, compatibility, and rollback.
- Large input, resource exhaustion, latency, log volume, secret leakage, destructive defaults, and irreversible operations.

## Completion checklist

- Behavior matches an explicit contract and repository conventions.
- The solution is the smallest coherent change, without unrelated churn or speculative abstraction.
- Dependencies, ownership, state, units, ordering, and failure policy are explicit.
- Tests assert observable behavior at appropriate layers and cover relevant boundaries and failures.
- Tests own their resources, avoid sleeps and ambient state, and clean up all background work they create.
- Errors and logs preserve useful context without secrets or duplicate reporting.
- Focused and broader checks were run where available, and outcomes are reported accurately.
- The final diff is reviewable, deterministic where required, and safe to merge or revert.
