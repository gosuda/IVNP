---
name: testing-practices
description: Creates, repairs, refactors, and reviews deterministic tests. Use when changing test coverage, asynchronous behavior, test doubles, fixtures, or assertions in any programming language.
license: MIT
---

# Testing Practices

Create tests that are deterministic, behavior-focused, appropriately layered, and useful when they fail. Apply this skill to production changes, test-only changes, defect regressions, asynchronous code, fixtures, test doubles, coverage work, performance checks, generated testing, and test review.

## Operating Procedure

1. Identify the observable contract, important scenarios, failure modes, boundaries, and risk before choosing a test technique.
2. Translate requirements and important user scenarios into acceptance conditions meaningful to users and implementers.
3. Select the lowest stable public boundary with enough fidelity to prove each condition.
4. Establish a hermetic boundary around every input, dependency, and resource the test uses.
5. For a bug fix or behavior change, write a focused failing example from the caller's perspective and confirm that it fails for the intended reason. For a behavior-preserving refactor or test review, establish a passing baseline or focused characterization instead.
6. Implement the smallest behavior that satisfies a failing contract, or make the structural change while the characterization remains green.
7. Run the focused test, its neighboring suite, and relevant component, contract, or integration suites.
8. Repeat the test in isolation, in a different order, concurrently where supported, and under relevant boundary conditions.
9. Review failure output, cleanup, runtime, distinct regression value, and susceptibility to flaking.

When repairing unclear tests, restore a trusted baseline first when practical. Preserve a deterministic regression for the defect before broad refactoring.

## Test-Layer Selection

Choose layers by speed, maintainability, resource use, reliability, diagnostic quality, and fidelity rather than a fixed ratio.

- Put business rules, behavior partitions, boundaries, and ordinary error handling in small deterministic tests.
- Use component and integration tests for real persistence, serialization, framework wiring, and process-local contracts.
- Use consumer-provider or shared contract tests for remote-service compatibility and reusable fakes.
- Reserve end-to-end tests for a small set of vital user journeys; do not repeat every API scenario through a user interface.
- Test through a domain interface or API unless the behavior is specifically visual, interactive, or cross-layer.
- Correct an hourglass suite that has many isolated tests and broad end-to-end tests but little component or contract coverage.
- Do not treat heavily mocked unit tests as evidence that a realistic request flow works.
- Assign each acceptance condition to the cheapest sufficiently faithful layer.

A valuable end-to-end test maps to an important use case, uses production-like wiring where fidelity matters, asserts user-observable outcomes, and captures enough context to locate the failing layer. It is a safety rail, not an exhaustive input matrix.

## Determinism and Hermeticity

- Own every file, directory, port, database, queue, configuration value, locale, random source, clock, process variable, and mutable fixture used by a test.
- Prefer in-memory dependencies or unique per-test temporary resources.
- Restore unavoidable process-wide mutation in guaranteed cleanup.
- Never depend on a developer machine, ambient configuration, real credentials, test order, shared mutable fixtures, or uncontrolled infrastructure.
- Treat time, randomness, scheduling, and network behavior as injected inputs.
- Supply a clock or timestamp, seeded random source, controllable scheduler, and explicit transport.
- Test timers, retries, and deadlines with virtual time or a controllable scheduler when available.
- Never use a fixed sleep for synchronization.
- Wait for an observable condition, explicit event, or framework-neutral idleness signal; use a diagnostic timeout only as a failure bound.
- Stop and await every task, process, server, stream, worker, connection, and other resource that the test creates or explicitly owns before the test returns, including after assertion failure.
- Make tests independent of execution order. Require concurrent execution only when their owned resources permit it; serialize legitimately exclusive process-global resources and restore their state.
- Identify every external connection point and fail closed if a small test attempts unapproved real I/O.
- Track flaky outcomes explicitly.
- Quarantine only with an owner and repair deadline; retries may gather evidence but must not silently convert failure to success.

## Behavioral Test Design

- Name the scenario and observable outcome.
- Avoid vague names, implementation method names, numbering, and names that join independent behaviors with “and.”
- Arrange only relevant facts, invoke one meaningful behavior, and assert its observable contract.
- Hide irrelevant defaults behind builders or factories, but leave scenario-defining values visible.
- Split unrelated scenarios so one failure cannot conceal another and the test name identifies the broken contract.
- Assert specific return values, fields, state transitions, or externally visible side effects.
- Avoid whole-object equality, serialized equality, broad snapshots, private-method checks, harmless formatting checks, and ordering assertions unless contractual.
- Prefer domain matchers or predicates that explain the violated constraint over opaque Boolean expressions or long lists of low-level calls.
- Keep test names, assertion wording, and expected and actual values semantically aligned.
- Include expected value, actual value, relevant input or operation, and domain identifiers in failure output.
- Use a fatal precondition check when continuing could crash or make later checks meaningless.
- Use non-fatal checks for independent properties when reporting all failures is useful.
- Test helpers must propagate failures with added operation context; never swallow errors or return a fallback that hides setup failure.
- Consider normal, failure, empty, partial, invalid, malformed, minimum, maximum, just-inside, just-outside, and interaction states by risk.
- Prefer explicit return values or typed results over ambiguous output mutation, hidden side effects, or exceptions for ordinary outcomes.

## Input Selection and Generated Testing

- Select examples from behavior partitions and boundaries rather than arbitrary values.
- Use pairwise or risk-based combinations when exhaustive Boolean combinations add little distinct signal.
- Use parameterized tests only for genuinely equivalent scenarios.
- Give each row a descriptive identifier and explicit expected outcome.
- Do not place unrelated contracts in one opaque table, generate expected results with the production algorithm, or let one failed row obscure the broken behavior.
- Use property-based or fuzz testing for broad input and call-sequence spaces, especially parsers, state machines, and APIs.
- Give generated tests a reproducible seed and bounded workload.
- Shrink or minimize failures and preserve every valuable discovery as a fixed regression example.
- Generated testing supplements rather than replaces scenario, boundary, contract, and integration tests.

## Design for Testability

- Separate computation from I/O, configuration, object construction, and framework lifecycle.
- Extract cohesive behavior from long branching procedures and inject collaborators explicitly.
- Wrap hard-to-test third-party interfaces behind small owned interfaces.
- Avoid hidden construction, global lookups, service locators, and singleton replacement.
- Make policy and arbitrary limits explicit validated parameters with sensible defaults instead of hardcoding them.
- Keep contracts directly observable so tests can prove behavior without reaching into private implementation.
- Before implementation, identify risky dependencies and failure modes and decide how each acceptance condition will be observed.

## Test Doubles

Choose the weakest double that proves the behavior:

1. Prefer a fast deterministic real implementation when safe and practical.
2. Use a stub to supply controlled answers from a slow, unavailable, or nondeterministic collaborator.
3. Use a reusable in-memory fake when meaningful state and behavior matter.
4. Use a mock only to observe an otherwise inaccessible mutation or boundary side effect.

Apply these rules:

- Do not mock domain entities, value objects, or lightweight utilities.
- Stub read-only queries when needed, but do not verify their count, order, or intermediate lookup sequence.
- Verify interactions only for mutations or externally observable side effects.
- Match only behaviorally significant arguments; ignore generated identifiers, timestamps, incidental metadata, and call order unless contractual.
- Stub the collaborator at an explicit seam, not the business logic under test.
- To replace one boundary behavior, prefer composition and a forwarding fake that delegates unaffected behavior to the real implementation rather than patching internals.
- Prefer service-owner-maintained fakes validated continuously by the same contract suite as the real adapter.
- Give an ad hoc fake explicit ownership, contract coverage, and a synchronization plan.
- Give stream and device fakes deterministic playback of small, meaningful, versioned fixtures.
- Add realistic component, contract, or system tests for routing, serialization, wiring, and business flow across doubles.

## Fixtures and State

- Create only the data needed by the scenario; avoid giant shared fixtures that hide causality.
- Give every mutable resource unique ownership and deterministic cleanup.
- Keep fixture files small, readable, versioned, and representative.
- Use builders for irrelevant defaults, but show values that explain the behavior.
- Ensure setup failures stop the test with path, operation, and cause rather than producing misleading assertion failures.
- Close databases, files, sockets, subscriptions, and background work in guaranteed cleanup blocks.

## Assertions and Diagnostics

A good failure lets a developer distinguish a product defect, infrastructure failure, and test defect without rerunning blindly.

- State the scenario, operation, expected outcome, actual outcome, and relevant identity.
- Retain useful request, event, trace, log, and environment context without exposing secrets.
- Prefer domain-level diffs to raw dumps.
- Assert one coherent behavior, not necessarily one assertion statement.
- When multiple properties independently define that behavior, report all useful mismatches after validating prerequisites.

## Coverage, Value, and Maintenance

- Treat coverage as a lossy diagnostic, never as a quality target.
- Inspect uncovered behavior and branch or condition semantics while accounting for tool granularity.
- Combine coverage with mutation results, escaped defects, flake rate, review, and risk analysis.
- Never add assertion-free execution solely to raise a percentage.
- Prioritize tests by expected defect detection and regression value against runtime, maintenance cost, diagnostic cost, and flake risk.
- Remove, merge, or rewrite repetitive automation that contributes no distinct signal.
- Separate must-pass compatibility cases from advisory or exploratory corpora when release semantics differ.
- Keep feedback fast by first removing unnecessary end-to-end work and shared-state coupling, then parallelizing independent tests.

## Specialized Testing

### Exploratory Testing

Use exploratory testing to find risks automation did not anticipate, especially across clients, configurations, qualitative output, and complex interactions. Record observations, useful data, and environment details. Convert repeatable high-value findings into focused deterministic regressions.

### Performance Testing

- Define representative workloads and explicit latency, throughput, resource, error-rate, and quality thresholds.
- Control and document the environment and use reproducible data and seeds.
- Capture service and host telemetry during the run.
- Keep the harness independent enough to compare builds.
- Simulate adverse network or storage behavior when it is part of the production contract.

### Nondeterministic or Qualitative Systems

For ranking, media, probabilistic, or learned behavior, test invariants, safety constraints, calibrated quality metrics, curated examples, distribution shifts, and online monitoring. Exact-output assertions alone are insufficient. Use tolerances and statistical checks only with documented sample sizes, seeds, and acceptable error bounds.

## Examples

### 1. Inject time instead of reading the wall clock

Why: A supplied timestamp makes an expiration boundary deterministic across scheduler pauses and calendar changes.

BAD
```python
def is_expired(token):
    return utc_now() >= token.expires_at

def test_expired():
    token = Token(expires_at=utc_now())
    assert is_expired(token)
```

GOOD
```python
def is_expired(token, now):
    return now >= token.expires_at

def test_expired_at_boundary():
    frozen = Instant("2030-01-01T00:00:00Z")
    token = Token(expires_at=frozen)
    assert is_expired(token, now=frozen)
```

### 2. Synchronize on an event instead of sleeping

Why: An explicit completion signal is fast when healthy, while a timeout only bounds and diagnoses failure.

BAD
```typescript
async function testIndexesDocument() {
  indexer.submit(document);
  await sleep(500);
  assert(store.has(document.id));
}
```

GOOD
```typescript
async function testIndexesDocument() {
  const operation = indexer.submit(document);
  try {
    await withTimeout(operation.completed(), 1000, `document ${document.id} was not indexed`);
    assert(store.has(document.id));
  } finally {
    operation.cancel();
    await operation.stopped();
  }
}
```

### 3. Own resources and guarantee cleanup

Why: Unique storage and guaranteed shutdown remove order dependence, leaks, and interference during parallel execution.

BAD
```python
DB_PATH = "/tmp/shared-test.db"

def test_create_user():
    db = Database(DB_PATH)
    db.insert(User("ada"))
    assert db.count() == 1
```

GOOD
```python
def test_create_user(test_resources):
    db = Database(test_resources.unique_path("users.db"))
    try:
        db.insert(User("ada"))
        assert db.count() == 1
    finally:
        db.close()
```

### 4. Separate computation from I/O

Why: Pure business rules support fast boundary tests while adapter tests independently establish infrastructure fidelity.

BAD
```typescript
async function checkout(userId: string) {
  const user = await database.queryUser(userId);
  const discount = user.age > 65 ? 0.2 : 0;
  return payment.charge(user.card, 100 * (1 - discount));
}
```

GOOD
```typescript
function totalFor(age: number, subtotal: number): number {
  return subtotal * (age > 65 ? 0.8 : 1);
}

assertEqual(totalFor(66, 100), 80);
// Separate adapter tests cover database and payment wiring.
```

### 5. Assert public behavior rather than private calls

Why: Observable-result assertions survive harmless caching and method refactoring while still detecting a broken contract.

BAD
```typescript
async function testLoadsProfile() {
  const service = new ProfileService(repository);
  const cacheSpy = spyOnPrivate(service, "readCache");
  await service.get("42");
  assertEqual(cacheSpy.calls, 1);
}
```

GOOD
```typescript
async function testReturnsStoredProfile() {
  const repository = new InMemoryProfiles([{ id: "42", name: "Ada" }]);
  const service = new ProfileService(repository);
  assertDeepEqual(await service.get("42"), { id: "42", name: "Ada" });
}
```

### 6. Use the weakest sufficient test double

Why: A stateful fake proves the outcome without freezing read counts, lookup order, or other implementation details.

BAD
```typescript
async function testGrantCredits() {
  const store = strictMock<UserStore>();
  store.expect("findById", "u1").once().returns({ id: "u1", credits: 0 });
  store.expect("update", { id: "u1", credits: 10 }).once();
  await new CreditService(store).grant("u1", 10);
  store.verifyAll();
}
```

GOOD
```typescript
async function testGrantCredits() {
  const store = new InMemoryUserStore([{ id: "u1", credits: 0 }]);
  await new CreditService(store).grant("u1", 10);
  assertEqual((await store.findById("u1")).credits, 10);
}
```

### 7. Verify only significant properties of a side effect

Why: Focused interaction checks protect the published contract without coupling the test to generated metadata.

BAD
```python
publisher.assert_called_once_with({
    "event_id": "generated-123",
    "created_at": "2030-01-01T00:00:00Z",
    "type": "order.shipped",
    "order_id": "o7",
    "attempt": 1,
})
```

GOOD
```python
assert publisher.call_count == 1
event = publisher.call_args.args[0]
assert event["type"] == "order.shipped"
assert event["order_id"] == "o7"
# Generated identifiers, timestamps, and retry metadata are unconstrained.
```

### 8. Parameterize equivalent boundaries descriptively

Why: Named partitions keep concise coverage readable and identify the exact boundary contract that failed.

BAD
```python
for row in huge_cartesian_product():
    assert decide(*row.inputs) == row.expected
```

GOOD
```python
import unittest

class MeetsMinimumTest(unittest.TestCase):
    def test_boundaries(self):
        cases = [
            ("equal boundary", 10, 10, True),
            ("just below minimum", 9, 10, False),
            ("just above minimum", 11, 10, True),
        ]
        for case_name, value, minimum, expected in cases:
            with self.subTest(case=case_name):
                self.assertIs(meets_minimum(value, minimum), expected)
```

### 9. Preserve generated discoveries as regressions

Why: A fixed minimized example remains covered even when later generated runs explore different inputs.

BAD
```python
def test_parser():
    fuzz(parse_packet)
```

GOOD
```python
def test_parser_rejects_truncated_length_prefix():
    packet = bytes([0, 5, 97, 98])
    error = capture_error(lambda: parse_packet(packet))
    assert error.kind == "truncated-payload"

# A separate bounded generated test uses a recorded seed.
```

### 10. Validate a reusable fake with the real contract

Why: Running one behavioral contract against both implementations prevents the fast fake from drifting from production behavior.

BAD
```text
class LocalInventoryFake:
  reserve(sku, count):
    return RESERVED
```

GOOD
```text
contract InventoryContract(factory):
  test "cannot reserve more than available":
    inventory = factory.with_stock("A", 2)
    ASSERT inventory.reserve("A", 3) == OUT_OF_STOCK

  test "reservation reduces availability":
    inventory = factory.with_stock("A", 2)
    ASSERT inventory.reserve("A", 1) == RESERVED
    ASSERT inventory.available("A") == 1

RUN InventoryContract against RealInventoryAdapter
RUN InventoryContract against MaintainedInventoryFake
```

## Verification Checklist

Before completing test work, verify:

- For a bug fix or behavior change, the regression fails before the fix or under an isolated mutation of the behavior. For a refactor, the focused characterization passes before and after.
- The chosen layer is the lowest stable boundary with sufficient fidelity.
- Normal, boundary, empty, invalid, malformed, partial, interaction, and failure cases were considered by risk.
- Time, randomness, scheduling, network, filesystem, configuration, locale, and process state are controlled.
- No fixed sleep, uncontrolled retry, ambient credential, shared mutable fixture, or accidental real connection remains.
- Every resource and background activity created or explicitly owned by the test stops in success and failure paths.
- Assertions describe observable behavior and constrain only contractual details.
- Failure output includes expected value, actual value, scenario, operation, and useful identifiers.
- Helpers expose setup failure with operation, path or resource identity, and cause.
- Doubles are no stronger than necessary, and realistic wiring or shared contracts cover fidelity gaps.
- Generated tests have reproducible seeds and bounded workloads; valuable defects have fixed regressions.
- Performance checks use representative workloads, explicit thresholds, controlled environments, and diagnostic telemetry.
- Coverage changes represent asserted behavior rather than score manufacturing.
- The test passes alone, with neighboring tests, in varied order, and concurrently where applicable.
- The suite's runtime, flake risk, maintenance cost, diagnostic value, and distinct regression value remain acceptable.

## Review and Ownership

Quality is a shared engineering responsibility. Build reusable infrastructure, make controlled environments and representative data available, review tests for clarity and distinct value, and give specific impersonal feedback about behavior and risk. Encourage requests for testing help. Route language- or framework-specific mechanics to the corresponding specialized skill while retaining these cross-language contracts.
