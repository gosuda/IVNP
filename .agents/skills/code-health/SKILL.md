---
name: code-health
description: Improves production code with clear control flow, precise naming, efficient data access, and focused cleanup. Use when writing, reviewing, or refactoring code in any programming language.
license: MIT
---

# Code Health

Improve production code without changing intended behavior. Favor readable control flow, precise domain language, deterministic data handling, explicit failure policies, and small, reviewable cleanup.

## Scope and routing

Use this specialized skill for language-neutral design and refactoring in application code, libraries, tests, automation programs, and configuration-like source files.

- Apply repository conventions and target-language idioms when they are stricter than this guidance.
- Let an umbrella good-practices skill route work here rather than duplicate these details.
- Route shell syntax, quoting, pipelines, process control, and strict-mode mechanics to `shell-practices`.
- Keep shell scripts as thin orchestration layers; move parsing, retries, business rules, and stateful workflows into a typed or readily testable general-purpose language.
- Route truly language-specific mechanics to the corresponding language skill.
- Derive requirements from concrete, transferable engineering needs, not announcements, promotional text, incomplete history, or unrelated repository anecdotes.

## Working method

1. Establish the behavior contract from tests, callers, types, documentation, and observable effects.
2. Identify the smallest problem that materially affects comprehension, correctness, determinism, performance, or operability.
3. Select a transformation using the rules below; prefer the least powerful change that solves the problem.
4. Preserve public inputs, outputs, side effects, errors, ordering, timing assumptions, and compatibility unless the request explicitly changes them.
5. Add or update focused tests before risky restructuring.
6. Keep incidental cleanup local, bounded, and separable from behavior changes.
7. Run repository-standard formatting, static analysis, tests, build checks, and relevant concurrency checks.
8. Review the diff for accidental semantics, stale comments, dead paths, duplicate logs, secret exposure, and order dependencies.

## Selection rules

### Control flow

- Handle invalid input, errors, and exceptional cases first with guard clauses or early exits.
- Keep the main path at minimal indentation and generally avoid nesting beyond three levels.
- After `return`, `throw`, `panic`, `break`, or `continue`, remove a redundant `else` and dedent the continuation.
- Use a switch, match, dispatch table, or equivalent for several mutually exclusive cases.
- Keep an `if` chain when conditions overlap, evaluation order matters, side effects are intentional, or ranges are clearer.
- Prefer positive predicate names such as `isEnabled`, `isAuthorized`, and `allowAnonymous`; put negation in the expression.
- Name explanatory conditions and parenthesize mixed conjunctions and disjunctions.
- Extract a predicate when a condition expresses a reusable domain rule or contains several logical operators.
- Extract deeply nested loops, large case bodies, and complex branches into focused helpers.
- Abstract repeated traversal when callers differ only by predicate or operation.
- Do not introduce a generic traversal helper for one trivial use or when it hides domain order, mutation, or failure behavior.
- Keep each function at one abstraction level; orchestration should call named operations rather than mix policy with parsing, indexing, persistence, or transport.
- Arrange statements in execution and data-flow order.
- Derive values near their use unless a wider lifetime or shared invariant requires otherwise.
- Keep functions, classes, and modules cohesive around one responsibility.

### Functions and data

- When a keyed collection API returns presence and value in one operation, bind both once and reuse them.
- If the collection permits storing its missing-value sentinel or lacks a combined lookup, use its explicit presence API even when that requires a separate retrieval.
- Separate a pure functional core from an imperative shell.
- Keep calculations and business decisions deterministic; isolate database, file, network, clock, random, locale, and other external state at orchestration boundaries.
- Pass time, randomness, locale, and configuration into pure functions as ordinary values rather than hiding them behind globals.
- Eliminate shared mutable state in concurrent work through local computation followed by aggregation.
- If sharing is unavoidable, protect each compound invariant or state transition with one appropriate synchronization boundary. Use atomics only when the independently atomic value is the complete invariant.
- Parallelize aggregation only when the combine operation has suitable semantics.
- Preserve order for non-commutative operations and define behavior for partial worker failure.
- Never rely on collection iteration order unless its contract guarantees the required order.
- Impose stable order whenever output, selection, serialization, generated files, or tests must be reproducible.

### Naming, comments, and structure

- Name symbols for domain purpose or resulting action.
- Replace vague names such as `handle`, `process`, `doThing`, and `onEvent` with names such as `rejectExpiredSession`, `persistInvoice`, or `recalculateTotal`.
- Make code explain itself with precise names, cohesive units, and direct flow.
- Use comments for purpose, contracts, external constraints, tradeoffs, invariants, or workaround rationale, not narration of syntax.
- Update or remove comments when their rationale changes.
- Keep composition roots and factories limited to constructing, connecting, and returning dependencies.
- Put business decisions, I/O workflows, and mutable runtime behavior in the composed objects.
- Delete dead functions, types, packages, tests, commented-out implementations, obsolete feature flags, and the legacy paths behind them.
- Treat version control, not dormant source code, as the recovery mechanism.
- Before deletion, check reflective loading, external consumers, generated references, configuration names, migrations, and rollback obligations.
- Apply the Boy Scout rule only to nearby, safe cleanup.
- Stop cleanup when it expands review scope, changes public contracts, weakens test confidence, or requires unrelated migration.

### Errors and observability

- Catch an error only to recover, add useful context, translate it into a domain error, clean up, or report it at the boundary that owns the response.
- Do not catch merely to log and rethrow.
- Catch narrowly and preserve the original cause and diagnostic chain when translating failures.
- Preserve cancellation, interruption, and process-termination signals according to host-language conventions.
- Avoid silent catches and replacement errors that erase the operation, resource, or relevant input.
- Redact credentials, tokens, private payloads, and other secrets while retaining useful context.
- Define an explicit failure policy: retry, fallback, rejection, propagation, or boundary response.
- Do not force callers to handle failures they cannot act on.
- Use structured, leveled logging with stable event names and contextual key-value fields.
- Log an error once at the handling boundary; avoid production print statements and duplicate logging across layers.
- Avoid per-item logging in large loops; emit aggregate progress, summary metrics, or bounded samples.

### Determinism, operations, and decisions

- Keep semantically unordered source lists in deterministic order when doing so improves scanning, merging, and duplicate detection.
- Use explicit keep-sorted markers where the repository supports them.
- Never sort routes, rules, migrations, middleware, statements, or other lists when order affects behavior.
- Treat first-match selection, insertion-order contracts, sequential migrations, and meaningful output order as precedence-sensitive.
- Record hard-won automation diagnoses near the affected automation.
- Include the symptom, root cause, remediation, verification, prevention, and dangerous actions to avoid.
- Compare multi-option designs in a compact decision matrix using the same named criteria.
- State assumptions, note meaningful tradeoffs, and identify the selected option.

### Automation programs

- Extract repeated authentication, environment initialization, fixture creation, and similar setup into named reusable modules.
- Keep automation focused on orchestration: invoke defined tools, pass explicit inputs, and connect a small number of steps.
- Move complex parsing, policy, retries, business rules, and state transitions into testable application code.
- Make automation deterministic and fail-fast.
- Declare and validate required inputs before side effects begin.
- Propagate command and pipeline failures; never continue silently with missing values or partial results.
- Route shell-only implementation details to `shell-practices`; this skill governs the language-neutral boundary and design.

## Safety constraints

- A guard clause must not bypass cleanup, transaction finalization, lock release, audit behavior, or required reporting.
- Use structured cleanup constructs or move the exit outside the protected region.
- Removing `else` is unsafe when declarations are branch-scoped and needed later, or when evaluation order or side effects change.
- A single map lookup needs an explicit presence result when stored values can equal the missing sentinel.
- Sorting is unsafe when first-match wins, insertion order is contractual, migrations are sequential, or order carries meaning.
- Pure functions may accept time, randomness, locale, and configuration explicitly; globals make them impure and tests nondeterministic.
- Parallel aggregation must preserve required order and define cancellation, retry, and partial-failure semantics.
- Exception translation must retain actionable, redacted context without swallowing control-flow signals.
- Cleanup must remain atomic, test-protected, and separate from broad or risky behavior changes.

## Examples

### 1. Flatten validation with guard clauses

Why: early exits expose failure conditions and leave the successful path at base indentation without changing the result.

**BAD**
```python
def publish(article, user):
    if article is not None:
        if user is not None:
            if user.is_authorized:
                if article.is_ready:
                    save(article)
                    notify_subscribers(article)
                    return True
    return False
```

**GOOD**
```python
def publish(article, user):
    if article is None or user is None:
        return False
    if not user.is_authorized:
        return False
    if not article.is_ready:
        return False

    save(article)
    notify_subscribers(article)
    return True
```

### 2. Use positive policy names and explicit multi-way selection

Why: named policy terms make logical grouping visible, while a switch shows that status cases are mutually exclusive.

**BAD**
```typescript
function displayState(enabled: boolean, user: User, status: Status): string {
  const isNotUnauthorized = user.authorized || user.admin;
  if (enabled && isNotUnauthorized) {
    if (status === "pending") return "waiting";
    else if (status === "running") return "active";
    else if (status === "done") return "complete";
  }
  return "unavailable";
}
```

**GOOD**
```typescript
function displayState(enabled: boolean, user: User, status: Status): string {
  const mayView = enabled && (user.authorized || user.admin);
  if (!mayView) return "unavailable";

  switch (status) {
    case "pending": return "waiting";
    case "running": return "active";
    case "done": return "complete";
    default: return "unavailable";
  }
}
```

### 3. Extract repeated traversal without hiding domain intent

Why: the helper removes duplicated mechanics while each caller retains its named business predicate.

**BAD**
```text
function overdue(root, today):
  result = []
  for project in root.projects:
    for task in project.tasks:
      if task.dueDate < today and task.status != DONE:
        result.add(task)
  return result

function blocked(root):
  result = []
  for project in root.projects:
    for task in project.tasks:
      if task.blockers.count > 0:
        result.add(task)
  return result
```

**GOOD**
```text
function tasksMatching(root, predicate):
  result = []
  for project in root.projects:
    for task in project.tasks:
      if predicate(task):
        result.add(task)
  return result

function overdue(root, today):
  return tasksMatching(root, task -> task.dueDate < today and task.status != DONE)

function blocked(root):
  return tasksMatching(root, task -> task.blockers.count > 0)
```

### 4. Perform one map lookup with an explicit missing-value policy

Why: one retrieval avoids repeated work and check-then-act logic while documenting whether the missing sentinel can be stored.

**BAD**
```typescript
function notifyUser(users: Map<string, User>, userId: string): void {
  if (users.has(userId)) {
    sendEmail(users.get(userId)!);
  }
}
```

**GOOD**
```typescript
function notifyUser(users: Map<string, User>, userId: string): void {
  const user = users.get(userId);
  if (user === undefined) return;

  sendEmail(user);
}
// This map never stores undefined; otherwise use an explicit presence API.
```

### 5. Separate deterministic policy from external effects

Why: ordinary values make the decision easy to test, while the outer function owns I/O and observability.

**BAD**
```python
async def should_offer_discount(customer_id):
    customer = await repository.load_customer(customer_id)
    campaign = await campaign_client.load_active()
    audit.write(f"evaluating {customer_id}")
    return customer.lifetime_spend >= campaign.minimum_spend
```

**GOOD**
```python
def should_offer_discount(customer, campaign):
    return customer.lifetime_spend >= campaign.minimum_spend

async def evaluate_discount(customer_id):
    customer = await repository.load_customer(customer_id)
    campaign = await campaign_client.load_active()
    audit.write(f"evaluating {customer_id}")
    return should_offer_discount(customer, campaign)
```

### 6. Remove concurrent shared mutation and impose stable order

Why: worker-local results prevent data races, and explicit sorting makes semantically unordered output reproducible.

**BAD**
```text
shared validNames = []
parallel_for batch in batches:
  for item in batch:
    if isValid(item):
      validNames.add(item.name)
return join(validNames, ",")
```

**GOOD**

```text
result = parallel_map(
  batches,
  cancel_on_error = true,
  worker = batch ->:
    localNames = []
    for item in batch:
      if isValid(item):
        localNames.add(item.name)
    return localNames
)
if result.error:
  await all workers stopped
  return error(result.error)

allNames = flatten(result.values)
return join(sortBy(allNames, name -> name), ",")
```

### 7. Document contracts and rationale rather than syntax

Why: the contract and external constraint explain information that precise names and direct code cannot convey alone.

**BAD**
```python
def eligible_users(users):
    """Loop through users and skip users less than 24 hours old."""
    for user in users:
        if clock.now() - user.created_at < HOURS_24:
            continue
        handle(user)
```

**GOOD**
```python
def submit_eligible_users(users, clock):
    """Submit users whose risk profiles are stable enough to evaluate."""
    for user in users:
        account_age = clock.now() - user.created_at
        # The risk service exposes no stable profile during the first 24 hours.
        if account_age < HOURS_24:
            continue
        submit_for_risk_review(user)
```

### 8. Translate narrowly and log once at the handling boundary

Why: narrow translation preserves the cause, while one structured boundary event prevents duplicate and unactionable logs.

**BAD**
```python
def load_order(order_id):
    try:
        return repository.fetch(order_id)
    except Exception as error:
        print("load failed", error)
        raise RuntimeError("request failed")

try:
    order = load_order(order_id)
except Exception as error:
    print("request failed", error)
```

**GOOD**
```python
def load_order(order_id):
    try:
        return repository.fetch(order_id)
    except StorageError as error:
        raise OrderLoadError(f"cannot load order {order_id}") from error

try:
    order = load_order(order_id)
except OrderLoadError as error:
    logger.error("order_request_failed", order_id=order_id,
                 request_id=request_id, exception=error)
    return temporary_failure_response()
```

### 9. Keep composition separate and remove obsolete paths

Why: a composition root should only wire dependencies, and a completed migration should not retain flags or legacy behavior.

**BAD**
```typescript
async function purchase(cart: Cart): Promise<Receipt> {
  const gateway = new PaymentGateway();
  cart.total = flags.enabled("current_pricing")
    ? calculateCurrentPrice(cart)
    : calculateLegacyPrice(cart);
  const receipt = await gateway.charge(cart);
  await new EmailClient().send(receipt);
  return receipt;
}
```

**GOOD**
```typescript
const checkout = new CheckoutService(
  new PaymentGateway(new HttpTransport()),
  new ReceiptNotifier(new EmailClient()),
  calculateCurrentPrice,
);

async function purchase(cart: Cart): Promise<Receipt> {
  return checkout.purchase(cart);
}
// The completed rollout's flag, legacy implementation, and obsolete tests are deleted.
```

### 10. Keep automation fail-fast, reusable, and orchestration-only

Why: explicit validation and reusable setup prevent partial execution while policy and retry behavior remain independently testable.

**BAD**
```text
function runReportJob(environment):
  token = login(readSecret())
  project = openProject(token, "reports")
  rows = parseCsv(readFile("reports.csv"))
  for row in rows:
    if row.enabled and environment != PRODUCTION:
      ignoreFailure(() -> publish(project, row))
  print("complete")
```

**GOOD**
```text
function authenticatedProject(credentials, projectName):
  token = login(credentials)
  return openProject(token, projectName)

function eligibleReports(rows, environment):
  validateRows(rows)
  return filter(rows, row -> row.enabled and environment != PRODUCTION)

function runReportJob(inputs):
  require(inputs.credentials, inputs.reportFile, inputs.environment)
  rows = parseAndValidateReportFile(inputs.reportFile)
  plan = eligibleReports(rows, inputs.environment)
  project = authenticatedProject(inputs.credentials, "reports")
  results = publishAllWithPolicy(project, plan)
  if results.failedCount > 0:
    raise ReportJobFailed(results.summary)
  logInfo("report_job_completed", results.summary)
```

## Review and verification checklist

### Contract and control flow

- Confirm public inputs, outputs, side effects, errors, ordering, and compatibility remain intentional.
- Exercise invalid input, empty collections, missing keys, stored null-like values, unknown cases, and boundary values.
- Verify guard clauses do not skip cleanup, commits, unlocks, audits, or required reporting.
- Confirm removed branches and dedented continuations preserve scope, evaluation order, and side effects.
- Test extracted predicates and pure functions with table-driven cases covering every policy branch.

### Data, determinism, and concurrency

- Confirm each map access distinguishes absence from any legal stored value.
- Pass clocks, random values, locale, and configuration explicitly where deterministic behavior matters.
- Run repeated or randomized-order tests when iteration order could affect results.
- Ensure sorted regions are semantically unordered and precedence-sensitive regions remain untouched.
- Use race detection, stress tests, or synchronization-focused tests when concurrency changes.
- Verify aggregation semantics, output ordering, cancellation, and partial-worker failure behavior.

### Errors and observability

- Confirm every translated error retains its cause and useful redacted context.
- Verify cancellation, interruption, and termination signals still propagate correctly.
- Confirm each failure has an explicit retry, fallback, rejection, propagation, or response policy.
- Search logs for one event per handled failure and bounded volume for batch operations.
- Check all fields and messages for credentials, tokens, private payloads, and other secrets.

### Structure and cleanup

- Search direct, reflective, generated, configured, and external references before deleting code or names.
- Check migration sequencing, feature rollback obligations, and compatibility commitments before removal.
- Keep composition roots free of business decisions and runtime workflows.
- Confirm comments describe current intent, constraints, contracts, or rationale.
- Keep the final diff focused; separate broad renames, generated changes, risky cleanup, and behavior changes.
- Record durable automation diagnoses with symptom, cause, remediation, verification, prevention, and unsafe actions.
- For design choices, use consistent criteria, state assumptions, and record the selected option.

### Final verification

- Run repository-standard formatting, linting, type checking, unit tests, integration tests, and build verification.
- Run relevant concurrency, determinism, and failure-path checks.
- Review the final diff for stale comments, dead paths, duplicate logs, hidden order dependencies, and accidental semantic changes.
