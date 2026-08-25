---
name: code-review
description: Reviews code changes and prepares focused pull requests with evidence-backed feedback. Use when reviewing diffs, organizing commits, or preparing a change in any programming language.
license: MIT
---

# Code Review

## Purpose

Review code changes and prepare focused, evidence-backed pull requests in any programming language. Optimize for correctness, security, maintainability, reviewer comprehension, safe rollout, and easy rollback.

## Routing and Scope

Use this skill when:

- Reviewing a diff, commit, branch, patch, or proposed pull request.
- Deciding whether a change is ready to merge.
- Splitting an initiative into reviewable, independently mergeable changes.
- Separating behavior-preserving prefactoring from feature behavior.
- Organizing commits or writing commit and pull request descriptions.
- Writing or responding to review feedback.
- Evaluating defaults, feature controls, migrations, or destructive behavior.

Apply this skill to universal review, risk, evidence, and change-organization concerns. Route syntax, framework conventions, package behavior, build configuration, and specialized static analysis to the relevant language or domain skill. An umbrella good-practices skill should route code-review work here rather than duplicate these rules; this specialized skill remains the comprehensive source for review procedure.

## Core Principles

1. Keep each pull request atomic, single-purpose, easy to explain, and safe to revert.
2. Aim for fewer than 200–300 changed lines when practical, excluding generated or low-review-value output, but treat size as a heuristic rather than a quota.
3. Prefer a coherent 350-line change over an artificial split that breaks the repository; still scrutinize a risky 40-line change closely.
4. Sequence multi-step initiatives as independently reviewable and mergeable changes, each leaving the repository valid with a clear rollback boundary.
5. Do not mix feature behavior with unrelated formatting, cleanup, dependency updates, file moves, broad renames, or structural refactoring.
6. When structure obstructs a feature, prefactor first: preserve and verify behavior, then add the feature separately.
7. Optimize the diff for comprehension by removing unrelated churn, minimizing mechanical noise, and explaining non-obvious boundaries.
8. Write imperative commit subjects that state a concrete outcome and stand alone in history; reserve the body for motivation, constraints, evidence, and tradeoffs.
9. Make feedback respectful, specific, actionable, and grounded in observable effects, evidence, documented conventions, or design constraints.
10. Separate blocking correctness, security, privacy, data integrity, and compatibility concerns from preferences; prefix optional cosmetic feedback with `nit:`.
11. Treat every comment as a clarity signal. Address its underlying concern even when the proposed patch is unsuitable, and explain the supported alternative without defensive debate.
12. For operator-facing destructive tools where accidental invocation is plausible, prefer preview or nondestructive defaults and explicit execution. For APIs and automated jobs, require safeguards appropriate to their contract: authorization, scope validation, idempotency, atomicity, recovery, and observability.
13. Treat historical announcements, event notices, hiring posts, statistics, and cultural slogans as context, never as blocking engineering requirements.
14. Never claim that a check passed unless it was run and its result was observed.

## Review Procedure

### 1. Establish Intent and Boundaries

Before judging implementation details:

- Read the description, linked requirements, acceptance criteria, and stated non-goals.
- Summarize the intended outcome in one sentence.
- Identify changed behavior, preserved behavior, affected interfaces, state transitions, and rollback expectations.
- Record assumptions that cannot be established from the diff.
- Separate enforceable requirements from historical or cultural context.
- Ask a focused question when intent is unclear instead of inferring a broad requirement.

### 2. Inspect the Diff Shape

Classify changed lines as:

- Required behavior.
- Tests or verification.
- Behavior-preserving structure.
- Mechanical churn, including formatting, renaming, generated output, and file movement.
- Unrelated change.

Request a split when categories obscure one another or create independent risk. Do not split solely to satisfy a line target when the pieces would be invalid, misleading, or impossible to verify independently.

Useful sequence boundaries are:

1. Characterization tests.
2. Behavior-preserving prefactoring.
3. A new interface or adapter with no callers.
4. Caller migration.
5. New behavior behind a safe default.
6. Cleanup after verified adoption.

### 3. Review by Risk

Prioritize effort in this order:

1. Security, authorization, privacy, secrets, and destructive actions.
2. Data integrity, migrations, concurrency, retries, and idempotency.
3. Correctness across normal, boundary, invalid, and failure paths.
4. Compatibility of public interfaces, stored data, configuration, and callers.
5. Operations, observability, resource use, rollout, and rollback.
6. Test quality and verification evidence.
7. Maintainability and readability.
8. Style and cosmetic preferences.

For important paths, trace inputs through validation, authorization, state changes, side effects, outputs, and failure handling. Inspect both the changed code and its callers, dependencies, and stored-state assumptions.

### 4. Demand Proportionate Evidence

Match evidence to risk. Prefer:

- A focused automated test that fails before the fix and passes after it.
- Characterization tests showing a prefactor preserves behavior.
- Boundary, invalid-input, timeout, retry, concurrency, and partial-failure tests where relevant.
- Results from the repository's standard formatting, static, type, unit, integration, and security checks.
- Before-and-after measurements using the same workload and method.
- A migration rehearsal or preview that reports affected records without changing them.
- A reproducible manual procedure stating inputs, expected results, and observed results.

Do not accept “tested” when the affected behavior is unclear. Do not demand broad suites, benchmarks, or an integration environment when a smaller deterministic check fully addresses the introduced risk.

### 5. Write Findings

Use the smallest useful location and include:

- **Severity:** blocking, important, question, or optional.
- **Observation:** what the code does.
- **Impact:** the concrete consequence and triggering conditions.
- **Evidence:** a reachable scenario, invariant, observed result, documented constraint, or enforced convention.
- **Action:** the outcome required, allowing equivalent solutions.

Use this structure:

```text
Blocking — billing/retry: A repeated request can create another invoice.
Impact: A timeout followed by a client retry can produce duplicate charges.
Evidence: The write has no stable request key and each attempt inserts a row.
Action: Make repeated execution idempotent and add focused regression evidence.
```

Do not inflate severity to win a preference. If evidence is incomplete, state the uncertainty and ask the question needed to resolve it.

### 6. Verify the Prepared Change

Before declaring readiness:

- Confirm the final diff has one coherent purpose and review it as a whole.
- Remove debug output, temporary workarounds, dead code, and unrelated churn.
- Run applicable repository-standard checks and focused tests for changed behavior and failure paths.
- For prefactoring, compare relevant results before and after the structural change.
- For operator-facing destructive tools, confirm that execution is explicit and preview is available where practical.
- Check new controls for clear names, help text, defaults, tests, ownership, and removal criteria.
- Check compatibility, migration, rollout, restart safety, and rollback when interfaces or state change.
- Record the procedures run, observed outcomes, baseline failures, and checks not run.

## Decision Rules

### Split the Change When

- Parts can be reviewed, merged, deployed, or reverted independently.
- Mechanical churn hides behavioral changes.
- Structure can be changed without behavior before the feature is added.
- Parts have different owners, rollout plans, or risk profiles.
- Reviewers cannot explain the diff as one coherent outcome.
- The change is too large to inspect thoroughly in a reasonable session.

### Keep the Change Together When

- Splitting would leave compilation, tests, schema, or runtime behavior invalid.
- An interface and its only caller must change atomically to preserve compatibility.
- Required generated output is inseparable from its source change.
- The combined diff establishes one invariant that cannot be verified in pieces.

For a large indivisible change, explain the boundary, isolate generated or mechanical sections, and provide a review map.

### Block the Change When

- A reachable path violates security, authorization, privacy, data integrity, or a stated correctness invariant.
- A destructive path lacks the authorization, scope validation, atomicity, recovery, or explicit operator intent required by its contract.
- Required compatibility, migration, restart, rollout, or rollback behavior is absent.
- Evidence is insufficient for a material risk introduced by the change.
- Unrelated changes prevent reliable review.

### Do Not Block When

- The concern is cosmetic and violates no enforced convention.
- The request is based only on personal preference.
- A different implementation resolves the documented risk.
- The supposed requirement comes only from announcements, statistics, slogans, events, or hiring material.

## Commit and Pull Request Preparation

### Commit Message

Use an imperative, concrete subject that makes sense without the pull request title. Avoid vague subjects such as `fix`, `updates`, `address comments`, or unspecified `cleanup`.

In the body, explain why the change is needed, why the approach was selected, important constraints, evidence, and tradeoffs. Do not merely narrate the diff.

### Pull Request Description

Use these sections:

```markdown
## Outcome
Prevent retries from creating duplicate invoices.

## Motivation
Clients retry after timeouts, so invoice creation must be idempotent.

## Scope
- Use a tenant- and operation-scoped request identifier enforced by a unique constraint or atomic conditional write.
- Add focused retry, concurrency, and key-conflict tests.

## Non-goals
- Redesign unrelated invoice fields or the transport retry policy.

## Evidence
- Retry regression test: one invoice remains after repeated requests.
- Existing invoice suite: all observed checks pass.

## Risk and rollback
The unique constraint adds write coordination. Rollback requires a compatible schema change and must preserve existing keys.

## Review map
Review the invariant and tests first, then storage, then request handling.
```

## Feedback and Response Style

Use labels consistently:

- `Blocking:` correctness, security, data loss, required compatibility, or unverified material risk.
- `Important:` meaningful design, operability, or maintainability concern to resolve or explicitly accept.
- `Question:` missing context that may establish or dismiss a concern.
- `nit:` optional naming, wording, or cosmetic preference.

Focus on outcomes rather than ownership or personality. When responding: acknowledge the concern, state evidence or constraints, describe the resolution, and point to the changed code, test, or explanation.

## Edge Cases

- **Pre-existing failures:** Record the baseline and determine whether the patch adds a failure; do not attribute an unverified failure to the change.
- **Generated files:** Review the source and generation boundary first; retain required output but isolate or collapse it in the review map.
- **Large moves or renames:** Land the mechanical operation separately from semantic edits so history and behavior remain inspectable.
- **Urgent fixes:** Keep the smallest safe correction with focused regression evidence; defer cleanup without lowering correctness standards.
- **Database or state migrations:** Require preview, bounded batches where appropriate, restart safety, mixed-version compatibility, observability, and rollback or forward repair.
- **Feature controls:** Default risky behavior off when uncertainty or rollback cost warrants it, and define ownership and removal criteria.
- **Destructive commands:** Preview by default, require explicit execution, report intended scope, and make retries safe where practical.
- **No tests exist:** Add a focused characterization test when feasible; otherwise document a reproducible manual check and why automation is not practical.
- **Unsuitable reviewer proposal:** Resolve the underlying risk with an evidenced alternative rather than rejecting the comment without resolution.
- **Mixed-language repository:** Apply these universal rules across the diff and delegate language mechanics to the relevant specialized skill.

## Examples

### 1. Separate Prefactoring from Feature Behavior

Why: independent changes let reviewers prove that structure preserves behavior before evaluating a new business rule.

**BAD**

```python
class Order:
    def total(self):
        subtotal = sum(item.price * item.quantity for item in self.items)
        return subtotal * 0.9 if self.customer.is_member else subtotal
```

**GOOD**

```python
# PR 1: behavior-preserving extraction
class Order:
    def subtotal(self):
        return sum(item.price * item.quantity for item in self.items)

    def total(self):
        amount = self.subtotal()
        return amount * 0.9 if self.customer.is_member else amount

# PR 2: feature behavior after characterization checks pass
class Order:
    def subtotal(self):
        return sum(item.price * item.quantity for item in self.items)

    def total(self):
        amount = self.subtotal()
        discount = 0.15 if self.customer.is_premium else 0.10
        return amount * (1 - discount) if self.customer.is_member else amount
```

### 2. Keep Mechanical Churn Out of Behavior Changes

Why: separating a rename from retry behavior makes the functional change inspectable and independently revertible.

**BAD**

```typescript
// One change renames the store, reformats the package, and adds retries.
export async function loadUser(id: string) {
  return retry(() => accountStore.get(id), 3);
}
```

**GOOD**

```typescript
// PR 1: rename UserStore to AccountStore without semantic edits.
// PR 2: add retry behavior with focused success and failure tests.
export async function loadUser(id: string) {
  return retry(() => accountStore.get(id), 3);
}
```

### 3. Write a Standalone Commit Message

Why: a concrete subject remains useful in abbreviated history while the body records motivation and cost.

**BAD**

```text
fix stuff

Address comments.
```

**GOOD**

```text
Prevent duplicate invoice creation during request retries

Use a tenant- and operation-scoped request identifier as an idempotency key
because clients may retry after timeouts. Enforce it with a unique constraint
or atomic conditional write so concurrent retries cannot create another invoice.
```

### 4. Give Evidence-Backed Feedback

Why: stating the contract violation and desired outcome separates a blocking defect from an optional naming preference.

**BAD**

```typescript
// This is bad. Rewrite it the normal way.
```

**GOOD**

```typescript
// Blocking: Promise.all rejects on the first failure, so this path omits
// later validation errors required by the response contract. Collect every
// validation result before constructing the response.

// nit: `result` could be `validationResult` for readability.
```

### 5. Resolve the Underlying Concern

Why: an evidenced alternative can address repeated I/O without introducing stale authorization data.

**BAD**

```text
Reviewer: Cache this lookup.
Author: No. The implementation is fine.
```

**GOOD**

```text
Reviewer: This lookup runs once per item. Can we avoid repeated I/O?
Author: Agreed on the I/O risk. At 20 items, the observed p95 rises by 35 ms.
I will batch the lookup rather than use a process-local cache because permission
changes must be visible immediately. A test now asserts one repository call.
```

### 6. Make Destructive Behavior Explicit

Why: preview-by-default turns an omitted option into a harmless inspection rather than an accidental production change.

**BAD**

```pseudocode
options = parse_options(dry_run = false)
apply_changes(preview = options.dry_run)
```

**GOOD**

```pseudocode
options = parse_options(apply = false)
if options.apply:
    report_scope()
    apply_changes_idempotently()
else:
    print_change_preview()
```

## Final Review Output

Produce a concise report in this order:

1. **Summary:** intended outcome and overall assessment.
2. **Blocking findings:** ordered by severity, each with location, impact, evidence, and action.
3. **Important findings:** material non-blocking concerns.
4. **Questions:** only those needed to establish correctness or scope.
5. **Optional feedback:** clearly labeled `nit:`.
6. **Verification:** observed checks and results, baseline failures, and checks not run.
7. **Change plan:** proposed commit or pull request split when the diff is not atomic.

If there are no findings, say so explicitly, summarize residual risk, and list the evidence reviewed. Do not invent issues to make the review appear thorough.
