---
name: api-design
description: "Designs hard-to-misuse APIs with explicit types, clear ownership, and injected collaborators. Use when changing signatures, data models, interfaces, constructors, or module boundaries in any language."
license: MIT
---

# API Design

Design language-neutral APIs and module boundaries that make valid use obvious, invalid states difficult or impossible to represent, dependencies explicit, and business behavior local to the concepts that own it.

## Use This Skill When

Use this skill when changing:

- Functions, methods, constructors, factories, builders, or initialization.
- Data models, commands, options, results, errors, or persisted representations.
- Interfaces, protocols, callbacks, extension points, or module boundaries.
- Dependency injection, collaborator ownership, resource lifecycle, or composition.
- Domain operations, state transitions, invariants, or cross-module orchestration.
- Repeated implementations that may or may not justify an abstraction.

Defer syntax, visibility, packaging, type-system mechanics, and language idioms to the relevant language skill. An umbrella good-practices skill should route API-design work here rather than duplicate these rules.

## Desired Outcome

A successful design makes:

1. Call-site intent clear without comments or positional-argument archaeology.
2. Units, identities, modes, states, constraints, and failures explicit in types.
3. Every constructed object immediately usable, or creation an explicit failure.
4. Long-lived collaborators constructor-supplied and request work call-supplied.
5. Concrete infrastructure creation the responsibility of the composition root.
6. Domain invariants and behavior local to the concepts that own the state.
7. Callers depend on immediate capabilities rather than traverse object graphs.
8. Abstractions represent demonstrated shared concepts, not speculative similarity.
9. Ownership, lifecycle, side effects, compatibility, and evolution unambiguous.

## Design Workflow

### 1. Identify the boundary

Record before changing a signature:

- The caller, owning module, and immediate collaborators.
- Whether the API is internal, externally consumed, or persisted as data.
- Request-scoped inputs versus long-lived dependencies.
- Values, resources, contexts, and collaborators crossing the boundary.
- Who creates, validates, mutates, shares, persists, retries, closes, or disposes each resource.
- Expected business failures versus broken invariants or programming defects.
- Existing source, behavior, and data compatibility obligations.

Do not redesign a signature in isolation when misplaced ownership or behavior is the real problem.

### 2. Model the domain vocabulary

- Replace ambiguous primitives when unit, identity, validation, or legal operations matter.
- Keep representation-compatible identities distinct, such as `OrderId` and `CustomerId`.
- Use enums or tagged variants for closed choices.
- Use separate state types or a validated state machine when capabilities differ by state.
- Reject invalid combinations at construction or transition time.
- Validate external and persisted representations before creating domain values.
- Avoid mechanical wrappers; add a type only when it prevents a realistic error, centralizes an invariant, clarifies a boundary, or owns useful behavior.

### 3. Shape operations around intent

- Prefer commands and capability-oriented methods over setters and flag bags.
- Ask an object to perform a domain operation instead of exporting its state and rules.
- Use names from stable domain language, not a screen, form, workflow, transport payload, or configuration layout.
- Use distinct operations when modes differ in permission, invariant, side effect, or result.
- Keep multi-aggregate and external-system coordination in an application service.

### 4. Assign dependencies and ownership

Make each dependency visible at the lifetime boundary that owns it. Inject externally managed, side-effecting, lifecycle-sensitive, deployment-configured, expensive, shared, or substitutable capabilities; construct immutable implementation-local values directly when substitution and independent lifecycle add no value.

- The composition root creates and connects concrete infrastructure.
- Business objects request capabilities; they do not create hidden clients or retrieve global services.
- Supply application- or object-scoped repositories, clocks, transports, gateways, and managed resources at construction.
- Supply commands, identifiers, authorization, locale, trace context, cancellation, deadlines, transactions, and other request-scoped capabilities per operation.
- Inject a factory only when the consumer must create multiple instances at runtime or choose per-instance parameters.
- Do not inject factories merely to defer ordinary composition-root work.
- State whether resource ownership transfers and who performs cleanup.

### 5. Minimize boundary knowledge

- Collaborate with immediate dependencies rather than navigate their internals.
- Treat deep field or call chains, especially five or more hops, as an architectural warning.
- Move behavior behind the object owning the relevant state or collaborator.
- Give containers intention-revealing operations that hide layout, traversal, and selection rules.
- Do not expose a nested dependency merely so a caller can reach something farther away.
- Keep infrastructure representations out of domain signatures.

### 6. Choose abstraction deliberately

- Keep small local duplication when implementations lack shared responsibilities, invariants, and reasons to change.
- Let features evolve independently when their requirements may diverge.
- Extract only after multiple implementations reveal a stable shared concept.
- Prefer the smallest capability interface satisfying a concrete consumer.
- Do not mirror every method of a concrete class in an interface.
- Avoid speculative base classes, broad interfaces, capability flags, no-op hooks, and generic common modules based on surface similarity.

### 7. Define failure and evolution

For each operation, specify:

- Whether failure is a result, declared error, absence, or invariant violation.
- Structured details callers need for recovery; never require parsing prose.
- Partial-success semantics, atomicity, cancellation, timeout, retry, and idempotency.
- Whether automatic retries can duplicate external effects.
- Whether unknown external variants are rejected, preserved, or mapped explicitly.

For a consumed API change:

- Classify it as additive, source-breaking, behavior-breaking, or data-breaking.
- Use a temporary adapter only when compatibility is required.
- Avoid ambiguous overloads where old and new meanings can be confused.
- Define migration steps, observability, a removal condition, and ownership of the shim.
- Test old and new paths while both remain supported.

## Selection Rules

### Parameter shape

- Use a named scalar or value object for one concept.
- Use an options or command object when values form one operation, optional fields may grow, or positional calls are unclear.
- Use an enum or tagged variant for a closed mode set.
- Avoid booleans whose meanings are not obvious at the call site.
- Do not hide required values in untyped maps.
- Avoid primitive sentinels that overlap valid data.

### Construction style

- Use a constructor when validation is immediate and failure fits normal construction semantics.
- Use a result-returning factory when creation validates, performs I/O, selects an implementation, or can fail normally.
- Use a builder only for genuinely complex optional assembly; `build` must validate every required invariant.
- Never expose a publicly usable partially initialized object.

### Domain placement

- Put an invariant where all state required to enforce it is owned.
- Put cross-capability orchestration in an application service.
- Add a high-level container method when callers otherwise repeat traversal or selection.
- Return capabilities and domain values, not internal storage or transport structures.

## Edge-Case Contract

Specify all relevant items rather than relying on convention:

- **Numbers:** bounds and whether zero, negative, or unbounded values are valid; use variants when zero could mean immediate, disabled, or unlimited.
- **Optional data:** distinguish omitted, unknown, empty, and explicitly cleared when behavior differs.
- **Time:** duration versus timestamp, clock source, precision, time zone, and inclusive or exclusive boundaries.
- **Collections:** ordering, uniqueness, mutability, empty-input behavior, and ownership of returned values.
- **Concurrency:** thread or task safety, atomicity, mutation rules, callback ordering, and reentrancy.
- **Resources:** creation, transfer, sharing, closure, disposal, and behavior after closure.
- **Retries:** idempotency keys, retryable failures, limits, and duplicate-effect behavior.
- **Serialization:** defaults, nullability, schema evolution, and validation before domain construction.
- **Variants:** forward-compatibility behavior for values unknown to the current implementation.

## Examples

### 1. Make units and modes explicit

Why: named units and policies prevent conversion mistakes and unreadable boolean calls.

**BAD**

```typescript
function fetchReport(timeout: number, cached: boolean): Promise<Report> {
  return reportGateway.fetch(timeout, cached);
}
const report = await fetchReport(5, true);
```

**GOOD**

```typescript
class Duration {
  private constructor(private readonly valueInMilliseconds: number) {}

  get milliseconds(): number {
    return this.valueInMilliseconds;
  }

  static seconds(value: number): Duration {
    if (!Number.isFinite(value) || value < 0) {
      throw new Error("duration must be finite and non-negative");
    }
    const milliseconds = value * 1000;
    if (!Number.isFinite(milliseconds)) {
      throw new Error("duration is too large");
    }
    return new Duration(milliseconds);
  }
}
enum CachePolicy { PreferCache, Refresh }
type FetchReportCommand = { timeout: Duration; cachePolicy: CachePolicy };
const report = await fetchReport({
  timeout: Duration.seconds(5),
  cachePolicy: CachePolicy.PreferCache,
});
```

### 2. Construct with collaborators and call with work

Why: supplying a repository once makes lifecycle and ownership visible while each call contains only request work.

**BAD**

```python
class ApproveOrder:
    def execute(self, order_id, actor_id, database):
        orders = SqlOrderRepository(database)
        order = orders.get(order_id)
        order.approve(actor_id)
        orders.save(order)
```

**GOOD**

```python
class ApproveOrder:
    def __init__(self, orders: "OrderRepository") -> None:
        self._orders = orders

    def execute(self, order_id: "OrderId", actor_id: "ActorId") -> None:
        order = self._orders.get(order_id)
        order.approve(actor_id)
        self._orders.save(order)

approve_order = ApproveOrder(order_repository)
approve_order.execute(order_id, actor_id)
```

### 3. Eliminate temporal initialization

Why: a validating factory returns either a usable client or a structured configuration failure.

**BAD**

```text
client = Client()
client.setEndpoint(config.endpoint)
client.setCredentials(config.credentials)
client.initialize()
client.send(message)
```

**GOOD**

```text
Client.create(config) -> Result<Client, ConfigError>:
    endpoint = Endpoint.parse(config.endpoint)
    if endpoint is Error: return Error(InvalidEndpoint)
    if config.credentials are absent: return Error(MissingCredentials)
    return Ok(Client(endpoint.value, config.credentials))

client = Client.create(config).orReportFailure()
client.send(message)
```

### 4. Inject managed capabilities, not trivial values

Why: external tax calculation needs substitution and lifecycle management; local immutable arithmetic values do not.

**BAD**

```python
class PriceService:
    def __init__(self, decimal_factory, quote_factory, gateway_factory):
        self._decimal_factory = decimal_factory
        self._quote_factory = quote_factory
        self._gateway_factory = gateway_factory
```

**GOOD**

```python
from decimal import Decimal

class PriceService:
    def __init__(self, tax_gateway: "TaxGateway") -> None:
        self._tax_gateway = tax_gateway

    def quote(self, request: "QuoteRequest") -> "Quote":
        subtotal = Decimal(request.unit_price) * request.quantity
        tax = self._tax_gateway.calculate(request.region, subtotal)
        return Quote(subtotal=subtotal, tax=tax)
```

### 5. Hide traversal behind an immediate collaborator

Why: checkout should request a customer capability, not depend on notification transport internals.

**BAD**

```python
def complete_checkout(order):
    order.customer.profile.preferences.channels.email.client.send(
        order.customer.email, "Your order is complete"
    )
```

**GOOD**

```python
class CheckoutService:
    def __init__(self, orders):
        self._orders = orders

    def complete(self, order):
        order.complete()
        event = OrderCompleted(
            order_number=order.number,
            customer_id=order.customer.id,
        )
        self._orders.save_with_outbox_event(order, event)
```

### 6. Let a container own selection rules

Why: a domain-level query prevents duplicated traversal and unsafe assumptions about a primary address.

**BAD**

```typescript
function shippingCountry(customer: Customer): string {
  return customer.profile.addresses
    .filter(a => a.active)
    .find(a => a.kind === "shipping" && a.primary)!.countryCode;
}
```

**GOOD**

```typescript
class AddressBook {
  private readonly primaryShipping?: Address;

  constructor(addresses: readonly Address[]) {
    const matches = addresses.filter(
      a => a.active && a.kind === "shipping" && a.primary,
    );
    if (matches.length > 1) {
      throw new InvalidAddressBook("multiple primary shipping addresses");
    }
    this.primaryShipping = matches[0];
  }

  primaryShippingCountry(): string | undefined {
    return this.primaryShipping?.countryCode;
  }
}
const country = customer.addressBook.primaryShippingCountry();
```

### 7. Keep policies separate until a concept stabilizes

Why: small duplication allows formatting policies with different rules and change axes to evolve independently.

**BAD**

```typescript
function formatCommon(
  amount: number,
  options: { accounting?: boolean; includeCode?: boolean },
): string {
  const value = Math.abs(amount).toFixed(2);
  const signed = options.accounting && amount < 0 ? `(${value})` : value;
  return options.includeCode ? `USD ${signed}` : `$${signed}`;
}
```

**GOOD**

```typescript
type Money = { readonly minorUnits: bigint; readonly currency: "USD" };

function absoluteDecimalAmount(money: Money): string {
  const absolute = money.minorUnits < 0n ? -money.minorUnits : money.minorUnits;
  return `${absolute / 100n}.${(absolute % 100n).toString().padStart(2, "0")}`;
}
function formatInvoiceTotal(money: Money): string {
  const sign = money.minorUnits < 0n ? "-" : "";
  return `${money.currency} ${sign}${absoluteDecimalAmount(money)}`;
}
function formatLedgerAmount(money: Money): string {
  const value = `$${absoluteDecimalAmount(money)}`;
  return money.minorUnits < 0n ? `(${value})` : value;
}
```

### 8. Expose a guarded domain transition

Why: a named transition validates the source state before applying every required state change behind one operation.

**BAD**

```text
updateSubscription(subscription, options):
    subscription.status = options.status
    subscription.endDate = options.clearEndDate ? None : options.endDate
    subscription.renewalEnabled = options.renewalEnabled
```

**GOOD**

```text
Subscription.reactivate() -> Result<Void, TransitionError>:
    if status != Expired:
        return Error(NotExpired)
    status = Active
    endDate = None
    renewalEnabled = true
    return Ok()
```

## Verification Checklist

### Call-site clarity and validity

- Can every argument be understood without reading the implementation?
- Are units, identities, modes, bounds, and optional meanings explicit?
- Are positional booleans, ambiguous sentinels, and untyped required values absent?
- Are different invariants or effects represented by different operations?
- Can an invalid state be constructed, serialized, or observed?
- Does creation produce a usable object or explicit failure?
- Are transitions guarded by the state owner, with required synchronization or transaction semantics explicit?
- Are boundary inputs validated before entering the domain?

### Dependencies, ownership, and effects

- Is each side-effecting or lifecycle-managed dependency visible at the construction or operation boundary that owns its lifetime?
- Does the composition root create concrete infrastructure?
- Do calls receive work rather than repeated infrastructure parameters?
- Are creation, mutation, sharing, transfer, retry, persistence, and disposal owners explicit?
- Are service location and hidden client construction absent?
- Were trivial immutable values kept out of injection wiring?
- Are timeout, cancellation, partial success, retries, and duplicate effects deliberate?

### Coupling, abstraction, and evolution

- Does each caller use only immediate collaborators and domain capabilities?
- Have deep navigation and repeated collection selection been hidden?
- Is behavior owned with its required state, with orchestration separated when necessary?
- Does each interface serve a concrete consumer with the smallest useful capability?
- Does each abstraction have demonstrated shared responsibilities, invariants, and change axes?
- Can similar features diverge without flags, no-op hooks, or unrelated breakage?
- Is remaining duplication small, local, and intentional?
- Are compatibility impact, migration, adapter ownership, and removal conditions explicit?

### Tests to request

Request tests covering:

- Valid construction and every rejected invariant.
- Unit conversion, bounds, zero meanings, and unknown variants.
- Every legal and illegal transition.
- Omitted, unknown, empty, and explicitly cleared values when distinct.
- Substitute collaborators without hidden infrastructure.
- Collection ordering, uniqueness, empty input, and returned-value ownership.
- Concurrency, reentrancy, cleanup, cancellation, timeout, retry, and duplicate effects where relevant.
- Old and new call paths during compatibility migration.

A design is complete when normal call sites are clear, invalid use is prevented or rejected at the earliest boundary, ownership is obvious, failures are actionable, and foreseeable evolution does not require callers to know internal structure.
