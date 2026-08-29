---
name: java-practices
description: "Applies Java-specific testing and design practices for framework boundaries, presenter separation, resource lifetime, and explicit collaborators. Use when Java runtime or framework mechanics matter."
license: MIT
---

# Java Practices

## Scope

Use this skill when Java language, JVM, class-loading, resource-management, or framework-runtime behavior affects implementation or testing.

This supplement translates universal boundary and testing decisions into Java and JVM mechanisms such as plain-object seams, runtime-backed tests, try-with-resources, and constructor-visible collaborators. Use the general skills to choose policy.

## Core Rules

1. Keep domain decisions and calculations in plain Java objects.
2. Put framework APIs behind thin adapters at the application boundary.
3. Use runtime-backed tests only for behavior that depends on the runtime or framework.
4. Keep presenters independent of widgets, generated bindings, event loops, and navigation implementations.
5. Represent required collaborators as constructor parameters.
6. Manage lexically owned `AutoCloseable` values with try-with-resources. When a resource must live across method calls, make the owning object `AutoCloseable` and close the field exactly once at the owner's lifecycle boundary.
7. Make time, locale, character encoding, scheduling, randomness, and external I/O explicit when they affect behavior.
8. Prefer fast, hermetic, single-process tests for ordinary Java logic.

## Test Selection

Choose the narrowest environment that can prove the behavior:

- **Plain JVM unit test:** calculations, validation, presenter decisions, state transitions, formatting with an explicit locale, and behavior using fakes or in-memory collaborators.
- **Boundary contract test:** adapter translation, persistence mappings, serialization shape, configuration binding, and exception conversion.
- **Framework-runtime test:** widget lifecycle, generated code, reflective discovery, event dispatch, dependency wiring, thread-affinity enforcement, or behavior that differs under the target runtime.
- **End-to-end test:** a small number of critical flows spanning multiple boundaries.

Do not select a framework test merely because production enters through a framework class. Extract the decision-making code first, then test it as plain Java. Retain focused runtime tests for the thin adapter and genuine runtime mechanics.

## Concrete Examples

### 1. Separate pure logic from framework UI classes

Why: Embedding arithmetic in a framework component makes a deterministic calculation require runtime startup and UI fixtures. A plain Java class can be tested quickly and reused by any adapter.

**BAD**

```java
import java.math.BigDecimal;
import java.util.List;

final class CheckoutPanel extends FrameworkPanel {
    private final FrameworkLabel totalLabel = new FrameworkLabel();

    void showTotal(List<LineItem> items) {
        BigDecimal total = BigDecimal.ZERO;
        for (LineItem item : items) {
            total = total.add(item.unitPrice().multiply(
                    BigDecimal.valueOf(item.quantity())));
        }
        totalLabel.setText(total.toPlainString());
    }
}
```

**GOOD**

```java
import java.math.BigDecimal;
import java.util.List;
import java.util.Objects;

final class LineItem {
    private final BigDecimal unitPrice;
    private final int quantity;

    LineItem(BigDecimal unitPrice, int quantity) {
        this.unitPrice = Objects.requireNonNull(unitPrice);
        if (quantity < 0) {
            throw new IllegalArgumentException("quantity must be non-negative");
        }
        this.quantity = quantity;
    }

    BigDecimal unitPrice() {
        return unitPrice;
    }

    int quantity() {
        return quantity;
    }
}

final class CartTotal {
    BigDecimal calculate(List<LineItem> items) {
        Objects.requireNonNull(items);
        BigDecimal total = BigDecimal.ZERO;
        for (LineItem item : items) {
            total = total.add(item.unitPrice().multiply(
                    BigDecimal.valueOf(item.quantity())));
        }
        return total;
    }
}
```

### 2. Keep presenters independent of framework widgets

Why: A presenter should decide what the user sees and what action follows, while a view adapter handles widget access. This allows presenter tests to use a small fake view without an event loop or generated UI binding.

**BAD**

```java
final class RegistrationPage extends FrameworkPage {
    private final FrameworkTextBox emailBox;
    private final FrameworkLabel errorLabel;
    private final AccountService accounts;

    RegistrationPage(AccountService accounts) {
        this.accounts = accounts;
        this.emailBox = findTextBox("email");
        this.errorLabel = findLabel("error");
    }

    void onSubmitClick() {
        String email = emailBox.getText().trim();
        if (!email.contains("@")) {
            errorLabel.setText("Invalid email");
            return;
        }
        accounts.register(email);
        FrameworkNavigation.goTo("welcome");
    }
}
```

**GOOD**

```java
import java.util.Objects;

interface RegistrationView {
    String email();
    void showError(String message);
}

interface AccountService {
    void register(String email);
}

interface Navigator {
    void showWelcome();
}

final class RegistrationPresenter {
    private final RegistrationView view;
    private final AccountService accounts;
    private final Navigator navigator;

    RegistrationPresenter(
            RegistrationView view,
            AccountService accounts,
            Navigator navigator) {
        this.view = Objects.requireNonNull(view);
        this.accounts = Objects.requireNonNull(accounts);
        this.navigator = Objects.requireNonNull(navigator);
    }

    void submit() {
        String email = view.email().trim();
        if (!email.contains("@")) {
            view.showError("Invalid email");
            return;
        }
        accounts.register(email);
        navigator.showWelcome();
    }
}
```

### 3. Let lexical scope own closeable resources

Why: Manual cleanup can leak an earlier resource when acquisition or cleanup fails. Try-with-resources closes successfully acquired resources in reverse order and preserves later cleanup failures as suppressed exceptions.

**BAD**

```java
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.sql.DataSource;

final class UserLookup {
    private final DataSource dataSource;

    UserLookup(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    String findName(long id) throws SQLException {
        Connection connection = dataSource.getConnection();
        PreparedStatement statement =
                connection.prepareStatement("select name from users where id = ?");
        statement.setLong(1, id);
        ResultSet results = statement.executeQuery();
        try {
            return results.next() ? results.getString(1) : null;
        } finally {
            results.close();
            statement.close();
            connection.close();
        }
    }
}
```

**GOOD**

```java
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import javax.sql.DataSource;

final class UserLookup {
    private final DataSource dataSource;

    UserLookup(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource);
    }

    String findName(long id) throws SQLException {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "select name from users where id = ?")) {
            statement.setLong(1, id);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? results.getString(1) : null;
            }
        }
    }
}
```

### 4. Make environmental collaborators explicit

Why: Static clocks and global sinks hide dependencies, couple tests through process-wide state, and make time-sensitive behavior nondeterministic. Constructor injection exposes required capabilities and permits fixed test values.

**BAD**

```java
import java.time.Instant;

final class SessionService {
    Session open(String userId) {
        Instant openedAt = Instant.now();
        AuditLog.global().write("opened:" + userId + ":" + openedAt);
        return new Session(userId, openedAt);
    }
}
```

**GOOD**

```java
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.function.Consumer;

final class SessionService {
    private final Clock clock;
    private final Consumer<String> auditSink;

    SessionService(Clock clock, Consumer<String> auditSink) {
        this.clock = Objects.requireNonNull(clock);
        this.auditSink = Objects.requireNonNull(auditSink);
    }

    Session open(String userId) {
        Instant openedAt = clock.instant();
        auditSink.accept("opened:" + userId + ":" + openedAt);
        return new Session(userId, openedAt);
    }
}
```

## Boundary Design

- Keep adapters small: read framework values, invoke plain Java behavior, and translate the result back.
- Define boundary interfaces in application terms rather than mirroring a framework API.
- Do not pass framework request, context, widget, session, or persistence objects into domain code.
- Convert framework exceptions at the boundary when callers need stable application-level failure semantics.
- If reflective construction requires a no-argument constructor or mutable fields, confine that shape to the adapter or persistence representation.
- Test each adapter with the least runtime support needed to prove its translation and lifecycle behavior.

## Java-Specific Edge Cases

- **Class initialization:** Static initializers run once per class loader and can retain state across tests. Avoid environment reads, threads, and I/O during class initialization.
- **Thread affinity:** UI and some framework objects may only be accessed on a designated thread. Keep that dispatch in the adapter; do not force presenters or domain objects onto that thread.
- **Asynchronous completion:** Do not block an event-loop thread with `Future.get()`, `join()`, or synchronous I/O. Make the executor or scheduler explicit when ordering matters.
- **Interruption:** When catching `InterruptedException`, either rethrow it or restore the interrupt flag before returning or throwing a translated exception. Consume interruption only when the method explicitly owns and completes the cancellation policy.
- **Resource ownership:** A method that creates an `AutoCloseable` normally closes it. A method that returns or accepts one must make ownership clear in its contract.
- **Streams:** Closing a stream may close its underlying resource. Do not return a lazy stream backed by a resource already closed by the producing method.
- **Suppressed exceptions:** Try-with-resources preserves cleanup failures through `Throwable.getSuppressed()`. Avoid replacing them with unconditional cleanup exceptions.
- **Locale and charset:** Use explicit `Locale` and `Charset` values for stable parsing, formatting, and byte conversion.
- **Time:** Use `Instant` for timeline points and an explicit `ZoneId` for civil-time rules. Inject `Clock` where current time affects behavior.
- **Equality:** Framework proxies and mutable persistence objects can make `equals` and `hashCode` unstable. Prefer immutable application identifiers at boundaries.
- **Reflection and modules:** Reflective access can succeed on a permissive class path and fail on a strict module path. Verify the deployment mode actually used.
- **Assertions:** Java `assert` statements are disabled unless enabled with `-ea`; do not rely on them for input validation or required test execution.
- **Version gating:** Compile with the configured `--release`. Records require Java 16, sealed classes require Java 17, and virtual threads require Java 21. Do not use them when the declared release is older.

## Review Checklist

- Is ordinary logic free of framework base classes, annotations, and runtime globals?
- Can presenter behavior run with simple in-memory collaborators?
- Are runtime-backed tests limited to genuine runtime mechanics?
- Are all closeable resources owned and closed exactly once?
- Are time, scheduling, locale, charset, randomness, and I/O explicit where relevant?
- Are static mutable fields absent or rigorously isolated?
- Does asynchronous code preserve interruption, cancellation, and thread-affinity rules?
- Does the code compile against the declared Java release rather than only the developer JDK?

## Verification Commands

Use the repository's checked-in build wrapper when present:

```sh
./mvnw test
./gradlew test
```

For a standard-library-only source tree targeting Java 17, compile with strict diagnostics:

```sh
rm -rf out
javac --release 17 -Xlint:all -Werror -d out $(find src/main/java src/test/java -name '*.java')
```

Inspect runtime and bytecode dependencies when class-path or module behavior matters:

```sh
java -version
jdeps --recursive --multi-release 17 build/libs/*.jar
```

Verification is complete only when plain JVM tests pass independently, focused boundary tests pass in their required runtime, resource-failure paths are covered, and compilation uses the project's declared Java release.
