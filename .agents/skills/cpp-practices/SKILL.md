---
name: cpp-practices
description: Applies C++-specific testing and design practices for ownership, private implementation boundaries, fatal assertions, death tests, and precise matchers. Use when C++ language or test-runtime semantics matter.
license: MIT
---

# C++ Practices

## Scope

Apply this skill only when C++ language rules, object lifetimes, access control, process termination, or C++ test-runtime behavior materially affect the design or test.

This supplement translates universal design and testing decisions into C++ ownership, access-control, lifetime, and test-runtime mechanisms. Use the general skills to choose policy; use this skill to implement that policy correctly in C++.

Framework-neutral pseudomacros such as `TEST`, `ASSERT_NE`, `EXPECT_EQ`, `EXPECT_DEATH`, and `EXPECT_CALL` below denote the equivalent operation in the selected C++ test framework.

## Core rules

- Make ownership explicit with values and standard smart pointers. Treat raw pointers, references, `std::span`, and `std::string_view` as non-owning.
- Keep implementation details private. Test through observable behavior or extract a cohesive collaborator instead of granting tests friendship.
- Use fatal assertions for prerequisites whose failure makes later expressions unsafe or meaningless.
- Use non-fatal expectations for independent properties that can all be evaluated safely.
- Test intentional process termination only with a death-test facility that isolates the statement in another process.
- Match the contract precisely without overspecifying irrelevant representation or incidental calls.
- Keep ordinary C++ tests in-process. Use isolated child-process execution only when termination itself is the contract or global-state containment is unavoidable.

## Selection rules

1. Prefer a value member or value parameter when copying or moving the object expresses the intended lifetime.
2. Use `std::unique_ptr<T>` for one owner and transfer it by value. Use `std::shared_ptr<T>` only when independently shared lifetime is part of the design.
3. Use `T&` or `std::reference_wrapper<T>` for a required non-owning dependency. Use `T*` only when absence is meaningful or an API requires pointer syntax.
4. Use `std::span<T>` and `std::string_view` only when the referenced storage is guaranteed to outlive every use of the view.
5. Test private behavior through the public contract. If private logic needs focused testing, extract it into a small type with its own public contract in an internal implementation boundary.
6. Choose a fatal assertion before dereferencing a pointer, indexing based on a checked precondition, or using failed setup output.
7. Choose non-fatal expectations for independent fields, elements, or invariants after all safety prerequisites hold.
8. Choose a death test only when termination itself is the contract. Prefer a returned status, exception, or error object when callers are expected to recover.
9. Choose exact equality for stable value contracts, predicate or structural matchers for relevant fields, and tolerant numeric matchers only when the algorithm's error model warrants them.
10. Verify required interactions only at externally significant boundaries. Do not encode call order, call count, or irrelevant arguments unless they are contractual.

## Examples

### 1. Express single ownership with `std::unique_ptr`

A raw owning pointer does not state who deletes the object and permits leaks, double deletion, and accidental copying. A move-only owner makes transfer and destruction explicit.

**BAD**

```cpp
class Engine {};

class Car {
 public:
  explicit Car(Engine* engine) : engine_(engine) {}
  ~Car() { delete engine_; }

 private:
  Engine* engine_;  // Owning, but indistinguishable from a borrowed pointer.
};

Car MakeCar() {
  return Car(new Engine());
}
```

**GOOD**

```cpp
#include <memory>
#include <utility>

class Engine {};

class Car {
 public:
  explicit Car(std::unique_ptr<Engine> engine)
      : engine_(std::move(engine)) {}

 private:
  std::unique_ptr<Engine> engine_;
};

Car MakeCar() {
  return Car(std::make_unique<Engine>());
}
```

### 2. Do not return a view into dead storage

`std::string_view` does not own characters. Returning a view into a local `std::string` creates a dangling view even though the code may appear to work in a test.

**BAD**

```cpp
#include <string>
#include <string_view>

std::string_view BuildLabel() {
  std::string label = "ready";
  return label;
}
```

**GOOD**

```cpp
#include <string>

std::string BuildLabel() {
  std::string label = "ready";
  return label;
}
```

### 3. Preserve private boundaries instead of befriending a test

A test-only friend couples tests to representation and makes refactoring private members unnecessarily expensive. Extract cohesive logic behind a small contract, then test that contract and the owning type's behavior.

**BAD**

```cpp
#include <string>
#include <string_view>

class ConfigTestAccess;

class Config {
  friend class ConfigTestAccess;

 private:
  static int ParsePort(std::string_view text) {
    return std::stoi(std::string(text));
  }
};

class ConfigTestAccess {
 public:
  static int ParsePort(std::string_view text) {
    return Config::ParsePort(text);
  }
};

TEST(ConfigTest, ParsesPrivatePort) {
  EXPECT_EQ(ConfigTestAccess::ParsePort("8080"), 8080);
}
```

**GOOD**

```cpp
#include <charconv>
#include <optional>
#include <string_view>

namespace config_internal {
class PortParser {
 public:
  static std::optional<int> Parse(std::string_view text) {
    if (text.empty()) {
      return std::nullopt;
    }
    int value = 0;
    const char* first = text.data();
    const char* last = first + text.size();
    auto result = std::from_chars(first, last, value);
    if (result.ec != std::errc{} || result.ptr != last ||
        value < 1 || value > 65535) {
      return std::nullopt;
    }
    return value;
  }
};
}  // namespace config_internal

TEST(PortParserTest, ParsesValidPort) {
  EXPECT_EQ(config_internal::PortParser::Parse("8080"),
            std::optional<int>{8080});
}
```

### 4. Make unsafe prerequisites fatal

After a failed null check, dereferencing the pointer is undefined behavior. Stop the current test at the prerequisite, while retaining non-fatal checks for independent fields.

**BAD**

```cpp
struct Reply {
  int code;
  int item_count;
};

TEST(ClientTest, ReturnsReply) {
  Reply* reply = FetchReply();
  EXPECT_NE(reply, nullptr);
  EXPECT_EQ(reply->code, 200);       // Unsafe if the expectation failed.
  EXPECT_EQ(reply->item_count, 3);
}
```

**GOOD**

```cpp
struct Reply {
  int code;
  int item_count;
};

TEST(ClientTest, ReturnsReply) {
  Reply* reply = FetchReply();
  ASSERT_NE(reply, nullptr);         // Stops this test on failure.
  EXPECT_EQ(reply->code, 200);       // Independent, safe checks.
  EXPECT_EQ(reply->item_count, 3);
}
```

### 5. Isolate intentional termination in a death test

Calling terminating code in an ordinary test kills the test process and prevents the harness from reporting subsequent results. A death test runs the statement in isolation and checks both termination and a stable diagnostic fragment.

**BAD**

```cpp
#include <cstdlib>
#include <iostream>

void RequirePositive(int value) {
  if (value <= 0) {
    std::cerr << "value must be positive\n";
    std::abort();
  }
}

TEST(RequirePositiveTest, RejectsZero) {
  RequirePositive(0);  // Terminates the entire ordinary test process.
}
```

**GOOD**

```cpp
#include <cstdlib>
#include <iostream>

void RequirePositive(int value) {
  if (value <= 0) {
    std::cerr << "value must be positive\n";
    std::abort();
  }
}

TEST(RequirePositiveDeathTest, RejectsZero) {
  EXPECT_DEATH(RequirePositive(0), "value must be positive");
}
```

### 6. Match relevant argument structure precisely

An unrestricted matcher can let a broken request pass, while matching every incidental field makes the test brittle. Match all contract-relevant fields and deliberately ignore only non-contractual data.

**BAD**

```cpp
struct Request {
  int account_id;
  int retry_limit;
};

TEST(SenderTest, SendsRequest) {
  MockTransport transport;
  EXPECT_CALL(transport, Send(ANY_ARGUMENT));
  Sender sender(transport);
  sender.SendFor(42);
}
```

**GOOD**

```cpp
struct Request {
  int account_id;
  int retry_limit;
};

TEST(SenderTest, SendsRequest) {
  MockTransport transport;
  EXPECT_CALL(transport,
              Send(ALL_OF(FIELD(&Request::account_id, EQUALS(42)),
                          FIELD(&Request::retry_limit, EQUALS(3)))));
  Sender sender(transport);
  sender.SendFor(42);
}
```

## C++ edge cases

### Ownership and lifetime

- Direct initialization of a local `const T&` can extend a temporary's lifetime to that reference. A temporary bound to a reference parameter lasts only through the full call expression; returning or storing that reference does not extend the lifetime.
- `std::string_view` constructed from a temporary `std::string` dangles; a view of a string literal has static storage duration.
- `std::span` becomes invalid when its backing container is destroyed or reallocated.
- A `std::unique_ptr<Base>` should delete through a virtual base destructor when dynamic derived objects are owned polymorphically.
- Cycles of `std::shared_ptr` leak. Break non-owning back-edges with `std::weak_ptr`.
- Custom deleters are part of a smart pointer's type or state; verify destruction behavior when wrapping handles from external APIs.
- Moved-from standard-library objects remain valid but generally have unspecified state. Test supported post-move operations, not an assumed representation.

### Private implementation boundaries

- Do not expose mutable internals merely to simplify tests.
- An internal namespace communicates organization, not language-enforced access control. Keep extracted contracts narrow and exclude them from the supported public API surface.
- The pointer-to-implementation technique can stabilize headers, but destruction and move operations may need out-of-line definitions where the implementation type is complete.
- Template and inline implementation details often reside in headers. Test behavior rather than symbol placement or private type names.

### Assertions and exceptions

- Fatal assertion macros commonly return from the current test function; they may be invalid in non-`void` helpers. Return a status from helpers or perform the fatal check in the test body.
- A fatal assertion usually stops only the current test, not worker threads. Communicate worker failures to the owning test thread.
- Never place an assertion with required side effects inside `assert(...)`; builds may compile it out.
- When exceptions are disabled, do not select exception-based verification. Test the configured error or termination contract.
- For floating-point values, account for NaN, infinities, signed zero, absolute error near zero, and relative error at large magnitudes.

### Death tests and process behavior

- Death tests require process-isolation support from the test runtime and operating environment. Skip or replace them only when the termination contract is not portable.
- Run death tests before starting threads when the runtime uses process cloning; inherited locks can deadlock the child.
- Buffered output may not be flushed on abrupt termination. Emit diagnostics to an unbuffered or explicitly flushed error channel if matching text is contractual.
- Match a stable diagnostic fragment, not addresses, thread identifiers, paths, timing, or full implementation-specific runtime text.
- Sanitizers can alter termination signals and diagnostics. Verify death tests under the same sanitizer configuration used in automation.

### Matchers and mocks

- Avoid retaining matcher references to local values past their lifetime; copy expected values when the framework permits it.
- Overloaded functions may require an explicit cast or typed matcher to resolve the intended signature.
- Move-only arguments require matchers and actions that do not accidentally copy them.
- Unordered containers need order-independent comparison unless iteration order is explicitly contractual.
- Prefer state verification or a small fake when interaction details are not part of the contract.

## Verification

Compile production and test translation units with a consistent language level and strict diagnostics:

```sh
c++ -std=c++20 -Wall -Wextra -Wpedantic -Wconversion -Werror \
  -Iinclude -c src/component.cpp -o build/component.o
c++ -std=c++20 -Wall -Wextra -Wpedantic -Wconversion -Werror \
  -Iinclude -c tests/component_test.cpp -o build/component_test.o
```

Build and run the configured test suite, including death tests:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Run memory and undefined-behavior instrumentation in a separate build when supported by the selected compiler and runtime:

```sh
cmake -S . -B build-sanitize \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build-sanitize --parallel
ctest --test-dir build-sanitize --output-on-failure
```

Verification is complete when strict compilation succeeds, ordinary and death tests pass in their intended runtime configuration, sanitizer runs report no lifetime or undefined-behavior defects, and tests do not depend on private representation or incidental interactions.
