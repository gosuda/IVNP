# IVNP Architecture & Development Guidelines

## Subsystems & Layered Hierarchy

IVNP follows a strict unidirectional layered DAG architecture. Subsystems are organized in ascending order of responsibility (L0 to L9). Higher layers may depend on lower layers, but lower layers must never depend on higher layers (acyclic dependencies).

| Layer | Subsystem / Package | Responsibility |
| :--- | :--- | :--- |
| **L8** | Root Module Facade | Public top-level API and facade for the IVNP embedded router and services |
| **L7** | Node Lifecycle | Compose the control plane and client services; own coordinated startup and shutdown |
| **L6** | Client Services | Client-facing protocols (SAM, HTTP/SOCKS5 proxies, address book services) |
| **L5** | Control Plane (`controlplane`) | NetDB, peer and tunnel policy, destination lifecycle, publication, route preparation, and durable control state |
| **L4** | Data Plane (`dataplane`) | Established transport I/O, installed circuit and route execution, cryptographic session state, streaming, and bounded packet queues |
| **L3** | Domain Interfaces & State | Shared destination/stream interfaces, configuration parsing, and encrypted state storage |
| **L2** | Foundation & Observability | Domain identities, wire structures, crypto verification, metrics registry, and health reporting |
| **L1** | Cryptography | Stateless cryptographic primitives and signature algorithms |
| **L0** | Internal Utilities | Wire cursor/writer primitives, bounded memory pools, slabs, and buffer management |
| **L9** | CLI & Integration Tests | Daemon entrypoint binaries and end-to-end integration tests |

## Architectural Invariants & Encapsulation

- **Layered Directionality**: Dependency graphs are strictly unidirectional. A lower layer must never import a higher layer.
- **Subsystem Encapsulation & Facades**: Each subsystem root acts as the sole public gateway. Cross-subsystem references must only import the subsystem root, never internal implementation packages of another subsystem.
- **Canonical Public Paths**: External and cross-subsystem code must use canonical subsystem root import paths without aliases or unauthorized nested paths.
- **Plane Ownership**: Only the control plane resolves peers and destinations, prepares routes, and changes routing policy. The data plane must not import control-plane, client, node, or persistent-state packages.
- **Execution Lifetime**: Circuit tokens identify one installation, not just a numeric tunnel ID. Policy replacement drains admitted uses before releasing sensitive route snapshots. Nonce, replay, ratchet, and retransmission state stay with the data-plane execution owner.
- **Control Ingress**: Preserve authenticated source and private-lookup provenance across bounded asynchronous delivery. Control-handler deadlines and established-session forwarding must not permit implicit lookup or connection setup in the bulk path.

## Memory & Wire Protocols

- **Domain Wire Primitives**: Common wire structures (identities, certificates, mappings, hashes, destinations, signatures, I2NP, RouterInfo, and LeaseSet variants) belong to the foundation layer.
- **Zero-Allocation Parsing & Serialization**: Wire parsers must provide views over caller-owned input without allocating memory on the heap. Serializers must write directly into caller-provided fixed-capacity storage and must never dynamically grow destinations.
- **Sensitive Memory Management**: Private cryptographic keys and sensitive credentials must be explicitly cleared/wiped from memory upon release or termination.
- **Unsafe & Host-ABI Isolation**: Non-test files must not import `"unsafe"` outside the explicit allowlist in `architecture/architecture_test.go`. Fixed-size kernel or C ABI structs declared in an unsafe file must embed `structs.HostLayout` as their leading field and assert size/offset invariants at compile time.

## Documentation & Technical Writing

- **Automatic Documentation Synchronization**: Whenever a code change alters public APIs, subsystem boundaries, wire formats, protocol state machines, configuration keys, CLI flags, or operational defaults, automatically load and apply the `technical-writing` skill (`.agents/skills/technical-writing/SKILL.md`) to update all affected documentation (`README.md`, `docs/*.md`, and `cmd/ivnp-reseed/README.md`) in the same task.
- **Editorial Discipline**: Write all documentation in clear, authoritative English prose suitable for a staff systems engineer. Never use em-dashes (`U+2014`) or spaced en-dashes (`U+2013`) as clause separators; use colons, semicolons, parentheses, commas, or periods instead. Eliminate all AI-slop phrasing, marketing clichés, and low-density filler in accordance with the `technical-writing` and `zero-slop` skills.

## Pre-Completion Verification & Formatting

Before completing any task, always:
- Audit whether your code changes invalidate or outdate any statements, signatures, tables, or diagrams in `README.md`, `docs/`, or `cmd/ivnp-reseed/README.md`, and update them using the `technical-writing` skill.
- Run `gosuda.org/ivnp/tools/importformatter` to format and consolidate Go imports canonically (`go run gosuda.org/ivnp/tools/importformatter -write`).
- Run `checklocks` static lock and atomic verification (`go vet -vettool="$(go env GOPATH)/bin/checklocks" -inferred=false ./...`).
- Run the `gojgp` linter to ensure code quality and guideline compliance (`gojgp lint ./...`).
