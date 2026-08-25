# IVNP Architecture & Development Guidelines

## Subsystems & Layered Hierarchy

IVNP follows a strict unidirectional layered DAG architecture. Subsystems are organized in ascending order of responsibility (L0 to L9). Higher layers may depend on lower layers, but lower layers must never depend on higher layers (acyclic dependencies).

| Layer | Subsystem / Package | Responsibility |
| :--- | :--- | :--- |
| **L8** | Root Module Facade | Public top-level API and facade for the IVNP embedded router and services |
| **L7** | Node Lifecycle | Complete node runtime composition, subsystem orchestration, and lifecycle management |
| **L6** | Client Services | Client-facing protocols (SAM, HTTP/SOCKS5 proxies, address book services) |
| **L5** | Networking | Core routing, tunnel pools, NetDB, and transport managers (NTCP2, SSU2) |
| **L4** | Networking Internals | Concrete networking engines, protocols, and handshake implementations |
| **L3** | Domain Interfaces & State | Shared destination/stream interfaces, configuration parsing, and encrypted state storage |
| **L2** | Foundation & Observability | Domain identities, wire structures, crypto verification, metrics registry, and health reporting |
| **L1** | Cryptography | Stateless cryptographic primitives and signature algorithms |
| **L0** | Internal Utilities | Wire cursor/writer primitives, bounded memory pools, slabs, and buffer management |
| **L9** | CLI & Integration Tests | Daemon entrypoint binaries and end-to-end integration tests |

## Architectural Invariants & Encapsulation

- **Layered Directionality**: Dependency graphs are strictly unidirectional. A lower layer must never import a higher layer.
- **Subsystem Encapsulation & Facades**: Each subsystem root acts as the sole public gateway. Cross-subsystem references must only import the subsystem root, never internal implementation packages of another subsystem.
- **Canonical Public Paths**: External and cross-subsystem code must use canonical subsystem root import paths without aliases or unauthorized nested paths.

## Memory & Wire Protocols

- **Domain Wire Primitives**: Common wire structures (identities, certificates, mappings, hashes, destinations, and signatures) belong to the foundation layer.
- **Zero-Allocation Parsing & Serialization**: Wire parsers must provide views over caller-owned input without allocating memory on the heap. Serializers must write directly into caller-provided fixed-capacity storage and must never dynamically grow destinations.
- **Sensitive Memory Management**: Private cryptographic keys and sensitive credentials must be explicitly cleared/wiped from memory upon release or termination.

## Pre-Completion Verification & Formatting

Before completing any task, always:
- Run `gosuda.org/ivnp/tools/importformatter` to format and consolidate Go imports canonically (`go run gosuda.org/ivnp/tools/importformatter -write`).
- Run the `gojgp` linter to ensure code quality and guideline compliance (`gojgp lint ./...`).
