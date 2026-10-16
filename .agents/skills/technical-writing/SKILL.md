---
name: technical-writing
description: Writes and maintains high-precision, zero-slop technical documentation, READMEs, architecture guides, and protocol specifications without em-dashes or LLM clichés. Use whenever creating, rewriting, reviewing, or synchronizing project documentation after code changes.
license: MIT
---

# Technical Writing & Documentation Engineering

Write like a principal systems engineer and staff technical editor. Good technical prose respects the reader's time, leads with concrete mechanics, and anchors every architectural claim in real code, wire formats, and invariants.

---

## 1. Voice, Tone, and Editorial Philosophy

1. **Concrete Mechanics Over Marketing Abstractions**: State what a component does in terms of bytes, state machines, locks, queues, sockets, and cryptographic primitives. Never describe software with emotional adjectives or vague promises.
2. **High Signal-to-Noise Ratio**: Assume the reader understands systems programming and networking fundamentals. Do not explain what a mutex or a TCP socket is; explain how *this* codebase bounds contention, manages lifetimes, or frames packets over that socket.
3. **Authoritative, Composed Cadence**: Vary sentence length deliberately. Pair a 20-word technical explanation with a 7-word declarative consequence. Rhythm comes from syntax and precision, not theatrical punctuation or exclamation marks.
4. **Code-Verified Accuracy**: Never invent or guess a function signature, struct name, constant value, CLI flag, or package path. Every symbol, byte size, timeout, and file path in documentation must match the current source tree.

---

## 2. Strict Punctuation & Typography Rules

### 🚫 Absolute Ban on Em-Dashes (`—`)

Never use the em-dash (`—`, U+2014), spaced en-dash (` – `, U+2013), or double-hyphen (`--`) as prose punctuation in any documentation file, comment, or table cell. Overuse of em-dashes is the most recognizable syntactic tic of LLM-generated text and produces loose, parenthetical sentences that weaken technical authority.

Choose the exact punctuation mark that expresses the logical relationship between clauses:

| Logical Relationship | Replacement | Example |
| :--- | :--- | :--- |
| **Elaboration, definition, or consequence** | Colon (`:`) | `Circuit tokens identify a specific installation: numeric tunnel IDs alone cannot distinguish replaced routes.` |
| **Two closely linked independent clauses** | Semicolon (`;`) | `NewRouter starts local infrastructure immediately; it does not block on network tunnel readiness.` |
| **Subordinate metadata (sizes, codes, defaults)** | Parentheses (`()`) | `Outbound datagrams support four wire protocols (Datagram1, Raw, Datagram2, and Datagram3).` |
| **Separate, high-impact technical claim** | Period (`.`) | `Private keys live exclusively in memory. The daemon wipes all key buffers on shutdown.` |
| **Continuous action or participial modifier** | Comma (`,`) | `The gateway fragments oversized I2NP messages into 1024-byte frames, padding any remainder with non-zero random bytes.` |

*Note*: Standard ASCII hyphens (`-`) in compound modifiers (`zero-allocation parser`, `in-memory mode`, `32-byte hash`), CLI flags (`-webui-listen`), and negative numbers remain mandatory.

---

## 3. Anti-Slop Lexicon & Structural Bans

### 🚫 Banned Vocabulary

Never use the following words or phrases in any technical document:

- **AI Hyperbole & Buzzwords**: `seamless`, `seamlessly`, `robust`, `battle-tested`, `cutting-edge`, `next-generation`, `state-of-the-art`, `powerhouse`, `unleash`, `empower`, `supercharge`, `elevate`, `delve`, `tapestry`, `testament`, `landscape`, `holistic`, `synergy`, `paradigm`, `first-class citizen`, `out of the box`, `under the hood`, `heavy lifting`, `breeze`, `effortlessly`, `meticulously`, `vital`, `crucial`, `pivotal`, `paramount`.
- **Throat-Clearing Prefaces**: `It is important to note that`, `It is worth mentioning that`, `In order to`, `At its core`, `Fundamentally`, `Essentially`, `Basically`, `When it comes to`, `In the realm of`, `Let's explore`, `Dive into`, `As mentioned earlier`.
- **Hollow Verb Phrases**:
  - Instead of `is responsible for handling` -> use `handles`, `dispatches`, `parses`, `validates`.
  - Instead of `serves as a` or `acts as a` -> state what it *is* or what it *does* (`is the public gateway`, `terminates inbound streams`).
  - Instead of `facilitates the process of` -> name the exact operation (`schedules`, `encrypts`, `retransmits`).
  - Instead of `provides the ability to` -> use `lets callers`, `exposes`, `supports`.
  - Instead of `ensures that` (when used vaguely) -> state the mechanism (`rejects`, `bounds`, `wipes`, `verifies`).

### 🚫 Banned Rhetorical Structures

1. **"Not only X, but also Y"**: State both facts directly (`The router validates the SU3 signature and filters stale RouterInfo entries`).
2. **"Whether you are X or Y"**: State the supported modes plainly (`IVNP runs as a standalone daemon or an embedded Go library`).
3. **Negative-Positive Tautologies ("It's not just X; it's Y")**: Delete the theatrical contrast and state the engineering truth.
4. **Repetitive Bullet Intros**: In bulleted lists, do not repeat the same participle (`Ensuring...`, `Providing...`, `Leveraging...`) at the start of every line.

### Paired Examples: AI Slop vs. Technical Precision

**Example 1: Architectural Overview**
- ❌ **BAD (Slop + Em-dash)**:
  > At its core, IVNP is a robust, next-generation I2P router designed to seamlessly bridge the gap between standalone daemons and embedded libraries — empowering developers to effortlessly build privacy-preserving applications under the hood.
- ✅ **GOOD (Technical Writer)**:
  > IVNP is an I2P router written in Go. It runs either as a standalone daemon (`ivnpd`) or as an in-memory embedded library (`gosuda.org/ivnp`) with standard `net.Conn` and `net.PacketConn` interfaces.

**Example 2: Subsystem Explanation**
- ❌ **BAD (Slop + Em-dash)**:
  > The Data Plane subsystem plays a crucial role in handling all the heavy lifting of cryptographic transport I/O — ensuring that packets are meticulously encrypted and routed without any hiccups.
- ✅ **GOOD (Technical Writer)**:
  > The data plane (`dataplane`) executes established NTCP2 and SSU2 transport sessions, layered AES-256-CBC tunnel encryption, ECIES-X25519-AEAD-Ratchet garlic sessions, and I2P streaming state machines. It never performs peer lookups or mutates routing policy.

**Example 3: Wire Protocol Specification**
- ❌ **BAD (Slop + Em-dash)**:
  > When it comes to wire parsing, IVNP leverages a cutting-edge zero-allocation cursor approach — which means it avoids heap allocations in order to supercharge performance.
- ✅ **GOOD (Technical Writer)**:
  > Wire parsers in `internal/wire` and `foundation` operate on caller-owned byte slices through `wire.Cursor`. Parsing returns zero-allocation views over the input buffer, and serializers write directly into fixed-capacity destination slices without growing the heap.

---

## 4. Document Architecture & Formatting Standards

### Opening Every Document and Section

1. **Document Lead**: The first paragraph after the `# Title` must define what the system or subsystem is, what boundary it owns, and how it fits into the broader architecture in 2 to 4 crisp sentences.
2. **Section Lead**: Never stack two headings (`## Section` followed immediately by `### Subsection`) without an introductory sentence or table establishing the section's scope.

### Code-Grounded Specificity

When documenting a package, subsystem, or protocol:

- **Name exact files and types**: Link or cite concrete files (`dataplane/internal/tunnel/gateway.go`), structs (`tunnel.Gateway`), interfaces (`destination.DestinationEndpoint`), and functions (`ivnp.NewRouter`).
- **Include real numbers and bounds**: Specify buffer sizes (`1024-byte tunnel message`), window limits, timeouts, port ranges (`49152..65535`), protocol numbers (`17` for Datagram1, `19` for Datagram2), and layer numbers (`L0` through `L9`).
- **Explain the "Why" Behind Invariants**: Do not stop at listing rules; state the failure mode each rule prevents. For example, explain *why* circuit tokens identify a specific installation rather than a raw 32-bit tunnel ID (to prevent stale teardown or replay collisions when tunnel IDs are reused across rotations).

### Tables, Diagrams, and Code Blocks

- **Tables**: Use tables whenever comparing 3 or more items across shared attributes (layer hierarchies, protocol numbers, CLI flags, HTTP endpoints, wire header fields, error sentinels).
- **Diagrams**: Use clean ASCII architecture diagrams or valid Mermaid diagrams (`flowchart`, `sequenceDiagram`, `stateDiagram-v2`) to illustrate multi-step handshakes, packet pipelines, and dependency DAGs. Quote Mermaid node labels that contain parentheses or special characters (`id["Label (Detail)"]`).
- **Code Snippets**: Keep examples runnable, idiomatic, and minimal. Show realistic error handling and resource cleanup (`defer router.Close()`, `defer dest.Close()`).

---

## 5. IVNP Documentation Map

Maintain a cohesive, navigable documentation suite across the repository:

| Document Path | Scope & Responsibility |
| :--- | :--- |
| `README.md` | Project entrypoint: value proposition, capability highlights, quickstart for daemon (`ivnpd`) and embedded library (`gosuda.org/ivnp`), multi-network dialing, documentation index, and development commands. |
| `docs/README.md` | Documentation hub and reading guide across architecture, subsystems, protocols, and operations. |
| `docs/architecture.md` | Strict L0-L9 unidirectional DAG architecture, dependency rules (`architecture/architecture_test.go`), plane separation (`controlplane` vs. `dataplane`), memory discipline, and execution lifetimes. |
| `docs/codebase-guide.md` | Complete package-by-package and file-by-file map of every subsystem (`L0` through `L9`), key types, entrypoints, and internal boundaries. |
| `docs/protocols-and-cryptography.md` | Cryptographic primitives (`cryptography`) and foundation wire structures (`foundation`): X25519, Ed25519, RedDSA, ElGamal, Elligator2, ChaCha20-Poly1305, ML-KEM hybrids, Streebog, Identities, Certificates, RouterInfo, LeaseSet2, EncryptedLeaseSet2, MetaLeaseSet, and I2NP framing. |
| `docs/transports-and-tunnels.md` | Data-plane transport and tunnel mechanics: NTCP2 and SSU2 (`Noise_XK_25519_ChaChaPoly_SHA256`, obfuscation, hole punching, peer test, congestion control), 1024-byte tunnel framing, layered AES-256-CBC/IV encryption, gateway fragmentation, endpoint reassembly, and STBM/VTBM tunnel building. |
| `docs/garlic-streaming-and-datagrams.md` | End-to-end session and transport protocols: ECIES-X25519-AEAD-Ratchet (New Session, Existing Session, DH/symmetric ratchets), I2P Streaming (`dataplane/internal/streaming` TCB, windowing, RTO), and Datagrams (Datagram1, Raw, Datagram2, Datagram3, replay resistance). |
| `docs/controlplane-and-netdb.md` | Control plane orchestration (`controlplane`): Kademlia XOR NetDB, floodfill operations, blinded EncryptedLeaseSet2 publication, exploratory/client tunnel pool lifecycle, SU3 reseed verification, and UPnP/NAT-PMP address discovery. |
| `docs/client-services-and-api.md` | Public Go API (`gosuda.org/ivnp`), multi-network contexts, Happy Eyeballs dialing, merged listeners, node lifecycle (`node`), SAM v3.3 bridge, HTTP proxy (outproxy, jump services, eepsites), SOCKS5 proxy, address book, and `ivnpd` WebUI. |
| `docs/testing-and-simulation.md` | Verification commands, architectural DAG checks (`architecture/architecture_test.go`), deterministic simulation testing (`internal/simnet`, `tools/dstoverlay`, `sim_*.go`), and live integration tests (`tests/integration`). |
| `docs/subsystems-l0-l3-foundation-and-state.md` | Code-level subsystem reference for Layers L0 (`internal/*`), L1 (`cryptography`), L2 (`foundation`, `observability`), and L3 (`interfaces/*`, `state`). |
| `docs/subsystems-l4-dataplane.md` | Code-level subsystem reference for Layer L4 (`dataplane`), covering `DataPlane`, `Service`, `GarlicReceiver`, `NTCP2Manager`, `SSU2Manager`, `tunnel.Runtime`, and `TunnelNetwork`. |
| `docs/subsystems-l5-controlplane.md` | Code-level subsystem reference for Layer L5 (`controlplane`), covering `Controller`, `destinationRuntime`, `StreamingTunnelSender`, `replyRouterInfoSeeds`, NetDB, and tunnel builders. |
| `docs/subsystems-l6-l9-services-node-and-cli.md` | Code-level subsystem reference for Layers L6 (`client`), L7 (`node`), L8 (`gosuda.org/ivnp`), and L9 (`cmd/*`, `tools/*`, `sim_*.go`). |
| `cmd/ivnp-reseed/README.md` | Standalone manual for the `ivnp-reseed` crawler, prober, Max-Min XOR selector, SU3 signer, and HTTP server. |

---

## 6. Post-Change Documentation Synchronization Workflow

Whenever a code modification alters public APIs, configuration keys, CLI flags, protocol behavior, wire formats, subsystem boundaries, package paths, or operational defaults, update the documentation before completing the task:

1. **Identify Impacted Surfaces**:
   - Public types, methods, or errors in root `gosuda.org/ivnp` -> check `README.md` and `docs/client-services-and-api.md`.
   - Layer boundaries or package additions/moves -> check `AGENTS.md`, `docs/architecture.md`, and `docs/codebase-guide.md`.
   - Crypto or wire format changes -> check `docs/protocols-and-cryptography.md`.
   - NTCP2, SSU2, or tunnel changes -> check `docs/transports-and-tunnels.md`.
   - Garlic, streaming, or datagram changes -> check `docs/garlic-streaming-and-datagrams.md`.
   - NetDB, tunnel pool policy, NAT, or reseed client changes -> check `docs/controlplane-and-netdb.md`.
   - Reseed server (`cmd/ivnp-reseed`) changes -> check `cmd/ivnp-reseed/README.md`.
2. **Verify Against Source**:
   - Inspect the modified `.go` files directly. Update any affected struct definitions, method signatures, default constants, or sequence diagrams.
3. **Apply Editorial Verification**:
   - Search all modified markdown files for forbidden em-dashes (`rg "—| – " README.md AGENTS.md docs/ cmd/`).
   - Search for banned AI-slop terms (`seamless`, `robust`, `delve`, `under the hood`, `heavy lifting`, `crucial`, `vital`, `empower`, `unleash`, `effortlessly`, `meticulously`).
   - Verify that all relative markdown links between `README.md`, `docs/*.md`, and source files resolve cleanly.
