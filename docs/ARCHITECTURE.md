# Architecture

HIVE is a privacy-preserving, peer-to-peer collective-intelligence system. The
core principle is simple: **reasoning happens locally on each device, and only
differentially-private, PII-stripped patterns are ever shared.** No raw data
leaves the device, and there is no central server.

## End-to-end flow

```
document ──▶ extraction ──▶ Rete-II engine ──▶ insights ──▶ privacy pipeline ──▶ P2P broadcast
              (local)        (+ JTMS)                          (local DP)          (Dandelion++ / Merkle)
```

1. **Ingest.** A document enters through the terminal UI, a watched folder, or a
   mobile client.
2. **Extraction.** The document is turned into structured tuples — either by a
   mock extractor (for tests/demos) or a local small language model. Nothing is
   sent to a remote API.
3. **Reasoning.** Tuples become working-memory elements (WMEs) and flow through a
   Rete production network that fires rules to produce candidate insights. A
   JTMS (justification-based truth-maintenance system) tracks *why* each belief
   holds and revises beliefs when their support changes.
4. **Privacy.** Before any rule or insight can be shared, it passes the local
   differential-privacy pipeline (below). Raw, identifying content never leaves.
5. **Distribution.** Privatized rules are gossiped to peers, so every device
   benefits from what the others learned.

## The reasoning engine — `crates/rete-alpha`

- **Alpha network** (`alpha_network.rs`, `wme.rs`, `dictionary.rs`): a
  dictionary-encoded Rete alpha network. Fields are interned to compact integer
  ids; alpha-memory indexes and conjunction bitmasks decide production firing.
- **Truth maintenance** (`jtms.rs`): justification-based belief tracking with
  support-driven revision, so retracting a fact correctly retracts everything
  that depended on it.
- **Rules and insights** (`rule_loader.rs`, `seed_rules.rs`, `generalization.rs`,
  `insight_gen.rs`): rule loading, a seed rule library, generalization of
  learned patterns, and insight-card generation.
- **Application** (`orchestrator.rs`, `pipeline.rs`, `tui.rs`, `watch_folder.rs`):
  the document-in / insight-out orchestration, the `hive` binary, and a terminal
  UI. Benchmarks for throughput and the JTMS live under `src/bin/`.

## The privacy pipeline — `crates/rete-alpha/src/privacy/`

Local differential privacy applied before anything is shared:

- **PII stripping** (`pii_stripper.rs`): deny-by-default removal of identifying
  fields.
- **Generalization and bucketing** (`generalizer.rs`, `amount_bucketer.rs`,
  `frequency_tables.rs`): coarsen values so individuals are not distinguishable.
- **k-anonymity and l-diversity** (`k_anonymity.rs`, `l_diversity.rs`): enforce
  that every released pattern is shared by at least *k* sources and carries at
  least *l* distinct sensitive values.
- **Randomized response** (`oue.rs`): optimized unary encoding for local DP on
  categorical patterns.
- **Budget and audit** (`budget_manager.rs`, `audit_log.rs`): an ε-budget
  accountant gates releases and an append-only log records them.
- **Timing** (`jitter_queue.rs`): decorrelates release timing from input timing.

## The peer-to-peer layer — `crates/p2p-node`

Built on `libp2p` (QUIC transport, mDNS + AutoNAT + relay for discovery and NAT
traversal):

- **Anonymized propagation** (`dandelion.rs`): Dandelion++ stem-then-fluff
  routing so a rule's originating peer is not observable.
- **Reconciliation** (`store.rs`, `bootstrap.rs`): Merkle-root set
  reconciliation and zip-bomb-guarded snapshot bootstrap for new peers.
- **Rule exchange** (`rule_broadcast.rs`, `rule_ingest.rs`, `tuple_wire.rs`):
  signed, rate-limited rule broadcast and a validating ingest pipeline over a
  compact wire format.

## Mobile — `mobile/`

Native iOS and Android clients share a single Rust core (`hive_core`) through an
FFI boundary (`cxx` + `cbindgen`), cross-compiled per platform. Security-sensitive
material (the device salt) is handled with explicit, non-elidable zeroization
(`write_volatile`) and HKDF-SHA256 derivation (RFC 5869), with parity tests on
both platforms. The apps ship a deliberately empty privacy/entitlement surface —
zero telemetry, no cloud egress by default.
