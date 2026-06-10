# HIVE

**A privacy-first, peer-to-peer collective-intelligence engine, written in Rust.**

Each device reasons locally over your own documents and shares only
differentially-private, PII-stripped patterns. The network gets smarter without
anyone's raw data ever leaving their device.

> Status: alpha / research prototype.

## The idea

"Document in, insight out," as a collective system with no central server. On
each device:

1. A **Rete-II reasoning engine** runs over your documents against a library of
   rules and surfaces insights. It pairs a dictionary-encoded Rete production
   network with a **JTMS** (justification-based truth-maintenance system) for
   belief tracking and revision.
2. A **local differential-privacy pipeline** strips PII and privatizes any
   pattern before it can be shared.
3. A **peer-to-peer node** distributes privatized rules and insights across the
   network, so every device benefits from what the others learned.

The result is collective intelligence with local-only data: the hive learns,
your documents stay on your device.

## Architecture

| Crate | What it does |
|---|---|
| `crates/rete-alpha` | The reasoning engine: a dictionary-encoded Rete alpha network, a JTMS for justification tracking and belief revision, rule loading and generalization, insight generation, the `hive` binary and a terminal UI, and the local differential-privacy pipeline. |
| `crates/p2p-node` | Peer discovery, NAT traversal, and shard distribution over `libp2p` (QUIC, mDNS, relay, AutoNAT). |
| `mobile/android`, `mobile/ios` | Native clients sharing a `hive_core` Rust FFI core (`cxx` + `cbindgen`), cross-compiled per platform. |

### The privacy pipeline — `crates/rete-alpha/src/privacy/`

Local differential privacy, applied before anything leaves the device. The
modules compose PII stripping, value generalization and bucketing, **k-anonymity**
and **l-diversity** enforcement, **optimized unary encoding (OUE)** for randomized
response, and timing **jitter**, all governed by a **privacy-budget manager**
(ε-accounting) with an append-only audit log.

## Quick start

```bash
cargo run --bin hive            # interactive terminal UI (mock extraction)
cargo run --bin hive -- --live  # live extraction with a local small model
cargo test                      # the suite (1,300+ tests)
```

In the TUI: `Enter` submits a document path, `j`/`k` scroll insights,
`s` shares a selected insight (PII-stripped), `q` quits.

## Layout

```
crates/rete-alpha/   reasoning engine + privacy pipeline + hive binary + TUI
crates/p2p-node/     libp2p peer node (discovery, NAT, shard distribution)
mobile/android/      Android client + hive_core FFI
mobile/ios/          iOS client + hive_core FFI
docs/                specs and architecture decision records (docs/adrs/)
```

## Provenance

HIVE was designed and built by an **autonomous multi-agent engineering
organization** that I designed and operate — a role-based agent lab running a
formal, ADR-driven governance process (proposal, review, anti-forgery
co-signing, and gated acceptance). I built and direct the lab: the
orchestration, the governance, and the architecture. The engineering agents
produced the implementation under it. The decision records that process
generated are in [`docs/adrs/`](docs/adrs/).

This repository is the curated engine. The lab's full operational history is
kept private.

## License

Apache-2.0. See [LICENSE](LICENSE).
