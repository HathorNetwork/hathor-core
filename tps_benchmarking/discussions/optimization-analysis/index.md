# Optimization analysis — PR #1729 "rust script executor"

Analysis of the external performance-optimization variant of the Hathor full-node, ahead of a
**flag-gated** merge. **No code is merged yet** — this is pure understanding. Source: GitHub PR
`HathorNetwork/hathor-core#1729`, branch `feat/rust-script-executor`, cloned (read-only, isolated)
to `../optimized-ref/`. Because the PR is based on **pre-shielded, pre-refactor master**, we read
its **own diff against its merge base** — so what's below is the *pure optimization signal*, with
zero noise from our CP-14 refactor or the shielded work.

## What this PR is

A multi-phase TPS optimization of the single-thread tx-processing pipeline, taking it from
**~980 tx/s (pure Python) → ~3,649 tx/s (3.7×)**. The arc: rewrite verification in **Rust** (one
GIL-released fused batch call), then — once verification fell to ~2% of the budget — attack the new
bottlenecks in **consensus, storage, and metadata** (S5). It ships its own design docs under
`optimized-ref/plans/` and a benchmark under `extras/benchmarking/script_verification/RESULTS.md`.

### The measured ladder (from `plans/tps-bottlenecks-and-roadmap.md`)

| state | TPS |
|---|---:|
| pure-Python service | ~980 |
| Rust verifiers, no batching | ~1,064 |
| two-call batching | ~1,161 |
| single fused call (`verify_tx_from_bytes`) | ~1,559 |
| + Phase A (stash retention, weight cache, yield batching, …) | ~1,861 |
| + B7 get fast path + B8 save dedup | ~2,259 |
| + static-metadata rewrite skip | ~2,485 |
| + info-index write-on-change, Rust static-metadata format, pipeline static-meta | ~2,601 |
| + NC block cache, wire-bytes reuse, scan-last `_is_tip` | ~3,114 |
| + Rust binary mutable-metadata format | ~3,145 |
| + weight-from-origin-bytes, WriteBatch flush, is_new tips hint | **~3,649** |

**Key insight (and a validation of our own Phase-1 work):** after the Rust rewrite, *all*
Rust-side verification is **~4.8 µs/tx ≈ 2% of the ~640 µs/tx budget** — so the later, bigger gains
are in **S5** (the `mempool_tips`/consensus/storage layer we independently identified as the
bottleneck). The PR also removes the **redundant 2nd `validate_full`** — exactly the top
single-thread optimization our Phase-1 study predicted.

## The sections

| Doc | Stage | Headline optimization(s) | Measured impact | Risk |
|---|---|---|---|---|
| [S1](./S1-deserialize-rust-vertex-parser.md) | deserialize | Rust vertex parser (+ native hash, `_origin_bytes` reuse) | parse ~0.78 µs/tx (tiny) | low — Python fallback + differential tests |
| [S2](./S2-prechecks-read-fastpaths.md) | pre-checks | `get_transaction` lock-free LRU fast path, scope fusion, miss-probe skip; stateless checks in Rust | ~178 µs/tx target (bottleneck #1) | low — localized branches |
| [S3S4](./S3S4-verify-rust-and-parallel-scripts.md) | verify | **Rust script interpreter + fused GIL-released batch** + parallel executor (rayon/process/thread) | verification → ~2% of pipeline | **high — consensus-critical** (chain-split risk); guarded by differential + shadow |
| [S5](./S5-save-consensus-storage-metadata-tips.md) | save+consensus | Rust RocksDB, binary metadata serde, **mempool-tips incremental/spender-first/is_new**, save-dedup/WriteBatch | the bulk of the later gains | medium — consensus end-state must match; **fresh-DB required** |
| [S6](./S6-post-consensus-indexes-and-double-validate.md) | post-consensus | **drop redundant 2nd `validate_full`**, info-index write-on-change, reactor-yield batching | ~1.3× (our Phase-1 estimate) + write reduction | low–medium |

## Gating reality — important for our `--opt` / `--no-opt` design

The PR does **not** uniformly flag-gate its optimizations. This directly shapes how much work our
section-gating needs:

- **Already flag-gated (S3S4 verify):** `--script-verification-executor {rust|shadow-rust|process|
  thread}` + `--script-verification-workers` already select Rust-vs-Python and parallel-vs-serial
  at runtime, with a builder switch (`builder.py:600-621`) choosing `RustVerificationService` vs
  the pure-Python `VerificationService`. **Our `-section-s3s4` flag can largely reuse this.**
- **Unconditional today (need a new flag):**
  - **S1** Rust parser — always tries Rust first (`_vertex_parser.py:65-70`); one branch to gate.
  - **S5 storage + binary metadata** — **no runtime flag at all** (effectively build-time: which
    `htr_lib`/`rocksdb_storage.py` is shipped). Gating these for A/B means *adding* a toggle at
    `RocksDBStorage.__init__` and the 4 `to_bytes`/`from_bytes` methods — and note the **fresh-DB /
    no-migration** constraint makes a pure runtime toggle non-trivial for storage.
  - **S5 consensus/index + S6** — each is a **single localized branch** (`mempool_tips_index.py`,
    `context.py`, `consensus.py`, `rocksdb_info_index.py`, `vertex_handler.py`), easy to gate
    individually (per-piece switch points are tabulated in each section doc).

So when we build the gating: **S2/S3S4/S6 and the consensus half of S5** are clean per-branch
toggles; the **storage+serde half of S5** is the one that needs the most care (build-time-ish,
fresh-DB), and may be better treated as a coarser on/off than a hot-swappable runtime flag.

## Cross-cutting correctness model

Every Rust path keeps **Python as the authoritative reference** and guards equivalence three ways:
**fallback** (anything Rust can't handle defers to Python — all rejection semantics stay Python),
**differential testing** (corpus + mutation + Hypothesis fuzz, asserting identical accept/reject
*and error category*), and **shadow mode** (Python authoritative in production while Rust runs
alongside and mismatches are logged). The single highest-risk item is the script interpreter's
**DER/low-S signature policy** (S3S4), frozen by fuzz rather than proof. The single biggest
operational caveat is S5's **fresh-DB / no-migration** requirement.

## Status / next

Report complete (S1, S2, S3S4, S5, S6 + this index). Awaiting explicit authorization to proceed to
the **gated merge**, after which all optimizations land **default-ON** behind the `--opt`/`--no-opt`
+ `-section-x` scheme (see the [optimizations-workstream memory] for the locked flag semantics).
The PR's existing `--script-verification-executor` flag is a ready-made building block for the
`-section-s3s4` toggle.
