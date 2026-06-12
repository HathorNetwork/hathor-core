# TPS strategy: Rust serde vs. metadata format vs. Rust storage

> **Context.** With the optimization arc on this branch complete (Rust scripts + stateless verification service,
> single validation, metadata-only flushes, incremental + deduplicated mempool tips — see
> `plans/profiling-on-new-tx-after-rust-scripts.md`), the question is which infrastructure investment raises TPS
> next: (a) move storage to Rust, (b) move vertex (de)serialization to Rust, or (c) replace the JSON metadata
> format. This document records the measurements, the analysis and the decided line of action.

## Ground truth (real timings, no cProfile)

All previous profiling tables used cProfile, which inflates Python-call-dense regions ~2–5× relative to C calls.
These are wall-clock measurements of the same workload (in-memory manager, rust:12 executor):

| measurement | real value | share of real hot path |
|---|---:|---:|
| **Full add-tx pipeline, 1-in/2-out** | **0.83 ms/tx → ~1,200 tx/s ceiling** | 100% |
| Full pipeline, 8-in/8-out | 1.26 ms/tx → ~800 tx/s | — |
| Vertex deserialize (Python) | 33 µs (1-in) / 87 µs (8-in) | ~4–7% |
| Vertex serialize | 8–25 µs, once per tx (flush fix) | ~1% |
| Metadata JSON `to_bytes` | 6–10 µs × ~5–17 saves per added tx | ~4–13% |
| Metadata JSON `from_bytes` | 8–12 µs per cache-miss load | small (hot path is cache-hit) |
| `get_transaction` cache hit | **2.55 µs** × ~38 gets/tx | ~12% |
| All Rust calls (scripts, stateless, sigops) | ~30 µs total | ~4% |
| **Everything else: diffuse Python orchestration** (dispatch, consensus logic, index predicates, static metadata, glue) | ~550 µs | **~65–70%** |

Metadata JSON payloads: 392 B (1-io tx) to 903 B (8-io), with hashes hex-encoded (2× size). An 8-input tx
triggers up to ~17 metadata saves in one consensus update (the same spent tx is saved once per input).

**Why "single-thread":** the entire add-tx pipeline runs synchronously on the Twisted reactor thread, one vertex
at a time (sync-v2 processes its queue serially; `on_new_tx` is one synchronous call chain; the GIL serializes the
Python parts regardless). The Rust executors parallelize only *within* one transaction (rayon over its
inputs/checks while the reactor waits) — they reduce latency, never process two transactions concurrently. So
throughput ceiling = 1/latency, and 23 of 24 cores idle during tx processing. The figures are also in-memory
(cache-hot RocksDB) and exclude the p2p/API work that shares the reactor thread — real sustained TPS sits below
the ceiling.

## Evaluation of the three options

### (a) Storage to Rust — wrong move *now*

The killer measurement: a cache-hit `get_transaction` costs **2.55 µs**. A Rust storage cannot beat that
meaningfully while the *consumers* are Python — every get would still cross the FFI and materialize a Python
`Transaction` object, trading LRU bookkeeping for marshalling at roughly break-even. Rust storage pays off only
when the readers are Rust too (no-GIL native reads for verification/consensus), which makes it the **end-state**
of the migration (`plans/rust-verification-service.md` § "Why not 100% Rust?"), not the next step. Today it is the
largest effort, a second consistency surface, a DB-compat burden, and ~0% immediate TPS.

### (b) Vertex serde to Rust — the right next step, for a structural reason

Direct CPU win is modest (~4–7% parse, plus sighash/`get_struct` slivers). Its real value is being the
**prerequisite for Phase 3** (pipeline batching, `plans/rust-verification-service.md` §B): sync hands a *batch of
raw vertex bytes* to one Rust call that parses, computes hashes/sighash, and runs all stateless checks + scripts
**in parallel across vertices, off the reactor**. That is the only lever in sight that *multiplies* TPS rather
than shaving percentages — the table shows the remaining cost is diffuse Python that no single port can reach,
but a batch boundary bypasses it wholesale. Rust-side parsing also removes the "trust the Python-computed
hash/target" caveats in the current PoW/sighash handling.

Consensus-exactness discipline as established: round-trip differential fuzz (`parse(bytes)` equivalence and
`serialize(parse(bytes)) == bytes`) plus malformed-bytes rejection equivalence, across every vertex type and
header (nano, fee, shielded; OCB/PoA may keep Python fallback as decided earlier).

### (c) Metadata format (replace JSON) — real but second-order; sequence it smartly

Real CPU is 4–13%, plus write-amplification benefits on disk-backed nodes that the in-memory profile does not
show. But a format change forces a DB migration, and there is a better sequencing: **define the binary metadata
format in Rust as part of the serde work** — it is needed for the eventual Rust storage anyway. One format, one
migration, designed once for the end state. Two cheap independent wins can land any time:

- **Dedupe metadata saves within one consensus update** — an 8-input tx saves the same spent-tx metadata up to 8×;
  `context.save` can mark dirty and flush each affected tx once per update.
- **orjson as a drop-in** (~5× JSON speed, zero migration) as an interim measure if desired.

## TPS projections

| state | ceiling (1-in shape, in-memory) |
|---|---:|
| today | ~1,200 tx/s |
| + serde + Phase-3 batching (serial core = consensus + commit + Tier-3 ≈ 0.35–0.4 ms) | **~2,500–3,000 tx/s** |
| beyond | serial consensus/storage core is the wall → that is when (a) becomes the right project |

IBD/sync improves more than mempool TPS (it is verification-bound, exactly what Phase 3 parallelizes).

## Decided line of action

1. **Vertex wire-format serde in Rust** — **parse side DONE**: `htr_lib.parse_vertex` parses regular
   blocks/txs/token-creation txs (no headers) and computes the vertex hash; `VertexParser.deserialize` uses it as a
   conservative fast path (any unsupported/malformed input falls back to the Python parser, so rejection semantics
   stay Python's; differential corpus + full mutation sweep + fuzz prove accepted bytes reconstruct identical
   vertices — the suite caught a real coupling: TokenCreationTransaction derives its tokens list from the ctor
   hash). Measured: deserialize 34.4 → 5.4 µs (6.4×) at 1-io, 8.7× at 8-io, 15.6× at 255-io; pipeline effect
   ~3–5% (within end-to-end noise; matters more for IBD where every vertex is parsed from network bytes). The Rust
   *serializer* lands with Phase 3, which is what actually consumes this work.
2. **Phase-3 pipeline batching** — **stateless stage DONE**: `htr_lib.verify_vertices_stateless_batch` runs
   all stateless checks of a whole batch in parallel (rayon across vertices, one FFI call, GIL released);
   `RustVerificationService.precompute_stateless_batch` stores per-vertex results keyed by hash (params-identity
   guarded) and `verify_without_storage` consumes them with the canonical Python check order preserved. Wired at
   the two sync call sites: `TransactionStreamingClient.process_queue` (batches of 64) and
   `VertexHandler.on_new_block` (block + its pending deps). On a real reactor the precompute runs on the reactor
   thread pool (`defer_stateless_precompute`), removing the stateless stage from the serial path entirely; under
   the simulated clock it runs inline. Measured: stateless stage 14.1 → 6.0 µs/vertex (2.3×, batch=64,
   rayon×12); end-to-end two-peer sync of 2,000 spend-chain txs (simulator, inline precompute — a lower bound):
   ~752 tx/s batched vs ~658 per-vertex (+14%) vs ~610 pure-Python service (+23%).

   **Script stage batched (DONE).** `precompute_stateless_batch` now also evaluates the input scripts of the
   whole batch with a single `verify_scripts_batch` call (parallel across all inputs of all txs): jobs are
   built per input with spent txs resolved from the batch itself (spend chains) or storage, raw results are
   stashed in the script pool keyed by tx hash + opcodes version, and
   `TransactionVerifier._verify_inputs_parallel` consumes them via `run_jobs_with_cache` — restricted to the
   inputs the fresh path would actually schedule, so precheck/conflict/raise-kind interleavings surface
   identically (differential suite: `hathor_tests/verification/test_script_precompute.py`). Any tx with an
   unresolvable dep is skipped and evaluated fresh at connect time.

   **Unified bytes entrypoint (DONE).** `VerificationService.verify_bytes(data, storage=...)` is now the
   single bytes→vertex entrypoint used by every caller (sync-v2 agent ×3, push_tx, mining APIs, mining WS,
   send_tokens, decode_tx); only the trusted DB-load path keeps calling the parser directly. This is where
   the future fused Rust parse+verify call slots in without touching callers again.

   **Fused script pipeline (DONE).** `htr_lib.verify_scripts_from_bytes`: raw tx bytes in, per-input script
   results out, with parse, sighash (a splice of the wire bytes' funds region — valid because the parser only
   accepts canonical encodings; differential suite `test_rust_sighash.py`), dependency resolution and
   evaluation all in one GIL-released Rust call. Deps resolve tiered: the batch's own bytes (spend chains) →
   caller-supplied bytes → a native RocksDB read of the `tx` column family through the shared handle (the
   first consumer of `RocksDb::native()`). Unflushed Python-cache deps are supplied in a second call;
   anything still unresolved or unparseable (header-carrying txs) falls back to the Python job-building
   path, so coverage and rejection semantics are unchanged. `verify_bytes` captures original wire bytes per
   vertex (FIFO-capped) so the pipeline usually skips re-serialization.

   Still open: folding the stateless checks into the same fused call (one FFI crossing per batch instead of
   two), and the remaining Python in the loop — the connect-time job rebuild in `_verify_inputs_parallel`'s
   precheck phase, and `verify_sigops_input`'s Python dep fetches.
3. **Alongside, cheap:** dedupe per-update metadata saves; binary metadata format defined in Rust, migrated once
   (or orjson interim).
4. **Defer storage-to-Rust** until the Rust core consumes it natively (post-Phase-3); by then Rust owns both wire
   and metadata formats, reducing the storage port to a RocksDB-handle + snapshot-consistency problem. Re-profile
   and re-evaluate at that point.
