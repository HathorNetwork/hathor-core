# on_new_tx profiling after Rust script verification: results & next bottlenecks

> **Context.** `plans/rust-script-verification.md` is implemented (commit `2cc83a00`): per-input script evaluation
> runs in Rust (`htr_lib.verify_scripts_batch`, rayon threads, GIL released) behind the `rust`/`shadow-rust`
> executors. This document records the CPU profiles of `HathorManager.on_new_tx()` taken right after that landed,
> what they reveal about the *new* bottlenecks, and the recommended order of attack. It feeds directly into the
> decision of when/how to execute `plans/rust-verification-service.md`.

## Method

- `tools/cpu_profiling/profile_new_tx.py` workload (DAG Builder, in-memory manager, cProfile over the full
  `on_new_tx` pipeline: deserialization → verification → consensus → indexes), driven with a wrapper that wires a
  `ScriptVerificationPool(mode=RUST, num_workers=12, min_inputs=1)` into the verifiers.
- Machine: 24 cores, CPython 3.13. Shapes: the common **1-input × 2-output** tx (50 txs) and a heavier
  **8-input × 8-output** tx (30 txs).
- Caveats: cProfile inflates regions made of many small Python calls relative to the single C-call into Rust, so
  Python shares are slight overestimates (ranking is robust). The DAG-Builder mempool is synthetic: each tx has its
  own funding tx, so the mempool tip set grows with tx count — which is exactly what exposed the tips-index scaling
  issue below.
- **Tooling gap found (fix separately):** the simulator's `_build_vertex_verifiers`
  (`hathor/simulator/simulator.py:246`) does not forward `script_verification_pool` to `VertexVerifiers.create`,
  so simulator- and profiler-built managers silently verify scripts serially regardless of the configured executor
  (this affects thread/process modes too). The profiling driver worked around it by closing over the builder's pool.

## Results

Wall time per `on_new_tx()` call (deserialization included):

| shape | serial | rust:12 | rust:12 + tips-update no-op | cumulative |
|---|---:|---:|---:|---:|
| 1-input × 2-out | 7.35 ms | 6.52 ms | **2.02 ms** | **3.6×** |
| 8-input × 8-out | 16.2 ms | ~10.5 ms | **6.1 ms** | **2.6×** |

Profile shares:

- **rust:12 (8-input):** scripts collapsed from ~49% of the call (239 ms cum, serial) to ~7% (23 ms). New top:
  `consensus.unsafe_update` ~55% — of which `get_transaction` (8,250 calls, ~104 ms) and
  `mempool_tips_index.update` (~96 ms); remaining Python verification (`_verify_tx`: sums/sigops/structure) ~25%.
- **rust:12 (1-input):** `mempool_tips_index.update` alone is **~69%** of the call (225 ms of 326 ms over 50 txs:
  12,850 `iter` iterations, 14,550 `get_transaction` calls).
- **rust:12 + tips no-op (1-input):** verification's Python overhead becomes #1 (`validate_full` ~58%, almost all
  non-script Tier-1/2 checks); `unsafe_update` drops from 199 ms to 20 ms — i.e. the consensus core is the cheap
  O(inputs + parents) work one would expect.
- **rust:12 + tips no-op (8-input):** verification ~47% and consensus ~43%, but consensus is now dominated by
  `mark_inputs_as_used` → `context.save` → **full tx re-serialization on metadata-only saves**
  (`get_struct`/`serialize` ≈ 45 ms across 510 saves + ~60 ms LRU churn).

## Findings

1. **`mempool_tips_index.update()` is O(mempool tips) per affected tx — the dominant cost for common txs.**
   `unsafe_update` calls it once per affected tx (~5 per added tx: the tx, spent txs, parents), and each call does a
   *full scan* of all mempool tips, fetching each tip and its children/spenders to re-derive "is it still a tip /
   did it become voided" (`hathor/indexes/mempool_tips_index.py:133`). Adding tx N scans ~N tips → quadratic in
   mempool size, i.e. worst exactly under load. The consensus logic itself (`mark_inputs_as_used`,
   `update_voided_info`, `set_conflict_twins`) is O(inputs + parents) for a conflict-free tx.

2. **Metadata-only saves re-serialize the whole transaction.** Metadata *is* stored in a separate column family and
   `consensus` saves with `only_metadata=True`, but the write-back cache's dirty set is just a set of hashes — the
   flag is lost — and every flush path (`_save_transaction_to_db`, `rocksdb_storage.py:211`) unconditionally
   re-serializes the immutable vertex bytes (`_tx_to_bytes`) and rewrites the tx CF alongside the metadata CF.
   Cache-capacity evictions (`_cache_popitem`) make these flushes happen synchronously on the reactor thread,
   roughly once per save under consensus's access pattern. The two issues compound: the tips scan's thousands of
   `get_transaction` calls churn the same LRU and trigger more dirty evictions.

3. **After both issues are removed, the bottleneck is Python Tier-1/2 verification** (47–58% of the call), which is
   precisely the target of `plans/rust-verification-service.md`. The premise of that plan is restored — but only
   *after* the tips/flush fixes, since no amount of parallel verification shrinks a serial consensus/index core
   that was 55–70% of the work.

4. **Every vertex is fully verified twice.** `_validate_vertex` runs `validate_full` (the real one,
   `vertex_handler.py:211`), and then `_post_consensus` runs the *entire* `validate_full` again inside an `assert`
   (`vertex_handler.py:247`, only `skip_block_weight_verification=True` / `init_static_metadata=False` differ).
   `validate_full` has no early-return for already-FULL vertices (`verification_service.py:64` — only checkpoints
   short-circuit), so the second pass re-runs every check including the ECDSA script evaluation. Every profile in
   this document shows the 2× call counts (`validate_full`/`verify`/`_verify_tx` at 60 calls for 30 txs). With
   verification at ~50–60% of `on_new_tx`, the redundant pass alone costs ~25–30% of the whole call. Note it is an
   `assert`: `python -O` already skips it, which confirms it is a sanity check, not consensus behavior.

5. **Rust script verification details, for reference:** rayon real-OS-threads, GIL released; the parallelism unit is
   one tx's inputs, so a 1-input tx uses one thread (its 6–11× microbenchmark win is single-thread efficiency:
   libsecp256k1 + no interpreter). Bench results in `extras/benchmarking/script_verification/RESULTS.md`.

## Recommendations (in order)

0. **Remove the redundant post-consensus re-validation** (finding #4) — **DONE**: `_post_consensus` now asserts
   `vertex.get_metadata().validation.is_fully_connected()` instead of re-running `validate_full`. Nothing between
   `_validate_vertex` and `_post_consensus` can invalidate the vertex (consensus only writes metadata like
   `voided_by`/`spent_outputs`; it never unsets the validation state), so the re-verification was pure defense at
   ~2× the entire verification cost. Measured: serial 8-input `on_new_tx` 16.2 → 10.0 ms (−38%); rust:12 (tips
   no-op) 3.94 → 3.35 ms (−15%) and 1-input 1.68 → 1.33 ms (−21%); `validate_full` call counts dropped 2× → 1×.
1. **Make `mempool_tips_index.update()` incremental** — pure Python, the single highest-leverage change
   (3.2× on 1-input txs in this profile). Only the new tx's parents/spent-txs can stop being tips on a normal add;
   the global "did any tip become voided" sweep is only needed on conflict/voiding events (known at that point) and
   on reorgs (already a separately-identified path via `context.reorg_info`).
2. **Split dirty-tracking in `rocksdb_storage.py`** so flushes after the first save write only the metadata CF
   (vertex bytes are immutable: tx-CF write should happen exactly once per tx). Removes the serialization CPU and
   the RocksDB write amplification from the consensus hot path (~45–55 ms of the remaining 78 ms `unsafe_update`
   in the 8-input profile).
3. **Fix the simulator wiring** (`_build_vertex_verifiers` → forward `script_verification_pool`) so simulator and
   profiling runs exercise the configured executor.
4. **Execute `plans/rust-verification-service.md` Phases 1–2** (Tier-1/2 stateless checks in Rust, marshalled
   fields) — attacks the then-dominant verification share. Re-profile the *sync/IBD* path first
   (`profile_new_block.py` with rust) to size the win there, since the mempool-tx profile mix differs from IBD.
5. **Move vertex (de)serialization to Rust as part of that plan's Phase 3, not as a standalone project.** The
   profile does not justify it on its own (deserialization ≈ 5–7% of `on_new_tx`; the scary serialization number
   was finding #2, a bug, not an inherent cost). Its real value is architectural: `verify_vertices_stateless(raw
   bytes)` lets sync batches skip Python parsing entirely, and some Tier-1 checks (PoW hash, sighash) need the wire
   format in Rust anyway. Same differential discipline as scripts: round-trip + malformed-bytes fuzz against the
   Python parser for every vertex type and header.

## Reproduce

- Profiles: `tools/cpu_profiling/profile_new_tx.py` (after fix #3 lands, pass the executor; until then use a
  driver that closes over `builder._get_or_create_script_verification_pool()`),
  e.g. `--inputs 1 --outputs 2 --count 50` and `--inputs 8 --outputs 8 --count 30`, sorted by `cumulative`.
- The tips-bottleneck experiment: no-op `manager.tx_storage.indexes.mempool_tips.update` after the manager is
  built and re-run the same profile.
