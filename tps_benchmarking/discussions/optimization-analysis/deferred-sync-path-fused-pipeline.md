# Deferred optimization — the Rust batch "fused pipeline" (sync-path precompute)

**Status: DEFERRED (intentionally not wired in the current merge).** This documents the one
optimization from PR #1729 we chose *not* to activate, why, and what it would take to bring it in
and measure it later.

## What it is

The PR's headline structural piece is `htr_lib.verify_tx_from_bytes` driven by
`RustVerificationService.precompute_stateless_batch`: **one GIL-released Rust call per sync batch**
that does, for a whole batch of vertices at once — parse (S1) + stateless checks (S2) + sighash +
input-sigops + full script evaluation (S3S4) — with **tiered dependency resolution**:
1. **batch bytes** — an input spending another tx *in the same batch*;
2. **supplied bytes** — caller-provided vertex bytes (Python cache entries not yet flushed);
3. **native RocksDB reads** — unknown hashes read in parallel through the *shared* Rust DB handle
   (the s5 storage backend), parsed natively, with the fetched hashes reported back to pre-warm the
   Python object cache.

The per-input script/sigops/stateless results are **stashed** keyed by tx hash and **consumed**
later during each tx's normal verification (`ScriptVerificationPool.consume_script_results`,
`has_script_results` — already present in our merged `script_verification_pool.py` and the
`_verify_inputs_parallel` cache path). The connect loop (`VertexHandler.on_new_block`) issues the
precompute once per batch and discards it at the end.

## Why we deferred it

Our benchmark **driver feeds transactions one at a time** through S1→S6 (the per-tx, white-box
latency path). The fused pipeline's entire value is **amortizing the FFI boundary and parallelizing
across a whole batch** — it only pays off when vertices arrive in **batches**, i.e. the **block-sync**
path (`on_new_block` with a list of `deps`). On our per-tx driver:
- the batch precompute would never be invoked (no batch is ever assembled), so it is **inert** for
  the current workload;
- the per-tx Rust **script pool** we *did* wire already delivers the S3S4 win on this path (Rust
  ECDSA per tx, GIL released).

So wiring the fused pipeline now would add code + risk with **zero measurable effect** on the
existing benchmark. It becomes worthwhile only alongside a **batch/sync workload** that exercises it.

## Expected benefit (from the PR roadmap)

On a real-reactor sync benchmark the PR measured the verification ladder:
`pure-Python ~980 → Rust no-batch ~1,064 → two-call batch ~1,161 → single fused call ~1,559 TPS`.
So the fused call is roughly a **further ~1.3–1.5× on the verification portion** *for sync
workloads*, on top of the per-tx Rust scripts — plus secondary wins: static-metadata computed
natively in the pipeline, and dependency-cache pre-warming. None of this shows up on a per-tx driver.

## What it would take to wire + measure

1. **Bring in `rust_verification_service.py`** (subclass *our shielded* `VerificationService`, so
   shielded falls through) and add **`verify_bytes`** to `verification_service.py` (it sets
   `base_transaction._origin_bytes` — the slot already exists from s3s4 sub-item A, currently inert).
2. **Wire the connect-loop precompute** in `VertexHandler.on_new_block`: the deferred
   `precompute_stateless_batch` over the batch + the `discard_precomputed` in a `finally`. ⚠️ Note
   the upstream connect-loop rewrite *fuses* s2 (miss-probe), s3s4 (precompute), s5 (`is_new`) and
   s6 (yield) — we already took the s2/s5/s6 bits; this adds the s3s4 precompute on top, so it must
   be gated carefully (s3s4 + rust-mode) and keep the shielded/serial fallback.
3. **Builder selection of `RustVerificationService`** when `s3s4` + rust mode (vs. today's harness
   pool injection), so the precompute path is reachable.
4. **Couples to s5 storage** — tier-3 native dep reads use the shared Rust RocksDB handle, so the
   fused pipeline is only fully effective with `s5` (Rust storage) also on.
5. **A new benchmark workload/driver** that feeds vertices in **batches** (mimicking `on_new_block`
   block sync), so the fused call is actually exercised and measurable — this is the real
   prerequisite; without it there is nothing to measure.

## Correctness notes

- Shielded vertices decline the fused path (the Rust pipeline only handles regular block/tx/
  token-creation, no headers) → they fall back to the inherited shielded Python verification, same
  as the per-tx script pool today.
- The fused pipeline preserves consensus semantics by construction (Python remains authoritative;
  differential + shadow tests gate it) — same discipline as the rest of the s3s4 work.

## Implemented + measured (2026-06-30)

We *did* wire it (opt-in, so the default per-tx path is untouched):
- `rust_verification_service.py` brought in (subclasses our shielded `VerificationService`); `verify_bytes`
  skipped (it's the p2p wire entrypoint; the in-process driver works on vertex objects).
- `NodeHarness(sync_precompute=True)` swaps in `RustVerificationService` when s3s4 is on.
- `scripts/sync_precompute_experiment.py` calls `precompute_stateless_batch([tx…], params,
  include_scripts=True)` over the batch, then drives the per-tx pipeline (which consumes the stash).

**Result (N=300, I=3, all opts on, median of 3):** standard per-tx ≈ 589 tx/s, sync-precompute ≈ 583 tx/s
→ **~0.99× (a wash)**. Correctness: the fused Rust call ran (stash populated) and the stored state is
**identical** to the standard path.

**Why no gain here (all consistent with the deferral rationale):**
1. **No off-thread overlap.** The fused pipeline's headline win is that the GIL-released batch call
   runs on the reactor's *thread pool*, overlapping reactor I/O. Our harness uses a simulated-clock
   test reactor with no thread pool, so `defer_stateless_precompute` runs the batch **synchronously**
   — the main benefit can't appear.
2. **Verification is already ~2%.** The per-tx path already uses the Rust script pool, and verification
   is a tiny slice of the per-tx budget (S5 consensus/save dominate). Amortizing the FFI of an already
   small, already-Rust operation over a batch saves a fraction of ~2%.
3. **Double-parse in this measurement.** On a real node the precompute's parse is reused by the
   connect loop; our per-tx driver re-deserializes each tx at S1 independently, so the batch's parse
   work is *additional* here, not reused — slightly working against the precompute.

**Conclusion:** the optimization is correct and consensus-safe, but its benefit is structurally a
**real-reactor, block-sync** phenomenon (off-thread overlap + verification as a larger share) that the
in-process per-tx latency harness cannot capture. To actually measure its upside we'd need a
**real-reactor threaded sync benchmark** (feed batches through `on_new_block` on a live reactor) — a
future load module, not the current driver. The wiring stays opt-in (`sync_precompute=False` default),
so it costs nothing on the existing benchmark.
