# Optimization speedup ladder — measured results (Step 6)

Measured on this machine (i5-class, WSL2 — *loaded*, so **read the ratios, not the absolutes**;
absolute TPS is noisy and varies run-to-run). In-process benchmark engine, 1-tip-transparent
workload, RocksDB temp-dir, real verifiers, weight-1 PoW. Each figure is the **median of 3 runs**.
The flag `--opt` = all optimizations ON; `--no-opt` = all OFF; `--no-opt sX` = section X baseline,
the rest optimized (so it isolates **section X's marginal contribution**).

## Headline

| config | tx/s (median) | vs baseline |
|---|---:|---:|
| `--no-opt` (all optimizations OFF) | 132 | 1.00× |
| `--opt` (all ON) | **574** | **~4.3×** |

A ~4.3× single-thread speedup with all sections on, consistent with the PR's own ~3.7×-vs-pure-Python
projection (our baseline is the gated-off path, ≈ the pre-merge shielded node).

## Per-section marginal contribution (N=400, I=2, O=2)

"Contribution" = how much throughput is lost when **only that section** is turned off (everything
else stays optimized), relative to full `--opt` (574 tx/s).

| section off | tx/s | drop from full | contribution |
|---|---:|---:|---:|
| `--no-opt s5` (storage + consensus) | 233 | −341 | **~59%** |
| `--no-opt s6` (drop 2nd validate_full, index write-on-change, yield) | 341 | −233 | **~41%** |
| `--no-opt s3s4` (Rust script verification) | 382 | −192 | **~33%** |
| `--no-opt s1` (Rust vertex parser) | 548 | −26 | ~5% |
| `--no-opt s2` (get_transaction read fast-paths) | 568 | −6 | ~1% |

**Ranking: s5 ≫ s6 ≈ s3s4 ≫ s1 > s2.**

> The contributions do **not** sum to the total (they overlap): e.g. s6's "drop the redundant 2nd
> `validate_full`" avoids *re-running* s3s4's script verification, so s3s4 and s6 share credit; s5
> and s6 both act on the consensus/save path. Turning a single section off therefore exposes more
> than its "independent" share.

## s3s4 scales with input count

The Rust script-verification win grows with the number of inputs (each input is one more ECDSA
check moved off the GIL into Rust):

| inputs | full (`--opt`) | s3s4 off | s3s4 contribution |
|---:|---:|---:|---:|
| I=1 | 711 | 532 | **25%** |
| I=6 | 429 | 191 | **55%** |

## What this validates (vs our Phase-1 study)

1. **s5 is the dominant lever** — the consensus/storage layer (mempool-tips incremental update,
   save-dedup, binary metadata, Rust RocksDB) is the single biggest win. This is exactly the
   bottleneck our Phase-1 work independently identified (`mempool_tips.update` being O(tip-count)),
   and matches the PR roadmap's "after verification, the gains moved to consensus/storage."
2. **s6's drop-2nd-`validate_full` is a top win (~41%)** — we predicted in Phase 1 that removing the
   redundant second `validate_full` was the top single-thread lever (~1.3× estimated). Measured here
   it's larger, because that second pass also re-ran script verification (now both skipped *and*
   Rust-accelerated).
3. **s3s4 (Rust scripts) matters and scales with inputs** — modest for 1-input txs, dominant for
   consolidation-style txs (I≥6).
4. **s1/s2 are minor** — parse is a rounding error (~0.78 µs/tx); the read fast-paths are a small
   constant-factor trim.

## Caveats

- Loaded WSL2 machine → run-to-run variance is real (e.g. the `--no-opt s6` runs spanned 329–450).
  Ratios and the ranking are the result; treat absolute TPS as indicative only.
- Small N (300–400) → node-startup/funding overhead and cache warm-up are a larger share than on a
  long production run; the warmup window (W=60–80) is discarded but the steady state is short.
- The s3s4 measurement reflects the **per-tx** Rust script pool only; the PR's batch
  stateless-precompute (sync-path fused pipeline) is intentionally not wired here (it doesn't apply
  to the per-tx driver) and would add further gains on a block-sync workload.
