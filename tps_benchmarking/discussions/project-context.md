# TPS Benchmark — project context & findings (agentic memo)

> Self-note for resuming after /compact. Dense on purpose. Paths are absolute-ish from repo root
> `~/hathor-projects/p6_tps_benchmark/hathor-core/`. Updated 2026-06-05.

## 0. What this project is
Building an **in-process benchmark engine** that measures how fast ONE Hathor full node can *process*
incoming transactions (deserialize → verify → save → consensus), per-stage, to get a defensible
processing-TPS. NOT wallet emission, NOT network. Design = the RFC (see §6).

## 1. How the engine works (the load-bearing facts)
- Lives at `tps_benchmarking/benchmarks/engine/`, package `hathor_tps_bench`, **editable-installed**
  into the hathor poetry venv. Run: `poetry run hathor-tps-bench {list,validate,run} ...`
  (or `python -m hathor_tps_bench`). `run --config scenarios/basic.yaml --num-txs N`.
- Runs a REAL `HathorManager` in-process on the **unittests** network + `TEST_ALL_WEIGHT` (weight=1
  → trivial PoW, but **REAL verifiers**) + RocksDB temp-dir. Must set `HATHOR_CONFIG_YAML` to
  unittests + `initialize_global_reactor()` BEFORE importing hathor_tests. `NodeHarness` wraps all this
  (`node/harness.py`).
- **Driver** (`driver/runner.py`) replays `VertexHandler._old_on_new_vertex` by hand, timing each
  stage (perf_counter_ns wall + process_time_ns cpu):
  - **S1** `vertex_parser.deserialize(raw)`
  - **S2** manager pre-checks (exists/double-spend/voided/reward-lock)
  - **S3S4** `vh._validate_vertex(vtx, params)`  (full verification)
  - **S5** `vh._unsafe_save_and_run_consensus(vtx)`  (= update_initial_metadata + save + consensus.unsafe_update)
  - **S6** `vh._post_consensus(vtx, params, events, quiet=True)`
  - `build_params(manager)` reconstructs `VerificationParams` (best_block is fixed during a batch → build once).
- **Workload** (`workload/transparent.py`, `@register_txtype("transparent")`): builds N independent
  txs via DAGBuilder fund-consolidation recipe (see §3). Preloads funding via `on_new_relayed_vertex`,
  returns `PreparedTx(tx, raw, n_inputs, n_outputs)`. The driver does NOT use the public `on_new_tx`.
- **Probes**: `probes/procstats.py` (/proc readers: VmRSS, VmHWM, FDs, io read/write_bytes — no psutil),
  `probes/sampler.py` (`ProcSampler` background thread = time-series), `probes/storage_stats.py`
  (`flush()` realises deferred RocksDB writes; SST size = 0 stub).
- **Metrics**: `metrics/model.py` (StageTiming, TxRecord, Sample, BatchResources, RunSummary),
  `metrics/collector.py` (`RunResult` + reductions: stage means, `processing_tps = N/Σ per-tx total`).
- TPS = `N / Σ(per-tx total wall)` = `1/mean` — serial single-thread, NOT 1/slowest-stage (no pipelining).
- wall ≈ cpu everywhere → CPU-bound, no I/O wait (deferred writes + frozen test clock).

## 2. ⚠️ THE BIG FINDING (consensus blow-up) — verified in code + measured
Per-stage (N=200): S1 ~137µs, S2 ~60µs, S3S4 ~1010µs (**flat in N**, ∝ inputs I), **S5 ~5030µs (60%,
grows ~linearly with N)**, S6 ~2040µs (mostly ∝I + smaller N-growth).
- **S5's entire cost is `consensus.unsafe_update` → dominated by `mempool_tips.update`**
  (`hathor/indexes/mempool_tips_index.py:133`), which **iterates EVERY current tip** on every call
  (`for tip_tx in self.iter(tx_storage)`) → **O(tip count)**. (RocksDB variant calls `super().update()`,
  so it scans too.) Diagnostic: meta/save sub-steps FLAT (~50µs); cons = 1.8ms→11.8ms→125ms; txs_affected
  const=5; 0 voided.
- A **"tip" = mempool tx with no tx-children**. DAGBuilder's filler (`fill_parents` uses `genesis_1/2`,
  NEVER user txs — CP-1 §3) parents EVERY tx to **genesis** → no tx has children → **ALL N txs are tips
  → tip count = N** → S5 = O(N) per tx → **O(N²) batch → perceived TPS falls as N grows** (243→121 tx/s
  from N=50→200). Measured: 250 txs → 251 tips.
- **Blocks can't fix it in this workload.** A block confirms only txs in its *past* (ancestors via
  PARENT edges; `block_consensus.update_score_and_mark_as_the_best_chain`). It names 2 tips as parents;
  in the flat genesis-fan those reach only those 2 (+genesis) → block confirmed **2/250** (measured).
  Mempool stays huge → O(tips) stays huge.
- **The ~10× post-block jump is a COLD-CACHE ARTIFACT, not consensus cost** (root-caused 2026-06-05):
  read COUNT ~unchanged at the block (1250→1340/tx) but read TIME ~10× (≈5µs warm → ≈90µs cold). A bare
  `tx_storage.flush()` does NOT reproduce it (1.0×) — so it's not the flush/SST; it's the block's
  *processing* evicting the in-memory tx-object LRU cache, so the O(tips) scan then RocksDB-reads +
  deserializes each tip cold. It only exists BECAUSE tips=N forces ~250 reads/tx. NOT real Hathor
  behaviour. Organic workload (tips ~2-3) eliminates O(N²) AND the cache cliff together.
- **⇒ Earlier "S5 grows with M" is a real but UNREPRESENTATIVE artifact of the tip explosion.**

## 3b. OPTION A — BUILT & VALIDATED (2026-06-05) ✓
Added `@register_txtype("organic") OrganicTxSource(TransparentTxSource)` in `workload/transparent.py`
(refactored a `_frontier_lines(t, name, tx_anchor)` hook; base = genesis-parented `[b{anchor} < name]`,
organic adds `tx{t} --> tx{t-1}` for t>=1 → linear chain, 1 tip). Funding/inputs/outputs UNCHANGED.
New `scenarios/organic.yaml`; `spike_cp4_diag.py` now takes argv `[tx_type] [M]`.
RESULTS (M=250): tips=2 (vs 251); **a single block confirms 250/250, mempool→0** (vs 2/250); **cons FLAT
1.5-1.9ms across N and across the block** (vs transparent 1.8→11.8→125ms); exact I/O 500/500; 0 voided.
TPS-vs-N: transparent 169/65/36 (N=100/500/1000, COLLAPSES) vs organic 162/220/205 (STABLE ~210-236).
Organic N=500 per-stage: S1 131µs(3%) S2 57µs(1%) S3S4 1007µs(24%) S5 1856µs(44%,flat) S6 1193µs(28%)
→ 236 tx/s. So consensus/post DO outweigh verify (real finding); only the *growth with N* was the artifact.
Watch: low-N warmup (N=100 slower → discard warmup prefix for τ₀); possible mild residual growth
(N=500→1000) = maybe the permanent S6/non-critical-index component — CP-5 C(N) curve will confirm.
Next after this: (optionally) a more representative k-tip-frontier DAG; then CP-4 checkpoint; then CP-5.

## 3. The fix = OPTION A (organic workload) — DONE (linear 1-tip); see §3b for results
Make each `tx_i` confirm **2 RECENT tips** as parents (not genesis). Then those tips gain a child → drop
out of the tip set → **tip count stays bounded (~2-3), not N** → `mempool_tips.update` O(1) → S5 flat →
no quadratic → and blocks can SWEEP the connected DAG (`b → tx_N → tx_{N-1} → ... → genesis`).
Two routes: **A = build-time DAG** (emit DSL parent edges `tx_i --> tx_{i-1} tx_{i-2}`; do this first) ;
B = drive-time tips (`get_new_tx_parents`, re-resolve PoW; higher fidelity, later).
Current (genesis) workload recipe to keep/generalise: a `fund` tx eats a coinbase (=6400) and emits ≤255
pinned UTXOs (FUND_CHUNK=200 for the 255 output-count cap); each tx spends disjoint UTXOs + emits pinned
outputs (both sides balanced → DAGBuilder filler adds nothing → exact I/O). Order auto-`dummy` past
reward lock (`b{lock} < dummy`).

## 4. The M/Tb throughput model (now in the RFC; status = HYPOTHESIS)
A single batch TPS is meaningless (mempool grows → S5 inflates → TPS falls). Two numbers:
clean-slate ceiling `1/τ₀` (optimistic) vs **sustainable `M/Tb`** where `C(M)=Tb` (cumulative processing
time fills the block interval). Geometric: `perceived_TPS(N)=N/C(N)` crossed with line **slope 1/Tb**
(not 1) → `(M, M/Tb)`. Faster blocks (smaller Tb) ⇒ higher sustainable TPS. Illustrative: clean-slate
~368 tx/s but sustainable ~33 tx/s @ Tb=30s. **NOT VALIDATED** — confounded by §2; deeper truth is the
tip structure (organic bounds tips regardless of blocks). Captured in RFC §"Throughput is bounded by
block cadence". Also: S6 has a PERMANENT, non-block-resettable component (non-critical indexes grow with
total storage) — should split S6 reporting into re-verify vs index.

## 5. Checkpoint / build state
COMMITTED (branch `tool/tps-benchmarking`): CP-1/2/3 at `5dc5a40e` (+ plans at `386ef18c`); **CP-4 at
`b70ed4c4`** ("add(tps): probes, tx-dag flow, spikes" — probes, driver, organic workload, spikes, CP-4
checkpoint doc, RFC M/Tb edits). **CP-5 is the ONLY uncommitted work** (`analysis/`, warm-up in
config/driver, cli reporting, pyproject matplotlib dep, scenario yamls, `.gitignore`, CP-5 checkpoint
doc). NOTE for future checkpoint diffs: base CP-N's diff on the CP-(N-1) COMMIT (not 5dc5a40e); the user
commits each checkpoint themselves. CP-5 doc's diff is correctly vs `b70ed4c4`.
Checkpoint docs: `tps_benchmarking/checkpoint-diffs/CP-{1,2,3}-*.md` (+ OneDrive `pr6-lifecycle`-sibling
`benchmark-checkpoints/` as md + colored PDF). Tasks: #1-5 done, #6 analysis/reporting (CP-5), #7
baseline run (CP-6) pending.
Throwaway de-risk spikes in `engine/spikes/`: spike_cp1, spike_cp3_batch, spike_cp4_stages,
spike_cp4_reset, spike_cp4_diag.

## 6. Conventions (IMPORTANT — follow these)
- **Workflow per checkpoint**: code → SHOW diff in chat → ASK before writing checkpoint markdown →
  on yes, write `checkpoint-diffs/CP-N-*.md` (full A→B diff + summary + comprehensive file-by-file +
  reasoning discourse) AND colored-diff PDF + md to OneDrive `benchmark-checkpoints/`. Folder name is
  `checkpoint-diffs` (hyphen). Ask EVERY time before a checkpoint markdown.
- **RFC source of truth**: `tps_benchmarking/planning/003-prime-rfc-fullnode-tps-benchmark.md`. Edit it
  first, then sync 2 mirrors: `planning/rfc-fullnode-tps-benchmark.md` and
  `~/hathor-projects/p6_tps_benchmark/rfc_tps/internal-rfcs/projects/tps-benchmarking/xxxx-tps-benchmarking.md`,
  + regen OneDrive PDF `pr6-lifecycle/003-prime-...pdf`. RFC follows Hathor internal-rfcs template;
  Author line still `<fill in your name>`.
- **PDF render**: `/tmp/md2pdf.py` (markdown + weasyprint + pygments codehilite; ```diff colored
  green/red). It gets cleared from /tmp — RECREATE it (recipe is in git history / prior turns). Render
  to /tmp then `cp` to OneDrive (PDFs lock if open in a viewer → write `-NEW.pdf` fallback). OneDrive
  Desktop = `/mnt/c/Users/luisf/OneDrive/Área de Trabalho/`.
- **Commits**: the USER commits (one bundle, themselves). I only `git add`/prepare on request. Branch
  `tool/tps-benchmarking`. End my own commit msgs with the Claude co-author trailer only if I commit.
- VS Code: select interpreter `~/.cache/pypoetry/virtualenvs/hathor-4nrGODYv-py3.11/bin/python`.

## 7. Immediate next actions
1. CP-1..**CP-5 DONE** (see §3b, §8). CP-5 = `analysis/` pkg (compute/persist/plots/report) + warm-up
   (config `warmup_txs` W, build W+K, drive W discarded, measure K) + CLI writes results/<run>/
   (per_tx_stages.csv, samples.csv, batch_summary.json, summary.md, 4 plots: rolling_tps, stage_means,
   latency_hist, cumulative_cn). matplotlib added as engine dep; results gitignored under engine.
   Checkpoint markdown `checkpoint-diffs/CP-5-analysis-reporting-and-warmup.md` (+15pp PDF in OneDrive).
   Validated: organic K=500/W=100 → 215 tx/s; per_tx CSV = K rows.
2. **CP-6 DONE → PHASE 1 COMPLETE.** Added `analysis/sweep.py` + `sweep` CLI (io|n, fresh node/point),
   `compute.mtb_table`+`scale_to_specs` (M/Tb in run json), `plots.sweep_plots`, `docs/baseline-results.md`.
   HEADLINE ~215 tx/s (i5-11300H, 1in/2out, band 160-270). Findings: N-cost bounded to 10k (no creep);
   inputs dominate ~base+2.6ms·(I-1), outputs free; M/Tb flat/Tb-indep; CPU single-thread is the lever
   (cores ~2× Amdahl ceiling; RAM=cache knob ~2-4GB). Top opt = drop redundant 2nd validate_full (~1.3×).
   CP-5+CP-6 UNCOMMITTED (user commits). NEXT: run examples + extract plots + build a report (usage phase).

## 8. CP-5/CP-6 DESIGN DECISIONS & REMINDERS (locked with user 2026-06-05)
- **Warm-up**: add a configurable `warmup_txs` (W, ~100). Drive W txs and DISCARD their records, then
  drive+measure the K real txs. This removes the cold-start transient (cold RocksDB cache + interpreter
  warm-up; seen as N=100 organic 162 < N=500 220 tx/s). **Do NOT inject a block before the measured txs**:
  in organic tips are already ~1 so a block resets nothing, and a block EVICTS the tx LRU cache → would
  reintroduce a cold transient (the very cliff we diagnosed). Block-cadence (for M/Tb realism) is a
  SEPARATE feature, not warm-up.
- **Per-tx curve**: we already collect per-tx S1-S6 TxRecords → CP-5 must plot per-tx time / rolling-TPS
  vs tx-index (the transient→steady-state curve). This also sizes W empirically (watch where it flattens).
- **REMINDER (baselines/CP-6)**: run the sweeps — I/O = {(1:2),(2:2),(3:2),...,(k:2)} then
  {(1:2),(1:3),...} (vary inputs, then outputs); N_txs = {10,20,...,10000}.
- **REMINDER (baselines/CP-6)**: SCALE this machine's measured numbers to a typical Hathor full-node's
  **recommended** specs AND **bare-minimum** specs (find Hathor's published node hardware requirements;
  scale CPU single-thread perf / RAM / disk accordingly to project the node's real-world TPS ceiling).
