# hathor_tps_bench

In-process benchmark engine for **Hathor full-node transaction processing**. It stands up a real
`HathorManager` in the same Python process, drives valid transactions through the node's own
S1–S6 pipeline, and measures the per-stage timing and resource cost — producing a defensible
processing-TPS plus plots and CSV/JSON.

Design / RFC: `tps_benchmarking/planning/003-prime-rfc-fullnode-tps-benchmark.md`.
Full Phase-1 results: `docs/baseline-results.md`. Headline: **~215 tx/s** single-thread for a 1-in/2-out
tx on an i5-11300H, dominated by *verification run twice* + consensus.

---

## Install (once)

Editable-install the package into the hathor-core poetry env so it resolves from any cwd (and so
editors/Pylance resolve `hathor_tps_bench.*`). Run from the **hathor-core repo root**:

```bash
poetry run pip install -e tps_benchmarking/benchmarks/engine
```

In VS Code, select the poetry interpreter (`Python: Select Interpreter` → the `hathor-…-py3.11` env) so
`hathor` / `hathor_tests` resolve too. All commands below are run from the hathor-core repo root.

---

## Commands

All commands at a glance (prefix each with `poetry run`):

```text
hathor-tps-bench list
hathor-tps-bench validate --config FILE
hathor-tps-bench run    [--config FILE] [--tx-type NAME] [-n K] [-i I] [-o O] [-w W] [--window N] [--seed S]
hathor-tps-bench run    ... --sweep-inputs  MIN MAX        # sweep inputs  (O, N fixed)
hathor-tps-bench run    ... --sweep-outputs MIN MAX        # sweep outputs (I, N fixed)
hathor-tps-bench run    ... --sweep-txs     N [N ...]      # sweep batch size
hathor-tps-bench sweep  --config FILE --axis io|n --values STR [-n K] [-w W]   # back-compat sweep
hathor-tps-bench script NAME [ARGS ...]
hathor-tps-bench --version
```

| Command | What it does |
|---|---|
| `list` | show registered tx types, benchmarks, and scripts |
| `validate --config X.yaml` | load + structurally validate a scenario YAML |
| `run [flags]` | **single run**, or a **sweep** if a `--sweep-*` flag is given |
| `sweep --axis io\|n …` | (back-compat) sweep via the older axis interface |
| `script NAME [args]` | run a bespoke experiment from `scripts/NAME.py` |
| `--version` | print the engine version |

`list` / `validate` import nothing from hathor (fast); `run` / `sweep` / `script` boot a real node.

### `run` flags

`--config` is optional — without it the built-in defaults are used; flags always override the config.

| Flag | Meaning | Default |
|---|---|---|
| `--config FILE` | base scenario YAML | (built-in defaults) |
| `--tx-type NAME` | workload: `1-tip-transparent` \| `defunct` \| `amount-shielded` \| `full-shielded` | `1-tip-transparent` |
| `-n, --num-txs K` | **measured** transactions | 500 |
| `-i, --num-inputs I` | inputs per tx | 1 |
| `-o, --num-outputs O` | outputs per tx | 2 |
| `-w, --warmup W` | warm-up txs (driven then **discarded**, for steady state) | 100 |
| `--window N` | rolling-curve window | adaptive `min(50, max(5, 10%·N))` |
| `--seed S` | RNG seed (reproducible builds) | 1234 |
| `--sweep-inputs MIN MAX` | sweep I over `[MIN..MAX]` (O, N fixed) — fresh node per point | — |
| `--sweep-outputs MIN MAX` | sweep O over `[MIN..MAX]` (I, N fixed) | — |
| `--sweep-txs N [N …]` | sweep batch size over the given list | — |

### Examples

```bash
hathor-tps-bench list

# Single run — pure flags, no config needed:
hathor-tps-bench run -n 2500 -i 7 -o 13            # 2500 txs, 7-in/13-out
hathor-tps-bench run -n 1000 --window 15           # custom rolling-curve window

# Sweeps — add ONE --sweep-* flag; the rest stay fixed (fresh node per point):
hathor-tps-bench run -n 3600 --sweep-inputs 1 10   # I = 1..10  (O=2, N=3600)
hathor-tps-bench run -n 3600 -i 1 --sweep-outputs 2 25
hathor-tps-bench run -i 2 -o 2 --sweep-txs 100 500 2500

# Named scripts (scripts/<name>.py) for bespoke multi-experiment runs:
hathor-tps-bench script demo_experiments all

# Optional config as a base; flags still override it:
hathor-tps-bench run --config tps_benchmarking/benchmarks/engine/scenarios/basic.yaml -n 500
```

---

## Output — where results and plots land

Everything is written under `results/` **inside the engine** (gitignored):
`tps_benchmarking/benchmarks/engine/results/`.

```
results/
  <name>_<txtype>_N<K>_I<I>_O<O>/         # a single run
    per_tx_stages.csv      # one row per measured tx: S1..S6 wall+cpu (µs) + total
    samples.csv            # background time-series: t, tx_done, RSS, FDs, disk I/O
    batch_summary.json     # headline TPS, per-stage stats, M/Tb table, resources
    summary.md             # human-readable summary + embedded plots
    plots/                 # PNGs (see below)
  sweep_<name>_<txtype>_<axis>/           # a sweep (inputs | outputs | txs | io | n)
    summary.md
    plots/
```

**Plots** (`plots/*.png`) are timestamped — `name-DD-MM-YYYY-HHh-MMmin-SSs.png` — so repeated runs
accumulate a history instead of overwriting:

- single run: `rolling_tps` (rolling **mean** faint + **median** bold), `stage_means`, `latency_hist`, `cumulative_cn` (C(N))
- sweep: `sweep_tps` (throughput vs axis), `sweep_stages` (stacked per-stage), `sweep_rolling` (overlaid rolling-median curves)

The CSV/JSON/summary.md are the "latest" view and *do* overwrite per run dir.

---

## The workload DAG

Each batch is mined + assembled with hathor-core's `DAGBuilder`. Two edge types connect it:
`═══▶` = **spend** (an input, consumes a UTXO); `──▶` = **parent** (confirms a vertex).

```text
 (1) BLOCKS — mined off genesis for coinbase value
       genesis ──▶ b1 ──▶ b2 ──▶ ··· ──▶ bn          (bi.out[0] = a coinbase reward)

 (2) FUNDS — consolidate coinbases, fan value into small UTXOs, CHAINED by change
       b1.out[0] ═╗
       b2.out[0] ═╬═══▶ fund0 ══change══▶ fund1 ══change══▶ ··· ══change══▶ fundM
          ···    ═╝       (each fund mints up to 200 pinned UTXOs of value `per`)

 (3) PAYLOAD — each txk spends its OWN disjoint UTXOs (inputs) and PARENTS the previous tx
                          fundF.out[k] ═══spend═══▶ txk
       genesis ◀── tx0 ◀── tx1 ◀── tx2 ◀── ··· ◀── tx(N-1)       ◀═══ the ONLY tip
                 each tx confirms its predecessor  ⇒  tips ≈ 1  ⇒  S5 is O(1), flat
```

The **parent-chaining in (3) is the key correctness fix**: the `1-tip-transparent` workload chains
transactions so only the latest is a tip. The alternative `defunct` workload parents every tx to genesis →
all N are tips → consensus (`mempool_tips.update`) is O(tips) = O(N) → the batch costs **O(N²)** (kept on
purpose to demonstrate the pathology — hence "defunct", not for real measurement).

---

## Caveats

- **Single machine — scale the numbers.** Figures are single-thread on an i5-11300H. Processing is
  single-thread CPU-bound, so re-scale by single-thread CPU performance (e.g. PassMark *Single Thread
  Rating*, cpubenchmark.net): `TPS_target ≈ TPS_here × score_target / score_i5-11300H`. Extra cores don't
  help the serial pipeline (Amdahl ceiling ~2× even if verification is parallelized).
- **Linear (single-tip) DAG.** `1-tip-transparent` keeps ≈ 1 tip; mainnet runs ~2–3 tips. Enough to remove
  the O(N²) artifact and measure steady cost, but not a perfect mainnet topology (room for `k-tip-transparent`).
- **No mainnet sync.** A fresh temp DB → RSS ≈ 100 MB. A synced node holds GBs (cache/UTXO/indexes), so
  this does **not** reveal the real RAM ceiling (~2–4–6 GB) or large-DB cache-miss penalties.
- **Time volatility.** WSL2 load + background RocksDB compaction inject run-to-run variance (~160–270
  tx/s); ~0.5% of txs are **write-stall spikes** in S5 — handled by the rolling **median** (the spiky mean
  is kept faint for reference).
- **Weight-1 PoW.** Trivial PoW speeds *batch setup* only; verification cost is weight-independent, so it
  doesn't inflate the result.
- **Double `validate_full`.** Verification runs twice (S3S4 + S6) — real per-tx cost here, and the top
  optimization target.
- **Funding scale.** The funding caps near ~253 fund txs (≈ 50k UTXOs, i.e. `(K+W)·I ≲ 50k`); beyond
  that, serialization byte-fields overflow. Keep `(K+W)·I` under ~50k.

---

## Layout

| Path | Purpose | CP |
|------|---------|----|
| `config.py` | scenario config (dataclasses + YAML) + `rolling_window` | CP-2/5 |
| `cli.py` | `list` / `validate` / `run` / `sweep` / `script` | CP-2→6 |
| `node/harness.py` | in-process `HathorManager` harness | CP-3 |
| `workload/{base,registry,transparent,shielded}.py` | `TxSource` registry + `defunct` / `1-tip-transparent` / shielded sources | CP-3/4/9 |
| `driver/runner.py` | replays S1–S6 with per-stage timing + warm-up | CP-4/5 |
| `probes/{procstats,sampler,storage_stats}.py` | `/proc` readers, time-series sampler, flush | CP-4 |
| `metrics/{model,collector}.py` | per-tx/batch records + reductions | CP-2/4 |
| `analysis/{compute,persist,plots,report,sweep}.py` | stats, CSV/JSON, plots, summary.md, sweeps | CP-5/6 |
| `scenarios/*.yaml` | example configs (`basic` = 1-tip-transparent, `defunct`) | CP-3 |
| `scripts/*.py` | bespoke experiment scripts (run via `script`) | CP-6 |
| `docs/baseline-results.md` | headline TPS + full analysis | CP-6 |
| `spikes/spike_cp*.py` | de-risk / diagnostic spikes (throwaway) | CP-1/4 |
