# hathor_tps_bench

In-process benchmark engine for Hathor full-node transaction processing.
Design: `tps_benchmarking/planning/003-prime-rfc-fullnode-tps-benchmark.md`.

## Install (once)

Editable-install the package into the hathor-core poetry env so it resolves from any cwd
(and so editors/Pylance can resolve `hathor_tps_bench.*`). Run from the hathor-core repo root:

```bash
poetry run pip install -e tps_benchmarking/benchmarks/engine
```

In VS Code, also select the poetry interpreter
(`Python: Select Interpreter` → the `hathor-...-py3.11` env) so `hathor` / `hathor_tests`
resolve too.

## Running

Everything is flag-driven; `--config` is optional (built-in defaults otherwise). `list` / `validate`
stay hathor-free (fast); `run` / `script` boot a real in-process node. Run from the hathor-core repo root:

```bash
poetry run hathor-tps-bench list                    # tx types · benchmarks · scripts

# Single run — pure flags, no config needed. -n txs · -i inputs · -o outputs · -w warm-up.
poetry run hathor-tps-bench run -n 2500 -i 7 -o 13              # 2500 txs, 7-in/13-out
poetry run hathor-tps-bench run -n 1000 --window 15            # set the rolling-curve window

# Sweeps — add ONE --sweep-* flag; others stay fixed. Fresh node per point.
poetry run hathor-tps-bench run -n 3600 --sweep-inputs 1 10     # I = 1..10  (O, N fixed)
poetry run hathor-tps-bench run -n 3600 --sweep-outputs 2 25    # O = 2..25
poetry run hathor-tps-bench run -i 2 -o 2 --sweep-txs 100 500 2500

# Named scripts (scripts/<name>.py) for bespoke experiments:
poetry run hathor-tps-bench script demo_experiments all

# Optional config as a base; flags still override it:
poetry run hathor-tps-bench run --config .../scenarios/organic.yaml -n 500
```

Each run writes `results/<run>/` (gitignored): `per_tx_stages.csv`, `samples.csv`, `batch_summary.json`,
`summary.md`, and plots (rolling mean+**median** TPS, per-stage, latency histogram, C(N); sweeps add
overlaid rolling-median curves + throughput-vs-axis). Two tx types: **`organic`** (default —
tip-confirming chain, realistic) and **`transparent`** (genesis-parented, kept to show the O(N²)
tip-explosion). Future tx types register in the workload registry → `--tx-type <name>`.

## Results

**~215 tx/s** single-thread for a 1-in/2-out tx on an i5-11300H (warmed steady state), dominated by
*verification run twice* and consensus. Full analysis — N-scaling, the I/O sweep, the M/Tb table, and
hardware scaling — in **`docs/baseline-results.md`**.

## Layout (built incrementally)

| Path | Purpose | Checkpoint |
|------|---------|-----------|
| `config.py` | scenario config (dataclasses + YAML) | CP-2 |
| `metrics/model.py` | per-tx / per-batch record dataclasses | CP-2 |
| `workload/registry.py` | `TxSource` registry (tx-type plugins) | CP-2 |
| `benchmarks/registry.py` | `Benchmark` registry (approach plugins) | CP-2 |
| `cli.py` | `list` / `validate` / `run` | CP-2 |
| `node/` | in-process `HathorManager` harness | CP-3 |
| `workload/transparent.py` | DAGBuilder transparent I-in/O-out source | CP-3 |
| `workload/transparent.py` | also `OrganicTxSource` (tip-confirming chain) | CP-4 |
| `probes/`, `driver/` | per-stage timing, sampler, single-thread loop, warm-up | CP-4/5 |
| `analysis/compute,persist,plots,report` | stats, CSV/JSON, plots, summary.md | CP-5 |
| `analysis/sweep.py` | I/O- and N-sweep orchestration | CP-6 |
| `docs/baseline-results.md` | the headline TPS + full analysis | CP-6 |
| `spikes/spike_cp*.py` | de-risk spikes (throwaway) | CP-1/4 |
