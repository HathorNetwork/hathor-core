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

`list` / `validate` import nothing from `hathor` (fast); `run` / `sweep` boot a real in-process node.
After the install above you can use the console script or `-m`, from anywhere (the hathor-core repo root):

```bash
poetry run hathor-tps-bench list
poetry run hathor-tps-bench validate --config tps_benchmarking/benchmarks/engine/scenarios/organic.yaml

# One measured run: K txs (+W warm-up, discarded). Writes results/<run>/ with
# per_tx_stages.csv, samples.csv, batch_summary.json, summary.md, and 4 plots.
poetry run hathor-tps-bench run --config .../scenarios/organic.yaml --num-txs 500 --warmup 100

# Sweeps (fresh node per point):
poetry run hathor-tps-bench sweep --config .../scenarios/organic.yaml --axis io           # tx shape I:O
poetry run hathor-tps-bench sweep --config .../scenarios/organic.yaml --axis n \
    --values 50,100,500,1000,5000                                                          # batch size
```

Two tx types: **`organic`** (tip-confirming chain, the realistic/representative workload) and
**`transparent`** (genesis-parented — kept to demonstrate the O(N²) tip-explosion pathology).

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
