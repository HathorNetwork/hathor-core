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

`list` / `validate` import nothing from `hathor` (fast); `run` boots a real in-process node.
After the install above you can use the console script or `-m`, from anywhere:

```bash
poetry run hathor-tps-bench list
poetry run hathor-tps-bench validate --config tps_benchmarking/benchmarks/engine/scenarios/basic.yaml
poetry run hathor-tps-bench run --config tps_benchmarking/benchmarks/engine/scenarios/basic.yaml --num-txs 100
# (equivalently: poetry run python -m hathor_tps_bench ...)
```

`run` currently builds the workload on a real node and reports it; per-stage timing + reports land in CP-4/CP-5.

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
| `probes/`, `driver/` | per-stage timing, sampler, single-thread loop | CP-4 |
| `analysis/` | compute, plots, CSV/markdown report | CP-5 |
| `spikes/spike_cp1.py` | CP-1 de-risk spike (throwaway) | CP-1 |
