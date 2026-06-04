# hathor_tps_bench

In-process benchmark engine for Hathor full-node transaction processing.
Design: `tps_benchmarking/planning/003-prime-rfc-fullnode-tps-benchmark.md`.

## Running

The package imports nothing from `hathor` for `list`/`validate` (scaffold only); the
node harness and driver arrive in CP-3/CP-4. Run from this `engine/` directory so the
package is importable:

```bash
cd tps_benchmarking/benchmarks/engine
poetry run python -m hathor_tps_bench list
poetry run python -m hathor_tps_bench validate --config scenarios/basic.yaml
poetry run python -m hathor_tps_bench run --config scenarios/basic.yaml   # stub until CP-4/CP-5
```

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
