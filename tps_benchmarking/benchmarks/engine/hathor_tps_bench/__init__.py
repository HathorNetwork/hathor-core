"""hathor_tps_bench — in-process benchmark engine for Hathor full-node tx processing.

See the RFC: tps_benchmarking/planning/003-prime-rfc-fullnode-tps-benchmark.md

Package layout (built incrementally across checkpoints):
  config.py        — run configuration (dataclasses + YAML loader)        [CP-2]
  metrics/model.py — per-tx / per-batch record dataclasses                [CP-2]
  workload/        — TxSource registry (+ transparent DAGBuilder source)  [CP-2 reg / CP-3 impl]
  benchmarks/      — Benchmark registry (+ stage-latency etc.)            [CP-2 reg / CP-4 impl]
  node/            — in-process HathorManager harness                      [CP-3]
  probes/          — per-stage timing, sampler, storage stats             [CP-4]
  driver/          — single-thread S1..S6 loop                            [CP-4]
  analysis/        — compute, plots, report                               [CP-5]
  cli.py           — `python -m hathor_tps_bench` (run / list / validate) [CP-2]
"""

__version__ = "0.0.1"
