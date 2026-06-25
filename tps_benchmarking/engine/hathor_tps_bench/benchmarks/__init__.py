"""Benchmark approaches. The `Benchmark` registry lives here; concrete benchmarks
(stage-latency, fullnode-ingestion, single-wallet-e2e) are added in CP-4+."""
from hathor_tps_bench.benchmarks.registry import (
    BENCHMARK_REGISTRY,
    get_benchmark,
    list_benchmarks,
    register_benchmark,
)

__all__ = ["BENCHMARK_REGISTRY", "register_benchmark", "get_benchmark", "list_benchmarks"]
