"""Single-thread driver: replays the node's S1..S6 processing with per-stage timing.
Imports hathor — import lazily (e.g. inside the CLI `run` handler)."""
from hathor_tps_bench.driver.runner import run_batch

__all__ = ["run_batch"]
