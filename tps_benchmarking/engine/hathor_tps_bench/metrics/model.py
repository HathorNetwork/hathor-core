"""The metrics data model.

Three views, matching the RFC's measurement scheme:
  - per-tx, per-stage TIME           -> TxRecord.stages (authoritative)
  - per-batch memory / I-O / FDs      -> BatchResources (authoritative)
  - background time-series            -> Sample (for over-time / vs-N charts)
RunSummary is the reduced, reportable result (filled by analysis in CP-5).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from hathor_tps_bench.config import STAGES


@dataclass
class StageTiming:
    """Cost of one pipeline stage for one transaction."""
    wall_ns: int = 0   # time.perf_counter_ns delta
    cpu_ns: int = 0    # time.process_time_ns delta


@dataclass
class TxRecord:
    """Per-transaction record. `stages` maps a stage key (see config.STAGES) to its timing."""
    index: int
    tx_id: str
    n_inputs: int
    n_outputs: int
    size_bytes: int
    accepted: bool = False
    error: str | None = None
    stages: dict[str, StageTiming] = field(default_factory=dict)

    def total_wall_ns(self) -> int:
        return sum(s.wall_ns for s in self.stages.values())

    def total_cpu_ns(self) -> int:
        return sum(s.cpu_ns for s in self.stages.values())


@dataclass
class Sample:
    """One background time-series sample (read from /proc)."""
    t_rel_s: float        # seconds since batch start
    tx_done: int          # how many txs processed by this instant
    rss_bytes: int      # shouldn't it be bytes here??
    num_fds: int
    io_read_bytes: int    # cumulative since process start
    io_write_bytes: int


@dataclass
class BatchResources:
    """Authoritative per-batch resource figures (totals + peaks)."""
    wall_s: float = 0.0
    cpu_s: float = 0.0
    io_read_bytes: int = 0      # delta across the batch
    io_write_bytes: int = 0     # delta across the batch (after flush)
    rss_start_bytes: int = 0
    rss_peak_bytes: int = 0
    rss_end_bytes: int = 0
    fd_peak: int = 0
    sst_bytes: int = 0          # rocksdb total_sst_files_size after flush

    @property
    def rss_growth_bytes(self) -> int:
        return self.rss_end_bytes - self.rss_start_bytes

    def energy_joules(self, tdp_watts: float, cpu_util: float) -> float:
        """Analytical node energy estimate (RFC: CPU_s * TDP * util)."""
        return self.cpu_s * tdp_watts * cpu_util


@dataclass
class RunSummary:
    """Reduced, reportable result for one run (one batch). Latency fields in microseconds."""
    name: str
    benchmark: str
    txtype: str
    num_txs: int
    num_inputs: int
    num_outputs: int
    # counts
    submitted: int = 0
    accepted: int = 0
    rejected: int = 0
    # throughput
    processing_tps: float = 0.0          # N / sum(per-tx total wall)
    processing_tps_inv_mean: float = 0.0  # 1 / mean(per-tx total wall)
    # per-stage mean wall (us) — keyed by stage
    stage_mean_us: dict[str, float] = field(default_factory=dict)
    # overall latency percentiles (us)
    lat_p50_us: float = 0.0
    lat_p90_us: float = 0.0
    lat_p99_us: float = 0.0
    # resources
    rss_peak_mb: float = 0.0
    rss_growth_mb: float = 0.0
    disk_write_mb: float = 0.0
    disk_read_mb: float = 0.0
    fd_peak: int = 0
    energy_j: float = 0.0
    # provenance
    seed: int = 0
    config_name: str = ""

    @property
    def stages(self) -> tuple[str, ...]:
        return STAGES
