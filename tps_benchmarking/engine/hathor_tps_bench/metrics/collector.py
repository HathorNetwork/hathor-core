"""RunResult — the bundle a driver run produces, plus light reductions.

Heavy analysis (percentiles, plots, CSV/markdown report) is CP-5; this holds the raw
records + batch resources + samples and a few convenience reductions for the CLI."""
from __future__ import annotations

from dataclasses import dataclass
from statistics import mean

from hathor_tps_bench.config import STAGES
from hathor_tps_bench.metrics.model import BatchResources, Sample, TxRecord


@dataclass
class RunResult:
    records: list[TxRecord]
    batch: BatchResources
    samples: list[Sample]

    @property
    def n(self) -> int:
        return len(self.records)

    @property
    def accepted(self) -> int:
        return sum(1 for r in self.records if r.accepted)

    def stage_mean_wall_us(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for s in STAGES:
            vals = [r.stages[s].wall_ns for r in self.records if s in r.stages]
            out[s] = (mean(vals) / 1000.0) if vals else 0.0
        return out

    def stage_mean_cpu_us(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for s in STAGES:
            vals = [r.stages[s].cpu_ns for r in self.records if s in r.stages]
            out[s] = (mean(vals) / 1000.0) if vals else 0.0
        return out

    def total_mean_wall_us(self) -> float:
        return sum(self.stage_mean_wall_us().values())

    def processing_tps(self) -> float:
        """N / sum(per-tx total wall) == 1 / mean(per-tx total wall)."""
        total_ns = sum(r.total_wall_ns() for r in self.records)
        return (self.n * 1e9 / total_ns) if total_ns else 0.0
