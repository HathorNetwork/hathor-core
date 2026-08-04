"""Persist a RunResult to disk — per-tx stages CSV, time-series samples CSV, and a
machine-readable summary JSON. Stdlib `csv`/`json` only (no pandas)."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from hathor_tps_bench.config import STAGES
from hathor_tps_bench.metrics.collector import RunResult


def write_per_tx_csv(path: Path, result: RunResult) -> None:
    """One row per measured tx: identity, I/O, accepted, each stage's wall+cpu, total."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            ["index", "tx_id", "n_inputs", "n_outputs", "size_bytes", "accepted"]
            + [f"{s}_wall_us" for s in STAGES]
            + [f"{s}_cpu_us" for s in STAGES]
            + ["total_wall_us"]
        )
        for r in result.records:
            w.writerow(
                [r.index, r.tx_id, r.n_inputs, r.n_outputs, r.size_bytes, int(r.accepted)]
                + [f"{r.stages[s].wall_ns / 1000:.3f}" if s in r.stages else "" for s in STAGES]
                + [f"{r.stages[s].cpu_ns / 1000:.3f}" if s in r.stages else "" for s in STAGES]
                + [f"{r.total_wall_ns() / 1000:.3f}"]
            )


def write_samples_csv(path: Path, result: RunResult) -> None:
    """The background /proc time-series (one row per sample)."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["t_rel_s", "tx_done", "rss_bytes", "num_fds", "io_read_bytes", "io_write_bytes"])
        for s in result.samples:
            w.writerow([f"{s.t_rel_s:.4f}", s.tx_done, s.rss_bytes, s.num_fds,
                        s.io_read_bytes, s.io_write_bytes])


def write_summary_json(path: Path, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
