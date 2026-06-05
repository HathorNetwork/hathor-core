"""Sweep orchestration — run the engine across a parameter axis (tx shape I/O, or batch
size N), ONE FRESH node per point so storage/mempool never carries over between points,
and collect a headline + per-stage means for each. Imports hathor lazily (inside the run)
so `list`/`validate` stay light."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SweepPoint:
    label: str
    num_inputs: int
    num_outputs: int
    num_txs: int          # K measured
    accepted: int
    tps: float
    mean_total_us: float
    stage_means_us: dict   # {S1..S6: µs}


def _run_one(cfg, tx_type: str, num_inputs: int, num_outputs: int, K: int, W: int):
    """Build a fresh funded node, drive W+K (measure K), return (SweepPoint, RunResult)."""
    from hathor_tps_bench.analysis import compute
    from hathor_tps_bench.driver import run_batch
    from hathor_tps_bench.node import NodeHarness
    from hathor_tps_bench.workload import get_txtype

    source = get_txtype(tx_type)()
    harness = NodeHarness(seed=cfg.env.seed, trivial_pow=cfg.env.trivial_pow).start()
    try:
        prepared = source.build(harness, W + K, num_inputs, num_outputs)
        result = run_batch(harness, prepared,
                           sampler_interval_s=cfg.measure.sampler_interval_s, warmup=W)
    finally:
        harness.stop()

    head = compute.headline(result, tdp_watts=cfg.measure.tdp_watts, cpu_util=cfg.measure.cpu_util)
    means = {r["stage"]: r["mean_wall_us"] for r in compute.stage_table(result)}
    point = SweepPoint(
        label=f"I{num_inputs}O{num_outputs}",
        num_inputs=num_inputs, num_outputs=num_outputs, num_txs=K,
        accepted=head["accepted"], tps=head["processing_tps"],
        mean_total_us=head["mean_total_us"], stage_means_us=means,
    )
    return point, result


def io_sweep(cfg, tx_type, shapes: list[tuple[int, int]], K: int, W: int,
             *, on_point=None) -> list[SweepPoint]:
    """shapes = [(I, O), ...] — one fresh run each."""
    points: list[SweepPoint] = []
    for num_inputs, num_outputs in shapes:
        pt, _ = _run_one(cfg, tx_type, num_inputs, num_outputs, K, W)
        points.append(pt)
        if on_point:
            on_point(pt)
    return points


def n_sweep(cfg, tx_type, ns: list[int], num_inputs: int, num_outputs: int, W: int,
            *, on_point=None) -> list[SweepPoint]:
    """ns = [K, ...] — one fresh run each, varying the measured batch size."""
    points: list[SweepPoint] = []
    for K in ns:
        pt, _ = _run_one(cfg, tx_type, num_inputs, num_outputs, K, W)
        pt.label = f"N{K}"
        points.append(pt)
        if on_point:
            on_point(pt)
    return points
