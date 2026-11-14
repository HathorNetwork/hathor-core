"""Reductions over a RunResult — percentiles, per-stage table, the transient->steady
rolling-TPS series, the cumulative C(N) curve, and the headline figures. Stdlib only."""
from __future__ import annotations

from statistics import mean, median

from hathor_tps_bench.config import STAGES
from hathor_tps_bench.metrics.collector import RunResult

_MB = 1024 * 1024


def rolling_window(n: int) -> int:
    """Window for rolling curves: 50 by default, but for small batches (N<=500) use 10%
    of N, never below 5. min(50, max(5, round(0.1*N))) satisfies all three at once."""
    return min(50, max(5, round(0.10 * n)))


def _pct(sorted_vals: list[float], p: float) -> float:
    """Nearest-rank percentile of an already-sorted list."""
    if not sorted_vals:
        return 0.0
    k = int(round((p / 100.0) * (len(sorted_vals) - 1)))
    return sorted_vals[max(0, min(len(sorted_vals) - 1, k))]


def per_tx_totals_us(result: RunResult) -> list[float]:
    return [r.total_wall_ns() / 1000.0 for r in result.records]


def stage_table(result: RunResult) -> list[dict]:
    """Per-stage mean/p50/p90/p99 wall (µs), mean cpu, and share of the per-tx total."""
    total_mean = result.total_mean_wall_us()
    rows: list[dict] = []
    for s in STAGES:
        wall = sorted(r.stages[s].wall_ns / 1000.0 for r in result.records if s in r.stages)
        cpu = [r.stages[s].cpu_ns / 1000.0 for r in result.records if s in r.stages]
        m = mean(wall) if wall else 0.0
        rows.append({
            "stage": s,
            "mean_wall_us": m,
            "mean_cpu_us": mean(cpu) if cpu else 0.0,
            "p50_us": _pct(wall, 50), "p90_us": _pct(wall, 90), "p99_us": _pct(wall, 99),
            "share": (m / total_mean) if total_mean else 0.0,
        })
    return rows


def rolling_tps(result: RunResult, window: int = 25) -> list[tuple[int, float]]:
    """Sliding-window MEAN TPS vs measured-tx index — the transient->steady-state curve.
    TPS at i = window_size / Σ(per-tx total wall over the window). Sensitive to outliers
    (a single RocksDB write-stall spike dips it for `window` txs) — use rolling_tps_median
    for a robust trend."""
    totals_ns = [r.total_wall_ns() for r in result.records]
    out: list[tuple[int, float]] = []
    for i in range(len(totals_ns)):
        win = totals_ns[max(0, i - window + 1): i + 1]
        s = sum(win)
        out.append((i, (len(win) * 1e9 / s) if s else 0.0))
    return out


def rolling_tps_median(result: RunResult, window: int | None = None) -> list[tuple[int, float]]:
    """Sliding-window MEDIAN TPS — robust to the ~0.5% RocksDB write-stall spikes that make
    the mean curve dip abruptly. TPS at i = 1 / median(per-tx total wall over the window).
    Window defaults to rolling_window(N)."""
    totals_ns = [r.total_wall_ns() for r in result.records]
    w = window if window is not None else rolling_window(len(totals_ns))
    out: list[tuple[int, float]] = []
    for i in range(len(totals_ns)):
        m = median(totals_ns[max(0, i - w + 1): i + 1])
        out.append((i, (1e9 / m) if m else 0.0))
    return out


def cumulative_curve(result: RunResult) -> list[tuple[int, float, float]]:
    """(N, C(N) seconds, perceived_TPS = N / C(N)) for N = 1..K — feeds the M/Tb model."""
    cum_ns = 0
    out: list[tuple[int, float, float]] = []
    for i, r in enumerate(result.records):
        cum_ns += r.total_wall_ns()
        n = i + 1
        out.append((n, cum_ns / 1e9, (n * 1e9 / cum_ns) if cum_ns else 0.0))
    return out


def mtb_table(cn_curve: list[tuple[int, float, float]], tbs_s: list[float]) -> list[dict]:
    """The M/Tb sustainable-rate table from a cumulative-cost curve.

    For each block interval Tb, M is the number of txs whose cumulative processing time
    fills Tb (C(M)=Tb), and the sustainable rate is M/Tb. In the ORGANIC (flat) regime
    C(N) is linear (C(N)=τ·N), so M=Tb/τ and M/Tb=1/τ — i.e. the sustainable rate equals
    the steady per-tx rate for EVERY Tb (block cadence does not bound it). The genesis
    O(N²) regime is the opposite: M/Tb falls as Tb grows."""
    if not cn_curve:
        return []
    max_n, max_c, _ = cn_curve[-1]
    tau_s = max_c / max_n  # mean per-tx wall time (s); linear C(N) ⇒ constant
    rows = []
    for tb in tbs_s:
        m = tb / tau_s if tau_s else 0.0
        rows.append({"tb_s": tb, "M": m, "sustainable_tps": (m / tb) if tb else 0.0})
    return rows


def scale_to_specs(measured_tps: float, machine_score: float, targets: list[dict]) -> list[dict]:
    """Project the single-thread TPS to other CPUs. Processing is single-thread CPU-bound,
    so TPS scales ~linearly with single-thread performance: tps_target ≈ tps · score_t/score_m.
    `score` is a single-thread performance proxy (e.g. PassMark single-thread); targets =
    [{"label","score","note"?}, ...]."""
    out = []
    for t in targets:
        ratio = (t["score"] / machine_score) if machine_score else 0.0
        out.append({**t, "ratio": ratio, "projected_tps": measured_tps * ratio})
    return out


def headline(result: RunResult, *, tdp_watts: float, cpu_util: float) -> dict:
    totals = sorted(per_tx_totals_us(result))
    b = result.batch
    return {
        "n_measured": result.n,
        "accepted": result.accepted,
        "processing_tps": result.processing_tps(),
        "mean_total_us": mean(totals) if totals else 0.0,
        "p50_total_us": _pct(totals, 50),
        "p90_total_us": _pct(totals, 90),
        "p99_total_us": _pct(totals, 99),
        "batch_wall_s": b.wall_s,
        "batch_cpu_s": b.cpu_s,
        "rss_peak_mb": b.rss_peak_bytes / _MB,
        "rss_growth_mb": b.rss_growth_bytes / _MB,
        "disk_written_mb": b.io_write_bytes / _MB,
        "fd_peak": b.fd_peak,
        "energy_j": b.energy_joules(tdp_watts, cpu_util),
    }
