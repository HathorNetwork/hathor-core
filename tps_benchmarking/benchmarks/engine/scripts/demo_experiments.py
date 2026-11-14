"""CP-6 demonstration experiments — three plots, using a robust rolling MEDIAN curve.

 1. N-scaling with the warm-up VISIBLE: I=1, O=2, 100 warm-up + 10000 measured driven
    with warmup=0 (warm-up recorded) → rolling mean (faint, shows RocksDB write-stall
    spikes) + rolling median (bold, robust), with the W=100 boundary marked.
 2. Input sweep at N=5000: one rolling-MEDIAN curve per I in {1,2,3,4,5,10} (O=2), overlaid.
 3. Output sweep at N=5000: one rolling-MEDIAN curve per O in {2,5,10,15,25} (I=1), overlaid.

Rolling window = compute.rolling_window(N) (50, or 10%-of-N floored at 5 for small N).
Each variant is a FRESH funded node. Robust: per-variant try/except + incremental saves.
Raw per-tx totals (µs) are also saved to demo_data.json so plots can be regenerated
WITHOUT re-running the nodes. Plots + data → results/demo/.

Run:  poetry run python tps_benchmarking/benchmarks/engine/scripts/demo_experiments.py [all|1|2|3]
"""
import json
import os
import sys
import time

from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH
os.environ.setdefault("HATHOR_CONFIG_YAML", UNITTESTS_SETTINGS_FILEPATH)

from hathor.reactor import initialize_global_reactor
initialize_global_reactor(use_asyncio_reactor=True)

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from hathor_tps_bench.analysis import compute, plots
from hathor_tps_bench.driver import run_batch
from hathor_tps_bench.node import NodeHarness
from hathor_tps_bench.workload import get_txtype

OUT = Path("tps_benchmarking/benchmarks/engine/results/demo")
OUT.mkdir(parents=True, exist_ok=True)
TXTYPE = "organic"
DATA = {}   # {plot: {variant_label: [per-tx total µs]}} — saved for free re-plots


def log(msg):
    print(msg, flush=True)


def run(num_inputs, num_outputs, K, W):
    h = NodeHarness(seed=1234).start()
    try:
        prepared = get_txtype(TXTYPE)().build(h, W + K, num_inputs, num_outputs)
        return run_batch(h, prepared, warmup=W)
    finally:
        h.stop()


def totals_us(res):
    return [r.total_wall_ns() / 1000.0 for r in res.records]


def roll_median(res):
    w = compute.rolling_window(len(res.records))
    s = compute.rolling_tps_median(res, window=w)
    return [i for i, _ in s], [t for _, t in s], w


def roll_mean(res, w):
    s = compute.rolling_tps(res, window=w)
    return [i for i, _ in s], [t for _, t in s]


def save_data():
    (OUT / "demo_data.json").write_text(json.dumps(DATA), encoding="utf-8")


# ---------- Experiment 1: warm-up rise visible ----------
def exp1():
    log("[exp1] I=1 O=2, 100 warm-up + 10000 measured (warm-up recorded)...")
    t0 = time.perf_counter()
    res = run(1, 2, 10100, 0)          # warmup=0 → all 10100 recorded; first 100 = warm-up
    DATA["exp1"] = {"I1O2": totals_us(res)}; save_data()
    xs, ys, w = roll_median(res)
    xm, ym = roll_mean(res, w)
    fig, ax = plt.subplots(figsize=(10, 4.5))
    ax.plot(xm, ym, lw=0.5, color="#cfcfcf", label="rolling mean (write-stall spikes)")
    ax.plot(xs, ys, lw=1.1, color="#1f6feb", label=f"rolling median (w={w})")
    ax.axvline(100, color="#d1242f", ls="--", lw=1.2, label="W=100 (warm-up → measured)")
    ax.set(xlabel="tx index (warm-up + measured)", ylabel="rolling TPS",
           title="I=1, O=2 — TPS rise from cold through warm-up to steady (100 + 10000)")
    ax.legend(); ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT / plots._stamped("exp1_warmup_rise.png", plots.timestamp()), dpi=130)
    plt.close(fig)
    log(f"[exp1] done in {time.perf_counter()-t0:.0f}s (steady ~{res.processing_tps():.0f} tps)")


# ---------- Experiments 2 & 3: overlaid rolling-median curves ----------
def overlay_sweep(name, title, legend_title, variants, make_args, out_png):
    fig, ax = plt.subplots(figsize=(10, 5))
    out_png = plots._stamped(out_png, plots.timestamp())   # one stamp for this sweep's plot
    DATA[name] = {}
    summary = []
    for v in variants:
        I, O, K, W, label = make_args(v)
        log(f"[{name}] {label}: building+driving N={K}...")
        t0 = time.perf_counter()
        try:
            res = run(I, O, K, W)
            DATA[name][label] = totals_us(res); save_data()
            xs, ys, w = roll_median(res)
            tps = res.processing_tps()
            ax.plot(xs, ys, lw=1.0, label=f"{label} (~{tps:.0f} tps)")
            summary.append((label, tps))
            log(f"[{name}] {label}: ~{tps:.0f} tps in {time.perf_counter()-t0:.0f}s")
        except Exception as e:  # noqa: BLE001 — keep the rest of the sweep alive
            log(f"[{name}] {label}: FAILED ({type(e).__name__}: {str(e)[:90]})")
        ax.set(xlabel="measured tx index", ylabel="rolling median TPS", title=title)
        ax.legend(title=legend_title, fontsize=8); ax.grid(alpha=0.3)
        fig.tight_layout(); fig.savefig(OUT / out_png, dpi=130)
    plt.close(fig)
    log(f"[{name}] done → {out_png}  summary: " + " · ".join(f"{l}={t:.0f}" for l, t in summary))


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("all", "1"):
        exp1()
    if which in ("all", "2"):
        overlay_sweep("exp2", "Input sweep (O=2, N=5000) — rolling median TPS per input count",
                      "inputs I", [1, 2, 3, 4, 5, 10],
                      lambda I: (I, 2, 5000, 100, f"I={I}"), "exp2_input_sweep.png")
    if which in ("all", "3"):
        overlay_sweep("exp3", "Output sweep (I=1, N=5000) — rolling median TPS per output count",
                      "outputs O", [2, 5, 10, 15, 25],
                      lambda O: (1, O, 5000, 100, f"O={O}"), "exp3_output_sweep.png")
    save_data()
    log(f"ALL DONE → {OUT}/")


if __name__ == "__main__":
    main()
