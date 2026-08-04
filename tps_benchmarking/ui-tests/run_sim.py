"""Simulation worker — runs ONE simulation and writes its artifacts.

Launched as a SUBPROCESS by server.py, deliberately: `NodeHarness` mutates process-global state
(it pins HATHOR_CONFIG_YAML, initialises the global reactor, and for shielded runs rewrites the
settings singleton), so a fresh interpreter per run is the only way to keep runs from
contaminating each other — and it keeps the web server free of hathor imports.

Two paths:

* **custom**   — one free-form cell, rendered with `plotting.py` (dark, UI-native figures).
* **scenario** — a report scenario P1–P12. Runs each cell through `report_data.run_cell`, writes
  the standard report-data layout (`<P>/<cell>.band.csv` + `.meta.json` + `manifest.json`), then
  calls `report_plots.render_scenario` — so the UI shows *the same figures the report uses*,
  rather than a second implementation that could drift. Those figures are light-themed; the front
  end puts them on a light surface instead of restyling them.

Protocol: params as one JSON object on argv[1]; newline-delimited JSON events on stdout, each
prefixed with SENTINEL. The prefix is not decoration — hathor logs to stdout too, so the server
needs to tell protocol lines from node output:

    @@TPSUI@@{"t":"phase","phase":"build","msg":"…"}
    @@TPSUI@@{"t":"progress","phase":"measure","done":120,"total":300,"cell":"2i2o","cell_index":1,"cells":4}
    @@TPSUI@@{"t":"done","run_dir":"…","figures":[…],"artifacts":[…]}
    @@TPSUI@@{"t":"error","msg":"…"}

Artifacts land in runs/<YYYYMMDD-HHMMSS>_<sim>_<run-id>/ — the run-id is what keeps two panels
started in the same second from sharing a directory and overwriting each other.
"""
from __future__ import annotations

import json
import os
import sys
import traceback
from dataclasses import replace
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENGINE_SCRIPTS = HERE.parent / "engine" / "scripts"   # tps_benchmarking/engine/scripts
for _p in (str(HERE), str(ENGINE_SCRIPTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SENTINEL = "@@TPSUI@@"


def emit(**ev) -> None:
    """One JSON event per line, flushed — the server tails these. Sentinel-prefixed so the
    server can pick them out of hathor's own stdout logging."""
    sys.stdout.write(SENTINEL + json.dumps(ev) + "\n")
    sys.stdout.flush()


# --- hathor bootstrapping: must happen before the engine imports (see node/harness.py) --------
os.environ.setdefault(
    "HATHOR_CONFIG_YAML",
    __import__("hathorlib.conf", fromlist=["UNITTESTS_SETTINGS_FILEPATH"]).UNITTESTS_SETTINGS_FILEPATH,
)
from hathor.reactor import initialize_global_reactor  # noqa: E402

initialize_global_reactor(use_asyncio_reactor=True)

import plotting  # noqa: E402
import report_data  # noqa: E402
import report_plots  # noqa: E402
from hathor_tps_bench.analysis import compute  # noqa: E402
from hathor_tps_bench.driver import run_batch  # noqa: E402
from hathor_tps_bench.node import NodeHarness  # noqa: E402
from hathor_tps_bench.workload import get_txtype  # noqa: E402
from report_scenarios import SCN_BY_ID  # noqa: E402
from simulations import BITS_IS_THE_EXPERIMENT, OPT_IS_THE_EXPERIMENT  # noqa: E402
from xlsx import write_workbook  # noqa: E402

SECTIONS = ("s1", "s2", "s3s4", "s5", "s6")
STAGE_TAGS = {"S1": "ser/de", "S2": "gate", "S3S4": "verify", "S5": "cons.", "S6": "post-cons."}
TDP_WATTS, CPU_UTIL = 65.0, 1.0


def _run_dir(params: dict) -> Path:
    """A directory unique to THIS run.

    A second-resolution timestamp alone is not unique: two panels started in the same second both
    resolved to the same directory (mkdir(exist_ok=True)), so the later run overwrote the earlier
    one's results.xlsx / summary.md / manifest.json — and for a custom run its figures and
    meta.json too, since those sit at the top level. The server's run_id makes it collision-proof;
    the scenario tag keeps the name readable and still sorts by time."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    tag = str(params.get("sim_id") or "custom")
    rid = str(params.get("run_id") or "")[:6]
    d = HERE / "runs" / "_".join(x for x in (stamp, tag, rid) if x)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _opt_map(params: dict) -> dict:
    return {s: bool(params.get(f"opt_{s}", True)) for s in SECTIONS}


# ==================================================================================================
# custom path — one free-form cell, UI-native figures
# ==================================================================================================
def run_custom(params: dict) -> dict:
    workload = params.get("workload") or "1-tip-transparent"
    n, i, o = int(params["num_txs"]), int(params["num_inputs"]), int(params["num_outputs"])
    w, seed = int(params["warmup_txs"]), int(params["seed"])
    opt = _opt_map(params)
    quiet_logs = bool(params.get("quiet_logs", True))

    cls = get_txtype(workload)
    is_shielded = bool(getattr(cls, "shielded", False))
    # Range-proof width is read at proof-creation time, so setting it here is enough.
    os.environ["HATHOR_RANGE_PROOF_BITS"] = str(int(params.get("bits", 64)))
    if is_shielded:
        os.environ["HATHOR_BENCH_CACHE_RANGE_PROOFS"] = "1"   # build-only; processing unaffected

    run_dir = _run_dir(params)
    emit(t="phase", phase="boot", msg="starting in-process node")
    harness = NodeHarness(seed=seed, trivial_pow=bool(params.get("trivial_pow", True)),
                          shielded=is_shielded, opt=opt, verbose_logs=not quiet_logs).start()
    try:
        emit(t="phase", phase="build", msg=f"building {w + n} transactions (untimed setup)")
        prepared = cls().build(harness, w + n, i, o)
        emit(t="phase", phase="measure", msg=f"driving {w} warm-up + {n} measured through S1–S6")
        result = run_batch(harness, prepared, sampler_interval_s=0.1, warmup=w,
                           on_progress=lambda ph, d, t: emit(t="progress", phase=ph, done=d, total=t))
    finally:
        harness.stop()

    emit(t="phase", phase="analyse", msg="reducing timings")
    head = compute.headline(result, tdp_watts=TDP_WATTS, cpu_util=CPU_UTIL)
    stages = compute.stage_table(result)
    meta = {"sim_id": "custom", "workload": workload, "n": n, "i": i, "o": o, "warmup": w,
            "seed": seed, "opt": opt, "bits": int(params.get("bits", 64)),
            "trivial_pow": bool(params.get("trivial_pow", True)), "quiet_logs": quiet_logs,
            "created": datetime.now().isoformat(timespec="seconds"),
            "headline": head, "stages": stages}

    emit(t="phase", phase="plot", msg="rendering figures")
    figs = [
        plotting.rolling_tps_figure(run_dir / "tps_over_time.png",
                                    compute.rolling_tps_median(result),
                                    compute.rolling_tps(result, window=compute.rolling_window(result.n)),
                                    head, meta),
        plotting.stage_breakdown_figure(run_dir / "stage_breakdown.png", stages, meta),
    ]

    emit(t="phase", phase="export", msg="writing results.xlsx")
    _write_custom_xlsx(run_dir / "results.xlsx", meta, head, stages, result)
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    figures = [f.name for f in figs]
    return {"run_dir": run_dir.name, "kind": "custom", "headline": head, "stages": stages,
            "figures": figures, "artifacts": figures + ["results.xlsx", "meta.json"],
            "cells": [{"label": "run", "tps": head["processing_tps"],
                       "accepted": f"{head['accepted']}/{head['n_measured']}",
                       "mean_total_us": head["mean_total_us"],
                       "stage_mean_us": {r["stage"]: r["mean_wall_us"] for r in stages}}]}


# ==================================================================================================
# scenario path — P1..P12 through report_data + report_plots
# ==================================================================================================
def _accepted(m: dict) -> str:
    """`accepted/driven`. A transition cell drives TWO segments of n, so its denominator is 2n —
    `meta['n']` is the per-segment count, not the stream length."""
    driven = m["n"] * 2 if m.get("transition") else m["n"]
    return f"{min(m['accepted'])}/{driven}"


def _prepare_scenario(sim_id: str, params: dict):
    """Clone the canonical scenario with the user's overrides applied to every cell.

    Two exclusions matter: P9/P10's cells ARE the optimization configurations and P12's cells ARE
    the range-proof widths, so overriding those would quietly destroy the experiment."""
    scn = SCN_BY_ID[sim_id]
    bits = params.get("bits")
    optmap = _opt_map(params)
    cells = []
    for c in scn.cells:
        kw = {}
        if bits is not None and sim_id not in BITS_IS_THE_EXPERIMENT:
            kw["bits"] = int(bits)
        if sim_id not in OPT_IS_THE_EXPERIMENT:
            kw["opt"] = optmap
        cells.append(replace(c, **kw) if kw else c)
    return replace(scn, cells=cells)


def run_scenario(sim_id: str, params: dict) -> dict:
    scn = _prepare_scenario(sim_id, params)
    n = int(params["num_txs"])
    k = int(params.get("k", 1))
    warmup = int(params.get("warmup_txs", scn.warmup))
    verbose = not bool(params.get("quiet_logs", True))

    run_dir = _run_dir(params)
    cell_dir = run_dir / scn.id
    manifest = {"cells": {}}
    total_cells = len(scn.cells)
    rows = []

    for idx, cell in enumerate(scn.cells):
        def progress(rep, kk, phase, done, total, _i=idx, _c=cell):
            emit(t="progress", phase=phase, done=done, total=total,
                 cell=_c.label, cell_index=_i, cells=total_cells, rep=rep + 1, reps=kk)

        # rep=1/reps=k here too, so the counter resets at each cell boundary instead of briefly
        # showing the previous cell's final repetition.
        emit(t="phase", phase="cell",
             msg=f"cell {idx + 1}/{total_cells}: {cell.label}"
                 f"{f' (x{k} reps)' if k > 1 else ''}",
             cell=cell.label, cell_index=idx, cells=total_cells, rep=1, reps=k)
        out = (report_data.run_cell_multibatch(scn, cell, n, k, on_progress=progress,
                                               verbose_logs=verbose)
               if cell.transition else
               report_data.run_cell(scn, cell, n, warmup, k, on_progress=progress,
                                    verbose_logs=verbose))
        report_data._write_cell(cell_dir, cell, out)
        m = out["meta"]
        manifest["cells"][f"{scn.id}/{cell.label}"] = {
            "status": "done", "tps": m["processing_tps"],
            "accepted": m["accepted"], "tps_reps": m["processing_tps_reps"]}
        report_data._save_manifest(run_dir, manifest)
        rows.append(m)
        emit(t="cell_done", cell=cell.label, tps=m["processing_tps"],
             accepted=_accepted(m), cell_index=idx, cells=total_cells)

    emit(t="phase", phase="plot", msg="rendering report figures")
    figures = report_plots.render_scenario(run_dir, scn.id)
    report_plots.build_summary(run_dir)          # summary.md over whatever is present

    emit(t="phase", phase="export", msg="writing results.xlsx")
    _write_scenario_xlsx(run_dir / "results.xlsx", scn, rows, n, warmup, k)

    rel = [f"{scn.id}/plots/{f}" for f in figures]
    artifacts = rel + ["results.xlsx", "summary.md", "manifest.json"]
    return {"run_dir": run_dir.name, "kind": "scenario", "scenario": scn.id,
            "figures": rel, "artifacts": artifacts,
            "cells": [{"label": m["cell"], "tps": m["processing_tps"],
                       "accepted": _accepted(m),
                       "mean_total_us": m["mean_total_us"],
                       "stage_mean_us": m["stage_mean_us"],
                       "seg_tps": m.get("seg_tps"), "bits": m["bits"]} for m in rows]}


# ==================================================================================================
# spreadsheets
# ==================================================================================================
def _write_custom_xlsx(path: Path, meta: dict, head: dict, stages: list[dict], result) -> None:
    cfg = [["Setting", "Value"],
           ["simulation", meta["sim_id"]], ["workload", meta["workload"]],
           ["measured txs (N)", meta["n"]], ["inputs (I)", meta["i"]], ["outputs (O)", meta["o"]],
           ["warm-up (W)", meta["warmup"]], ["seed", meta["seed"]],
           ["range-proof bits", meta["bits"]], ["trivial PoW", meta["trivial_pow"]],
           ["node debug logging suppressed", meta["quiet_logs"]], ["created", meta["created"]],
           [], ["Optimization section", "Enabled"]]
    cfg += [[s, meta["opt"][s]] for s in SECTIONS]

    summary = [["Metric", "Value", "Unit"],
               ["processing throughput", round(head["processing_tps"], 2), "tx/s"],
               ["mean per-tx total", round(head["mean_total_us"], 2), "us"],
               ["p50 per-tx total", round(head["p50_total_us"], 2), "us"],
               ["p90 per-tx total", round(head["p90_total_us"], 2), "us"],
               ["p99 per-tx total", round(head["p99_total_us"], 2), "us"],
               ["accepted", head["accepted"], f"of {head['n_measured']}"],
               ["batch wall", round(head["batch_wall_s"], 3), "s"],
               ["batch cpu", round(head["batch_cpu_s"], 3), "s"],
               ["peak RSS", round(head["rss_peak_mb"], 1), "MB"],
               ["RSS growth", round(head["rss_growth_mb"], 1), "MB"],
               ["disk written", round(head["disk_written_mb"], 2), "MB"],
               ["peak open FDs", head["fd_peak"], "count"],
               ["energy (analytical)", round(head["energy_j"], 2), "J"]]

    stage_rows = [["Stage", "Tag", "Mean wall (us)", "Mean cpu (us)", "p50 (us)", "p90 (us)",
                   "p99 (us)", "Share of total"]]
    stage_rows += [[r["stage"], STAGE_TAGS.get(r["stage"], ""), round(r["mean_wall_us"], 2),
                    round(r["mean_cpu_us"], 2), round(r["p50_us"], 2), round(r["p90_us"], 2),
                    round(r["p99_us"], 2), round(r["share"], 4)] for r in stages]

    per_tx = [["tx index", "accepted", "inputs", "outputs", "size (bytes)"]
              + [f"{s} (us)" for s in ("S1", "S2", "S3S4", "S5", "S6")] + ["total (us)"]]
    for rec in result.records:
        row = [rec.index, rec.accepted, rec.n_inputs, rec.n_outputs, rec.size_bytes]
        row += [round(rec.stages[s].wall_ns / 1000.0, 3) if s in rec.stages else None
                for s in ("S1", "S2", "S3S4", "S5", "S6")]
        row.append(round(rec.total_wall_ns() / 1000.0, 3))
        per_tx.append(row)

    write_workbook(path, {"Summary": summary, "Stages": stage_rows,
                          "Configuration": cfg, "Per-transaction": per_tx})


def _write_scenario_xlsx(path: Path, scn, rows: list[dict], n: int, warmup: int, k: int) -> None:
    cfg = [["Setting", "Value"],
           ["scenario", scn.id], ["title", scn.title], ["workload", scn.workload],
           ["measured txs per cell (N)", n], ["warm-up per cell (W)", warmup],
           ["repetitions (k)", k], ["cells", len(scn.cells)],
           ["created", datetime.now().isoformat(timespec="seconds")],
           ["note", scn.note or ""]]

    head = [["Cell", "Workload", "I", "O", "Bits", "TPS (median)", "Accepted", "Mean total (us)",
             "RSS peak (MB)", "Disk (MB)", "FD peak", "Energy (J)", "Wall (s)", "TPS reps"]]
    for m in rows:
        head.append([m["cell"], m["workload"], m["i"], m["o"], m["bits"], m["processing_tps"],
                     _accepted(m), m["mean_total_us"], m["rss_peak_mb"],
                     m["disk_written_mb"], m["fd_peak"], m["energy_j"], m["batch_wall_s"],
                     ", ".join(str(x) for x in m["processing_tps_reps"])])

    stage_rows = [["Cell"] + [f"{s} ({STAGE_TAGS[s]}) us" for s in ("S1", "S2", "S3S4", "S5", "S6")]]
    for m in rows:
        sm = m.get("stage_mean_us") or {}
        stage_rows.append([m["cell"]] + [sm.get(s) for s in ("S1", "S2", "S3S4", "S5", "S6")])

    sheets = {"Headline": head, "Stages": stage_rows, "Configuration": cfg}
    if any(m.get("seg_tps") for m in rows):      # P11 only
        seg = [["Cell", "Direction", "Segment 1", "TPS 1", "Segment 2", "TPS 2", "Boundary"]]
        for m in rows:
            if m.get("seg_tps"):
                labels = m.get("seg_labels") or ["seg1", "seg2"]
                seg.append([m["cell"], m.get("transition", ""), labels[0], m["seg_tps"][0],
                            labels[1], m["seg_tps"][1], m.get("boundary", "")])
        sheets["Segments"] = seg
    write_workbook(path, sheets)


def main() -> int:
    try:
        params = json.loads(sys.argv[1])
    except (IndexError, ValueError) as e:
        emit(t="error", msg=f"bad params: {e}")
        return 2
    try:
        sim_id = params.get("sim_id", "custom")
        out = run_scenario(sim_id, params) if sim_id in SCN_BY_ID else run_custom(params)
        emit(t="done", **out)
        return 0
    except Exception as e:  # noqa: BLE001 — surface anything to the UI rather than dying silently
        emit(t="error", msg=f"{type(e).__name__}: {e}", trace=traceback.format_exc()[-2000:])
        return 1


if __name__ == "__main__":
    sys.exit(main())
