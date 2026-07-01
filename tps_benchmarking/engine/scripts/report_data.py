"""Master report-data script (P1–P11) — STAGE 1: core runner (no plots yet).

Produces the raw data for the Phase-report plots. Each scenario P* is a set of CELLS (one
(workload, I, O, range-proof-bits, opt-flags) combination); every cell is run k times, each rep a
FRESH funded node driven through S1..S6 (reusing the proven NodeHarness + run_batch + headline path).

Per cell we record:
  * a k-rep min/avg/max BAND over per-tx-index total latency (band CSV) — shows run-to-run spread
    and the WSL head transient per position;
  * headline medians (processing TPS, accepted) + consumables (peak RSS, disk written, FD peak,
    analytical energy) across the k reps (meta JSON).

Design goals honoured here (Stage 1): declarative scenario registry, run each P* individually
(light→heavy for --all), timestamped + RESUMABLE report dir (manifest; a completed cell is skipped),
--opt default with P9/P10 driving the opt flags, range-proof-bits carried per cell, and the range-proof
BUILD cache (HATHOR_BENCH_CACHE_RANGE_PROOFS) enabled for shielded cells (build-only speedup; the
measured processing is unaffected — see CP-16).

Plots + the summary.md assembler land in Stage 2/3.

Decisions locked with the user: shielded scenarios use `capless-full-shielded` (truly confidential
in+out at full N — capless busts the 255 source cap); `full-shielded` (transparent-in) is kept only as
an optional reference. P11 (multibatch transition) needs its own runner → deferred to a later stage.

Run (from repo root):
  PYTHONPATH=tps_benchmarking/engine:. <venv>/bin/python tps_benchmarking/engine/scripts/report_data.py --list
  ... report_data.py P1                 # one scenario
  ... report_data.py P1 P9 --smoke      # fast plumbing check (tiny N/k)
  ... report_data.py --all              # everything, light→heavy
  ... report_data.py --resume report-data/<ts>   # continue an interrupted run
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from statistics import mean, median

os.environ.setdefault(
    "HATHOR_CONFIG_YAML",
    __import__("hathorlib.conf", fromlist=["UNITTESTS_SETTINGS_FILEPATH"]).UNITTESTS_SETTINGS_FILEPATH,
)
from hathor.reactor import initialize_global_reactor  # noqa: E402

initialize_global_reactor(use_asyncio_reactor=True)

from hathor_tps_bench.analysis import compute  # noqa: E402
from hathor_tps_bench.driver import run_batch  # noqa: E402
from hathor_tps_bench.node import NodeHarness  # noqa: E402
from hathor_tps_bench.workload import get_txtype  # noqa: E402

SEED = 1234
TDP_WATTS, CPU_UTIL = 65.0, 1.0
SECTIONS = ("s1", "s2", "s3s4", "s5", "s6")
ALL_ON = {s: True for s in SECTIONS}
TRANSPARENT = "1-tip-transparent"
SHIELDED = "capless-full-shielded"          # truly confidential in+out (locked decision)
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "report-data"


def _opt_off(section: str) -> dict[str, bool]:
    """all sections ON except `section` (P10 per-section isolation)."""
    return {s: (s != section) for s in SECTIONS}


@dataclass
class Cell:
    i: int
    o: int
    label: str                              # short id used for filenames, e.g. "8i2o", "no-opt", "no-s5"
    bits: int = 64
    opt: dict[str, bool] | None = None      # None → all-ON (--opt). Sets NodeHarness(opt=...)
    workload: str | None = None             # override the scenario workload (P6/P7 "both")
    transition: str | None = None           # P11 only: "T2S" | "S2T" — a two-segment multibatch stream


@dataclass
class Scenario:
    id: str
    title: str
    workload: str
    cells: list[Cell]
    n: int
    warmup: int
    k: int = 3
    shielded: bool = False                   # scenario default; a cell's own workload can override
    cost: int = 0                            # light→heavy ordering hint for --all
    deferred: str = ""                       # non-empty → skip in Stage 1 (needs a dedicated runner)
    note: str = ""


def _io(i: int, o: int) -> str:
    return f"{i}i{o}o"


def _scaling(workload: str, ios: list[tuple[int, int]]) -> list[Cell]:
    return [Cell(i, o, _io(i, o)) for i, o in ios]


# --------------------------------------------------------------------------------------------------
# The P1–P11 matrix (reconstructed + locked decisions applied). N / warmup are the report-scale
# values; --smoke shrinks them for plumbing checks.
# --------------------------------------------------------------------------------------------------
SCENARIOS: list[Scenario] = [
    Scenario("P1", "transparent baseline", TRANSPARENT,
             _scaling(TRANSPARENT, [(1, 2)]), n=5000, warmup=200, cost=10),
    Scenario("P2", "transparent input scaling", TRANSPARENT,
             _scaling(TRANSPARENT, [(1, 2), (2, 2), (4, 2), (8, 2)]), n=5000, warmup=200, cost=40),
    Scenario("P3", "shielded baseline", SHIELDED,
             _scaling(SHIELDED, [(1, 2)]), n=2000, warmup=200, shielded=True, cost=30),
    Scenario("P4", "shielded input scaling", SHIELDED,
             _scaling(SHIELDED, [(1, 2), (2, 2), (4, 2), (8, 2)]), n=2000, warmup=200,
             shielded=True, cost=80),
    Scenario("P5", "shielded output scaling", SHIELDED,
             _scaling(SHIELDED, [(2, 2), (2, 4), (2, 8)]), n=2000, warmup=200, shielded=True, cost=60),
    Scenario("P6", "transparent vs shielded", SHIELDED, [
        Cell(1, 2, "transparent", workload=TRANSPARENT),
        Cell(1, 2, "shielded", workload=SHIELDED),
    ], n=2000, warmup=200, shielded=True, cost=25),
    Scenario("P7", "transparent vs shielded, scaled", SHIELDED, [
        Cell(i, o, f"{tag}-{_io(i, o)}", workload=wl)
        for (tag, wl) in (("transparent", TRANSPARENT), ("shielded", SHIELDED))
        for (i, o) in [(1, 2), (4, 4), (8, 8)]
    ], n=2000, warmup=200, shielded=True, cost=90),
    Scenario("P8", "shielded surjection grid", SHIELDED,
             _scaling(SHIELDED, [(i, o) for i in (2, 4, 8) for o in (2, 4, 8)]),
             n=1000, warmup=100, shielded=True, cost=100),
    Scenario("P9", "opt vs no-opt", TRANSPARENT, [
        Cell(1, 2, "opt", opt=dict(ALL_ON)),
        Cell(1, 2, "no-opt", opt={s: False for s in SECTIONS}),
    ], n=5000, warmup=200, cost=20),
    Scenario("P10", "per-section isolation", TRANSPARENT,
             [Cell(1, 2, "full", opt=dict(ALL_ON))]
             + [Cell(1, 2, f"no-{s}", opt=_opt_off(s)) for s in SECTIONS],
             n=5000, warmup=200, cost=50),
    Scenario("P11", "transition (multi-batch)", "multibatch",
             [Cell(i, o, f"{d}-{_io(i, o)}", transition=d)
              for d in ("T2S", "S2T") for (i, o) in [(1, 2), (2, 4), (4, 8)]],
             n=1000, warmup=0, shielded=True, cost=110,
             note="two-segment stream (n each); transparent↔full-shielded, driven continuously"),
]
SCN_BY_ID = {s.id: s for s in SCENARIOS}


# --------------------------------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------------------------------
def _apply_cell_env(scn: Scenario, cell: Cell, is_shielded: bool) -> None:
    os.environ["HATHOR_RANGE_PROOF_BITS"] = str(cell.bits)   # read at proof-creation (shielded only)
    if is_shielded:
        os.environ["HATHOR_BENCH_CACHE_RANGE_PROOFS"] = "1"  # build-only speedup; processing unchanged
    else:
        os.environ.pop("HATHOR_BENCH_CACHE_RANGE_PROOFS", None)


def run_cell(scn: Scenario, cell: Cell, n: int, warmup: int, k: int) -> dict:
    """Run one cell k times; return {band:[(idx,min,avg,max)], meta:{...}}."""
    workload = cell.workload or scn.workload
    cls = get_txtype(workload)
    is_shielded = bool(getattr(cls, "shielded", False))
    _apply_cell_env(scn, cell, is_shielded)

    per_rep_totals: list[list[float]] = []   # [rep][tx-index] total wall µs
    heads: list[dict] = []
    stage_reps: list[dict[str, float]] = []   # [rep] {stage -> mean wall µs}
    for rep in range(k):
        h = NodeHarness(seed=SEED + rep, trivial_pow=True, shielded=is_shielded,
                        opt=(dict(cell.opt) if cell.opt is not None else None)).start()
        try:
            prepared = cls().build(h, warmup + n, cell.i, cell.o)
            result = run_batch(h, prepared, sampler_interval_s=0.1, warmup=warmup)
        finally:
            h.stop()
        heads.append(compute.headline(result, tdp_watts=TDP_WATTS, cpu_util=CPU_UTIL))
        stage_reps.append(result.stage_mean_wall_us())
        per_rep_totals.append(
            [sum(s.wall_ns for s in r.stages.values()) / 1000.0 for r in result.records]
        )

    # per-tx-index band over the k reps (truncate to the shortest — all equal in practice)
    m = min(len(t) for t in per_rep_totals)
    band = []
    for idx in range(m):
        vals = [t[idx] for t in per_rep_totals]
        band.append((idx, min(vals), mean(vals), max(vals)))

    def med(key: str) -> float:
        return median(hd[key] for hd in heads)

    stages = sorted({s for sr in stage_reps for s in sr})
    stage_mean_us = {s: round(median(sr.get(s, 0.0) for sr in stage_reps), 2) for s in stages}

    meta = {
        "scenario": scn.id, "title": scn.title, "cell": cell.label,
        "workload": workload, "shielded": is_shielded,
        "i": cell.i, "o": cell.o, "bits": cell.bits,
        "opt": cell.opt if cell.opt is not None else ALL_ON,
        "n": n, "warmup": warmup, "k": k,
        "accepted": [hd["accepted"] for hd in heads],
        "processing_tps_reps": [round(hd["processing_tps"], 1) for hd in heads],
        "processing_tps": round(med("processing_tps"), 1),
        "mean_total_us": round(med("mean_total_us"), 2),
        "stage_mean_us": stage_mean_us,
        "rss_peak_mb": round(med("rss_peak_mb"), 1),
        "disk_written_mb": round(med("disk_written_mb"), 2),
        "fd_peak": int(median(hd["fd_peak"] for hd in heads)),
        "energy_j": round(med("energy_j"), 3),
        "batch_wall_s": round(med("batch_wall_s"), 2),
    }
    return {"band": band, "meta": meta}


def run_cell_multibatch(scn: Scenario, cell: Cell, n: int, k: int) -> dict:
    """P11: one continuous stream of two n-tx segments (transparent + full-shielded, ordered by the
    cell's transition direction), driven with NO warm-up so the transition itself is measured. Records
    a per-GLOBAL-index band + each segment's own TPS."""
    from hathor_tps_bench.workload.multibatch import Segment, build_multibatch
    forward = cell.transition == "T2S"                       # T2S: transparent then shielded
    trans = Segment(n=n, t_i=cell.i, t_o=cell.o)
    shield = Segment(n=n, s_i=cell.i, s_o=cell.o, mode="full")
    segs = [trans, shield] if forward else [shield, trans]
    seg_labels = ["transparent", "shielded"] if forward else ["shielded", "transparent"]
    os.environ["HATHOR_RANGE_PROOF_BITS"] = str(cell.bits)
    os.environ["HATHOR_BENCH_CACHE_RANGE_PROOFS"] = "1"       # shielded segment build only

    per_rep_totals: list[list[float]] = []
    heads: list[dict] = []
    seg_tps_reps: list[list[float]] = [[], []]
    boundary = n
    for rep in range(k):
        h = NodeHarness(seed=SEED + rep, trivial_pow=True, shielded=True).start()
        try:
            fa = h.manager._settings.FEE_PER_AMOUNT_SHIELDED_OUTPUT
            ff = h.manager._settings.FEE_PER_FULL_SHIELDED_OUTPUT
            prepared, starts = build_multibatch(h, segs, fa, ff)
            result = run_batch(h, prepared, sampler_interval_s=0.1, warmup=0)
        finally:
            h.stop()
        heads.append(compute.headline(result, tdp_watts=TDP_WATTS, cpu_util=CPU_UTIL))
        totals = [sum(s.wall_ns for s in r.stages.values()) / 1000.0 for r in result.records]
        per_rep_totals.append(totals)
        boundary = starts[1] if len(starts) > 1 else len(totals)
        for si, (lo, hi) in enumerate(((0, boundary), (boundary, len(totals)))):
            seg = totals[lo:hi]
            seg_tps_reps[si].append((len(seg) / (sum(seg) / 1e6)) if sum(seg) else 0.0)

    m = min(len(t) for t in per_rep_totals)
    band = [(idx, *(f(v) for f in (min, mean, max)))
            for idx in range(m) for v in [[t[idx] for t in per_rep_totals]]]

    def med(key: str) -> float:
        return median(hd[key] for hd in heads)

    meta = {
        "scenario": scn.id, "title": scn.title, "cell": cell.label,
        "workload": "multibatch", "shielded": True,
        "i": cell.i, "o": cell.o, "bits": cell.bits, "opt": ALL_ON,
        "n": n, "warmup": 0, "k": k,
        "transition": cell.transition, "boundary": boundary, "seg_labels": seg_labels,
        "seg_tps": [round(median(x), 1) for x in seg_tps_reps],
        "accepted": [hd["accepted"] for hd in heads],
        "processing_tps_reps": [round(hd["processing_tps"], 1) for hd in heads],
        "processing_tps": round(med("processing_tps"), 1),
        "mean_total_us": round(med("mean_total_us"), 2),
        "stage_mean_us": {},
        "rss_peak_mb": round(med("rss_peak_mb"), 1),
        "disk_written_mb": round(med("disk_written_mb"), 2),
        "fd_peak": int(median(hd["fd_peak"] for hd in heads)),
        "energy_j": round(med("energy_j"), 3),
        "batch_wall_s": round(med("batch_wall_s"), 2),
    }
    return {"band": band, "meta": meta}


def _write_cell(cell_dir: Path, cell: Cell, out: dict) -> None:
    cell_dir.mkdir(parents=True, exist_ok=True)
    csv = cell_dir / f"{cell.label}.band.csv"
    lines = ["tx_index,min_us,avg_us,max_us"]
    lines += [f"{i},{lo:.3f},{av:.3f},{hi:.3f}" for i, lo, av, hi in out["band"]]
    csv.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (cell_dir / f"{cell.label}.meta.json").write_text(json.dumps(out["meta"], indent=2), encoding="utf-8")


def _manifest_path(out_dir: Path) -> Path:
    return out_dir / "manifest.json"


def _load_manifest(out_dir: Path) -> dict:
    p = _manifest_path(out_dir)
    return json.loads(p.read_text()) if p.exists() else {"cells": {}}


def _save_manifest(out_dir: Path, man: dict) -> None:
    _manifest_path(out_dir).write_text(json.dumps(man, indent=2), encoding="utf-8")


def run_scenario(scn: Scenario, out_dir: Path, *, smoke: bool, resume: bool) -> None:
    if scn.deferred:
        print(f"[{scn.id}] DEFERRED: {scn.deferred}\n")
        return
    n, warmup, k = scn.n, scn.warmup, scn.k
    if smoke:
        n, warmup, k = min(n, 100), min(warmup, 10), 2
    print(f"== {scn.id}: {scn.title}  ({scn.workload}, N={n} W={warmup} k={k}, {len(scn.cells)} cells) ==")
    man = _load_manifest(out_dir)
    cell_dir = out_dir / scn.id
    for cell in scn.cells:
        key = f"{scn.id}/{cell.label}"
        done = man["cells"].get(key, {}).get("status") == "done"
        if resume and done and (cell_dir / f"{cell.label}.band.csv").exists():
            print(f"  {cell.label:16s} SKIP (already done)")
            continue
        out = run_cell_multibatch(scn, cell, n, k) if cell.transition else run_cell(scn, cell, n, warmup, k)
        _write_cell(cell_dir, cell, out)
        mt = out["meta"]
        man["cells"][key] = {"status": "done", "tps": mt["processing_tps"],
                             "accepted": mt["accepted"], "tps_reps": mt["processing_tps_reps"]}
        _save_manifest(out_dir, man)
        extra = f"  seg_tps={mt['seg_tps']}" if cell.transition else ""
        print(f"  {cell.label:16s} TPS={mt['processing_tps']:>7.1f}  acc={mt['accepted']}  "
              f"RSS={mt['rss_peak_mb']:.0f}MB  wall={mt['batch_wall_s']:.1f}s{extra}")
    print()


def order_for_all() -> list[Scenario]:
    return sorted((s for s in SCENARIOS if not s.deferred), key=lambda s: s.cost)


def cmd_list() -> None:
    print(f"{'id':4s} {'cost':4s} {'workload':22s} {'N':>5s} {'W':>4s} {'k':>2s}  cells")
    for s in SCENARIOS:
        cells = ", ".join(c.label for c in s.cells) or (s.deferred and "(deferred)") or "-"
        print(f"{s.id:4s} {s.cost:4d} {s.workload:22s} {s.n:>5d} {s.warmup:>4d} {s.k:>2d}  {cells}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Master report-data runner (P1–P11), Stage 1 (no plots).")
    ap.add_argument("scenarios", nargs="*", help="scenario ids to run, e.g. P1 P4 (default: none)")
    ap.add_argument("--all", action="store_true", help="run every scenario, light→heavy")
    ap.add_argument("--list", action="store_true", help="print the scenario matrix and exit")
    ap.add_argument("--smoke", action="store_true", help="tiny N/warmup/k for a fast plumbing check")
    ap.add_argument("--out", type=Path, default=None, help="report dir (default: report-data/<timestamp>)")
    ap.add_argument("--resume", type=Path, default=None, help="resume into an existing report dir")
    ap.add_argument("--no-plots", action="store_true", help="skip figure rendering after the run")
    ap.add_argument("--plots", type=Path, default=None, help="only render figures for an existing dir, then exit")
    args = ap.parse_args()

    if args.list:
        cmd_list()
        return 0

    if args.plots:
        from report_plots import render_report
        render_report(args.plots)
        return 0

    ids = [s.id for s in order_for_all()] if args.all else [x.upper() for x in args.scenarios]
    if not ids:
        ap.print_help()
        return 2
    unknown = [i for i in ids if i not in SCN_BY_ID]
    if unknown:
        print(f"unknown scenarios: {unknown}  (see --list)")
        return 2

    if args.resume:
        out_dir, resume = args.resume, True
    else:
        base = args.out or DEFAULT_OUT
        out_dir = base if args.out else base / datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        resume = False
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"report dir: {out_dir}\n")

    for i in ids:
        run_scenario(SCN_BY_ID[i], out_dir, smoke=args.smoke, resume=resume)
    print(f"done → {out_dir}")

    if not args.no_plots:
        from report_plots import render_report
        render_report(out_dir, [i for i in ids if not SCN_BY_ID[i].deferred])
    return 0


if __name__ == "__main__":
    sys.exit(main())
