"""Command-line entry point: `python -m hathor_tps_bench <command>`.

Commands:
  list                       — show registered tx types and benchmarks
  validate --config X.yaml   — load + structurally validate a scenario, print resolved config
  run      --config X.yaml   — run the scenario (wired up in CP-4/CP-5; stub for now)

Uses stdlib argparse only (no click/typer). CP-2 is intentionally hathor-free.
"""
from __future__ import annotations

import argparse
import json
import sys

from hathor_tps_bench import __version__
from hathor_tps_bench.benchmarks import list_benchmarks
from hathor_tps_bench.config import RootConfig
from hathor_tps_bench.workload import list_txtypes


def _cmd_list(args: argparse.Namespace) -> int:
    txtypes = list_txtypes()
    benches = list_benchmarks()
    scripts = _list_scripts()
    print(f"hathor_tps_bench v{__version__}")
    print(f"\ntx types   ({len(txtypes)}): {', '.join(txtypes) or '(none registered yet)'}")
    print(f"benchmarks ({len(benches)}): {', '.join(benches) or '(none registered yet)'}")
    print(f"scripts    ({len(scripts)}): {', '.join(scripts) or '(none)'}")
    return 0


def _load_and_validate(path: str) -> tuple[RootConfig | None, list[str]]:
    try:
        cfg = RootConfig.from_yaml(path)
    except FileNotFoundError:
        return None, [f"config file not found: {path}"]
    except Exception as e:  # noqa: BLE001 — surface any parse/build error cleanly
        return None, [f"failed to parse config: {e}"]
    return cfg, cfg.validate()


def _cmd_validate(args: argparse.Namespace) -> int:
    cfg, errs = _load_and_validate(args.config)
    if errs:
        print(f"INVALID ({len(errs)} problem(s)):", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print("VALID ✓  resolved config:")
    print(json.dumps(cfg.to_dict(), indent=2))
    return 0


def _apply_overrides(cfg: RootConfig, args: argparse.Namespace) -> None:
    """Apply CLI flag overrides onto a (possibly default) config. Flags win over the YAML."""
    w = cfg.workload
    for attr, val in (("tx_type", getattr(args, "tx_type", None)),
                      ("num_txs", args.num_txs), ("num_inputs", getattr(args, "num_inputs", None)),
                      ("num_outputs", getattr(args, "num_outputs", None)),
                      ("shielded_inputs", getattr(args, "shielded_inputs", None)),
                      ("shielded_outputs", getattr(args, "shielded_outputs", None)),
                      ("warmup_txs", args.warmup)):
        if val is not None:
            setattr(w, attr, val)
    if getattr(args, "window", None) is not None:
        cfg.reporting.window = args.window
    if getattr(args, "seed", None) is not None:
        cfg.env.seed = args.seed


def _load_config(args: argparse.Namespace) -> tuple[RootConfig | None, list[str]]:
    """Load --config if given (else built-in defaults), apply flag overrides, then validate."""
    try:
        cfg = RootConfig.from_yaml(args.config) if args.config else RootConfig()
    except FileNotFoundError:
        return None, [f"config file not found: {args.config}"]
    except Exception as e:  # noqa: BLE001
        return None, [f"failed to parse config: {e}"]
    _apply_overrides(cfg, args)
    return cfg, cfg.validate()


def _apply_shielded_env(args: argparse.Namespace) -> None:
    """Translate the shielded CLI flags into the env vars the crypto/caps read. Must run
    BEFORE hathor/hathorlib are imported: HATHOR_MAX_SHIELDED_OUTPUTS (and the proof-size
    cap) are resolved at module import time; HATHOR_RANGE_PROOF_BITS is read per proof at
    creation time. No-ops when the flags are unset."""
    import os
    bits = getattr(args, "range_proof_bits", None)
    if bits is not None:
        os.environ["HATHOR_RANGE_PROOF_BITS"] = str(bits)
    cap = getattr(args, "max_shielded_outputs", None)
    if cap is not None:
        os.environ["HATHOR_MAX_SHIELDED_OUTPUTS"] = str(cap)


def _cmd_run(args: argparse.Namespace) -> int:
    cfg, errs = _load_config(args)
    if errs:
        print("config invalid:", *(f"\n  - {e}" for e in errs), file=sys.stderr)
        return 1
    # Apply shielded parameter env overrides BEFORE any hathor/hathorlib import (the
    # MAX_SHIELDED_OUTPUTS / proof-size caps are resolved at import time).
    _apply_shielded_env(args)

    # Multi-batch mode: a sequence of segments driven as one timed stream (TPS-over-time).
    if getattr(args, "mult_batches", None):
        return _run_multibatch(cfg, args)

    # Sweep mode if any --sweep-* flag is present; else a single run.
    if args.sweep_inputs or args.sweep_outputs or args.sweep_txs:
        return _run_sweep(cfg, args)

    from dataclasses import asdict
    from pathlib import Path

    from hathor_tps_bench.analysis import compute, persist, plots, report
    from hathor_tps_bench.driver import run_batch
    from hathor_tps_bench.node import NodeHarness
    from hathor_tps_bench.workload import get_txtype

    w = cfg.workload
    K, W = w.num_txs, w.warmup_txs
    print(f"[run] {w.tx_type} I={w.num_inputs} O={w.num_outputs}, "
          f"K={K} measured (+{W} warm-up) on an in-process node...")

    source_cls = get_txtype(w.tx_type)
    source = source_cls()
    if hasattr(source_cls, "shielded_inputs"):   # mixed-* sources carry a shielded slice
        source.shielded_inputs = w.shielded_inputs
        source.shielded_outputs = w.shielded_outputs
    harness = NodeHarness(seed=cfg.env.seed, trivial_pow=cfg.env.trivial_pow,
                          shielded=source_cls.shielded).start()
    try:
        prepared = source.build(harness, W + K, w.num_inputs, w.num_outputs)  # build W+K
        print(f"[run] built {len(prepared)} txs; warming {W}, measuring {K} through S1..S6...")
        result = run_batch(harness, prepared,
                           sampler_interval_s=cfg.measure.sampler_interval_s, warmup=W)
        _print_run_summary(result, cfg)
    finally:
        harness.stop()

    # ---- reporting: CSV + JSON + plots + summary.md into results/<run>/ ----
    head = compute.headline(result, tdp_watts=cfg.measure.tdp_watts, cpu_util=cfg.measure.cpu_util)
    rows = compute.stage_table(result)
    # M/Tb sustainable-rate table (flat ⇒ Tb-independent for 1-tip-transparent; see RFC).
    mtb = compute.mtb_table(compute.cumulative_curve(result), [7.5, 15, 30, 60, 90])
    run_dir = Path(cfg.results_root) / f"{cfg.name}_{w.tx_type}_N{K}_I{w.num_inputs}_O{w.num_outputs}"
    run_dir.mkdir(parents=True, exist_ok=True)
    fmts = cfg.reporting.formats
    if "csv" in fmts:
        persist.write_per_tx_csv(run_dir / "per_tx_stages.csv", result)
        persist.write_samples_csv(run_dir / "samples.csv", result)
    persist.write_summary_json(run_dir / "batch_summary.json",
                               {"scenario": cfg.name, "workload": asdict(w),
                                "headline": head, "stages": rows, "mtb": mtb})
    plot_names = (plots.generate(run_dir / "plots", result, window=cfg.reporting.window)
                  if "plots" in fmts else [])
    if "markdown" in fmts:
        report.write_report(run_dir / "summary.md", cfg, head, rows, plot_names)
    print(f"\n[run] results → {run_dir}/  ({len(plot_names)} plots)")
    return 0


def _print_run_summary(result, cfg) -> None:
    means_w = result.stage_mean_wall_us()
    means_c = result.stage_mean_cpu_us()
    total = result.total_mean_wall_us()
    b = result.batch
    mb = 1024 * 1024

    print(f"\n[result] accepted {result.accepted}/{result.n}")
    print(f"  {'stage':6} {'mean wall us':>13} {'mean cpu us':>12} {'share':>7}")
    for s in result.stage_mean_wall_us():
        share = (means_w[s] / total) if total else 0.0
        print(f"  {s:6} {means_w[s]:13.1f} {means_c[s]:12.1f} {share:7.1%}")
    print(f"  {'TOTAL':6} {total:13.1f}")
    print(f"\n  processing throughput : {result.processing_tps():.0f} tx/s "
          f"(1 / mean per-tx total wall)")
    print(f"  batch wall / cpu      : {b.wall_s:.3f} s / {b.cpu_s:.3f} s")
    print(f"  peak RSS / growth     : {b.rss_peak_bytes / mb:.1f} MB / {b.rss_growth_bytes / mb:.1f} MB")
    print(f"  disk written (flushed): {b.io_write_bytes / mb:.2f} MB")
    print(f"  peak open FDs         : {b.fd_peak}")
    energy = b.energy_joules(cfg.measure.tdp_watts, cfg.measure.cpu_util)
    print(f"  energy (analytical)   : {energy:.2f} J  (cpu_s x {cfg.measure.tdp_watts} W x {cfg.measure.cpu_util})")


def _emit_sweep(cfg, points, axis: str, x_label: str) -> int:
    from pathlib import Path

    from hathor_tps_bench.analysis import plots
    run_dir = Path(cfg.results_root) / f"sweep_{cfg.name}_{cfg.workload.tx_type}_{axis}"
    run_dir.mkdir(parents=True, exist_ok=True)
    plot_names = (plots.sweep_plots(run_dir / "plots", points, x_label=x_label,
                                    window=cfg.reporting.window)
                  if "plots" in cfg.reporting.formats else [])
    _write_sweep_report(run_dir / "summary.md", cfg, axis, x_label, points, plot_names)
    print(f"\n[sweep] results → {run_dir}/  ({len(plot_names)} plots)")
    return 0


def _run_sweep(cfg, args) -> int:
    """Dispatch a sweep from the friendly --sweep-* flags on `run`."""
    from hathor_tps_bench.analysis import sweep
    w = cfg.workload
    W = w.warmup_txs
    log = lambda p: print(f"  {p.label:10} {p.tps:6.0f} tps   acc {p.accepted}/{p.num_txs}")
    if args.sweep_inputs:
        lo, hi = args.sweep_inputs
        print(f"[sweep] inputs {lo}..{hi} (O={w.num_outputs}, N={w.num_txs}, {w.tx_type})...")
        pts = sweep.io_sweep(cfg, w.tx_type, [(i, w.num_outputs) for i in range(lo, hi + 1)],
                             w.num_txs, W, on_point=log)
        return _emit_sweep(cfg, pts, "inputs", "inputs I")
    if args.sweep_outputs:
        lo, hi = args.sweep_outputs
        print(f"[sweep] outputs {lo}..{hi} (I={w.num_inputs}, N={w.num_txs}, {w.tx_type})...")
        pts = sweep.io_sweep(cfg, w.tx_type, [(w.num_inputs, o) for o in range(lo, hi + 1)],
                             w.num_txs, W, on_point=log)
        return _emit_sweep(cfg, pts, "outputs", "outputs O")
    ns = args.sweep_txs
    print(f"[sweep] txs {ns} (I={w.num_inputs}, O={w.num_outputs}, {w.tx_type})...")
    pts = sweep.n_sweep(cfg, w.tx_type, ns, w.num_inputs, w.num_outputs, W, on_point=log)
    return _emit_sweep(cfg, pts, "txs", "batch size N")


def _scripts_dir():
    from pathlib import Path
    return Path(__file__).resolve().parent.parent / "scripts"


def _list_scripts() -> list[str]:
    d = _scripts_dir()
    return sorted(p.stem for p in d.glob("*.py")) if d.exists() else []


def _cmd_script(args: argparse.Namespace) -> int:
    import runpy
    path = _scripts_dir() / f"{args.name}.py"
    if not path.exists():
        print(f"no script {args.name!r}; available: {', '.join(_list_scripts()) or '(none)'}",
              file=sys.stderr)
        return 2
    sys.argv = [str(path)] + (args.args or [])
    runpy.run_path(str(path), run_name="__main__")
    return 0


def _parse_shapes(s: str | None):
    return [(int(i), int(o)) for i, o in (tok.split(":") for tok in s.split(","))] if s else None


def _parse_ints(s: str | None):
    return [int(x) for x in s.split(",")] if s else None


def _cmd_sweep(args: argparse.Namespace) -> int:
    """Back-compat axis interface (`--axis io|n --values ...`). The friendly way is
    `run --sweep-inputs/--sweep-outputs/--sweep-txs`."""
    cfg, errs = _load_config(args)
    if errs:
        print("config invalid:", *(f"\n  - {e}" for e in errs), file=sys.stderr)
        return 2
    _apply_shielded_env(args)
    from hathor_tps_bench.analysis import sweep
    w = cfg.workload
    W = w.warmup_txs
    log = lambda p: print(f"  {p.label:10} {p.tps:6.0f} tps   acc {p.accepted}/{p.num_txs}")
    print(f"[sweep] axis={args.axis} on {w.tx_type} — fresh node per point...")
    if args.axis == "io":
        shapes = _parse_shapes(args.values) or [(1, 2), (2, 2), (3, 2), (4, 2), (5, 2), (1, 3), (1, 4), (1, 5)]
        points = sweep.io_sweep(cfg, w.tx_type, shapes, w.num_txs, W, on_point=log)
        return _emit_sweep(cfg, points, "io", "tx shape (I:O)")
    ns = _parse_ints(args.values) or [50, 100, 200, 500, 1000, 2000]
    points = sweep.n_sweep(cfg, w.tx_type, ns, w.num_inputs, w.num_outputs, W, on_point=log)
    return _emit_sweep(cfg, points, "n", "batch size N")


def _write_sweep_report(path, cfg, axis, x_label, points, plot_names) -> None:
    from pathlib import Path
    L = [f"# Sweep — {cfg.name} ({axis})", "",
         f"- workload **{cfg.workload.tx_type}**, varying {x_label} (+{cfg.workload.warmup_txs} warm-up/point)",
         "",
         "| point | I | O | K | TPS | mean total µs | S3S4 | S5 | S6 |",
         "|---|---|---|---|---|---|---|---|---|"]
    for p in points:
        sm = p.stage_means_us
        L.append(f"| {p.label} | {p.num_inputs} | {p.num_outputs} | {p.num_txs} | **{p.tps:.0f}** | "
                 f"{p.mean_total_us:.0f} | {sm.get('S3S4', 0):.0f} | {sm.get('S5', 0):.0f} | {sm.get('S6', 0):.0f} |")
    if plot_names:
        L += ["", "## Plots", ""] + [f"![{n}](plots/{n})" for n in plot_names]
    Path(path).write_text("\n".join(L) + "\n", encoding="utf-8")


def _parse_segments(tokens: list[str]):
    """Parse the --mult-batches token stream into a list of Segment (each carries its own mode).
    Grammar per segment: --n N [-i I -o O] [--shielded|--full-shielded|--amount-shielded -i Is -o Os].
    The shielded flag is a section separator (transparent slice before it, shielded slice after) AND
    sets that segment's shielded mode; segments may use different modes."""
    from hathor_tps_bench.workload.multibatch import Segment
    segs: list = []
    cur = None
    section = "t"
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--n":
            cur = Segment(n=int(tokens[i + 1])); segs.append(cur); section = "t"; i += 2
            continue
        if cur is None:
            raise ValueError("each segment must start with --n N")
        if tok in ("--shielded", "--full-shielded"):
            section = "s"; cur.mode = "full"; i += 1
        elif tok == "--amount-shielded":
            section = "s"; cur.mode = "amount"; i += 1
        elif tok in ("-i", "--num-inputs", "-o", "--num-outputs"):
            v = int(tokens[i + 1])
            field = ("t_i" if section == "t" else "s_i") if tok in ("-i", "--num-inputs") \
                else ("t_o" if section == "t" else "s_o")
            setattr(cur, field, v); i += 2
        else:
            raise ValueError(f"unexpected token {tok!r}")
    if cur is None:
        raise ValueError("needs at least one segment (start with --n N)")
    return segs


def _run_multibatch(cfg: RootConfig, args: argparse.Namespace) -> int:
    """Drive a sequence of segments (per-segment mode) as one continuous timed stream; per-segment TPS."""
    from pathlib import Path
    try:
        segments = _parse_segments(args.mult_batches)
    except (ValueError, IndexError) as e:
        print(f"--mult-batches: {e}", file=sys.stderr)
        return 2

    from hathor_tps_bench.analysis import persist, plots
    from hathor_tps_bench.driver import run_batch
    from hathor_tps_bench.node import NodeHarness
    from hathor_tps_bench.workload.multibatch import build_multibatch

    has_shielded = any(s.s_i or s.s_o for s in segments)
    total = sum(s.n for s in segments)
    W = args.warmup or 0
    desc = "  ".join(f"[{i}] n={s.n} t{s.t_i}/{s.t_o} s{s.s_i}/{s.s_o} {s.mode or '-'}"
                     for i, s in enumerate(segments))
    print(f"[mult-batches] {len(segments)} segments, {total} txs (warmup {W})\n  {desc}")

    harness = NodeHarness(seed=cfg.env.seed, trivial_pow=cfg.env.trivial_pow, shielded=has_shielded).start()
    try:
        st = harness.manager._settings
        prepared, starts = build_multibatch(harness, segments,
                                            st.FEE_PER_AMOUNT_SHIELDED_OUTPUT, st.FEE_PER_FULL_SHIELDED_OUTPUT)
        print(f"[mult-batches] built {len(prepared)} txs; driving as one stream...")
        result = run_batch(harness, prepared, sampler_interval_s=cfg.measure.sampler_interval_s, warmup=W)
    finally:
        harness.stop()

    # per-segment TPS over the measured records (record index i == stream index W+i)
    print(f"\n[result] accepted {result.accepted}/{result.n}  (warmup {W} discarded)")
    print(f"  {'seg':4} {'shape (t_in/t_out s_in/s_out + mode)':38} {'n':>6} {'TPS':>7}")
    starts_m = [max(0, s - W) for s in starts] + [len(result.records)]
    seg_rows = []
    for k, seg in enumerate(segments):
        sl = result.records[starts_m[k]:starts_m[k + 1]]
        wall = sum(r.total_wall_ns() for r in sl)
        tps = (len(sl) * 1e9 / wall) if wall else 0.0
        shape = f"t{seg.t_i}/{seg.t_o} s{seg.s_i}/{seg.s_o} {seg.mode or '-'}"
        print(f"  {k:<4} {shape:38} {len(sl):>6} {tps:>7.0f}")
        seg_rows.append((k, shape, len(sl), tps, starts_m[k]))
    print(f"  overall processing throughput: {result.processing_tps():.0f} tx/s")

    run_dir = Path(cfg.results_root) / f"multibatch_{len(segments)}seg_{total}tx"
    run_dir.mkdir(parents=True, exist_ok=True)
    if "csv" in cfg.reporting.formats:
        persist.write_per_tx_csv(run_dir / "per_tx_stages.csv", result)
    plot_names = (plots.generate(run_dir / "plots", result, window=cfg.reporting.window)
                  if "plots" in cfg.reporting.formats else [])
    L = [f"# Multi-batch — {len(segments)} segments, {total} txs (warmup {W})", "",
         "| seg | shape (t_in/t_out s_in/s_out + mode) | n | TPS | measured start |", "|---|---|---|---|---|"]
    for k, shape, n, tps, start in seg_rows:
        L.append(f"| {k} | {shape} | {n} | **{tps:.0f}** | {start} |")
    L += ["", f"overall: **{result.processing_tps():.0f}** tx/s, accepted {result.accepted}/{result.n}"]
    if plot_names:
        L += ["", "## TPS over time (segment shifts visible in the rolling curve)", ""] + \
             [f"![{n}](plots/{n})" for n in plot_names]
    (run_dir / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"\n[mult-batches] results → {run_dir}/  ({len(plot_names)} plots)")
    return 0


def _add_shielded_flags(parser: argparse.ArgumentParser) -> None:
    """Shielded workload selectors + parameter overrides, shared by `run` and `sweep`.
    The selector flags store into the `tx_type` dest; the parameter flags are translated
    to env vars by `_apply_shielded_env` before the node is built."""
    parser.add_argument("--shielded", action="store_const", const="full-shielded", dest="tx_type",
                        help="shorthand for --full-shielded")
    parser.add_argument("--full-shielded", action="store_const", const="full-shielded", dest="tx_type",
                        help="FULLY_SHIELDED outputs (amount+token hidden; range+surjection proofs)")
    parser.add_argument("--amount-shielded", action="store_const", const="amount-shielded", dest="tx_type",
                        help="AMOUNT_ONLY shielded outputs (amount hidden; range proof only)")
    parser.add_argument("--mixed-full", action="store_const", const="mixed-full", dest="tx_type",
                        help="MIXED tx: transparent slice (-i/-o) + a FULLY_SHIELDED slice "
                             "(--shielded-inputs/--shielded-outputs) in one tx")
    parser.add_argument("--mixed-amount", action="store_const", const="mixed-amount", dest="tx_type",
                        help="MIXED tx with an AMOUNT_ONLY shielded slice")
    parser.add_argument("--shielded-inputs", type=int, dest="shielded_inputs", metavar="N",
                        help="shielded inputs per tx (mixed-* only); the transparent slice is -i")
    parser.add_argument("--shielded-outputs", type=int, dest="shielded_outputs", metavar="N",
                        help="shielded outputs per tx (mixed-* only, 0 or >=2); transparent slice is -o")
    parser.add_argument("--range-proof-bits", type=int, dest="range_proof_bits", metavar="N",
                        help="range-proof bit-width 1..=64 (default 64); sets HATHOR_RANGE_PROOF_BITS")
    parser.add_argument("--max-shielded-outputs", dest="max_shielded_outputs", metavar="N|max",
                        help="lift the per-tx shielded-output cap (default 32, ceiling 255); "
                             "sets HATHOR_MAX_SHIELDED_OUTPUTS")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hathor_tps_bench", description=__doc__)
    p.add_argument("--version", action="version", version=f"hathor_tps_bench {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show registered tx types and benchmarks").set_defaults(fn=_cmd_list)

    pv = sub.add_parser("validate", help="validate a scenario YAML")
    pv.add_argument("--config", required=True, help="path to scenario YAML")
    pv.set_defaults(fn=_cmd_validate)

    pr = sub.add_parser("run", help="single run, OR a sweep if a --sweep-* flag is given")
    pr.add_argument("--config", help="optional base scenario YAML (else built-in defaults)")
    pr.add_argument("--tx-type", dest="tx_type",
                    help="tx type (1-tip-transparent | defunct | amount-shielded | full-shielded)")
    pr.add_argument("-n", "--num-txs", type=int, dest="num_txs", help="measured txs K")
    pr.add_argument("-i", "--num-inputs", type=int, dest="num_inputs", help="inputs per tx I")
    pr.add_argument("-o", "--num-outputs", type=int, dest="num_outputs", help="outputs per tx O")
    pr.add_argument("-w", "--warmup", type=int, dest="warmup", help="warm-up txs W (discarded)")
    pr.add_argument("--window", type=int, help="rolling-curve window (default: adaptive)")
    pr.add_argument("--seed", type=int, help="RNG seed")
    pr.add_argument("--sweep-inputs", nargs=2, type=int, metavar=("MIN", "MAX"),
                    help="sweep I over [MIN..MAX] (O, N fixed)")
    pr.add_argument("--sweep-outputs", nargs=2, type=int, metavar=("MIN", "MAX"),
                    help="sweep O over [MIN..MAX] (I, N fixed)")
    pr.add_argument("--sweep-txs", nargs="+", type=int, metavar="N",
                    help="sweep batch size over the given list")
    _add_shielded_flags(pr)
    pr.add_argument("--mult-batches", nargs=argparse.REMAINDER, dest="mult_batches",
                    help="run a SEQUENCE of segments as one timed stream (TPS-over-time). Each segment: "
                         "--n N [-i I -o O] [--shielded|--amount-shielded -i Is -o Os]. "
                         "Example: --mult-batches --n 2000 -i 5 -o 2 --n 2000 -i 5 -o 2 --shielded -i 2 -o 2")
    pr.set_defaults(fn=_cmd_run)

    psw = sub.add_parser("sweep", help="(back-compat) sweep via --axis io|n --values ...")
    psw.add_argument("--config", help="optional base scenario YAML")
    psw.add_argument("--axis", choices=["io", "n"], default="io")
    psw.add_argument("--values", help="io: '1:2,2:2,3:2'   n: '50,100,500,1000'")
    psw.add_argument("-n", "--num-txs", type=int, dest="num_txs")
    psw.add_argument("-w", "--warmup", type=int, dest="warmup")
    _add_shielded_flags(psw)
    psw.set_defaults(fn=_cmd_sweep)

    psc = sub.add_parser("script", help="run a named script from scripts/ (e.g. demo_experiments)")
    psc.add_argument("name", help="script name (without .py); see `list`")
    psc.add_argument("args", nargs=argparse.REMAINDER, help="extra args passed to the script")
    psc.set_defaults(fn=_cmd_script)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # `--mult-batches` is followed by a free-form segment stream (--n/-i/-o/--shielded ...)
    # that argparse would mis-parse (abbreviation clashes). Split it off before argparse and
    # attach the raw tokens to args; the parser keeps the flag only for --help visibility.
    seg_tokens = None
    if "--mult-batches" in argv:
        idx = argv.index("--mult-batches")
        seg_tokens, argv = argv[idx + 1:], argv[:idx]
    args = build_parser().parse_args(argv)
    if seg_tokens is not None:
        args.mult_batches = seg_tokens
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
