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
    print(f"hathor_tps_bench v{__version__}")
    print(f"\ntx types   ({len(txtypes)}): {', '.join(txtypes) or '(none registered yet)'}")
    print(f"benchmarks ({len(benches)}): {', '.join(benches) or '(none registered yet)'}")
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


def _cmd_run(args: argparse.Namespace) -> int:
    cfg, errs = _load_and_validate(args.config)
    if errs:
        print("config invalid; run `validate` for details", file=sys.stderr)
        return 1

    # CP-3 builds the workload; CP-4 drives + measures it. (Reporting = CP-5.)
    # Imports are lazy here so `list`/`validate` never pull in hathor/matplotlib.
    from dataclasses import asdict
    from pathlib import Path

    from hathor_tps_bench.analysis import compute, persist, plots, report
    from hathor_tps_bench.driver import run_batch
    from hathor_tps_bench.node import NodeHarness
    from hathor_tps_bench.workload import get_txtype

    w = cfg.workload
    if args.num_txs:
        w.num_txs = args.num_txs            # override K (measured)
    if args.warmup is not None:
        w.warmup_txs = args.warmup          # override W (warm-up, discarded)
    K, W = w.num_txs, w.warmup_txs
    print(f"[run] scenario '{cfg.name}': {w.tx_type} I={w.num_inputs} O={w.num_outputs}, "
          f"K={K} measured (+{W} warm-up) on an in-process node...")

    source = get_txtype(w.tx_type)()
    harness = NodeHarness(seed=cfg.env.seed, trivial_pow=cfg.env.trivial_pow).start()
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
    # M/Tb sustainable-rate table (flat ⇒ Tb-independent for organic; see RFC).
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
    plot_names = plots.generate(run_dir / "plots", result) if "plots" in fmts else []
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


def _parse_shapes(s: str | None):
    return [(int(i), int(o)) for i, o in (tok.split(":") for tok in s.split(","))] if s else None


def _parse_ints(s: str | None):
    return [int(x) for x in s.split(",")] if s else None


def _cmd_sweep(args: argparse.Namespace) -> int:
    cfg, errs = _load_and_validate(args.config)
    if errs:
        print("config invalid:", *(f"\n  - {e}" for e in errs))
        return 2
    from pathlib import Path

    from hathor_tps_bench.analysis import plots, sweep

    w = cfg.workload
    W = args.warmup if args.warmup is not None else w.warmup_txs
    log = lambda p: print(f"  {p.label:9} {p.tps:6.0f} tps   total {p.mean_total_us:7.0f} us   "
                          f"acc {p.accepted}/{p.num_txs}")
    print(f"[sweep] axis={args.axis} on {w.tx_type} (W={W}) — fresh node per point...")
    if args.axis == "io":
        shapes = _parse_shapes(args.values) or [(1, 2), (2, 2), (3, 2), (4, 2), (5, 2), (1, 3), (1, 4), (1, 5)]
        K = args.num_txs or 300
        points = sweep.io_sweep(cfg, w.tx_type, shapes, K, W, on_point=log)
        x_label = "tx shape (I:O)"
    else:
        ns = _parse_ints(args.values) or [50, 100, 200, 500, 1000, 2000]
        points = sweep.n_sweep(cfg, w.tx_type, ns, w.num_inputs, w.num_outputs, W, on_point=log)
        x_label = "batch size N"

    run_dir = Path(cfg.results_root) / f"sweep_{cfg.name}_{w.tx_type}_{args.axis}"
    run_dir.mkdir(parents=True, exist_ok=True)
    plot_names = (plots.sweep_plots(run_dir / "plots", points, x_label=x_label)
                  if "plots" in cfg.reporting.formats else [])
    _write_sweep_report(run_dir / "summary.md", cfg, args.axis, x_label, points, plot_names)
    print(f"\n[sweep] results → {run_dir}/  ({len(plot_names)} plots)")
    return 0


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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hathor_tps_bench", description=__doc__)
    p.add_argument("--version", action="version", version=f"hathor_tps_bench {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show registered tx types and benchmarks").set_defaults(fn=_cmd_list)

    pv = sub.add_parser("validate", help="validate a scenario YAML")
    pv.add_argument("--config", required=True, help="path to scenario YAML")
    pv.set_defaults(fn=_cmd_validate)

    pr = sub.add_parser("run", help="run a scenario (CP-4/CP-5)")
    pr.add_argument("--config", required=True, help="path to scenario YAML")
    pr.add_argument("--select", nargs="*", help="override which benchmarks to run")
    pr.add_argument("--num-txs", type=int, dest="num_txs", help="override workload.num_txs (K, measured)")
    pr.add_argument("--warmup", type=int, dest="warmup", help="override workload.warmup_txs (W, discarded)")
    pr.set_defaults(fn=_cmd_run)

    psw = sub.add_parser("sweep", help="run a parameter sweep (io | n), fresh node per point")
    psw.add_argument("--config", required=True, help="path to scenario YAML")
    psw.add_argument("--axis", choices=["io", "n"], default="io", help="sweep tx shape (io) or batch size (n)")
    psw.add_argument("--values", help="io: '1:2,2:2,3:2'   n: '50,100,500,1000'")
    psw.add_argument("--num-txs", type=int, dest="num_txs", help="K per point (io sweep)")
    psw.add_argument("--warmup", type=int, dest="warmup", help="override warmup_txs per point")
    psw.set_defaults(fn=_cmd_sweep)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
