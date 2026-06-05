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
    # Imports are lazy here so `list`/`validate` never pull in hathor.
    from hathor_tps_bench.config import STAGES
    from hathor_tps_bench.driver import run_batch
    from hathor_tps_bench.node import NodeHarness
    from hathor_tps_bench.workload import get_txtype

    w = cfg.workload
    if args.num_txs:
        w.num_txs = args.num_txs  # quick override for smoke tests
    print(f"[run] scenario '{cfg.name}': building {w.num_txs} {w.tx_type} tx "
          f"(I={w.num_inputs}, O={w.num_outputs}) on an in-process node...")

    source = get_txtype(w.tx_type)()
    harness = NodeHarness(seed=cfg.env.seed, trivial_pow=cfg.env.trivial_pow).start()
    try:
        prepared = source.build(harness, w.num_txs, w.num_inputs, w.num_outputs)
        print(f"[run] built {len(prepared)} txs; driving S1..S6 on the single thread...")
        result = run_batch(harness, prepared, sampler_interval_s=cfg.measure.sampler_interval_s)
        _print_run_summary(result, cfg)
    finally:
        harness.stop()
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
    print("\n  [note] CSV / plots / report land in CP-5.")


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
    pr.add_argument("--num-txs", type=int, dest="num_txs", help="override workload.num_txs")
    pr.set_defaults(fn=_cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
