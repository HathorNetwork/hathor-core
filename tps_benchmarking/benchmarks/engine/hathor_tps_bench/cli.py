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

    # CP-3: build the workload on a real in-process node and report it.
    # (Per-stage timing + reporting are wired in CP-4 / CP-5.) Imports are lazy here so
    # `list`/`validate` never pull in hathor.
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
        exact = sum(1 for p in prepared
                    if p.n_inputs == w.num_inputs and p.n_outputs == w.num_outputs)
        distinct_inputs = {(i.tx_id, i.index) for p in prepared for i in p.tx.inputs}
        print(f"[run] built {len(prepared)} txs preloaded with funding")
        print(f"[run] exact I/O     : {exact}/{len(prepared)}")
        print(f"[run] distinct inputs: {len(distinct_inputs)} (expected {w.num_txs * w.num_inputs})")
        print("[run] driver/timing lands in CP-4 — nothing measured yet.")
    finally:
        harness.stop()
    return 0


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
