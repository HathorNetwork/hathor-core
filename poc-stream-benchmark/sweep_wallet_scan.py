#!/usr/bin/env python3
"""
Grid sweep driver for the wallet-scan benchmark across crypto bindings.

Runs the FULL Cartesian product  N × M  (NOT a dot product):
  - N (stream size)     default: 150,200,250,300,350,400,450,500
  - M (shielded outputs) default: 1,2,3,4

Per cell the tx shape is "M shielded outputs + M transparent inputs", i.e.
  -M M  --total-outputs M  -Q 0  --total-inputs M
(no transparent outputs, no shielded inputs; an equal number of transparent
inputs to shielded outputs). Single token (HTR), k-bit amounts.

For each binding it invokes the right runner, all of which append a row with the
same CSV schema (tagged by `binding`) to <output-dir>/wallet_scan.csv:
  - rust-pure : the native cargo example  (../hathor-ct-crypto, no FFI/runtime)
  - node-napi : benchmark_wallet_scan_node.js  (@hathor/ct-crypto-node)
  - wasm      : benchmark_wallet_scan_wasm.js   (@hathor/ct-crypto-wasm, recovery-only)

This driver is plain python3 — it does NOT import `hathor`, so it needs no
poetry env. It shells out to `cargo` (rust-pure) and `node` (node/wasm) directly,
sidestepping the python launcher's module-level hathor import.

NOTE on shapes: the wasm binding is recovery-only and ignores M'/Q/Q' — it just
recovers the M shielded outputs/tx. So wasm rows always record total_inputs=0;
the "M transparent inputs" only participates in the rust-pure / node-napi rows
(where inputs feed range/balance verification). This is inherent to wasm having
no verify/create surface, not a bug.

Examples:
  # Full default grid, all three bindings, into results_sweep/:
  python3 sweep_wallet_scan.py --node "$(nvm which 18 2>/dev/null || echo node)"

  # Just rust-pure, quick check on a 2x2 grid:
  python3 sweep_wallet_scan.py --bindings rust-pure --n-list 150,300 --m-list 1,2

  # See the commands without running them:
  python3 sweep_wallet_scan.py --dry-run
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CRATE_MANIFEST = os.path.normpath(os.path.join(HERE, '..', 'hathor-ct-crypto', 'Cargo.toml'))
ALL_BINDINGS = ('rust-pure', 'node-napi', 'wasm')


def _parse_int_list(s: str) -> list[int]:
    return [int(x) for x in s.replace(' ', '').split(',') if x]


def _build_command(binding: str, n: int, m: int, k: int, runs: int, output_dir: str, node: str) -> list[str]:
    """Build the argv for one (binding, N, M) cell.

    Shape: M shielded + 0 transparent outputs; 0 shielded + M transparent inputs.
    """
    shape = ['-N', str(n), '-M', str(m), '--total-outputs', str(m),
             '-Q', '0', '--total-inputs', str(m), '-k', str(k), '--runs', str(runs),
             '--binding', binding, '--output-dir', output_dir]
    if binding == 'rust-pure':
        return ['cargo', 'run', '--release', '--quiet', '--example', 'wallet_scan_native',
                '--manifest-path', CRATE_MANIFEST, '--', *shape]
    if binding == 'node-napi':
        return [node, os.path.join(HERE, 'benchmark_wallet_scan_node.js'), *shape]
    if binding == 'wasm':
        return [node, os.path.join(HERE, 'benchmark_wallet_scan_wasm.js'), *shape]
    raise SystemExit(f'unknown binding: {binding}')


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--n-list', default='150,200,250,300,350,400,450,500',
                   help='comma-separated stream sizes N (default 150..500 step 50)')
    p.add_argument('--m-list', default='1,2,3,4',
                   help='comma-separated shielded-output counts M (default 1,2,3,4)')
    # k=63, not 64: with M'=M (no budget split) an M=1 tx's single amount is the
    # whole k-bit budget. The secp256k1 rangeproof uses min_value=1 (VULN-005), and
    # it CANNOT prove a top-bit-set 64-bit amount — min_value + 2^64 overflows u64,
    # so create_range_proof fails. k=63 keeps every amount < 2^63 (always provable).
    p.add_argument('-k', '--bits', type=int, default=63,
                   help='amount bit-width (default 63 — the max a min_value=1 rangeproof can prove; '
                        'k=64 fails for un-split single amounts)')
    p.add_argument('--runs', type=int, default=1, help='runs averaged per cell (default 1)')
    p.add_argument('--bindings', default=','.join(ALL_BINDINGS),
                   help=f'comma-separated bindings to run (default {",".join(ALL_BINDINGS)})')
    p.add_argument('--output-dir', default=os.path.join(HERE, 'results_sweep'),
                   help='dir for the shared wallet_scan.csv (default results_sweep/)')
    p.add_argument('--node', default='node',
                   help='node binary for the node/wasm bindings (e.g. an nvm path). Default: node on PATH')
    p.add_argument('--dry-run', action='store_true', help='print the commands without running them')
    args = p.parse_args()

    n_list = _parse_int_list(args.n_list)
    m_list = _parse_int_list(args.m_list)
    bindings = [b for b in args.bindings.replace(' ', '').split(',') if b]
    for b in bindings:
        if b not in ALL_BINDINGS:
            raise SystemExit(f"unknown binding '{b}'; choose from {ALL_BINDINGS}")
    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    total_cells = len(bindings) * len(n_list) * len(m_list)
    print(f'Grid sweep: bindings={bindings}  N={n_list}  M={m_list}  k={args.bits}  runs={args.runs}')
    print(f'  {len(n_list)}×{len(m_list)} grid × {len(bindings)} binding(s) = {total_cells} cells')
    print(f'  CSV -> {os.path.join(output_dir, "wallet_scan.csv")}')
    if args.dry_run:
        print('  (dry run)\n')

    started = time.time()
    done = 0
    failures: list[tuple[str, int, int, str]] = []
    for binding in bindings:  # outer loop groups each binding's rows together
        binding_failed_fast = False
        for n in n_list:
            for m in m_list:
                done += 1
                cmd = _build_command(binding, n, m, args.bits, args.runs, output_dir, args.node)
                tag = f'[{done}/{total_cells}] {binding} N={n} M={m}'
                if args.dry_run:
                    print(f'{tag}\n    {" ".join(cmd)}')
                    continue
                if binding_failed_fast:
                    print(f'{tag}: SKIPPED (binding {binding} failed on its first cell)')
                    continue
                print(f'\n=== {tag} ===', flush=True)
                t0 = time.time()
                result = subprocess.run(cmd)
                dt = time.time() - t0
                if result.returncode != 0:
                    msg = f'exit {result.returncode}'
                    print(f'{tag}: FAILED ({msg}, {dt:.1f}s)')
                    failures.append((binding, n, m, msg))
                    # First cell of a binding failing usually means a setup problem
                    # (wrong node, missing package) — skip the rest of this binding
                    # so the user gets fast feedback instead of N×M identical errors.
                    if n == n_list[0] and m == m_list[0]:
                        binding_failed_fast = True
                        print(f'  -> skipping remaining {binding} cells (setup issue?)')
                else:
                    print(f'{tag}: ok ({dt:.1f}s)')

    elapsed = time.time() - started
    print(f'\nSweep finished in {elapsed:.1f}s. CSV: {os.path.join(output_dir, "wallet_scan.csv")}')
    if failures:
        print(f'{len(failures)} cell(s) FAILED:')
        for b, n, m, msg in failures:
            print(f'  {b} N={n} M={m}: {msg}')
        sys.exit(1)


if __name__ == '__main__':
    main()
