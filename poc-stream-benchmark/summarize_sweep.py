#!/usr/bin/env python3
"""
Summarize results_sweep/wallet_scan.csv into cross-binding comparison tables.

The apples-to-apples metric across ALL three bindings is the per-shielded-output
RECOVERY cost:
  - rust-pure / node-napi : ecdh + rewind + recover_check (three split timers)
  - wasm                  : the bundled rewindFullShieldedOutput (ecdh + rewind +
                            the internal AUDIT-C015 recheck in one call)
Recovery is per-output, so the ms/output figure is ~independent of N and M; we
group by M and average over the N sweep.

Verify-side phases (range / surjection / balance) exist only for rust-pure and
node-napi (wasm has no verify surface), so those tables omit wasm.

Usage: python3 summarize_sweep.py [--csv results_sweep/wallet_scan.csv]
"""
from __future__ import annotations

import argparse
import csv
import os
import statistics as st
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))


def f(x: str) -> float:
    return float(x) if x not in ('', None) else float('nan')


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--csv', default=os.path.join(HERE, 'results_sweep', 'wallet_scan.csv'))
    args = p.parse_args()

    rows = list(csv.DictReader(open(args.csv)))
    # index: (binding, M) -> list of rows ; and (binding, N, M) -> row
    by_bm: dict[tuple, list] = defaultdict(list)
    cell: dict[tuple, dict] = {}
    bindings, ms, ns = [], set(), set()
    for r in rows:
        b, n, m = r['binding'], int(r['n']), int(r['shielded_outputs'])
        by_bm[(b, m)].append(r)
        cell[(b, n, m)] = r
        if b not in bindings:
            bindings.append(b)
        ms.add(m); ns.add(n)
    ms = sorted(ms); ns = sorted(ns)
    order = [b for b in ('rust-pure', 'node-napi', 'wasm') if b in bindings]

    def recov_ms(r: dict) -> float:
        if r['binding'] == 'wasm':
            return f(r['per_rewind_ms'])  # bundled
        return f(r['per_ecdh_ms']) + f(r['per_rewind_ms']) + f(r['per_recover_check_ms'])

    def mean_over_n(b: str, m: int, fn) -> float:
        return st.mean(fn(r) for r in by_bm[(b, m)])

    print(f'Sweep: bindings={order}  N={ns}  M={ms}  ({len(rows)} rows)\n')

    # ── Table 1: per-output recovery cost, grouped by M (mean over N) ──────────
    print('RECOVERY — ms per shielded output  (cross-binding apples-to-apples)')
    print('  rust-pure/node = ecdh+rewind+recheck;  wasm = bundled rewindFullShieldedOutput')
    hdr = f'  {"M":>2} | ' + ' | '.join(f'{b:>9}' for b in order)
    extra = ' | wasm/rust | node/rust' if {'wasm', 'rust-pure', 'node-napi'} <= set(order) else ''
    print(hdr + extra)
    print('  ' + '-' * (len(hdr) + len(extra) - 2))
    rec_means = {}
    for m in ms:
        vals = {b: mean_over_n(b, m, recov_ms) for b in order}
        rec_means[m] = vals
        line = f'  {m:>2} | ' + ' | '.join(f'{vals[b]:9.3f}' for b in order)
        if extra:
            line += f' | {vals["wasm"]/vals["rust-pure"]:8.2f}x | {vals["node-napi"]/vals["rust-pure"]:8.2f}x'
        print(line)
    # overall mean across all cells
    allv = {b: st.mean(recov_ms(r) for (bb, m) in by_bm for r in by_bm[(bb, m)] if bb == b) for b in order}
    line = f'  {"all":>2} | ' + ' | '.join(f'{allv[b]:9.3f}' for b in order)
    if extra:
        line += f' | {allv["wasm"]/allv["rust-pure"]:8.2f}x | {allv["node-napi"]/allv["rust-pure"]:8.2f}x'
    print(line)

    # ── Table 2: range-proof verify per proof (rust vs node) ───────────────────
    vbind = [b for b in order if b != 'wasm']
    if vbind:
        print('\nRANGE-PROOF VERIFY — ms per proof  (wasm has no verify surface)')
        print(f'  {"M":>2} | ' + ' | '.join(f'{b:>9}' for b in vbind)
              + (' | node/rust' if set(vbind) == {'rust-pure', 'node-napi'} else ''))
        for m in ms:
            vals = {b: mean_over_n(b, m, lambda r: f(r['per_range_verify_ms'])) for b in vbind}
            line = f'  {m:>2} | ' + ' | '.join(f'{vals[b]:9.3f}' for b in vbind)
            if set(vbind) == {'rust-pure', 'node-napi'}:
                line += f' | {vals["node-napi"]/vals["rust-pure"]:8.2f}x'
            print(line)

    # ── Table 3: full-stream total wall time at the largest N ──────────────────
    nmax = ns[-1]
    print(f'\nTOTAL wall time per stream (s) at N={nmax}  '
          f'(rust/node = full 7-phase pass; wasm = recovery-only)')
    print(f'  {"M":>2} | ' + ' | '.join(f'{b:>9}' for b in order))
    for m in ms:
        vals = {b: f(cell[(b, nmax, m)]['total_s']) for b in order}
        print(f'  {m:>2} | ' + ' | '.join(f'{vals[b]:9.3f}' for b in order))

    print('\nNote: wasm rows record total_inputs=0 (recovery ignores inputs); the '
          '"M transparent\n  inputs" only participates in rust-pure / node-napi '
          '(range + balance verify).')


if __name__ == '__main__':
    main()
