"""B3 — capless workload equivalence vs the originals.

Proves the two capless workloads MEASURE THE SAME THING as the sources they parallel, so results
collected with them are comparable to the earlier ones:

  * capless-1-tip     == 1-tip-transparent
      A bare subclass of OneTipTransparentTxSource (no overrides) → the rendered DSL is byte-identical
      AND, built through a fresh same-seed node, the measured-tx hashes are identical. Noise-free, exact.

  * capless-full-shielded == mixed-full (with the transparent slice zeroed: t_i=t_o=0)
      Both compute per/base/rem identically and emit the same measured txs (s_i shielded inputs, s_o
      shielded outputs, same output values, same SRC_CHUNK source chunking). The ONLY difference is the
      UNTIMED source funding (capless: explicit chunked transparent funds; mixed: the dummy auto-filler
      — which is why mixed overflows past ~6.4k source UTXOs and capless does not). So the MEASURED txs
      are structurally identical; we assert that exactly, then check processing throughput agrees within
      a loose band (single-thread WSL timings are noisy).

Structural checks are HARD ASSERTS (script exits non-zero on any mismatch). Timing is a loose sanity
band only. Caching (HATHOR_BENCH_CACHE_RANGE_PROOFS) is irrelevant here — it only affects build, not
the measured processing — so we leave it off.

Run (from repo root):
  PYTHONPATH=tps_benchmarking/engine:. <venv>/bin/python \
      tps_benchmarking/engine/scripts/capless_equivalence_experiment.py
"""
from __future__ import annotations

import os
import re
import sys

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
TIMING_TOL = 0.20  # ±20% band for the loose processing-throughput sanity check

_IN_RE = re.compile(r"<<< (tx\d+)$")                       # `<src>.out[k] <<< tx{t}`
_OUT_RE = re.compile(r"^(tx\d+)\.out\[\d+\] = (\d+) HTR")   # `tx{t}.out[o] = V HTR[ suffix]`


def measured_shape(dsl: str) -> dict[str, dict]:
    """Extract, per measured tx, {n_in, outs:[values]} from a rendered DSL — ignoring the source/
    funding lines entirely (they never reference a `tx{t}` name). This is the measurement target."""
    shape: dict[str, dict] = {}
    for line in dsl.splitlines():
        line = line.strip()
        m = _IN_RE.search(line)
        if m:
            shape.setdefault(m.group(1), {"n_in": 0, "outs": []})["n_in"] += 1
            continue
        m = _OUT_RE.match(line)
        if m:
            shape.setdefault(m.group(1), {"n_in": 0, "outs": []})["outs"].append(int(m.group(2)))
    return shape


def build_hashes(tx_type: str, n: int, i: int, o: int) -> list[bytes]:
    """Build `n` measured txs through a fresh same-seed node; return their hashes (bytes)."""
    cls = get_txtype(tx_type)
    h = NodeHarness(seed=SEED, trivial_pow=True, shielded=cls.shielded).start()
    try:
        prepared = cls().build(h, n, i, o)
        return [p.tx.hash for p in prepared]
    finally:
        h.stop()


def measure_tps(tx_type: str, n: int, i: int, o: int, warmup: int = 5,
                shielded_slice: tuple[int, int] | None = None) -> tuple[float, int]:
    """Build + drive a workload; return (processing_tps, accepted). `shielded_slice` sets the
    (s_i, s_o) instance attrs used by mixed-* to render a fully-shielded tx (transparent slice 0)."""
    cls = get_txtype(tx_type)
    h = NodeHarness(seed=SEED, trivial_pow=True, shielded=cls.shielded).start()
    try:
        src = cls()
        if shielded_slice is not None:
            src.shielded_inputs, src.shielded_outputs = shielded_slice
        prepared = src.build(h, warmup + n, i, o)
        result = run_batch(h, prepared, sampler_interval_s=0.1, warmup=warmup)
    finally:
        h.stop()
    head = compute.headline(result, tdp_watts=65.0, cpu_util=1.0)
    return head["processing_tps"], head["accepted"]


def full_shielded_fee() -> int:
    """Read FEE_PER_FULL_SHIELDED_OUTPUT from a real node's settings (needed so both instances render
    identical per/base/rem in the structural comparison)."""
    h = NodeHarness(seed=SEED, trivial_pow=True, shielded=True).start()
    try:
        return h.manager._settings.FEE_PER_FULL_SHIELDED_OUTPUT
    finally:
        h.stop()


def part1_transparent() -> bool:
    print("== Part 1: capless-1-tip  ==  1-tip-transparent (exact) ==")
    N, ni, no = 20, 2, 2
    cap, base = get_txtype("capless-1-tip")(), get_txtype("1-tip-transparent")()
    dsl_cap, dsl_base = cap.render_dsl(N, ni, no), base.render_dsl(N, ni, no)
    dsl_ok = dsl_cap == dsl_base
    print(f"  rendered DSL identical (N={N} I{ni} O{no}): {dsl_ok}")

    h_cap = build_hashes("capless-1-tip", N, ni, no)
    h_base = build_hashes("1-tip-transparent", N, ni, no)
    hash_ok = h_cap == h_base
    print(f"  measured-tx hashes identical ({len(h_cap)} txs, same seed): {hash_ok}")
    ok = dsl_ok and hash_ok
    print(f"  -> {'PASS' if ok else 'FAIL'}\n")
    return ok


def part2_full_shielded(fee: int) -> bool:
    print("== Part 2: capless-full-shielded  ==  mixed-full (transparent slice 0) ==")
    N, s_i, s_o = 30, 8, 8    # 240 shielded source UTXOs — inside mixed-full's ~6.4k dummy-filler cap
    ok = True

    # -- structural: identical measured txs (input counts + shielded output values) --------------
    cap = get_txtype("capless-full-shielded")()
    cap._fee = fee
    mix = get_txtype("mixed-full")()
    mix._fee = fee
    mix.shielded_inputs, mix.shielded_outputs = s_i, s_o
    shape_cap = measured_shape(cap.render_dsl(N, s_i, s_o))
    shape_mix = measured_shape(mix.render_dsl(N, 0, 0))   # transparent slice 0 -> fully shielded

    same_txs = set(shape_cap) == set(shape_mix) == {f"tx{t}" for t in range(N)}
    struct_ok = same_txs and all(shape_cap[k] == shape_mix[k] for k in shape_cap)
    print(f"  measured txs: capless={len(shape_cap)} mixed={len(shape_mix)} (expect {N} each)")
    print(f"  per-tx input-count + output-value lists identical: {struct_ok}")
    if not struct_ok:
        # surface the first divergence for debugging
        for k in sorted(shape_cap, key=lambda s: int(s[2:])):
            if shape_cap.get(k) != shape_mix.get(k):
                print(f"    first diff @ {k}: capless={shape_cap.get(k)} mixed={shape_mix.get(k)}")
                break
    ok = ok and struct_ok

    # -- timing sanity: processing throughput agrees within the band ----------------------------
    tps_cap, acc_cap = measure_tps("capless-full-shielded", N, s_i, s_o)
    tps_mix, acc_mix = measure_tps("mixed-full", N, 0, 0, shielded_slice=(s_i, s_o))
    acc_ok = acc_cap == acc_mix == N
    ratio = tps_cap / tps_mix if tps_mix else 0.0
    timing_ok = (1 - TIMING_TOL) <= ratio <= (1 + TIMING_TOL)
    print(f"  accepted: capless={acc_cap}/{N} mixed={acc_mix}/{N}  ({'ok' if acc_ok else 'MISMATCH'})")
    print(f"  processing TPS: capless={tps_cap:.0f} mixed={tps_mix:.0f}  ratio={ratio:.2f} "
          f"(band {1-TIMING_TOL:.2f}-{1+TIMING_TOL:.2f}: {'ok' if timing_ok else 'OUT OF BAND'})")
    ok = ok and acc_ok and timing_ok
    print(f"  -> {'PASS' if ok else 'FAIL'}\n")
    return ok


def main() -> int:
    print("B3 capless equivalence experiment (seed=%d)\n" % SEED)
    fee = full_shielded_fee()
    p1 = part1_transparent()
    p2 = part2_full_shielded(fee)
    allok = p1 and p2
    print(f"OVERALL: {'PASS' if allok else 'FAIL'}  (part1={p1} part2={p2})")
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
