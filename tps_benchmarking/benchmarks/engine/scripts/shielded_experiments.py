"""
CP-10 shielded measurement matrix. Produces the numbers folded into the RFC/report:
  1. headline: 1-tip-transparent vs amount-shielded vs full-shielded (I1 O2);
  2. range-proof bit-width sweep (full-shielded I1 O2 @ 40/52/64 bits);
  3. shielded-output-count sweep (full-shielded I1 @ O=2/4/8).

Each row builds a FRESH funded node (no state carryover), drives W warm-up + K measured txs
through S1..S6, and reports per-stage mean wall (us), processing TPS, and mean serialized
tx size. Writes a markdown table to docs/shielded-results.md.

Run:  cd tps_benchmarking/benchmarks/engine
      PYTHONPATH="<repo-root>:$PWD" <venv-python> -m hathor_tps_bench script shielded_experiments
  (or invoke this file directly with the same PYTHONPATH)
"""
import os
import sys
from pathlib import Path
from statistics import mean

from hathor_tps_bench.analysis import compute
from hathor_tps_bench.driver import run_batch
from hathor_tps_bench.node import NodeHarness
from hathor_tps_bench.workload import get_txtype

K, W = 30, 5  # measured / warm-up per row


def run_row(tx_type: str, num_inputs: int, num_outputs: int, bits: int | None) -> dict:
    # Range-proof bit-width is read at proof-creation time, so setting it per row works.
    if bits is None:
        os.environ.pop("HATHOR_RANGE_PROOF_BITS", None)
    else:
        os.environ["HATHOR_RANGE_PROOF_BITS"] = str(bits)
    cls = get_txtype(tx_type)
    harness = NodeHarness(seed=1234, trivial_pow=True, shielded=cls.shielded).start()
    try:
        prepared = cls().build(harness, W + K, num_inputs, num_outputs)
        result = run_batch(harness, prepared, sampler_interval_s=0.1, warmup=W)
    finally:
        harness.stop()
    head = compute.headline(result, tdp_watts=65.0, cpu_util=1.0)
    st = {r["stage"]: r["mean_wall_us"] for r in compute.stage_table(result)}
    size = mean(len(p.raw) for p in prepared[W:])
    return {
        "label": f"{tx_type} I{num_inputs} O{num_outputs} @{bits or 64}b",
        "tx_type": tx_type, "I": num_inputs, "O": num_outputs, "bits": bits or 64,
        "accepted": f"{head['accepted']}/{K}", "tps": head["processing_tps"],
        "S1": st["S1"], "S3S4": st["S3S4"], "S5": st["S5"], "S6": st["S6"],
        "total": head["mean_total_us"], "size": size,
    }


def table(title: str, rows: list[dict]) -> str:
    L = [f"### {title}", "",
         "| workload | acc | TPS | S1 µs | S3S4 µs | S5 µs | S6 µs | total µs | size B |",
         "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        L.append(f"| {r['label']} | {r['accepted']} | **{r['tps']:.0f}** | {r['S1']:.0f} | "
                 f"{r['S3S4']:.0f} | {r['S5']:.0f} | {r['S6']:.0f} | {r['total']:.0f} | {r['size']:.0f} |")
    return "\n".join(L)


def main() -> int:
    headline = [run_row("1-tip-transparent", 1, 2, None),
                run_row("amount-shielded", 1, 2, None),
                run_row("full-shielded", 1, 2, None)]
    bits = [run_row("full-shielded", 1, 2, b) for b in (40, 52, 64)]
    outs = [run_row("full-shielded", 1, o, 64) for o in (2, 4, 8)]

    doc = "\n\n".join([
        "# Shielded measurement results (CP-10)",
        f"_K={K} measured (+{W} warm-up) per row, 1-tip-transparent chain (tips≈1), 64-bit unless noted, "
        "single-thread in-process node._",
        table("1. Transparent vs shielded (I1 O2)", headline),
        table("2. Range-proof bit-width (full-shielded I1 O2)", bits),
        table("3. Shielded output count (full-shielded I1, 64-bit)", outs),
    ]) + "\n"
    out = Path(__file__).resolve().parent.parent / "docs" / "shielded-results.md"
    out.write_text(doc, encoding="utf-8")
    print(doc)
    print(f"\n[shielded_experiments] wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
