"""Multi-batch workloads (Phase B part 2, CP-12; per-mode in CP-13+) — concatenate several
per-segment shapes into ONE timed run, so the throughput-over-time curve shows TPS shifting as
the transaction composition changes on the fly.

A *segment* is a count + a mixed shape + a shielded mode: `n` txs, each with `t_i` transparent +
`s_i` shielded inputs and `t_o` transparent + `s_o` shielded outputs (the CP-11 mixed shape); the
shielded slice is AMOUNT_ONLY (`mode='amount'`) or FULLY_SHIELDED (`mode='full'`). Different
segments may use different modes in one run.

One DSL (separate build_from_str calls collide on `blockchain genesis`), with:
  * a shared transparent fund pool (`fund` txs, chained, coinbase-funded);
  * a shared AMOUNT shielded source pool (`ssrc_a`) and FULL shielded source pool (`ssrc_f`),
    chained, filler-funded, providing shielded UTXOs of the matching mode for shielded inputs;
  * per-segment targets `s{k}_tx{t}` consuming from those pools, with the segment's shape + mode;
  * one continuous organic chain — every target parents the previous one across segment boundaries
    (tips≈1, so the curve reflects composition, not consensus).

Scale note: shielded INPUTS need pre-created shielded UTXOs from the source pools, which are
filler-funded — bounded by the dummy/genesis ~255 caps (a few thousand shielded UTXOs total). Large
shielded-input runs must therefore keep `Σ n·s_i` modest. (Transparent inputs scale far higher via
coinbases, and give the same surjection-domain size — #inputs — for the full-shielded cost.)
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from hathor_tps_bench.workload.base import PreparedTx
from hathor_tps_bench.workload.mixed import SRC_CHUNK
from hathor_tps_bench.workload.transparent import COINBASE_VALUE, FUND_CHUNK

_SUFFIX = {"amount": " [shielded]", "full": " [full-shielded]"}


@dataclass
class Segment:
    """One batch in the sequence: `n` txs of shape (t_i transparent + s_i shielded inputs,
    t_o transparent + s_o shielded outputs); the shielded slice's mode is 'amount' | 'full'
    (or None when there is no shielded slice)."""
    n: int
    t_i: int = 0
    t_o: int = 0
    s_i: int = 0
    s_o: int = 0
    mode: str | None = None

    def n_in(self) -> int:
        return self.t_i + self.s_i

    def n_out(self) -> int:
        return self.t_o + self.s_o


def _chunks(total: int, size: int, *, min_each: int = 1) -> list[int]:
    out: list[int] = []
    rem = total
    while rem > 0:
        c = min(size, rem)
        if 0 < c < min_each:
            c = min_each          # mint the minimum (e.g. a lone shielded UTXO -> a 2-output source;
        out.append(c)             # the spare is just unconsumed). Don't clamp back down to `total`.
        rem -= c
    return out


def render_multibatch_dsl(segments: list[Segment], fee_amount: int, fee_full: int) -> tuple[str, list[int], list[str]]:
    """Return (dsl, segment_start_indices, target_names_in_stream_order)."""
    fee = {"amount": fee_amount, "full": fee_full}

    def fee_per_output(seg: Segment) -> int:
        return fee.get(seg.mode, 0) if seg.s_o else 0

    for seg in segments:
        if seg.n < 1 or seg.n_in() < 1 or seg.n_out() < 1:
            raise ValueError(f"each segment needs n>=1 and >=1 input and >=1 output (got {seg})")
        if seg.s_o == 1:
            raise ValueError("a shielded slice needs s_o == 0 or >= 2 (verify_trivial_commitment_protection)")
        if (seg.s_i or seg.s_o) and seg.mode not in ("amount", "full"):
            raise ValueError("a shielded slice needs a mode (--shielded/--full-shielded or --amount-shielded)")

    per = max(max(1, math.ceil((s.n_out() + s.s_o * fee_per_output(s)) / s.n_in())) for s in segments)

    total_t = sum(s.n * s.t_i for s in segments)
    total_sa = sum(s.n * s.s_i for s in segments if s.mode == "amount")
    total_sf = sum(s.n * s.s_i for s in segments if s.mode == "full")

    t_sizes = _chunks(total_t, FUND_CHUNK)
    sa_sizes = _chunks(total_sa, SRC_CHUNK, min_each=2)
    sf_sizes = _chunks(total_sf, SRC_CHUNK, min_each=2)
    n_coin = max(1, math.ceil((total_t * per) / COINBASE_VALUE) + 1) if total_t else 1 # What if I start solely with shielded inputs?
    lock = n_coin + 12 # What
    tx_anchor = lock + 5 # What
    total_blocks = tx_anchor + 3 # What

    lines = [f"blockchain genesis b[1..{total_blocks}]", f"b{lock} < dummy"]

    # transparent fund pool (chained; consolidate coinbases -> pinned `per`-valued UTXOs)
    for f, size in enumerate(t_sizes):
        if f == 0:
            for c in range(n_coin):
                lines.append(f"b{c + 1}.out[0] <<< fund0")
        for k in range(size):
            lines.append(f"fund{f}.out[{k}] = {per} HTR")
        if f + 1 < len(t_sizes):
            lines.append(f"fund{f}.out[{size}] <<< fund{f + 1}")
        if f >= 2:
            lines.append(f"fund{f} --> fund{f - 1}")
            lines.append(f"fund{f} --> fund{f - 2}")
        elif f == 1:
            lines.append("fund1 --> fund0")
        lines.append(f"b{lock} < fund{f}")

    # shielded source pools (chained via 2 explicit parents so they don't overflow genesis children)
    def emit_sources(prefix: str, sizes: list[int], suffix: str) -> None:
        for j, size in enumerate(sizes):
            for k in range(size):
                lines.append(f"{prefix}{j}.out[{k}] = {per} HTR{suffix}")
            if j >= 2:
                lines.append(f"{prefix}{j} --> {prefix}{j - 1}")
                lines.append(f"{prefix}{j} --> {prefix}{j - 2}")
            elif j == 1:
                lines.append(f"{prefix}1 --> {prefix}0")
            lines.append(f"b{lock} < {prefix}{j}")

    emit_sources("ssrc_a", sa_sizes, _SUFFIX["amount"])
    emit_sources("ssrc_f", sf_sizes, _SUFFIX["full"])

    t_utxos = [(f, k) for f, size in enumerate(t_sizes) for k in range(size)]
    sa_utxos = [(j, k) for j, size in enumerate(sa_sizes) for k in range(size)]
    sf_utxos = [(j, k) for j, size in enumerate(sf_sizes) for k in range(size)]
    ut = ua = uf = 0

    target_names: list[str] = []
    starts: list[int] = []
    prev: str | None = None
    for k, seg in enumerate(segments):
        starts.append(len(target_names))
        suffix = _SUFFIX.get(seg.mode, "")
        base, rem = divmod(seg.n_in() * per - seg.s_o * fee_per_output(seg), seg.n_out())
        for t in range(seg.n):
            name = f"s{k}_tx{t}"
            target_names.append(name)
            for _ in range(seg.t_i):
                f, idx = t_utxos[ut]; ut += 1
                lines.append(f"fund{f}.out[{idx}] <<< {name}")
            for _ in range(seg.s_i):
                if seg.mode == "amount":
                    j, idx = sa_utxos[ua]; ua += 1; src = f"ssrc_a{j}"
                else:
                    j, idx = sf_utxos[uf]; uf += 1; src = f"ssrc_f{j}"
                lines.append(f"{src}.out[{idx}] <<< {name}")
            for o in range(seg.n_out()):
                v = base + (rem if o == seg.n_out() - 1 else 0)
                sfx = suffix if o >= seg.t_o else ""
                lines.append(f"{name}.out[{o}] = {v} HTR{sfx}")
            lines.append(f"b{tx_anchor} < {name}")
            if prev is not None:
                lines.append(f"{name} --> {prev}")
            prev = name
    return "\n".join(lines), starts, target_names


def build_multibatch(harness: Any, segments: list[Segment], fee_amount: int, fee_full: int) -> tuple[list[PreparedTx], list[int]]:
    """Build the whole multi-batch on `harness`; return (prepared targets in stream order, segment
    start indices). Funding is preloaded (untimed); the targets are returned for the timed driver."""
    dsl, starts, target_names = render_multibatch_dsl(segments, fee_amount, fee_full)
    artifacts = harness.dag_builder().build_from_str(dsl)

    targets = set(target_names)
    manager = harness.manager
    by_name: dict[str, Any] = {}
    for node, vertex in artifacts.list:
        if node.name in targets:
            by_name[node.name] = vertex
            continue
        if manager.tx_storage.transaction_exists(vertex.hash):
            continue
        if not manager.vertex_handler.on_new_relayed_vertex(vertex):
            raise RuntimeError(f"funding vertex {node.name!r} was rejected")

    prepared = [
        PreparedTx(tx=(tx := by_name[name]), raw=bytes(tx),
                   n_inputs=len(tx.inputs), n_outputs=len(tx.outputs))
        for name in target_names
    ]
    return prepared, starts
