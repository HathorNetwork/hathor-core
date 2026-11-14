"""Transparent I-in/O-out workloads, built with hathor-core's **DAGBuilder**.

================================================================================
WHAT THIS MODULE PRODUCES
================================================================================
A batch of N valid, signed, transparent transactions (each with exactly `num_inputs`
inputs and `num_outputs` outputs) plus all the blocks/funding they depend on, ready to
be fed one-at-a-time through the node's S1..S6 pipeline by the driver.

The whole DAG looks like this (numbers for N=500, I=1):

    blocks:   genesis -> b1 -> b2 -> ... -> b23        (~23 blocks, NOT N of them)
              each block b{i} carries one coinbase reward output  b{i}.out[0] = 6400 HTR
    funding:  b1.out[0]  --spends-->  fund0   (re-mints it as up to 200 small UTXOs)
              b2.out[0]  --spends-->  fund1
              b3.out[0]  --spends-->  fund2                 (n_funds = ceil(N*I / 200))
    payload:  fundF.out[k]  --spends-->  tx_k              (each tx spends its own UTXOs)
              tx_k emits `num_outputs` pinned outputs
    parents:  set by the subclass (see TIP MECHANICS below)

So: a short fixed-ish chain of blocks just to *mint money*, a handful of fat `fund`
txs to *fan that money out* into many spendable UTXOs, then the N payload txs.

================================================================================
THE DAGBuilder DSL (the strings we emit; parsed by hathor.dag_builder)
================================================================================
We describe the DAG as text and `build_from_str` assembles, signs, and PoW-resolves it.
Operators we use (see hathor/dag_builder/tokenizer.py for the full grammar):

    blockchain genesis b[1..N]   a chain of N blocks b1..bN extending genesis
    a.out[i] <<< b               b SPENDS a's i-th output  (an INPUT/spend edge)
    a.out[i] = V HTR             PIN a's i-th output to value V (constrains balance)
    a < b                        ORDER: a is created before b (=> b.timestamp > a.timestamp)
    a --> b                      PARENT: b is a PARENT of a   (a confirms b)
    (a <-- b would mean a is a parent of b — we don't use it here)

================================================================================
THE FILLER, AND HOW WE CONTROL IT  (hathor/dag_builder/default_filler.py)
================================================================================
DAGBuilder runs a constraint-solving "filler" that makes every vertex *valid* by
auto-completing whatever we leave unspecified. Two behaviours matter to us:

 1. BALANCE. For each tx it computes sum(outputs) - sum(inputs) and, if they don't
    match, it adds inputs (funded from a hidden `dummy` tx that spends genesis) or a
    change output. We DON'T want it improvising on the payload txs, because that would
    change their input/output counts. So we PIN both sides to equal totals (see
    render_dsl): then balance is already 0, the filler adds nothing, and each tx has
    EXACTLY the requested I/O. (On the `fund` txs we let it add change — that's fine.)

 2. PARENTS. Every Hathor tx needs exactly 2 parents. `fill_parents` tops a vertex up
    to 2 using **genesis** and *deliberately never uses other DAG txs* ("it would
    confirm them, violating the DAG description"). This is the crux of TIP MECHANICS.

================================================================================
TIP MECHANICS  (why two subclasses exist)  — the central performance finding
================================================================================
A "tip" = a mempool tx that no other unconfirmed tx names as a parent (no tx-child).
The node's consensus re-scans ALL current tips on every tx (mempool_tips.update is
O(tip count); see CP-4 checkpoint), so the tip count drives per-tx consensus cost.

 * `TransparentTxSource` (genesis-parented): we DON'T emit parent edges, so the filler
   gives every tx two genesis parents. No tx is ever a parent of another => EVERY tx is
   a tip => tips = N => consensus is O(N) per tx => O(N^2) for the batch. This is the
   pathological baseline (kept to demonstrate the effect).

 * `OrganicTxSource` (tip-confirming chain): each tx names the previous tx as a parent
   (`tx_k --> tx_{k-1}`), so each tx confirms its predecessor and only the latest tx is
   ever a tip => tips ~= 1 => consensus is O(1) per tx => flat. This is the realistic
   workload (Option A).

Funding/inputs/outputs are IDENTICAL between the two — the ONLY difference is the
parent edges, isolated in `_frontier_lines`.

This module imports nothing from hathor (all hathor work happens lazily in `build`).
"""
from __future__ import annotations

import math
from typing import Any

from hathor_tps_bench.workload.base import PreparedTx, TxSource
from hathor_tps_bench.workload.registry import register_txtype

# A transaction's output COUNT is serialized as a single unsigned byte, so a tx can hold
# at most 255 outputs. Each `fund` tx therefore mints at most that many UTXOs; we cap at
# 200 for headroom (each fund also carries one change output that chains to the next fund).
FUND_CHUNK = 200

# The unittests block reward (sub-units). Constant within the few blocks we mine — see the
# funding note in render_dsl for why we depend on total *value*, not on this exact figure.
COINBASE_VALUE = 6400


@register_txtype("transparent")
class TransparentTxSource(TxSource):
    """Genesis-parented baseline: every tx is a tip (tips = N). See module docstring."""

    def render_dsl(self, num_txs: int, num_inputs: int, num_outputs: int) -> str:
        """Emit the DAGBuilder DSL describing the whole batch (blocks + funds + N txs)."""
        # --- value bookkeeping -------------------------------------------------------
        # `per` = the value we give each minted UTXO, and hence each tx input. We set it
        # to `num_outputs` so the per-tx arithmetic below divides cleanly into >=1 per
        # output (a tx spending I inputs of value O has I*O to split across O outputs).
        per = max(num_outputs, 1)
        n_utxos = num_txs * num_inputs                     # one disjoint UTXO per tx-input
        n_funds = max(1, math.ceil(n_utxos / FUND_CHUNK))  # how many fat fund txs we need

        # --- block-height anchors ----------------------------------------------------
        # A coinbase reward can't be spent until REWARD_SPEND_MIN_BLOCKS (=10) blocks
        # later (the "reward lock"). The funds spend coinbases b1..b{n_funds}, so the
        # latest coinbase is at height n_funds; `lock` sits comfortably past its maturity.
        # How much value we must mint = n_utxos UTXOs of value `per`. We source it from a
        # CHAIN of fund txs: the FIRST fund consolidates a few coinbases, then each fund
        # mints its UTXOs and passes the leftover (its change output) to the NEXT fund. The
        # number of COINBASE BLOCKS is therefore bounded by total *value* (≈ value/6400),
        # NOT by the UTXO count. (One-coinbase-per-fund would need n_utxos/200 blocks, which
        # for large N*I crosses the reward halving at block BLOCKS_PER_HALVING=120 and a
        # 255-block cap — the funding would break above N*I ~ 20k.)
        total_value = n_utxos * per
        n_coin = max(1, math.ceil(total_value / COINBASE_VALUE) + 1)  # +1 = change headroom
        lock = n_coin + 12             # past the last coinbase's reward maturity (10 blocks)
        tx_anchor = lock + 5           # payload txs are ordered after this block
        total_blocks = tx_anchor + 3   # a few spare blocks past the last anchor

        # Output split: a tx has num_inputs*per HTR to distribute across num_outputs
        # outputs. Give each `base`, and let the LAST output absorb any remainder so the
        # outputs sum EXACTLY to the inputs (=> balanced => filler adds nothing => exact I/O).
        base, rem = divmod(num_inputs * per, num_outputs)

        # Spread the n_utxos across the fund txs, <=FUND_CHUNK each (the last fund may hold
        # fewer). sizes[f] = how many UTXOs fund{f} mints.
        sizes: list[int] = []
        remaining = n_utxos
        for _ in range(n_funds):
            s = min(FUND_CHUNK, remaining)
            sizes.append(s)
            remaining -= s

        # --- emit the DSL ------------------------------------------------------------
        # Pin the auto-`dummy`'s creation past the reward lock (the filler funds shortfalls
        # from a hidden `dummy` that spends genesis; dated too early it trips the reward lock).
        lines = [f"blockchain genesis b[1..{total_blocks}]", f"b{lock} < dummy"]

        # fund0 CONSOLIDATES all the coinbases (b1..b{n_coin}) — the whole funding value.
        for c in range(n_coin):
            lines.append(f"b{c + 1}.out[0] <<< fund0")
        # Each fund mints `size` pinned UTXOs of value `per`; its CHANGE output (index = size,
        # the value the filler computes to balance) is spent by the NEXT fund — the chain.
        # We ALSO chain the funds in the PARENT DAG (`fund_f --> fund_{f-1} fund_{f-2}`): without
        # it the filler parents every fund to genesis, and once n_funds exceeds ~253 genesis's
        # children count overflows its 1-byte field ("ubyte ... 0..255"). Chaining leaves only
        # fund0/fund1 on genesis. (Funds are never mempool tips anyway — their outputs are spent.)
        for f, size in enumerate(sizes):
            for k in range(size):
                lines.append(f"fund{f}.out[{k}] = {per} HTR")      # pin each minted UTXO
            if f + 1 < n_funds:
                lines.append(f"fund{f}.out[{size}] <<< fund{f + 1}")  # change → next fund
            if f >= 2:
                lines.append(f"fund{f} --> fund{f - 1}")           # 2 explicit parents => the
                lines.append(f"fund{f} --> fund{f - 2}")           # filler adds no genesis parent
            elif f == 1:
                lines.append("fund1 --> fund0")
            lines.append(f"b{lock} < fund{f}")                     # created past reward maturity

        # 3) Payload txs. Walk the flat list of (fund, output-index) UTXOs and hand each
        #    tx its own disjoint slice of `num_inputs` of them — disjoint so no two txs
        #    spend the same UTXO (which would be a double-spend and get one voided).
        utxos = [(f, k) for f, size in enumerate(sizes) for k in range(size)]
        u = 0
        for t in range(num_txs):
            name = f"tx{t}"
            for _ in range(num_inputs):
                f, k = utxos[u]
                u += 1
                lines.append(f"fund{f}.out[{k}] <<< {name}")       # tx spends this disjoint UTXO
            for j in range(num_outputs):
                v = base + (rem if j == num_outputs - 1 else 0)     # last output takes the remainder
                lines.append(f"{name}.out[{j}] = {v} HTR")          # pin each output (=> balanced)
            # The parent/ordering line(s) — the ONLY thing that differs between the
            # genesis-parented baseline and the organic chain. See _frontier_lines.
            lines.extend(self._frontier_lines(t, name, tx_anchor))
        return "\n".join(lines)

    def _frontier_lines(self, t: int, name: str, tx_anchor: int) -> list[str]:
        """Parent/ordering DSL line(s) for tx `t` — the workload's "frontier" policy.

        Base policy: no parent edges, just a timestamp anchor (`b{anchor} < tx`). The
        filler then fills BOTH parent slots with genesis, so no tx confirms any other tx
        => every tx is a tip => the mempool-tips scan is O(N). OrganicTxSource overrides
        this to chain the txs and keep the tip set at ~1."""
        return [f"b{tx_anchor} < {name}"]

    def build(self, harness: Any, num_txs: int, num_inputs: int, num_outputs: int) -> list[PreparedTx]:
        """Realise the DSL on the node and return the N payload txs ready to drive.

        DAGBuilder.build_from_str produces `artifacts.list`: a TOPOLOGICALLY-ORDERED list
        of (node, vertex) pairs (dependencies before dependents). We preload everything
        that ISN'T a payload tx (blocks, the dummy, the funds) straight into the node —
        this is untimed setup so the timed driver starts from a fully-funded state — and
        hand back the payload txs as raw bytes for the driver to deserialize + time."""
        dsl = self.render_dsl(num_txs, num_inputs, num_outputs)
        artifacts = harness.dag_builder().build_from_str(dsl)

        targets = {f"tx{t}" for t in range(num_txs)}
        manager = harness.manager
        by_name: dict[str, Any] = {}

        for node, vertex in artifacts.list:
            if node.name in targets:
                # A payload tx: keep it aside (we do NOT preload it — the driver will
                # feed it through S1..S6 and time it). Topological order guarantees that
                # by the time the driver reaches tx_k, its parents (tx_{k-1} in the
                # organic chain) have already been driven and exist in storage.
                by_name[node.name] = vertex
                continue
            if manager.tx_storage.transaction_exists(vertex.hash):
                continue  # genesis (and anything already present) — skip
            # Blocks / dummy / fund txs: push straight into the node via the real
            # processing path so the funding is genuinely in storage + consensus.
            if not manager.vertex_handler.on_new_relayed_vertex(vertex):
                raise RuntimeError(f"funding vertex {node.name!r} was rejected")

        # Return payload txs in t-order (tx0..tx_{N-1}); raw bytes so S1 (deserialize) is
        # measurable, plus the realised I/O counts as ground truth for assertions.
        return [
            PreparedTx(
                tx=(tx := by_name[f"tx{t}"]),
                raw=bytes(tx),
                n_inputs=len(tx.inputs),
                n_outputs=len(tx.outputs),
            )
            for t in range(num_txs)
        ]


@register_txtype("organic")
class OrganicTxSource(TransparentTxSource):
    """Organic, tip-confirming workload: each tx names the PREVIOUS tx as a parent, so
    the chain is `tx0 <- tx1 <- tx2 <- ...`. Every tx therefore confirms its predecessor
    => only the latest tx is ever a tip => the mempool-tips set stays at ~1 instead of
    growing to N, so consensus (S5) stays O(1) per tx (see module docstring / CP-4).

    Funding / inputs / outputs are IDENTICAL to `transparent`; ONLY the parent edges
    change. `tx_k --> tx_{k-1}` makes tx_{k-1} one of tx_k's two parents; the filler
    fills the 2nd slot with genesis (which is never a mempool tip, so it doesn't add to
    the tip count). `tx0` has no predecessor, so it keeps both genesis parents and seeds
    the chain. This is the linear-chain, single-tip variant (Option A); a wider k-tip
    frontier (each tx confirming 2 recent tips, ~2-3 tips, no genesis filler) can come
    later for a more mainnet-like DAG shape."""

    def _frontier_lines(self, t: int, name: str, tx_anchor: int) -> list[str]:
        # Keep the timestamp anchor (harmless belt-and-suspenders; in the chain each tx
        # also inherits a late timestamp from its parent tx_{t-1}). For t>=1 add the
        # parent edge that links this tx to its predecessor — the whole of Option A.
        lines = [f"b{tx_anchor} < {name}"]
        if t >= 1:
            lines.append(f"tx{t} --> tx{t - 1}")  # tx_{t-1} becomes a parent of tx_t
        return lines
