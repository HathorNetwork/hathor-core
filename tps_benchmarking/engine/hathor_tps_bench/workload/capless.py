"""Capless workloads — lift the 255-per-tx cap on the SOURCE supply so fully-shielded
(shielded-input + shielded-output) txs can be measured at high N × inputs.

Background: the transparent funding already scales (value-based coinbase consolidation — 40k+
UTXOs verified), so it needs no change. The shielded `mixed-full` source pool, however, leans on
the DAGBuilder auto-filler (the single `dummy` tx) to fund ALL shielded sources at once — which
overflows the 255-output cap past ~6.4k source UTXOs (`struct.error: ubyte ... <= 255`). This
module funds each shielded source EXPLICITLY from a chunked transparent fund chain (every fund tx
emits <= FUND_CHUNK outputs; every source spends its own UTXO), removing the ceiling.

tx-types registered:
  * capless-1-tip          — transparent 1-tip on the existing robust funding (here for symmetry +
                             as the equivalence baseline vs 1-tip-transparent).
  * capless-full-shielded  — fully shielded in+out: the `-i`/`-o` counts are the SHIELDED input/
                             output counts (mirrors mixed-full with the transparent slice = 0),
                             funded via the chunked core.
"""
from __future__ import annotations

import math
from typing import Any

from hathor_tps_bench.workload.base import PreparedTx
from hathor_tps_bench.workload.registry import register_txtype
from hathor_tps_bench.workload.transparent import COINBASE_VALUE, FUND_CHUNK, OneTipTransparentTxSource

SRC_CHUNK = 16  # shielded UTXOs minted per source tx (>= 2 for verify_trivial_commitment_protection)


@register_txtype("capless-1-tip")
class CaplessOneTipTransparent(OneTipTransparentTxSource):
    """Transparent 1-tip on the value-based robust funding (already capless to 40k+ UTXOs).
    Behaviour-identical to 1-tip-transparent — registered for symmetry and as the equivalence
    baseline for capless-full-shielded."""


@register_txtype("capless-full-shielded")
class CaplessFullShielded(OneTipTransparentTxSource):
    """Fully shielded in+out (shielded inputs + shielded outputs) with EXPLICIT chunked source
    funding, so `N × shielded-inputs` is not bounded by the dummy-filler 255 cap."""

    shielded = True
    _suffix = " [full-shielded]"
    _fee_setting = "FEE_PER_FULL_SHIELDED_OUTPUT"
    _fee = 0

    def _output_suffix(self) -> str:
        return self._suffix

    def _fee_per_output(self) -> int:
        return self._fee

    def build(self, harness: Any, num_txs: int, num_inputs: int, num_outputs: int) -> list[PreparedTx]:
        self._fee = getattr(harness.manager._settings, self._fee_setting)
        return super().build(harness, num_txs, num_inputs, num_outputs)

    def render_dsl(self, num_txs: int, num_inputs: int, num_outputs: int) -> str:
        # here num_inputs/num_outputs are the SHIELDED input/output counts (transparent slice = 0)
        s_i, s_o = num_inputs, num_outputs
        if s_i < 1:
            raise ValueError("capless-full-shielded needs >= 1 shielded input")
        if s_o < 2:
            raise ValueError("capless-full-shielded needs >= 2 shielded outputs "
                             "(verify_trivial_commitment_protection)")
        fpo, suffix = self._fee_per_output(), self._output_suffix()
        # value per source UTXO (== a measured tx's per-input value); chosen so each measured
        # output gets >= 1 after the per-output fee (mirrors mixed.py's `per`).
        per = max(1, math.ceil((s_o + s_o * fpo) / s_i))
        base, rem = divmod(s_i * per - s_o * fpo, s_o)

        # --- size the shielded source pool: n_s UTXOs, chunked <= SRC_CHUNK per source tx -------
        n_s = num_txs * s_i
        s_sizes: list[int] = []
        rem_s = n_s
        while rem_s > 0:
            c = min(SRC_CHUNK, rem_s)
            s_sizes.append(max(c, 2))          # never leave a 1-output shielded source
            rem_s -= c
        n_src = len(s_sizes)

        # each source is funded by ONE transparent UTXO covering its shielded outputs + their fee
        # exactly (input = size*per + size*fpo), so no auto-filler is needed for the sources.
        fund_values = [size * (per + fpo) for size in s_sizes]
        total_fund_value = sum(fund_values)

        # --- transparent fund chain mints those UTXOs, <= FUND_CHUNK per fund tx ----------------
        f_sizes: list[int] = []
        rem_f = n_src
        while rem_f > 0:
            f_sizes.append(min(FUND_CHUNK, rem_f))
            rem_f -= min(FUND_CHUNK, rem_f)
        n_funds = len(f_sizes)
        # value-based coinbase count (stays small; NOTE: a single consolidation tx assumes
        # n_coin <= 255 — true for all realistic value totals here).
        n_coin = max(1, math.ceil(total_fund_value / COINBASE_VALUE) + 1)
        lock = n_coin + 12
        tx_anchor = lock + 5
        total_blocks = tx_anchor + 3

        lines = [f"blockchain genesis b[1..{total_blocks}]", f"b{lock} < dummy"]

        vals = iter(fund_values)
        for f, size in enumerate(f_sizes):
            if f == 0:
                for c in range(n_coin):
                    lines.append(f"b{c + 1}.out[0] <<< fund0")
            for k in range(size):
                lines.append(f"fund{f}.out[{k}] = {next(vals)} HTR")
            if f + 1 < n_funds:
                lines.append(f"fund{f}.out[{size}] <<< fund{f + 1}")   # change chains to next fund
            if f >= 2:
                lines.append(f"fund{f} --> fund{f - 1}")
                lines.append(f"fund{f} --> fund{f - 2}")
            elif f == 1:
                lines.append("fund1 --> fund0")
            lines.append(f"b{lock} < fund{f}")

        fund_utxos = [(f, k) for f, size in enumerate(f_sizes) for k in range(size)]

        # --- shielded sources: each spends its fund UTXO, emits `size` shielded outputs ---------
        for j, size in enumerate(s_sizes):
            ff, fk = fund_utxos[j]
            lines.append(f"fund{ff}.out[{fk}] <<< ssrc{j}")
            for k in range(size):
                lines.append(f"ssrc{j}.out[{k}] = {per} HTR{suffix}")
            if j >= 2:
                lines.append(f"ssrc{j} --> ssrc{j - 1}")
                lines.append(f"ssrc{j} --> ssrc{j - 2}")
            elif j == 1:
                lines.append("ssrc1 --> ssrc0")
            lines.append(f"b{lock} < ssrc{j}")

        # --- measured txs: spend s_i shielded UTXOs, emit s_o shielded outputs, tip-chained -----
        s_utxos = [(j, k) for j, size in enumerate(s_sizes) for k in range(size)]
        us = 0
        for t in range(num_txs):
            name = f"tx{t}"
            for _ in range(s_i):
                j, k = s_utxos[us]
                us += 1
                lines.append(f"ssrc{j}.out[{k}] <<< {name}")
            for o in range(s_o):
                v = base + (rem if o == s_o - 1 else 0)
                lines.append(f"{name}.out[{o}] = {v} HTR{suffix}")
            lines.extend(self._frontier_lines(t, name, tx_anchor))
        return "\n".join(lines)
