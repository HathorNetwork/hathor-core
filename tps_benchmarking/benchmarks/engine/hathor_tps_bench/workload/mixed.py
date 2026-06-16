"""Mixed (superposition) workloads — one transaction carrying BOTH transparent and
shielded inputs/outputs. This is Phase B part 1 (CP-11).

A mixed tx shape is four numbers: t_i transparent inputs + s_i shielded inputs, and
t_o transparent outputs + s_o shielded outputs. The pure cases fall out (s_i=s_o=0 →
transparent; t_i=t_o=0 → fully shielded), so this generalises the CP-9 sources.

Construction (organic, tips≈1 — inherited from OneTipTransparentTxSource):
  * transparent input UTXOs come from `fund` txs spending coinbases (as in transparent.py);
  * shielded input UTXOs come from `ssrc` source txs — each is a transparent-in → shielded-out
    tx (filler-funded from the dummy) carrying only shielded outputs, so its shielded output k
    is spendable via DSL `ssrc.out[k]` (on-chain index = k, since it has no transparent outputs);
  * each target `tx{t}` spends t_i transparent UTXOs + s_i shielded UTXOs and emits t_o
    transparent + s_o shielded outputs, value-balanced (the CP-7 reconciliation fixes the last
    shielded output's blinding using ALL inputs, including the recorded shielded-input blindings).

The per-output fee + DSL attribute reuse the `_fee_per_output` / `_output_suffix` hooks; the
shielded mode (amount vs full) is chosen by the subclasses below. The shielded slice (s_i, s_o)
is carried on the instance (set by the caller before build); the transparent slice (t_i, t_o)
is the usual num_inputs/num_outputs build argument.
"""
from __future__ import annotations

import math
from typing import Any

from hathor_tps_bench.workload.base import PreparedTx
from hathor_tps_bench.workload.registry import register_txtype
from hathor_tps_bench.workload.transparent import COINBASE_VALUE, FUND_CHUNK, OneTipTransparentTxSource

SRC_CHUNK = 16  # shielded outputs minted per `ssrc` source tx (>=2 for verify_trivial_commitment_protection; <= MAX_SHIELDED_OUTPUTS)


class _MixedTxSource(OneTipTransparentTxSource):
    """Mixed transparent+shielded workload. Subclasses pick the shielded mode."""

    shielded = True
    _suffix = ""           # " [shielded]" | " [full-shielded]"
    _fee_setting = ""      # FEE_PER_{AMOUNT,FULL}_SHIELDED_OUTPUT
    _fee = 0
    # shielded slice (transparent slice = num_inputs/num_outputs build args):
    shielded_inputs: int = 0
    shielded_outputs: int = 0

    def _output_suffix(self) -> str:
        return self._suffix

    def _fee_per_output(self) -> int:
        return self._fee

    def render_dsl(self, num_txs: int, num_inputs: int, num_outputs: int) -> str:
        t_i, t_o = num_inputs, num_outputs            # transparent slice
        s_i, s_o = self.shielded_inputs, self.shielded_outputs  # shielded slice
        n_in, n_out = t_i + s_i, t_o + s_o
        if n_in < 1 or n_out < 1:
            raise ValueError("mixed tx needs >= 1 input and >= 1 output total")
        if s_o == 1:
            raise ValueError("a shielded tx needs >= 2 shielded outputs (verify_trivial_commitment_protection)")
        fpo, suffix = self._fee_per_output(), self._output_suffix()

        # Value per UTXO: big enough that after the shielded-output fee each output gets >= 1.
        per = max(1, math.ceil((n_out + s_o * fpo) / n_in))
        base, rem = divmod(n_in * per - s_o * fpo, n_out)   # output split (last absorbs remainder)

        n_t, n_s = num_txs * t_i, num_txs * s_i             # transparent / shielded input UTXOs needed

        # --- transparent funding (coinbases -> fund txs minting `per`-valued UTXOs) -----------
        n_t_funds = math.ceil(n_t / FUND_CHUNK) if n_t else 0
        t_sizes = []
        rem_t = n_t
        for _ in range(n_t_funds):
            t_sizes.append(min(FUND_CHUNK, rem_t)); rem_t -= min(FUND_CHUNK, rem_t)
        # value the transparent funds must consolidate from coinbases:
        n_coin = max(1, math.ceil((n_t * per) / COINBASE_VALUE) + 1)

        # --- shielded sources (ssrc txs, filler-funded, only shielded outputs) ---------------
        n_src = math.ceil(n_s / SRC_CHUNK) if n_s else 0
        s_sizes = []
        rem_s = n_s
        for _ in range(n_src):
            c = min(SRC_CHUNK, rem_s)
            if c == 1:           # never leave a 1-output shielded source (verify needs >=2)
                c = min(2, rem_s) if rem_s >= 2 else 2
            s_sizes.append(max(c, 2)); rem_s -= c

        lock = max(n_coin, 1) + 12
        tx_anchor = lock + 5
        total_blocks = tx_anchor + 3

        lines = [f"blockchain genesis b[1..{total_blocks}]", f"b{lock} < dummy"]

        # transparent funds consolidate the coinbases, then mint pinned UTXOs of value `per`
        for f, size in enumerate(t_sizes):
            if f == 0:
                for c in range(n_coin):
                    lines.append(f"b{c + 1}.out[0] <<< fund0")
            for k in range(size):
                lines.append(f"fund{f}.out[{k}] = {per} HTR")
            if f + 1 < n_t_funds:
                lines.append(f"fund{f}.out[{size}] <<< fund{f + 1}")
            if f >= 1:
                lines.append(f"fund{f} --> fund{f - 1}")
            lines.append(f"b{lock} < fund{f}")

        # shielded sources: each mints `size` shielded UTXOs of value `per` (filler funds from dummy)
        for j, size in enumerate(s_sizes):
            for k in range(size):
                lines.append(f"ssrc{j}.out[{k}] = {per} HTR{suffix}")
            lines.append(f"b{lock} < ssrc{j}")

        # flat lists of available (fund, idx) transparent UTXOs and (src, idx) shielded UTXOs
        t_utxos = [(f, k) for f, size in enumerate(t_sizes) for k in range(size)]
        s_utxos = [(j, k) for j, size in enumerate(s_sizes) for k in range(size)]
        ut = us = 0

        for t in range(num_txs):
            name = f"tx{t}"
            for _ in range(t_i):
                f, k = t_utxos[ut]; ut += 1
                lines.append(f"fund{f}.out[{k}] <<< {name}")
            for _ in range(s_i):
                j, k = s_utxos[us]; us += 1
                lines.append(f"ssrc{j}.out[{k}] <<< {name}")
            # outputs: t_o transparent first, then s_o shielded; last output takes the remainder
            for o in range(n_out):
                v = base + (rem if o == n_out - 1 else 0)
                sfx = suffix if o >= t_o else ""        # first t_o transparent, rest shielded
                lines.append(f"{name}.out[{o}] = {v} HTR{sfx}")
            lines.extend(self._frontier_lines(t, name, tx_anchor))
        return "\n".join(lines)

    def build(self, harness: Any, num_txs: int, num_inputs: int, num_outputs: int) -> list[PreparedTx]:
        self._fee = getattr(harness.manager._settings, self._fee_setting)
        return super().build(harness, num_txs, num_inputs, num_outputs)


@register_txtype("mixed-amount")
class MixedAmountTxSource(_MixedTxSource):
    """Mixed tx with AMOUNT_ONLY shielded parts."""
    _suffix = " [shielded]"
    _fee_setting = "FEE_PER_AMOUNT_SHIELDED_OUTPUT"


@register_txtype("mixed-full")
class MixedFullTxSource(_MixedTxSource):
    """Mixed tx with FULLY_SHIELDED parts (default for the `--shielded` segment separator)."""
    _suffix = " [full-shielded]"
    _fee_setting = "FEE_PER_FULL_SHIELDED_OUTPUT"
