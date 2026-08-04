"""Shielded I-in/O-out workloads, built with hathor-core's DAGBuilder.

These mirror the 1-tip-transparent source exactly — same funding, same disjoint UTXOs,
same tip-confirming chain (so consensus stays O(1) and we isolate the shielded *crypto*
cost, not the O(N^2) consensus blow-up) — and differ in only two things:

  1. each payload output carries a `[shielded]` / `[full-shielded]` DSL attribute, so the
     DAGBuilder emits a ShieldedOutputsHeader (Pedersen commitment + range proof, plus an
     asset commitment + surjection proof for full-shielded); and
  2. each shielded output costs a per-output HTR fee (FEE_PER_{AMOUNT,FULL}_SHIELDED_OUTPUT),
     which `TransparentTxSource.render_dsl` already accounts for via the `_fee_per_output`
     hook so the txs stay balanced and exact-I/O.

Requirements (handled here):
  * the node must have ENABLE_SHIELDED_TRANSACTIONS on — `shielded = True` tells the harness
    to enable it (NodeHarness(shielded=True));
  * a shielded tx needs >= 2 shielded outputs (verify_trivial_commitment_protection), so we
    reject O < 2 with a clear message;
  * the per-output fee is read from the node's live settings at build time (not hard-coded),
    so it tracks any settings override.

This module imports nothing from hathor at import time (the hathor work happens lazily inside
build(), inherited from TransparentTxSource), so `list`/`validate` stay light.
"""
from __future__ import annotations

from typing import Any

from hathor_tps_bench.workload.base import PreparedTx
from hathor_tps_bench.workload.registry import register_txtype
from hathor_tps_bench.workload.transparent import OneTipTransparentTxSource


class _ShieldedTxSource(OneTipTransparentTxSource):
    """1-tip-transparent (tip-confirming) workload whose payload outputs are shielded. Concrete
    subclasses set the DSL attribute and the matching fee setting name."""

    shielded = True               # tells the harness/CLI to enable ENABLE_SHIELDED_TRANSACTIONS
    _suffix = ""                  # " [shielded]" or " [full-shielded]"
    _fee_setting = ""             # "FEE_PER_AMOUNT_SHIELDED_OUTPUT" | "FEE_PER_FULL_SHIELDED_OUTPUT"
    _fee = 0                      # resolved from settings in build()

    def _output_suffix(self) -> str:
        return self._suffix

    def _fee_per_output(self) -> int:
        return self._fee

    def build(self, harness: Any, num_txs: int, num_inputs: int, num_outputs: int) -> list[PreparedTx]:
        if num_outputs < 2:
            raise ValueError(
                f"{self.name!r} needs num_outputs >= 2 "
                "(a shielded tx must carry >= 2 shielded outputs — verify_trivial_commitment_protection)"
            )
        # Read the live per-output fee from the node's settings so the value bookkeeping in
        # render_dsl (inherited) keeps the txs balanced even if the setting is overridden.
        self._fee = getattr(harness.manager._settings, self._fee_setting)
        return super().build(harness, num_txs, num_inputs, num_outputs)


@register_txtype("amount-shielded")
class AmountShieldedTxSource(_ShieldedTxSource):
    """AMOUNT_ONLY shielded outputs: amount hidden, token visible (Pedersen commitment +
    range proof, no surjection proof). Cheaper/smaller than full-shielded."""
    _suffix = " [shielded]"
    _fee_setting = "FEE_PER_AMOUNT_SHIELDED_OUTPUT"


@register_txtype("full-shielded")
class FullShieldedTxSource(_ShieldedTxSource):
    """FULLY_SHIELDED outputs: amount AND token hidden (adds an asset commitment + a
    surjection proof). This is what a bare `--shielded` selects."""
    _suffix = " [full-shielded]"
    _fee_setting = "FEE_PER_FULL_SHIELDED_OUTPUT"
