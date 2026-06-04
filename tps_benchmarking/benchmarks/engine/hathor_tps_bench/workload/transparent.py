"""Transparent I-in/O-out workload via DAGBuilder.

Generalises the CP-1 fund-consolidation recipe to a whole batch (see
checkpoint-diffs/CP-1 §3 for how the filler is controlled):

  * `fund` txs consolidate coinbases into fully-pinned UTXOs of value `per`;
  * each `tx_t` spends its own disjoint slice of `num_inputs` UTXOs and emits
    `num_outputs` pinned outputs — both sides balanced, so the filler adds nothing,
    giving exact I/O and no cross-tx conflicts.

Because a transaction can hold at most 255 outputs (the count is a single byte), a
single `fund` tx can mint at most that many UTXOs; for larger batches we use several
`fund` txs, each eating its own coinbase. This module imports nothing from hathor.
"""
from __future__ import annotations

import math
from typing import Any

from hathor_tps_bench.workload.base import PreparedTx, TxSource
from hathor_tps_bench.workload.registry import register_txtype

# UTXOs minted per `fund` tx. Kept below the 255 hard cap for headroom.
FUND_CHUNK = 200


@register_txtype("transparent")
class TransparentTxSource(TxSource):
    def render_dsl(self, num_txs: int, num_inputs: int, num_outputs: int) -> str:
        per = max(num_outputs, 1)                  # value of each UTXO / each tx input
        n_utxos = num_txs * num_inputs
        n_funds = max(1, math.ceil(n_utxos / FUND_CHUNK))
        lock = n_funds + 12                        # >= reward maturity (10) past last coinbase
        tx_anchor = lock + 5
        total_blocks = tx_anchor + 3
        base, rem = divmod(num_inputs * per, num_outputs)  # output split (last absorbs remainder)

        # chunk the UTXOs across the fund txs
        sizes: list[int] = []
        remaining = n_utxos
        for _ in range(n_funds):
            s = min(FUND_CHUNK, remaining)
            sizes.append(s)
            remaining -= s

        # Order the filler's auto-`dummy` past the reward lock: it spends genesis, so an
        # early anchor would trip "reward still needs N to be unlocked".
        lines = [f"blockchain genesis b[1..{total_blocks}]", f"b{lock} < dummy"]
        for f in range(n_funds):
            lines.append(f"b{f + 1}.out[0] <<< fund{f}")          # one coinbase per fund
        for f, size in enumerate(sizes):
            for k in range(size):
                lines.append(f"fund{f}.out[{k}] = {per} HTR")      # pinned UTXOs
            lines.append(f"b{lock} < fund{f}")                     # after reward lock

        utxos = [(f, k) for f, size in enumerate(sizes) for k in range(size)]
        u = 0
        for t in range(num_txs):
            name = f"tx{t}"
            for _ in range(num_inputs):
                f, k = utxos[u]
                u += 1
                lines.append(f"fund{f}.out[{k}] <<< {name}")       # disjoint UTXO per input
            for j in range(num_outputs):
                v = base + (rem if j == num_outputs - 1 else 0)
                lines.append(f"{name}.out[{j}] = {v} HTR")         # pinned outputs
            lines.append(f"b{tx_anchor} < {name}")
        return "\n".join(lines)

    def build(self, harness: Any, num_txs: int, num_inputs: int, num_outputs: int) -> list[PreparedTx]:
        dsl = self.render_dsl(num_txs, num_inputs, num_outputs)
        artifacts = harness.dag_builder().build_from_str(dsl)

        targets = {f"tx{t}" for t in range(num_txs)}
        manager = harness.manager
        by_name: dict[str, Any] = {}

        # Preload everything that isn't a target tx (blocks, dummy, funds) in topological
        # order — untimed setup. Skip vertices already present (e.g. genesis).
        for node, vertex in artifacts.list:
            if node.name in targets:
                by_name[node.name] = vertex
                continue
            if manager.tx_storage.transaction_exists(vertex.hash):
                continue
            if not manager.vertex_handler.on_new_relayed_vertex(vertex):
                raise RuntimeError(f"funding vertex {node.name!r} was rejected")

        return [
            PreparedTx(
                tx=(tx := by_name[f"tx{t}"]),
                raw=bytes(tx),
                n_inputs=len(tx.inputs),
                n_outputs=len(tx.outputs),
            )
            for t in range(num_txs)
        ]
