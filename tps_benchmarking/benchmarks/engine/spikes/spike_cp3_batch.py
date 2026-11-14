"""
CP-3 batch mini-spike: de-risk building a BATCH of N independent transparent txs.

Generalises the CP-1 fund-consolidation recipe: one `fund` tx mints N*I pinned UTXOs;
each tx_t spends its own I of them (distinct -> no conflicts) and emits O pinned
outputs. Confirms, under REAL verifiers, that all N are accepted with exact I/O and
disjoint inputs. De-risks: (1) the 255-output cap, (2) parents-at-scale (all parented
to genesis), (3) input disjointness.

Run:  poetry run python tps_benchmarking/benchmarks/engine/spikes/spike_cp3_batch.py
"""
import os

from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH
os.environ.setdefault('HATHOR_CONFIG_YAML', UNITTESTS_SETTINGS_FILEPATH)

from hathor.reactor import initialize_global_reactor
initialize_global_reactor(use_asyncio_reactor=True)

import sys
import time

from hathor.daa import TestMode
from hathor.transaction import Transaction
from hathor.util import Random
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.test_memory_reactor_clock import TestMemoryReactorClock
from hathor_tests.unittest import TestBuilder

# Optional CLI overrides:  python spike_cp3_batch.py [N_TXS [N_INPUTS [N_OUTPUTS]]]
N_TXS = int(sys.argv[1]) if len(sys.argv) > 1 else 20
N_INPUTS = int(sys.argv[2]) if len(sys.argv) > 2 else 1
N_OUTPUTS = int(sys.argv[3]) if len(sys.argv) > 3 else 2


def build_manager():
    clock = TestMemoryReactorClock()
    clock.advance(time.time())
    builder = TestBuilder()
    builder.set_rng(Random(1234)).set_reactor(clock)
    manager = builder.build().manager
    manager.daa_factory.TEST_MODE = TestMode.TEST_ALL_WEIGHT
    manager.start()
    clock.run()
    clock.advance(5)
    return manager, clock


def render_batch_dsl(n_txs: int, n_inputs: int, n_outputs: int) -> str:
    # One `fund` tx eats a coinbase and mints n_txs*n_inputs pinned UTXOs of value `per`.
    # Each tx_t spends its own slice of `n_inputs` of them and emits `n_outputs` pinned
    # outputs (both sides balanced -> filler adds nothing -> exact I/O per tx).
    per = max(n_outputs, 1)                 # value of each fund UTXO / each tx input
    n_utxos = n_txs * n_inputs
    base, rem = divmod(n_inputs * per, n_outputs)

    lines = ["blockchain genesis b[1..50]", "b20 < dummy", "b1.out[0] <<< fund"]
    for u in range(n_utxos):
        lines.append(f"fund.out[{u}] = {per} HTR")
    lines.append("b30 < fund")

    u = 0
    for t in range(n_txs):
        name = f"tx{t}"
        for _ in range(n_inputs):
            lines.append(f"fund.out[{u}] <<< {name}")     # disjoint UTXO per input
            u += 1
        for j in range(n_outputs):
            v = base + (rem if j == n_outputs - 1 else 0)
            lines.append(f"{name}.out[{j}] = {v} HTR")
        lines.append(f"b45 < {name}")
    return "\n".join(lines)


def main():
    manager, _ = build_manager()
    print(f"network={manager._settings.NETWORK_NAME}  "
          f"verifiers={type(manager.verification_service.verifiers.tx).__name__}")

    dag = TestDAGBuilder.from_manager(manager)
    artifacts = dag.build_from_str(render_batch_dsl(N_TXS, N_INPUTS, N_OUTPUTS))

    # Funding (blocks + dummy + fund) is setup -> propagate up to and including `fund`.
    artifacts.propagate_with(manager, up_to="fund")
    fund = artifacts.get_typed_vertex("fund", Transaction)
    print(f"fund outputs       : {len(fund.outputs)}  (<= 255 cap)")

    accepted = 0
    bad_io = 0
    seen_inputs: set[tuple[bytes, int]] = set()
    t0 = time.perf_counter()
    for t in range(N_TXS):
        tx = artifacts.get_typed_vertex(f"tx{t}", Transaction)
        if len(tx.inputs) != N_INPUTS or len(tx.outputs) != N_OUTPUTS:
            bad_io += 1
        for i in tx.inputs:
            seen_inputs.add((i.tx_id, i.index))
        ok = manager.on_new_tx(tx, propagate_to_peers=False, quiet=True)
        if ok and not tx.get_metadata().voided_by:
            accepted += 1
    dt = time.perf_counter() - t0

    expected_distinct = N_TXS * N_INPUTS
    print(f"txs accepted       : {accepted} / {N_TXS}")
    print(f"exact I/O          : {N_TXS - bad_io} / {N_TXS} have {N_INPUTS}-in / {N_OUTPUTS}-out")
    print(f"distinct inputs    : {len(seen_inputs)} (expected {expected_distinct})")
    print(f"drive {N_TXS} txs   : {dt * 1e3:.1f} ms  (~{N_TXS / dt:.0f} tx/s, coarse)")

    ok = accepted == N_TXS and bad_io == 0 and len(seen_inputs) == expected_distinct
    print(f"\nMINI-SPIKE RESULT  : {'PASS ✓' if ok else 'FAIL ✗'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
