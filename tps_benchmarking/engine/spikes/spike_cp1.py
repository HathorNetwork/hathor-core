"""
CP-1 spike: de-risk the in-process drive + DAGBuilder workload for the TPS benchmark.

Goal (throwaway script): build a real HathorManager in-process (RocksDB temp-dir,
unittests network so REAL verifiers run cheaply), use DAGBuilder to build funding
blocks + a single transparent tx with a chosen #inputs/#outputs, then feed that tx
through the node's real processing path and confirm it is ACCEPTED under real
verification. Also confirm S1 (deserialize from bytes) round-trips.

Run:  poetry run python tps_benchmarking/engine/spikes/spike_cp1.py
"""
import os

# Must be set BEFORE importing anything from hathor.conf — selects the unittests
# network (low PoW weights, test-mode allowed), so real verification is cheap.
from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH
os.environ.setdefault('HATHOR_CONFIG_YAML', UNITTESTS_SETTINGS_FILEPATH)

# The global reactor must be initialized before importing test helpers, because
# hathor_tests.utils builds an HDWallet at import time (which calls get_global_reactor).
from hathor.reactor import initialize_global_reactor
initialize_global_reactor(use_asyncio_reactor=True)

import time

from hathor.daa import TestMode
from hathor.transaction import Transaction
from hathor.util import Random
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.test_memory_reactor_clock import TestMemoryReactorClock
from hathor_tests.unittest import TestBuilder

N_INPUTS = 1
N_OUTPUTS = 2


def build_manager():
    # Use a false reactor clock to pass time
    #   Does it pass time as it should? Correct pace?
    clock = TestMemoryReactorClock()
    clock.advance(time.time())
    rng = Random(1234)

    builder = TestBuilder()
    builder.set_rng(rng).set_reactor(clock)
    artifacts = builder.build()  # default storage is RocksDBStorage.create_temp()
    manager = artifacts.manager

    # trivial PoW: weights -> 1 (allowed on the unittests network)
    manager.daa_factory.TEST_MODE = TestMode.TEST_ALL_WEIGHT

    manager.start()
    clock.run()
    clock.advance(5)
    return manager, clock, artifacts


def render_dsl(n_inputs: int, n_outputs: int) -> str:
    # Fund tx1 by spending the coinbase output of n_inputs distinct blocks.
    # `b45 < tx1` orders tx1 after the blocks so the rewards are unlocked.
    #
    # Exact I-in / O-out control. The block coinbase is large (6400) and the DAGBuilder
    # filler *sizes/tops-up* any UNpinned funding to balance — so spending a raw coinbase
    # lets the filler choose the input count. To pin BOTH sides we add a `fund` tx that
    # consumes one mature coinbase and emits exactly n_inputs fully-pinned outputs (value
    # `per` each). tx1 then spends those n_inputs outputs and emits n_outputs pinned
    # outputs. Both sides are pinned and balanced (n_inputs*per == sum(outputs)), so the
    # filler adds nothing to tx1 -> exactly n_inputs inputs and n_outputs outputs.
    # Exact I-in / O-out: a `fund` tx eats one mature coinbase and emits n_inputs
    # fully-pinned outputs (value `per` each); tx1 spends them (=> n_inputs inputs) and
    # emits n_outputs pinned outputs. Both sides pinned + balanced => filler adds nothing
    # to tx1. `b20 < dummy` orders the filler's auto-funder past the reward lock.
    per = max(n_outputs, 1)              # each fund output / tx1 input value
    total = n_inputs * per               # tx1 total value
    base, rem = divmod(total, n_outputs)
    lines = ["blockchain genesis b[1..50]", "b20 < dummy",
             "b1.out[0] <<< fund"]                       # fund eats one block coinbase
    for k in range(n_inputs):
        lines.append(f"fund.out[{k}] = {per} HTR")
    lines.append("b30 < fund")                           # fund after reward lock
    for k in range(n_inputs):
        lines.append(f"fund.out[{k}] <<< tx1")           # tx1 spends them => n_inputs inputs
    for j in range(n_outputs):
        v = base + (rem if j == n_outputs - 1 else 0)
        lines.append(f"tx1.out[{j}] = {v} HTR")          # n_outputs pinned outputs
    lines.append("b45 < tx1")
    return "\n".join(lines)


def main():
    manager, clock, _ = build_manager()
    settings = manager._settings
    print(f"network            : {settings.NETWORK_NAME}")
    print(f"storage            : {type(manager.tx_storage).__name__}")
    print(f"verifiers          : {type(manager.verification_service.verifiers.tx).__name__}")
    print(f"cpu_mining_service : {type(manager.cpu_mining_service).__name__}")

    dag = TestDAGBuilder.from_manager(manager)
    artifacts = dag.build_from_str(render_dsl(N_INPUTS, N_OUTPUTS))

    # fund: propagate everything up to (but not including) tx1
    artifacts.propagate_with(manager, up_to_before="tx1")  # Block stream comes from here.

    tx1 = artifacts.get_typed_vertex("tx1", Transaction)
    raw = bytes(tx1)
    print(f"\ntx1.hash           : {tx1.hash_hex}")
    print(f"tx1 inputs/outputs : {len(tx1.inputs)} / {len(tx1.outputs)}  (asked {N_INPUTS}/{N_OUTPUTS})")
    print(f"  output values    : {[o.value for o in tx1.outputs]}")
    print(f"  input value(s)   : {[manager.tx_storage.get_transaction(i.tx_id).outputs[i.index].value for i in tx1.inputs]}")
    print(f"tx1 serialized     : {len(raw)} bytes, weight={tx1.weight}")

    # S1: deserialize round-trips from bytes
    reparsed = manager.vertex_parser.deserialize(raw)
    assert reparsed.hash == tx1.hash, "deserialize round-trip mismatch"
    print("S1 deserialize     : round-trip OK")

    # S2..S6: drive the real processing path and time it coarsely
    t0 = time.perf_counter()
    accepted = manager.on_new_tx(tx1, propagate_to_peers=False, quiet=True)
    dt_us = (time.perf_counter() - t0) * 1e6

    meta = tx1.get_metadata()
    in_storage = manager.tx_storage.transaction_exists(tx1.hash)
    print(f"\non_new_tx accepted : {accepted}")
    print(f"voided_by          : {meta.voided_by or 'none'}")
    print(f"in storage         : {in_storage}")
    print(f"first_block        : {meta.first_block}  (None => unconfirmed mempool tip)")
    print(f"process time       : {dt_us:.1f} us (whole S2..S6, coarse)")

    # Core de-risk: accepted under REAL verification, persisted, with the requested
    # input AND output counts (exact O-control via pinned values — see render_dsl).
    ok = (bool(accepted) and not meta.voided_by and in_storage
          and len(tx1.inputs) == N_INPUTS and len(tx1.outputs) == N_OUTPUTS)
    print(f"NOTE               : tx1 produced {len(tx1.outputs)} outputs (asked {N_OUTPUTS}) "
          f"— exact O-control via pinned values + fund consolidation")
    print(f"\nSPIKE RESULT       : {'PASS ✓' if ok else 'FAIL ✗'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
