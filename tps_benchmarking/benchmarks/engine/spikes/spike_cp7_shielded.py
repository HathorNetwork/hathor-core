"""
CP-7 shielded de-risk spike: prove the shielded stack works end-to-end on the new
`feat/shielded-outputs`-based branch, before any engine code is written.

Proves three things:
  (A) the native Rust crypto module `hathor_ct_crypto` imports and round-trips
      (commit -> range-proof -> verify);
  (B) a node with ENABLE_SHIELDED_TRANSACTIONS=ENABLED can BUILD a tx carrying
      `[full-shielded]` and `[shielded]` outputs via the DAGBuilder DSL and DRIVE it
      through real verification (the range/surjection/balance crypto actually runs and
      passes) — i.e. the tx is accepted and not voided;
  (C) reports the on-wire size blow-up (shielded output vs ~34 B transparent).

The transparent-baseline-still-runs check (C of CP-7) is done separately via the CLI:
  poetry run python -m hathor_tps_bench run --num-txs 30 -w 5

Manager setup mirrors hathor_tests/dag_builder/test_shielded_dag_builder.py (the simulator
cpu-mining service + simulator vertex verifiers + the feature flag), combined with our
NodeHarness import-order discipline (init the reactor before importing test helpers).

Run:  cd tps_benchmarking/benchmarks/engine && poetry run python spikes/spike_cp7_shielded.py
"""
import os
import time

# 1) unittests network BEFORE importing hathor.conf (cheap real verifiers).
from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH

os.environ.setdefault("HATHOR_CONFIG_YAML", UNITTESTS_SETTINGS_FILEPATH)

# 2) the global reactor must exist before importing the test helpers.
from hathor.reactor import initialize_global_reactor

initialize_global_reactor(use_asyncio_reactor=True)

from hathor.conf.get_settings import get_global_settings  # noqa: E402
from hathor.conf.settings import FeatureSetting  # noqa: E402
from hathor.daa import TestMode  # noqa: E402
from hathor.simulator.patches import SimulatorCpuMiningService  # noqa: E402
from hathor.simulator.simulator import _build_vertex_verifiers  # noqa: E402
from hathor.transaction import Transaction  # noqa: E402
from hathor.util import Random  # noqa: E402
from hathor_tests.dag_builder.builder import TestDAGBuilder  # noqa: E402
from hathor_tests.test_memory_reactor_clock import TestMemoryReactorClock  # noqa: E402
from hathor_tests.unittest import TestBuilder  # noqa: E402


def build_shielded_manager(seed: int = 1234):
    """A real in-process node with shielded transactions ENABLED. This is the CP-8
    blueprint for adapting NodeHarness: TestBuilder(settings-with-flag) + the simulator
    mining service + simulator vertex verifiers."""
    clock = TestMemoryReactorClock()
    clock.advance(time.time())

    settings = get_global_settings().model_copy(update={
        "ENABLE_SHIELDED_TRANSACTIONS": FeatureSetting.ENABLED,
    })
    builder = (
        TestBuilder(settings)
        .set_rng(Random(seed))
        .set_reactor(clock)
        .set_cpu_mining_service(SimulatorCpuMiningService())
        .set_vertex_verifiers_builder(_build_vertex_verifiers)
    )
    manager = builder.build().manager
    manager.daa_factory.TEST_MODE = TestMode.TEST_ALL_WEIGHT  # trivial PoW
    manager.start()
    clock.run()
    clock.advance(5)
    return manager, clock


def proof_a_crypto() -> bool:
    import hathor_ct_crypto as lib
    gen = lib.htr_asset_tag()
    bf = bytes(range(32))
    amt = 50
    c = lib.create_commitment(amt, bf, gen)
    rp = lib.create_range_proof(amt, bf, c, gen)
    ok = lib.verify_range_proof(rp, c, gen)
    print(f"(A) crypto round-trip : commitment={len(c)}B range_proof={len(rp)}B verify={ok}")
    return bool(ok) and len(c) == 33


def proof_b_build_and_verify(manager) -> bool:
    """Build a tx with both shielded output kinds, drive every vertex through real
    verification, and confirm the shielded txs are accepted (=> the crypto verified)."""
    dag = TestDAGBuilder.from_manager(manager)
    artifacts = dag.build_from_str("""
        blockchain genesis b[1..50]
        b30 < dummy

        tx_full.out[0] = 50 HTR [full-shielded]
        tx_full.out[1] = 50 HTR [full-shielded]

        tx_amt.out[0] = 50 HTR [shielded]
        tx_amt.out[1] = 50 HTR [shielded]
    """)

    targets = {"tx_full", "tx_amt"}
    by_name = {}
    for node, vertex in artifacts.list:
        if node.name in targets:
            by_name[node.name] = vertex
        if manager.tx_storage.transaction_exists(vertex.hash):
            continue
        ok = manager.vertex_handler.on_new_relayed_vertex(vertex)
        if not ok:
            print(f"    vertex {node.name!r} REJECTED by verification")
            return False

    all_ok = True
    for name in ("tx_full", "tx_amt"):
        tx = by_name[name]
        voided = tx.get_metadata().voided_by
        n_sh = len(tx.shielded_outputs)
        size = len(bytes(tx))
        print(f"(B) {name:8} : shielded_outputs={n_sh} accepted={not voided} "
              f"serialized={size}B")
        all_ok = all_ok and not voided and n_sh == 2
    return all_ok


def proof_c_sizes(manager) -> None:
    """Print the per-output size blow-up vs a transparent output (~34 B)."""
    dag = TestDAGBuilder.from_manager(manager)
    artifacts = dag.build_from_str("""
        blockchain genesis b[1..50]
        b30 < dummy
        tx_a.out[0] = 50 HTR [shielded]
        tx_a.out[1] = 50 HTR [shielded]
        tx_f.out[0] = 50 HTR [full-shielded]
        tx_f.out[1] = 50 HTR [full-shielded]
    """)
    for name in ("tx_a", "tx_f"):
        tx = artifacts.get_typed_vertex(name, Transaction)
        o = tx.shielded_outputs[0]
        rp = len(o.range_proof)
        sp = len(getattr(o, "surjection_proof", b""))
        kind = type(o).__name__
        print(f"(C) {name:5} {kind:20} range_proof={rp}B surjection_proof={sp}B "
              f"(transparent output ~34B)")


def main() -> int:
    print("== CP-7 shielded de-risk spike ==")
    a = proof_a_crypto()

    manager, _ = build_shielded_manager()
    print(f"    node: network={manager._settings.NETWORK_NAME} "
          f"shielded_enabled={manager._settings.ENABLE_SHIELDED_TRANSACTIONS}")
    b = proof_b_build_and_verify(manager)
    proof_c_sizes(manager)

    ok = a and b
    print(f"\nSPIKE RESULT: {'PASS ✓' if ok else 'FAIL ✗'}  "
          f"(crypto={'ok' if a else 'BAD'}, build+verify={'ok' if b else 'BAD'})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
