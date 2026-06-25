"""
CP-10 probe: confirm the shielded crypto runs in S3S4 (validate_full) but NOT in S6
(the 2nd validate_full in post-consensus). The CP-9 timing suggested it (S6 << S3S4);
this counts the actual crypto calls per stage to settle it.

Method: monkeypatch the shielded-crypto verify functions (imported function-level inside
the verifier, so the patch is picked up per call) with counters, build one full-shielded
tx via the engine's workload, and drive it stage-by-stage like the driver does — tallying
verify_range_proof / verify_surjection_proof / verify_balance in S3S4 vs S6.

Run:  cd tps_benchmarking/engine
      PYTHONPATH="<repo-root>:$PWD" <venv-python> spikes/spike_cp10_verify_count.py
"""
import collections

import hathor.crypto.shielded as shmod
from hathor_tps_bench.driver.runner import build_params
from hathor_tps_bench.node import NodeHarness
from hathor_tps_bench.workload import get_txtype

COUNTS: collections.Counter = collections.Counter()
_CRYPTO = ("verify_range_proof", "verify_surjection_proof", "verify_balance",
           "validate_commitment", "validate_generator")


def _install_counters() -> None:
    for name in _CRYPTO:
        orig = getattr(shmod, name)

        def make(_orig, _name):
            def wrapper(*a, **k):
                COUNTS[_name] += 1
                return _orig(*a, **k)
            return wrapper
        setattr(shmod, name, make(orig, name))


def _snapshot_and_reset() -> dict:
    snap = {k: COUNTS[k] for k in _CRYPTO if COUNTS[k]}
    COUNTS.clear()
    return snap


def main() -> int:
    _install_counters()
    O = 2
    harness = NodeHarness(seed=1234, trivial_pow=True, shielded=True).start()
    try:
        # Build a small full-shielded batch; we drive tx0 (genesis-parented, standalone).
        prepared = get_txtype("full-shielded")().build(harness, num_txs=2, num_inputs=1, num_outputs=O)
        manager = harness.manager
        vh = manager.vertex_handler
        params = build_params(manager)
        raw = prepared[0].raw

        # S1: deserialize
        vtx = manager.vertex_parser.deserialize(raw)
        vtx.storage = manager.tx_storage
        COUNTS.clear()

        # S3S4: validate_full (verify_basic + verify)
        vh._validate_vertex(vtx, params)
        s34 = _snapshot_and_reset()

        # S5: save + consensus
        events = vh._unsafe_save_and_run_consensus(vtx)
        s5 = _snapshot_and_reset()

        # S6: post-consensus (the 2nd validate_full)
        vh._post_consensus(vtx, params, events, quiet=True)
        s6 = _snapshot_and_reset()

        print(f"full-shielded tx, O={O} shielded outputs")
        print(f"  S3S4 (validate_full #1) crypto calls : {s34}")
        print(f"  S5   (save+consensus)   crypto calls : {s5 or '{}'}")
        print(f"  S6   (validate_full #2) crypto calls : {s6 or '{}'}")
        rp34 = s34.get("verify_range_proof", 0)
        rp6 = s6.get("verify_range_proof", 0)
        verdict = ("CONFIRMED: range-proof crypto runs in S3S4 only, NOT re-run in S6"
                   if rp34 == O and rp6 == 0 else
                   f"UNEXPECTED: range-proof verifies S3S4={rp34} S6={rp6} (expected {O} and 0)")
        print(f"\n  {verdict}")
        return 0 if (rp34 == O and rp6 == 0) else 1
    finally:
        harness.stop()


if __name__ == "__main__":
    raise SystemExit(main())
