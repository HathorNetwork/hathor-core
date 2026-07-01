"""Demonstration tests for bug #1 — DAGBuilder shielded-output txs fail the Pedersen balance.

See ../bug-shielded-pedersen-balance-not-reconciled.md.

Two levels:
  * test_crypto_root_cause   — UNIT, branch-independent: independent random blindings make the
                               homomorphic commitment sum NOT balance; reconciling the last one
                               makes it balance. This is the root cause, true on any branch.
  * test_dsl_shielded_tx_verifies — INTEGRATION/e2e: a `[full-shielded]` output tx built by the
                               DAGBuilder is accepted by full verification. On UNPATCHED upstream
                               this fails with "shielded balance equation does not hold"; on the
                               CP-7 reconciliation patch it passes. (Regression guard for the fix.)

Run (from the engine dir, with the shielded native crypto built):
  cd tps_benchmarking/engine
  PYTHONPATH="<repo>:$PWD" <venv-python> -m unittest \
      tps_benchmarking.bugs-found.tests.test_bug1_pedersen_balance
or directly:  <venv-python> path/to/test_bug1_pedersen_balance.py
"""
import os
import unittest


class Bug1PedersenBalance(unittest.TestCase):
    def test_crypto_root_cause(self):
        """Independent random blindings -> sum doesn't balance; reconciled -> it does."""
        import hathor_ct_crypto as lib
        from hathor.crypto.shielded import (
            create_commitment, verify_commitments_sum, compute_balancing_blinding_factor,
        )
        gen, ZERO = lib.htr_asset_tag(), bytes(32)
        c_in = create_commitment(100, ZERO, gen)            # 100-HTR input (trivial commitment)
        r1 = os.urandom(32)

        # BUG: each shielded output gets an independent random blinding -> does NOT balance.
        r2_bug = os.urandom(32)
        self.assertFalse(
            verify_commitments_sum([c_in], [create_commitment(50, r1, gen),
                                            create_commitment(50, r2_bug, gen)]),
            "independent random blindings unexpectedly balanced (astronomically unlikely)")

        # FIX: last blinding = residual -> balances.
        r2_fix = compute_balancing_blinding_factor(50, ZERO, [(100, ZERO, ZERO)], [(50, r1, ZERO)])
        self.assertTrue(
            verify_commitments_sum([c_in], [create_commitment(50, r1, gen),
                                            create_commitment(50, r2_fix, gen)]),
            "reconciled blindings failed to balance")

    def test_dsl_shielded_tx_verifies(self):
        """A DAGBuilder [full-shielded] tx must pass full verification (RED on unpatched upstream)."""
        from hathor.exception import InvalidNewTransaction
        from hathor_tps_bench.node import NodeHarness
        h = NodeHarness(seed=1234, trivial_pow=True, shielded=True).start()
        try:
            art = h.dag_builder().build_from_str("""
                blockchain genesis b[1..50]
                b30 < dummy
                tx1.out[0] = 50 HTR [full-shielded]
                tx1.out[1] = 50 HTR [full-shielded]
            """)
            accepted = None
            for node, vertex in art.list:
                if h.manager.tx_storage.transaction_exists(vertex.hash):
                    continue
                try:
                    ok = h.manager.vertex_handler.on_new_relayed_vertex(vertex)
                except InvalidNewTransaction as e:
                    if node.name == "tx1":
                        self.fail(f"shielded-output tx rejected (bug #1 present): {e}")
                    raise
                if node.name == "tx1":
                    accepted = ok
            self.assertTrue(accepted, "shielded-output tx not accepted")
        finally:
            h.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
