"""Regression tests for bug #3 — full-shielded surjection over the real input domain.

See ../bug-shielded-surjection-trivial-domain.md.

Originally the builder made each FullShieldedOutput's surjection proof over a hard-coded
single-input "trivial" domain, so a FULLY_SHIELDED tx verified only with exactly one
*unblinded* (transparent / amount-shielded) input. The fix builds the surjection domain
from the REAL inputs (mirroring verify_surjection_proofs), so full-shielded verifies for
any input set.

These assert the FIXED behavior (all green on the patched branch); on the unpatched builder
the multi-input / full-shielded-input cases fail with "surjection proof verification failed".
(Before the fix, `test_full_shielded_multi_input` was marked @unittest.expectedFailure to
document the live bug; the decorator is removed now that it passes.)

Run:  <venv-python> path/to/test_bug3_surjection.py
"""
import unittest

from hathor_tps_bench.driver import run_batch
from hathor_tps_bench.node import NodeHarness
from hathor_tps_bench.workload import get_txtype


def _drive(txtype: str, num_inputs: int, num_outputs: int = 2, *, s_i: int = 0, s_o: int = 0, n: int = 3):
    """Build + drive a small batch; return accepted == n (raises on a verification rejection)."""
    h = NodeHarness(seed=1234, trivial_pow=True, shielded=True).start()
    try:
        src = get_txtype(txtype)()
        if hasattr(type(src), "shielded_inputs"):   # mixed-* sources carry a shielded slice
            src.shielded_inputs, src.shielded_outputs = s_i, s_o
        prepared = src.build(h, n, num_inputs, num_outputs)
        res = run_batch(h, prepared, sampler_interval_s=0.1, warmup=0)
        return res.accepted == res.n
    finally:
        h.stop()


class Bug3Surjection(unittest.TestCase):
    def test_amount_shielded_multi_input_ok(self):
        """Control: AMOUNT_ONLY (no surjection proof) accepted with >1 input."""
        self.assertTrue(_drive("amount-shielded", num_inputs=3))

    def test_full_shielded_single_input_ok(self):
        """Control: FULLY_SHIELDED with exactly 1 transparent input accepted."""
        self.assertTrue(_drive("full-shielded", num_inputs=1))

    def test_full_shielded_multi_input(self):
        """FIXED: FULLY_SHIELDED with >1 input now verifies (real surjection domain)."""
        self.assertTrue(_drive("full-shielded", num_inputs=3))

    def test_full_shielded_with_full_shielded_inputs(self):
        """FIXED: a full-shielded tx spending full-shielded inputs (blinded asset domain) verifies."""
        self.assertTrue(_drive("mixed-full", num_inputs=0, num_outputs=0, s_i=2, s_o=2))

    def test_mixed_full_transparent_and_shielded_inputs(self):
        """FIXED: mixed tx with transparent + full-shielded inputs and full-shielded outputs verifies."""
        self.assertTrue(_drive("mixed-full", num_inputs=3, num_outputs=2, s_i=2, s_o=2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
