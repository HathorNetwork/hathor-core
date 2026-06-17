"""Demonstration test for bug #2 — shielded txs can't be deserialized from bytes.

See ../bug-shielded-deserialize-replace-remaining.md.

INTEGRATION/e2e: build a shielded tx, serialize it, and parse it back via the standard
`vertex_parser.deserialize` (-> create_from_struct -> make_vertex_deserializer().with_max_bytes()).
On UNPATCHED upstream this raises `TypeError: this deserializer does not support replace_remaining`;
with the generic_adapter `replace_remaining` forward it round-trips. (Regression guard.)

Run:  <venv-python> path/to/test_bug2_deserialize.py
"""
import unittest


class Bug2Deserialize(unittest.TestCase):
    def test_shielded_tx_roundtrips_from_bytes(self):
        from hathor.transaction import Transaction
        from hathor_tps_bench.node import NodeHarness
        h = NodeHarness(seed=1234, trivial_pow=True, shielded=True).start()
        try:
            art = h.dag_builder().build_from_str("""
                blockchain genesis b[1..50]
                b30 < dummy
                tx1.out[0] = 50 HTR [shielded]
                tx1.out[1] = 50 HTR [shielded]
            """)
            tx1 = art.get_typed_vertex("tx1", Transaction)
            raw = bytes(tx1)

            # The standard parse path. RED on unpatched upstream: raises
            # "this deserializer does not support replace_remaining".
            try:
                parsed = h.manager.vertex_parser.deserialize(raw)
            except TypeError as e:
                self.fail(f"shielded tx failed to deserialize from bytes (bug #2 present): {e}")

            self.assertEqual(parsed.hash, tx1.hash, "round-tripped tx hash mismatch")
            self.assertTrue(parsed.has_shielded_outputs())
            self.assertEqual(len(parsed.shielded_outputs), 2)
        finally:
            h.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
