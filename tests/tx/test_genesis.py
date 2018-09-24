from tests import unittest

from hathor.transaction.genesis import genesis_transactions


class GenesisTest(unittest.TestCase):
    def test_pow(self):
        genesis = genesis_transactions(None)

        for g in genesis:
            self.assertEqual(g.calculate_hash(), g.hash)
            self.assertIsNone(g.verify_pow())
