from tests import unittest

from hathor.transaction.genesis import genesis_transactions, get_genesis_output
from hathor.constants import GENESIS_TOKENS


class GenesisTest(unittest.TestCase):
    def test_pow(self):
        genesis = genesis_transactions(None)

        for g in genesis:
            self.assertEqual(g.calculate_hash(), g.hash)
            self.assertIsNone(g.verify_pow())

    def test_output(self):
        # Test if block output is valid
        genesis = genesis_transactions(None)

        for g in genesis:
            if g.is_block:
                for output in g.outputs:
                    self.assertEqual(output.script.hex(), get_genesis_output())

    def test_genesis_tokens(self):
        genesis_blocks = [tx for tx in genesis_transactions(None) if tx.is_block]
        genesis_block = genesis_blocks[0]

        self.assertEqual(GENESIS_TOKENS, sum([output.value for output in genesis_block.outputs]))


if __name__ == '__main__':
    unittest.main()
