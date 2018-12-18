from tests import unittest

from hathor.transaction.genesis import genesis_transactions, get_genesis_output
from hathor.constants import GENESIS_TOKENS

from twisted.internet.task import Clock

import time


class GenesisTest(unittest.TestCase):
    def test_pow(self):
        super().setUp()
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

    def test_genesis_weight(self):
        genesis_blocks = [tx for tx in genesis_transactions(None) if tx.is_block]
        genesis_block = genesis_blocks[0]

        genesis_txs = [tx for tx in genesis_transactions(None) if not tx.is_block]
        genesis_tx = genesis_txs[0]


        clock = Clock()
        clock.advance(time.time())
        network = 'testnet'
        manager = self.create_peer(network, unlock_wallet=True)

        # Validate the block and tx weight
        # in test mode weight is always 1
        self.assertEqual(manager.calculate_block_difficulty(genesis_block), 1)
        self.assertEqual(manager.minimum_tx_weight(genesis_tx), 1)
        manager.test_mode = False
        self.assertEqual(manager.calculate_block_difficulty(genesis_block), genesis_block.weight)
        self.assertEqual(manager.minimum_tx_weight(genesis_tx), genesis_tx.weight)
