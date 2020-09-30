from hathor.conf import HathorSettings
from hathor.mining import BlockTemplate
from hathor.transaction import sum_weights
from hathor.transaction.storage import TransactionMemoryStorage
from tests import unittest
from tests.utils import add_new_blocks

settings = HathorSettings()


class BlockchainTestCase(unittest.TestCase):
    """
    Thus, there are eight cases to be handled when a new block arrives, which are:
    (i)    Single best chain, connected to the head of the best chain
    (ii)   Single best chain, connected to the tail of the best chain
    (iii)  Single best chain, connected to the head of a side chain
    (iv)   Single best chain, connected to the tail of a side chain
    (v)    Multiple best chains, connected to the head of a best chain
    (vi)   Multiple best chains, connected to the tail of a best chain
    (vii)  Multiple best chains, connected to the head of a side chain
    (viii) Multiple best chains, connected to the tail of a side chain
    """
    def setUp(self):
        super().setUp()
        self.tx_storage = TransactionMemoryStorage()
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

    def test_block_template_after_genesis(self):
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        block_templates = manager.get_block_templates()
        self.assertEqual(len(block_templates), 1)
        self.assertEqual(block_templates[0], BlockTemplate(
            versions={0, 3},
            reward=settings.INITIAL_TOKEN_UNITS_PER_BLOCK * 100,
            weight=1.0,
            timestamp_now=int(manager.reactor.seconds()),
            timestamp_min=settings.GENESIS_TIMESTAMP + 3,
            timestamp_max=0xffffffff,  # no limit for next block after genesis
            # parents=[tx.hash for tx in self.genesis_blocks + self.genesis_txs],
            parents=block_templates[0].parents,
            parents_any=[],
            height=1,  # genesis is 0
            score=sum_weights(self.genesis_blocks[0].weight, 1.0),
        ))

    def test_regular_block_template(self):
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # add 100 blocks
        blocks = add_new_blocks(manager, 100, advance_clock=15)

        block_templates = manager.get_block_templates()
        self.assertEqual(len(block_templates), 1)
        self.assertEqual(block_templates[0], BlockTemplate(
            versions={0, 3},
            reward=settings.INITIAL_TOKEN_UNITS_PER_BLOCK * 100,
            weight=1.0,
            timestamp_now=int(manager.reactor.seconds()),
            timestamp_min=blocks[-1].timestamp + 1,
            timestamp_max=blocks[-1].timestamp + settings.MAX_DISTANCE_BETWEEN_BLOCKS - 1,
            # parents=[blocks[-1].hash, self.genesis_txs[-1].hash, self.genesis_txs[-2].hash],
            parents=block_templates[0].parents,
            parents_any=[],
            height=101,  # genesis is 0
            score=sum_weights(blocks[-1].get_metadata().score, 1.0),
        ))

        self.assertConsensusValid(manager)


if __name__ == '__main__':
    unittest.main()
