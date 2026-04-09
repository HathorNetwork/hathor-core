from typing import Any

from hathor.mining import BlockTemplate
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Block
from hathor.utils.weight import weight_to_work
from hathor_tests import unittest


class MiningTest(unittest.TestCase):
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
        self.tx_storage = self.create_tx_storage()
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

    def test_block_template_after_genesis(self) -> None:
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        block_templates = manager.get_block_templates()
        self.assertEqual(len(block_templates), 1)

        timestamp_max = min(
            0xffffffff,
            int(manager.reactor.seconds()) + self._settings.MAX_FUTURE_TIMESTAMP_ALLOWED
        )

        self.assertEqual(block_templates[0], BlockTemplate(
            versions={0, 3},
            reward=self._settings.INITIAL_TOKEN_UNITS_PER_BLOCK * 100,
            weight=1.0,
            timestamp_now=int(manager.reactor.seconds()),
            timestamp_min=self._settings.GENESIS_BLOCK_TIMESTAMP + 3,
            timestamp_max=timestamp_max,  # no limit for next block after genesis
            # parents=[tx.hash for tx in self.genesis_blocks + self.genesis_txs],
            parents=block_templates[0].parents,
            parents_any=[],
            height=1,  # genesis is 0
            score=weight_to_work(self.genesis_blocks[0].weight) + weight_to_work(1),
            signal_bits=0
        ))

    def test_regular_block_template(self) -> None:
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # add 100 blocks
        blocks = add_new_blocks(manager, 100, advance_clock=15)

        block_templates = manager.get_block_templates()
        self.assertEqual(len(block_templates), 1)

        timestamp_max = min(
            blocks[-1].timestamp + self._settings.MAX_DISTANCE_BETWEEN_BLOCKS - 1,
            int(manager.reactor.seconds()) + self._settings.MAX_FUTURE_TIMESTAMP_ALLOWED
        )

        self.assertEqual(block_templates[0], BlockTemplate(
            versions={0, 3},
            reward=self._settings.INITIAL_TOKEN_UNITS_PER_BLOCK * 100,
            weight=1.0,
            timestamp_now=int(manager.reactor.seconds()),
            timestamp_min=blocks[-1].timestamp + 1,
            timestamp_max=timestamp_max,
            # parents=[blocks[-1].hash, self.genesis_txs[-1].hash, self.genesis_txs[-2].hash],
            parents=block_templates[0].parents,
            parents_any=[],
            height=101,  # genesis is 0
            score=blocks[-1].get_metadata().score + weight_to_work(1),
            signal_bits=0
        ))

        self.assertConsensusValid(manager)

    def test_minimally_valid_block(self) -> None:
        template = BlockTemplate(
            versions={0},
            reward=6400,
            weight=60,
            timestamp_now=12345,
            timestamp_min=12344,
            timestamp_max=12346,
            parents=[b'\x01', b'\x02', b'\x03'],
            parents_any=[],
            height=999,
            score=100,
            signal_bits=0b0101,
        )
        block = template.generate_minimally_valid_block()
        json = block.to_json()
        expected: dict[str, Any] = dict(
            data='',
            hash=None,
            inputs=[],
            nonce=0,
            outputs=[dict(script='', token_data=0, value=6400)],
            parents=['01', '02', '03'],
            signal_bits=0b0101,
            timestamp=12344,
            tokens=[],
            version=0,
            weight=60
        )

        self.assertTrue(isinstance(block, Block))
        self.assertEqual(json, expected)
