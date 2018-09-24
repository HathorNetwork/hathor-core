from twisted.python import log
from twisted.internet.task import Clock

from hathor.p2p.peer_id import PeerId
from hathor.manager import HathorManager
from hathor.wallet import Wallet

from tests import unittest

import sys
import tempfile
import shutil


class HathorSyncMethodsTestCase(unittest.TestCase):
    def generate_peer(self, network, peer_id=None):
        if peer_id is None:
            peer_id = PeerId()

        self.tmpdir = tempfile.mkdtemp(dir='/tmp/')
        wallet = Wallet(directory=self.tmpdir)
        wallet.unlock(b'teste')

        manager = HathorManager(self.reactor, peer_id=peer_id, network=network, wallet=wallet)
        manager.start()
        return manager

    def setUp(self):
        log.startLogging(sys.stdout)
        self.reactor = Clock()
        self.network = 'testnet'
        self.manager = self.generate_peer(self.network)

        self.genesis = self.manager.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]

    def tearDown(self):
        shutil.rmtree(self.tmpdir)
        self.clean_pending(required_to_quiesce=False)

    def _add_new_block(self):
        block = self.manager.generate_mining_block()
        block.weight = 10
        self.assertTrue(block.resolve())
        self.manager.tx_storage.save_transaction(block)
        return block

    def _add_new_blocks(self, num_blocks):
        blocks = []
        for _ in range(num_blocks):
            blocks.append(self._add_new_block())
        return blocks

    def test_get_blocks_before(self):
        genesis_block = self.genesis_blocks[0]
        result = self.manager.tx_storage.get_blocks_before(genesis_block.hash.hex())
        self.assertEqual(0, len(result))

        blocks = self._add_new_blocks(20)
        num_blocks = 5

        for i, block in enumerate(blocks):
            result = self.manager.tx_storage.get_blocks_before(block.hash.hex(), num_blocks=num_blocks)

            expected_result = [genesis_block] + blocks[:i]
            expected_result = expected_result[-num_blocks:]
            expected_result = expected_result[::-1]
            self.assertEqual(result, expected_result)

    def test_block_sync(self):
        pass
