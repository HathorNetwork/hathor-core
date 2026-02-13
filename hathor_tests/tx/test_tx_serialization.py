from hathor.crypto.util import decode_address
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Transaction
from hathor.transaction.vertex_parser import vertex_deserializer, vertex_serializer
from hathor.wallet.base_wallet import WalletOutputInfo
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward


class BaseSerializationTest(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True)
        self.tx_storage = self.manager.tx_storage

        data = b'This is a test block.'
        self.blocks = add_new_blocks(self.manager, 3, advance_clock=15, block_data=data)
        add_blocks_unlock_reward(self.manager)

        address = self.get_address(0)
        value = 100

        outputs = [
            WalletOutputInfo(address=decode_address(address), value=int(value), timelock=None)
        ]

        self.tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.tx_storage)
        self.tx1.weight = 10
        self.tx1.parents = self.manager.get_new_tx_parents()
        self.tx1.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(self.tx1)
        self.manager.propagate_tx(self.tx1)

        # Change of parents only, so it's a twin.
        # With less weight, so the balance will continue because tx1 will be the winner
        self.tx2 = vertex_deserializer.deserialize(vertex_serializer.serialize(self.tx1))
        self.tx2.parents = [self.tx1.parents[1], self.tx1.parents[0]]
        self.tx2.weight = 9
        self.manager.cpu_mining_service.resolve(self.tx2)

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(self.tx2)

    def _reserialize(self, tx):
        raise NotImplementedError

    def _assertTxEq(self, tx1, tx2):
        raise NotImplementedError

    def test_serialization_simple(self):
        tx2_re = self._reserialize(self.tx2)
        self._assertTxEq(self.tx2, tx2_re)

        tx1_re = self._reserialize(self.tx1)
        self._assertTxEq(self.tx1, tx1_re)

    def test_serialization_genesis(self):
        for tx in self.tx_storage.get_all_genesis():
            tx_re = self._reserialize(tx)
            self._assertTxEq(tx, tx_re)


class NoSerializationTest(BaseSerializationTest):
    """This should absolutely not fail, or the tests are wrong."""

    __test__ = True

    def _reserialize(self, tx):
        return tx

    def _assertTxEq(self, tx1, tx2):
        self.log.info('assertEqual tx with metadata', a=tx1.to_json(), b=tx2.to_json())
        self.assertEqual(tx1, tx2)
        self.log.info('assertEqual tx metadata', a=tx1.get_metadata().to_json(), b=tx2.get_metadata().to_json())
        self.assertEqual(tx1.get_metadata(), tx2.get_metadata())

    def test_serialization_tips(self):
        from itertools import chain
        it_mempool_tips = (x.hash for x in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage))
        it_block_height_entries = iter([self.tx_storage.indexes.height.get_tip()])
        for tx_hash in chain(it_mempool_tips, it_block_height_entries):
            tx = self.tx_storage.get_transaction(tx_hash)
            tx_re = self._reserialize(tx)
            self._assertTxEq(tx, tx_re)


class StructSerializationTest(BaseSerializationTest):
    __test__ = True

    def _reserialize(self, tx):
        tx_struct = vertex_serializer.serialize(tx)
        return vertex_deserializer.deserialize(tx_struct)

    def _assertTxEq(self, tx1, tx2):
        self.log.info('assertEqual tx without metadata', a=tx1.to_json(), b=tx2.to_json())
        self.assertEqual(tx1, tx2)
