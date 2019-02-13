import time

from twisted.internet.task import Clock

import hathor.protos.transaction_pb2_grpc  # noqa this file has nothing to test, only import
from hathor.crypto.util import decode_address
from hathor.transaction import Transaction
from hathor.wallet.base_wallet import WalletOutputInfo
from tests import unittest
from tests.utils import add_new_blocks


class _Base:
    class _SerializationTest(unittest.TestCase):
        def setUp(self):
            super().setUp()

            self.clock = Clock()
            self.clock.advance(time.time())
            self.network = 'testnet'
            self.manager = self.create_peer(self.network, unlock_wallet=True)
            self.tx_storage = self.manager.tx_storage

            data = b'This is a test block.'
            self.blocks = add_new_blocks(self.manager, 3, advance_clock=15, block_data=data)

            address = '15d14K5jMqsN2uwUEFqiPG5SoD7Vr1BfnH'
            value = 100

            outputs = [
                WalletOutputInfo(address=decode_address(address), value=int(value), timelock=None)
            ]

            self.tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs)
            self.tx1.weight = 10
            self.tx1.parents = self.manager.get_new_tx_parents()
            self.tx1.timestamp = int(self.clock.seconds())
            self.tx1.resolve()
            self.manager.propagate_tx(self.tx1)

            # Change of parents only, so it's a twin.
            # With less weight, so the balance will continue because tx1 will be the winner
            self.tx2 = Transaction.create_from_struct(self.tx1.get_struct())
            self.tx2.parents = [self.tx1.parents[1], self.tx1.parents[0]]
            self.tx2.weight = 9
            self.tx2.resolve()

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

        def test_serialization_tips(self):
            from itertools import chain
            for tip_interval in chain(self.tx_storage.get_tx_tips(), self.tx_storage.get_block_tips()):
                tx = self.tx_storage.get_transaction(tip_interval.data)
                tx_re = self._reserialize(tx)
                self._assertTxEq(tx, tx_re)

    class _SerializationWithoutMetadataTest(_SerializationTest):
        def _assertTxEq(self, tx1, tx2):
            self.assertEqual(tx1, tx2)

    class _SerializationWithMetadataTest(_SerializationTest):
        def _assertTxEq(self, tx1, tx2):
            self.assertEqual(tx1, tx2)
            self.assertEqual(tx1.get_metadata(), tx2.get_metadata())


class NoSerializationTest(_Base._SerializationWithMetadataTest):
    """This should absolutely not fail, or the tests are wrong."""

    def _reserialize(self, tx):
        return tx


class StructSerializationTest(_Base._SerializationWithoutMetadataTest):
    def _reserialize(self, tx):
        cls = tx.__class__
        tx_struct = tx.get_struct()
        return cls.create_from_struct(tx_struct)


class ProtobufSerializationTest(_Base._SerializationWithMetadataTest):
    def _reserialize(self, tx):
        from hathor.transaction import tx_or_block_from_proto
        tx_proto = tx.to_proto()
        print(tx.get_metadata().to_json(), flush=True)
        tx_re = tx_or_block_from_proto(tx_proto)
        print(tx_re.get_metadata().to_json(), flush=True)
        return tx_re


if __name__ == '__main__':
    unittest.main()
