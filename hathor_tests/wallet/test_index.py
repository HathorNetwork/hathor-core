from hathor.crypto.util import decode_address
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Transaction
from hathor.transaction.vertex_parser import vertex_deserializer, vertex_serializer
from hathor.wallet.base_wallet import WalletOutputInfo
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward


class WalletIndexTest(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True, wallet_index=True)

    def test_twin_tx(self):
        add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)

        address = self.get_address(0)
        value1 = 100
        value2 = 101

        outputs = [
            WalletOutputInfo(address=decode_address(address), value=int(value1), timelock=None),
            WalletOutputInfo(address=decode_address(address), value=int(value2), timelock=None)
        ]

        tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx1.weight = 10
        tx1.parents = self.manager.get_new_tx_parents()
        tx1.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(tx1)

        # Change of parents only, so it's a twin
        tx2 = vertex_deserializer.deserialize(vertex_serializer.serialize(tx1))
        tx2.parents = [tx1.parents[1], tx1.parents[0]]
        self.manager.cpu_mining_service.resolve(tx2)
        self.assertNotEqual(tx1.hash, tx2.hash)

        self.manager.propagate_tx(tx1)
        self.run_to_completion()

        wallet_data = self.manager.tx_storage.indexes.addresses.get_from_address(address)
        self.assertEqual(len(wallet_data), 1)
        self.assertEqual(wallet_data, [tx1.hash])

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)
        self.run_to_completion()

        wallet_data = self.manager.tx_storage.indexes.addresses.get_from_address(address)
        self.assertEqual(len(wallet_data), 2)
        self.assertEqual(set(wallet_data), set([tx1.hash, tx2.hash]))
