from hathor.crypto.util import decode_address
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Transaction
from hathor.util import not_none
from hathor.wallet.base_wallet import WalletOutputInfo
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward, add_new_double_spending


class TwinTransactionTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True)

    def test_twin_tx(self) -> None:
        add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)

        address = not_none(self.get_address(0))
        value1 = 100
        value2 = 101
        value3 = 102

        outputs = [
            WalletOutputInfo(address=decode_address(address), value=int(value1), timelock=None),
            WalletOutputInfo(address=decode_address(address), value=int(value2), timelock=None)
        ]

        outputs2 = [
            WalletOutputInfo(address=decode_address(address), value=int(value1), timelock=None),
            WalletOutputInfo(address=decode_address(address), value=int(value3), timelock=None)
        ]

        tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx1.weight = 10
        tx1.parents = self.manager.get_new_tx_parents()
        tx1.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(tx1)

        # Change of parents only, so it's a twin
        tx2 = Transaction.create_from_struct(tx1.get_struct())
        tx2.parents = [tx1.parents[1], tx1.parents[0]]
        self.manager.cpu_mining_service.resolve(tx2)
        self.assertNotEqual(tx1.hash, tx2.hash)

        # The same as tx1 but with one input different, so it's not a twin
        tx3 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs2, self.manager.tx_storage)
        tx3.inputs = tx1.inputs
        tx3.weight = tx1.weight
        tx3.parents = tx1.parents
        tx3.timestamp = tx1.timestamp
        self.manager.cpu_mining_service.resolve(tx3)

        self.manager.propagate_tx(tx1)
        meta1 = tx1.get_metadata()
        self.assertEqual(meta1.conflict_with, None)
        self.assertEqual(meta1.voided_by, None)
        self.assertEqual(meta1.twins, [])

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)

        meta1 = tx1.get_metadata(force_reload=True)
        self.assertEqual(meta1.conflict_with, [tx2.hash])
        self.assertEqual(meta1.voided_by, {tx1.hash})
        self.assertEqual(meta1.twins, [tx2.hash])

        meta2 = tx2.get_metadata()
        self.assertEqual(meta2.conflict_with, [tx1.hash])
        self.assertEqual(meta2.voided_by, {tx2.hash})
        self.assertEqual(meta2.twins, [tx1.hash])

        # The same as tx1 but with one output different, so it's not a twin
        tx3 = add_new_double_spending(self.manager, tx=tx1)

        meta1 = tx1.get_metadata()
        self.assertEqual(meta1.twins, [tx2.hash])

        meta3 = tx3.get_metadata()
        self.assertEqual(meta3.twins, [])
        self.assertEqual(meta3.conflict_with, [tx1.hash, tx2.hash])

        self.assertConsensusValid(self.manager)
