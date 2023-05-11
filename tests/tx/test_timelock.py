from hathor.conf import constants
from hathor.crypto.util import decode_address
from hathor.transaction import Transaction
from hathor.wallet.base_wallet import WalletBalance, WalletInputInfo, WalletOutputInfo
from hathor.wallet.exceptions import InsufficientFunds
from tests import unittest
from tests.utils import add_blocks_unlock_reward, add_new_blocks


class BaseTimelockTransactionTestCase(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True)

    def test_timelock(self):
        blocks = add_new_blocks(self.manager, 5, advance_clock=15)
        blocks_tokens = [sum(txout.value for txout in blk.outputs) for blk in blocks]
        add_blocks_unlock_reward(self.manager)

        address = self.manager.wallet.get_unused_address()
        outside_address = self.get_address(0)

        outputs = [
            WalletOutputInfo(
                address=decode_address(address), value=500,
                timelock=int(self.clock.seconds()) + 10),
            WalletOutputInfo(
                address=decode_address(address), value=700,
                timelock=int(self.clock.seconds()) - 10),
            WalletOutputInfo(
                address=decode_address(address), value=sum(blocks_tokens[:2]) - 500 - 700,
                timelock=None)
        ]

        tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx1.weight = 10
        tx1.parents = self.manager.get_new_tx_parents()
        tx1.timestamp = int(self.clock.seconds())
        tx1.resolve()
        self.manager.propagate_tx(tx1)

        self.assertEqual(self.manager.wallet.balance[constants.HATHOR_TOKEN_UID],
                         WalletBalance(500, sum(blocks_tokens) - 500))

        self.clock.advance(1)

        outputs1 = [
            WalletOutputInfo(address=decode_address(outside_address), value=500, timelock=None)
        ]

        inputs1 = [WalletInputInfo(tx_id=tx1.hash, index=0, private_key=None)]

        tx2 = self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs1,
                                                                        outputs1, self.manager.tx_storage)
        tx2.weight = 10
        tx2.parents = self.manager.get_new_tx_parents()
        tx2.timestamp = int(self.clock.seconds())
        tx2.resolve()
        propagated = self.manager.propagate_tx(tx2)

        self.assertEqual(self.manager.wallet.balance[constants.HATHOR_TOKEN_UID],
                         WalletBalance(500, sum(blocks_tokens) - 500))
        self.assertFalse(propagated)

        self.clock.advance(1)

        outputs2 = [
            WalletOutputInfo(address=decode_address(outside_address), value=700, timelock=None)
        ]

        inputs2 = [WalletInputInfo(tx_id=tx1.hash, index=1, private_key=None)]

        tx3 = self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs2,
                                                                        outputs2, self.manager.tx_storage)
        tx3.weight = 10
        tx3.parents = self.manager.get_new_tx_parents()
        tx3.timestamp = int(self.clock.seconds())
        tx3.resolve()
        propagated = self.manager.propagate_tx(tx3, False)
        self.assertEqual(self.manager.wallet.balance[constants.HATHOR_TOKEN_UID],
                         WalletBalance(500, sum(blocks_tokens) - 500 - 700))
        self.assertTrue(propagated)
        self.clock.advance(1)

        outputs3 = [
            WalletOutputInfo(
                address=decode_address(outside_address), value=sum(blocks_tokens[:2]) - 500 - 700,
                timelock=None)
        ]

        inputs3 = [WalletInputInfo(tx_id=tx1.hash, index=2, private_key=None)]

        tx4 = self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs3,
                                                                        outputs3, self.manager.tx_storage)
        tx4.weight = 10
        tx4.parents = self.manager.get_new_tx_parents()
        tx4.timestamp = int(self.clock.seconds())
        tx4.resolve()
        propagated = self.manager.propagate_tx(tx4, False)
        self.assertEqual(self.manager.wallet.balance[constants.HATHOR_TOKEN_UID],
                         WalletBalance(500, sum(blocks_tokens[:3])))
        self.assertTrue(propagated)

        self.clock.advance(8)
        tx2.timestamp = int(self.clock.seconds())
        tx2.resolve()
        propagated = self.manager.propagate_tx(tx2, False)
        self.assertEqual(self.manager.wallet.balance[constants.HATHOR_TOKEN_UID],
                         WalletBalance(0, sum(blocks_tokens[:3])))
        self.assertTrue(propagated)

    def test_choose_inputs(self):
        blocks = add_new_blocks(self.manager, 1, advance_clock=15)
        blocks_tokens = [sum(txout.value for txout in blk.outputs) for blk in blocks]
        add_blocks_unlock_reward(self.manager)

        address = self.manager.wallet.get_unused_address(mark_as_used=False)

        outputs = [
            WalletOutputInfo(
                address=decode_address(address), value=blocks_tokens[0],
                timelock=int(self.clock.seconds()) + 10)
        ]

        tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx1.weight = 10
        tx1.parents = self.manager.get_new_tx_parents()
        tx1.timestamp = int(self.clock.seconds())
        tx1.resolve()
        self.manager.propagate_tx(tx1)
        self.clock.advance(1)

        self.assertEqual(self.manager.wallet.balance[constants.HATHOR_TOKEN_UID],
                         WalletBalance(blocks_tokens[0], 0))

        outputs = [WalletOutputInfo(address=decode_address(address), value=blocks_tokens[0], timelock=None)]

        with self.assertRaises(InsufficientFunds):
            self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)

        self.clock.advance(10)

        tx2 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx2.weight = 10
        tx2.parents = self.manager.get_new_tx_parents()
        tx2.timestamp = int(self.clock.seconds())
        tx2.resolve()
        self.manager.propagate_tx(tx2)

        self.assertEqual(self.manager.wallet.balance[constants.HATHOR_TOKEN_UID],
                         WalletBalance(0, blocks_tokens[0]))


class SyncV1TimelockTransactionTestCase(unittest.SyncV1Params, BaseTimelockTransactionTestCase):
    __test__ = True


class SyncV2TimelockTransactionTestCase(unittest.SyncV2Params, BaseTimelockTransactionTestCase):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeTimelockTransactionTestCase(unittest.SyncBridgeParams, SyncV2TimelockTransactionTestCase):
    pass
