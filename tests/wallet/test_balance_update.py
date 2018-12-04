from twisted.internet.task import Clock

from tests import unittest
from tests.utils import add_new_blocks

from hathor.transaction import Transaction
from hathor.wallet.base_wallet import WalletOutputInfo, WalletInputInfo, UnspentTx, SpentTx, WalletBalance
from hathor.wallet.exceptions import PrivateKeyNotFound

import time


class HathorSyncMethodsTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.clock = Clock()
        self.clock.advance(time.time())
        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True)

        add_new_blocks(self.manager, 3, advance_clock=15)

        address = '3JEcJKVsHddj1Td2KDjowZ1JqGF1'
        value = 100

        outputs = [
            WalletOutputInfo(address=self.manager.wallet.decode_address(address), value=int(value), timelock=None)
        ]

        self.tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs)
        self.tx1.weight = 10
        self.tx1.parents = self.manager.get_new_tx_parents()
        self.tx1.timestamp = int(self.clock.seconds())
        self.tx1.resolve()
        self.manager.propagate_tx(self.tx1)

    def test_balance_update1(self):
        # Tx2 is twin with tx1 but less acc weight, so it will get voided

        # Start balance
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

        # Change of parents only, so it's a twin.
        # With less weight, so the balance will continue because tx1 will be the winner
        tx2 = Transaction.create_from_struct(self.tx1.get_struct())
        tx2.parents = [self.tx1.parents[1], self.tx1.parents[0]]
        tx2.weight = 9
        tx2.resolve()

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)

        meta1 = self.tx1.get_metadata()
        self.assertEqual(meta1.twins, {tx2.hash})

        meta2 = tx2.get_metadata()
        self.assertEqual(meta2.voided_by, {tx2.hash})

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

        # Voided wallet history
        index_voided = 0
        output_voided = tx2.outputs[index_voided]
        voided_unspent = UnspentTx(tx2.hash, index_voided, output_voided.value, tx2.timestamp, voided=True)
        address = output_voided.to_human_readable()['address']
        self.assertEqual(len(self.manager.wallet.voided_unspent), 1)
        self.assertEqual(len(self.manager.wallet.voided_unspent[address]), 1)
        self.assertEqual(self.manager.wallet.voided_unspent[address][0].to_dict(), voided_unspent.to_dict())

        input_voided = tx2.inputs[0]
        key = (input_voided.tx_id, input_voided.index)
        voided_spent = SpentTx(tx2.hash, input_voided.tx_id, input_voided.index, 2000, tx2.timestamp, voided=True)
        self.assertEqual(len(self.manager.wallet.voided_spent), 1)
        self.assertEqual(len(self.manager.wallet.voided_spent[key]), 1)
        self.assertEqual(self.manager.wallet.voided_spent[key][0].to_dict(), voided_spent.to_dict())

    def test_balance_update2(self):
        # Tx2 is twin with tx1 with equal acc weight, so both will get voided

        # Start balance
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

        # Change of parents only, so it's a twin.
        # Same weight, so both will be voided then the balance increases
        tx2 = Transaction.create_from_struct(self.tx1.get_struct())
        tx2.parents = [self.tx1.parents[1], self.tx1.parents[0]]
        tx2.resolve()

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)

        meta1 = self.tx1.get_metadata()
        self.assertEqual(meta1.twins, {tx2.hash})
        self.assertEqual(meta1.voided_by, {self.tx1.hash})

        meta2 = tx2.get_metadata()
        self.assertEqual(meta2.voided_by, {tx2.hash})

        # Balance changed
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 6000))

    def test_balance_update3(self):
        # Tx2 is twin with tx1 with higher acc weight, so tx1 will get voided

        # Start balance
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

        # Change of parents only, so it's a twin.
        # With higher weight, so the balance will continue because tx2 will be the winner
        tx2 = Transaction.create_from_struct(self.tx1.get_struct())
        tx2.parents = [self.tx1.parents[1], self.tx1.parents[0]]
        tx2.weight = 13
        tx2.resolve()

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)

        meta1 = self.tx1.get_metadata()
        self.assertEqual(meta1.twins, {tx2.hash})
        self.assertEqual(meta1.voided_by, {self.tx1.hash})

        meta2 = tx2.get_metadata()
        self.assertEqual(meta2.voided_by, set())

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

    def test_balance_update4(self):
        # Tx2 spends Tx1 output
        # Tx3 is twin of Tx2 with same acc weight, so both will get voided

        self.clock.advance(1)

        # Start balance
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

        address = self.manager.wallet.get_unused_address_bytes()
        value = 1900
        inputs = [
            WalletInputInfo(tx_id=self.tx1.hash, index=0, private_key=None)
        ]
        outputs = [
            WalletOutputInfo(address=address, value=int(value), timelock=None)
        ]
        tx2 = self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs, outputs)
        tx2.weight = 10
        tx2.parents = [self.tx1.hash, self.tx1.parents[0]]
        tx2.timestamp = int(self.clock.seconds())
        tx2.resolve()
        self.manager.propagate_tx(tx2)

        # Test create same tx with allow double spending
        with self.assertRaises(PrivateKeyNotFound):
            self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs=inputs, outputs=outputs)

        self.manager.wallet.prepare_transaction_incomplete_inputs(
            Transaction,
            inputs=inputs,
            outputs=outputs,
            force=True,
            tx_storage=self.manager.tx_storage
        )

        # Change of parents only, so it's a twin.
        tx3 = Transaction.create_from_struct(tx2.get_struct())
        tx3.parents = [tx2.parents[1], tx2.parents[0]]
        tx3.resolve()

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx3)

        meta2 = tx2.get_metadata()
        self.assertEqual(meta2.twins, {tx3.hash})
        self.assertEqual(meta2.voided_by, {tx2.hash})

        meta3 = tx3.get_metadata()
        self.assertEqual(meta3.voided_by, {tx3.hash})

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

    def test_balance_update5(self):
        # Tx2 spends Tx1 output
        # Tx3 is twin of Tx1, with less acc weight
        # So we have conflict between all three txs but tx1 and tx2 are winners and tx3 is voided

        self.clock.advance(1)

        # Start balance
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

        address = self.manager.wallet.get_unused_address_bytes()
        value = 1900
        inputs = [
            WalletInputInfo(tx_id=self.tx1.hash, index=0, private_key=None)
        ]
        outputs = [
            WalletOutputInfo(address=address, value=int(value), timelock=None)
        ]
        tx2 = self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs, outputs)
        tx2.weight = 10
        tx2.parents = [self.tx1.hash, self.tx1.parents[0]]
        tx2.timestamp = int(self.clock.seconds())
        tx2.resolve()

        # Change of parents only, so it's a twin.
        tx3 = Transaction.create_from_struct(self.tx1.get_struct())
        tx3.parents = [self.tx1.parents[1], self.tx1.parents[0]]
        tx3.resolve()

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)
        self.manager.propagate_tx(tx3)

        meta2 = tx2.get_metadata()
        self.assertEqual(meta2.twins, set())
        self.assertEqual(meta2.voided_by, set())

        meta3 = tx3.get_metadata()
        self.assertEqual(meta3.voided_by, {tx3.hash})
        self.assertEqual(meta3.twins, {self.tx1.hash})

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

    def test_balance_update6(self):
        # Tx2 is twin of tx1, so both voided
        # Tx3 has tx1 as parent, so increases tx1 acc weight, then tx1 is winner against tx2

        self.clock.advance(1)

        # Start balance
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

        # Change of parents only, so it's a twin.
        tx2 = Transaction.create_from_struct(self.tx1.get_struct())
        tx2.parents = [self.tx1.parents[1], self.tx1.parents[0]]
        tx2.resolve()

        address = '3JEcJKVsHddj1Td2KDjowZ1JqGF1'
        value = 100

        outputs = [
            WalletOutputInfo(address=self.manager.wallet.decode_address(address), value=int(value), timelock=None)
        ]

        tx3 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs)
        tx3.weight = 10
        tx3.parents = [self.tx1.hash, self.tx1.parents[0]]
        tx3.timestamp = int(self.clock.seconds())
        tx3.resolve()

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)
        self.manager.propagate_tx(tx3)

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5800))

    def test_balance_update7(self):
        # Tx2 spends Tx1 output
        # Tx3 is twin of Tx1 with higher acc weight, so tx1 and tx2 are voided and tx3 is the winner

        self.clock.advance(1)

        # Start balance
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

        address = self.manager.wallet.get_unused_address_bytes()
        value = 1900
        inputs = [
            WalletInputInfo(tx_id=self.tx1.hash, index=0, private_key=None)
        ]
        outputs = [
            WalletOutputInfo(address=address, value=int(value), timelock=None)
        ]
        tx2 = self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs, outputs)
        tx2.weight = 10
        tx2.parents = [self.tx1.hash, self.tx1.parents[0]]
        tx2.timestamp = int(self.clock.seconds())
        tx2.resolve()

        # Change of parents only, so it's a twin.
        tx3 = Transaction.create_from_struct(self.tx1.get_struct())
        tx3.parents = [self.tx1.parents[1], self.tx1.parents[0]]
        tx3.weight = 14
        tx3.resolve()

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)
        self.manager.propagate_tx(tx3)

        meta2 = tx2.get_metadata()
        self.assertEqual(meta2.twins, set())
        self.assertEqual(meta2.voided_by, {self.tx1.hash})

        meta3 = tx3.get_metadata()
        self.assertEqual(meta3.voided_by, set())
        self.assertEqual(meta3.twins, {self.tx1.hash})

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

    def test_balance_update_twin_tx(self):
        # Start balance
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

        wallet_address = self.manager.wallet.get_unused_address()

        outputs2 = [
            WalletOutputInfo(address=self.manager.wallet.decode_address(wallet_address), value=1000, timelock=None)
        ]

        tx2 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs2)
        tx2.weight = 10
        tx2.parents = self.manager.get_new_tx_parents()
        tx2.timestamp = int(self.clock.seconds())
        tx2.resolve()
        self.manager.propagate_tx(tx2)

        self.clock.advance(1)

        outputs3 = [
            WalletOutputInfo(address=self.manager.wallet.decode_address(wallet_address), value=2000, timelock=None)
        ]
        tx3 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs3)
        tx3.weight = 10
        tx3.parents = self.manager.get_new_tx_parents()
        tx3.timestamp = int(self.clock.seconds())
        tx3.resolve()
        self.manager.propagate_tx(tx3)

        self.clock.advance(1)
        new_address = self.manager.wallet.get_unused_address_bytes()
        inputs = [
            WalletInputInfo(tx_id=tx3.hash, index=0, private_key=None)
        ]
        outputs = [
            WalletOutputInfo(address=new_address, value=2000, timelock=None)
        ]
        tx4 = self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs, outputs)
        tx4.weight = 10
        tx4.parents = [tx3.hash, tx3.parents[0]]
        tx4.timestamp = int(self.clock.seconds())
        tx4.resolve()
        self.manager.propagate_tx(tx4)
        self.clock.advance(1)

        # Change of parents only, so it's a twin.
        tx5 = Transaction.create_from_struct(tx4.get_struct())
        tx5.parents = [tx4.parents[1], tx4.parents[0]]
        tx5.weight = 10
        tx5.resolve()

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx5)

        meta4 = tx4.get_metadata()
        self.assertEqual(meta4.twins, {tx5.hash})

        meta5 = tx5.get_metadata()
        self.assertEqual(meta5.voided_by, {tx5.hash})

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))
