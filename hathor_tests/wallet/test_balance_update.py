from hathor.crypto.util import decode_address
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.scripts import P2PKH
from hathor.transaction.vertex_parser import vertex_deserializer
from hathor.wallet.base_wallet import SpentTx, UnspentTx, WalletBalance, WalletInputInfo, WalletOutputInfo
from hathor.wallet.exceptions import PrivateKeyNotFound
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward, create_tokens


class HathorSyncMethodsTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True)

        blocks = add_new_blocks(self.manager, 3, advance_clock=15)
        self.blocks_tokens = [sum(txout.value for txout in blk.outputs) for blk in blocks]

        address = self.get_address(0)
        value = 100

        self.initial_balance = sum(self.blocks_tokens[:3]) - 100

        outputs = [
            WalletOutputInfo(address=decode_address(address), value=int(value), timelock=None)
        ]

        add_blocks_unlock_reward(self.manager)

        self.tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs,
                                                                          self.manager.tx_storage)
        self.tx1.weight = 10
        self.tx1.parents = self.manager.get_new_tx_parents()
        self.tx1.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(self.tx1)
        self.manager.propagate_tx(self.tx1)
        self.run_to_completion()

    def test_balance_update1(self):
        # Tx2 is twin with tx1 but less acc weight, so it will get voided

        # Start balance
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance))

        # Change of parents only, so it's a twin.
        # With less weight, so the balance will continue because tx1 will be the winner
        tx2 = vertex_deserializer.deserialize(self.tx1.get_struct())
        tx2.parents = [self.tx1.parents[1], self.tx1.parents[0]]
        tx2.weight = 9
        self.manager.cpu_mining_service.resolve(tx2)

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)
        self.run_to_completion()

        meta1 = self.tx1.get_metadata(force_reload=True)
        self.assertEqual(meta1.twins, [tx2.hash])

        meta2 = tx2.get_metadata(force_reload=True)
        self.assertEqual(meta2.voided_by, {tx2.hash})

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance))

        # Voided wallet history
        index_voided = 0
        output_voided = tx2.outputs[index_voided]
        address = output_voided.to_human_readable()['address']
        voided_unspent = UnspentTx(tx2.hash, index_voided, output_voided.value, tx2.timestamp,
                                   address, output_voided.token_data, voided=True)
        self.assertEqual(len(self.manager.wallet.voided_unspent), 1)
        voided_utxo = self.manager.wallet.voided_unspent.get((voided_unspent.tx_id, index_voided))
        self.assertIsNotNone(voided_utxo)
        self.assertEqual(voided_utxo.to_dict(), voided_unspent.to_dict())

        input_voided = tx2.inputs[0]
        key = (input_voided.tx_id, input_voided.index)
        voided_spent = SpentTx(tx2.hash, input_voided.tx_id, input_voided.index, self.blocks_tokens[0],
                               tx2.timestamp, voided=True)
        self.assertEqual(len(self.manager.wallet.voided_spent), 1)
        self.assertEqual(len(self.manager.wallet.voided_spent[key]), 1)
        self.assertEqual(self.manager.wallet.voided_spent[key][0].to_dict(), voided_spent.to_dict())

    def test_balance_update2(self):
        # Tx2 is twin with tx1 with equal acc weight, so both will get voided

        # Start balance
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance))

        # Change of parents only, so it's a twin.
        # Same weight, so both will be voided then the balance increases
        tx2 = vertex_deserializer.deserialize(self.tx1.get_struct())
        tx2.parents = [self.tx1.parents[1], self.tx1.parents[0]]
        self.manager.cpu_mining_service.resolve(tx2)

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)
        self.run_to_completion()

        meta1 = self.tx1.get_metadata(force_reload=True)
        self.assertEqual(meta1.twins, [tx2.hash])
        self.assertEqual(meta1.voided_by, {self.tx1.hash})

        meta2 = tx2.get_metadata()
        self.assertEqual(meta2.voided_by, {tx2.hash})

        # Balance changed
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, sum(self.blocks_tokens[:3])))

    def test_balance_update3(self):
        # Tx2 is twin with tx1 with higher acc weight, so tx1 will get voided

        # Start balance
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance))

        # Change of parents only, so it's a twin.
        # With higher weight, so the balance will continue because tx2 will be the winner
        tx2 = vertex_deserializer.deserialize(self.tx1.get_struct())
        tx2.parents = [self.tx1.parents[1], self.tx1.parents[0]]
        tx2.weight = 13
        self.manager.cpu_mining_service.resolve(tx2)

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)
        self.run_to_completion()

        meta1 = self.tx1.get_metadata(force_reload=True)
        self.assertEqual(meta1.twins, [tx2.hash])
        self.assertEqual(meta1.voided_by, {self.tx1.hash})

        meta2 = tx2.get_metadata()
        self.assertEqual(meta2.voided_by, None)

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance))

    def test_balance_update4(self):
        # Tx2 spends Tx1 output
        # Tx3 is twin of Tx2 with same acc weight, so both will get voided

        self.manager.reactor.advance(1)

        # Start balance
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance))

        address = self.manager.wallet.get_unused_address_bytes()
        value = self.blocks_tokens[0] - 100
        inputs = [WalletInputInfo(tx_id=self.tx1.hash, index=0, private_key=None)]
        outputs = [WalletOutputInfo(address=address, value=int(value), timelock=None)]
        tx2 = self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs, outputs,
                                                                        self.manager.tx_storage)
        tx2.weight = 10
        tx2.parents = [self.tx1.hash, self.tx1.parents[0]]
        tx2.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(tx2)
        self.manager.propagate_tx(tx2)
        self.run_to_completion()

        # Test create same tx with allow double spending
        with self.assertRaises(PrivateKeyNotFound):
            self.manager.wallet.prepare_transaction_incomplete_inputs(
                Transaction,
                inputs=inputs,
                outputs=outputs,
                tx_storage=self.manager.tx_storage
            )

        self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs=inputs, outputs=outputs,
                                                                  force=True, tx_storage=self.manager.tx_storage)

        # Change of parents only, so it's a twin.
        tx3 = vertex_deserializer.deserialize(tx2.get_struct())
        tx3.parents = [tx2.parents[1], tx2.parents[0]]
        self.manager.cpu_mining_service.resolve(tx3)

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx3)
        self.run_to_completion()

        meta2 = tx2.get_metadata(force_reload=True)
        self.assertEqual(meta2.twins, [tx3.hash])
        self.assertEqual(meta2.voided_by, {tx2.hash})

        meta3 = tx3.get_metadata()
        self.assertEqual(meta3.voided_by, {tx3.hash})

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance))

    def test_balance_update5(self):
        # Tx2 spends Tx1 output
        # Tx3 is twin of Tx1, with less acc weight
        # So we have conflict between all three txs but tx1 and tx2 are winners and tx3 is voided

        self.clock.advance(1)

        # Start balance
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance))

        address = self.manager.wallet.get_unused_address_bytes()
        value = self.blocks_tokens[0] - 100
        inputs = [WalletInputInfo(tx_id=self.tx1.hash, index=0, private_key=None)]
        outputs = [WalletOutputInfo(address=address, value=int(value), timelock=None)]
        tx2 = self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs, outputs,
                                                                        self.manager.tx_storage)
        tx2.weight = 10
        tx2.parents = [self.tx1.hash, self.tx1.parents[0]]
        tx2.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(tx2)

        # Change of parents only, so it's a twin.
        tx3 = vertex_deserializer.deserialize(self.tx1.get_struct())
        tx3.parents = [self.tx1.parents[1], self.tx1.parents[0]]
        self.manager.cpu_mining_service.resolve(tx3)

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)
        self.manager.propagate_tx(tx3)
        self.run_to_completion()

        meta2 = tx2.get_metadata()
        self.assertEqual(meta2.twins, [])
        self.assertEqual(meta2.voided_by, None)

        meta3 = tx3.get_metadata()
        self.assertEqual(meta3.voided_by, {tx3.hash})
        self.assertEqual(meta3.twins, [self.tx1.hash])

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance))

    def test_balance_update6(self):
        # Tx2 is twin of tx1, so both voided
        # Tx3 has tx1 as parent, so increases tx1 acc weight, then tx1 is winner against tx2

        self.manager.reactor.advance(1)

        # Start balance
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance))

        # Change of parents only, so it's a twin.
        tx2 = vertex_deserializer.deserialize(self.tx1.get_struct())
        tx2.parents = [self.tx1.parents[1], self.tx1.parents[0]]
        self.manager.cpu_mining_service.resolve(tx2)

        address = self.get_address(0)
        value = 100

        outputs = [
            WalletOutputInfo(address=decode_address(address), value=int(value), timelock=None)
        ]

        tx3 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx3.weight = 10
        tx3.parents = [self.tx1.hash, self.tx1.parents[0]]
        tx3.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(tx3)

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)
        self.manager.propagate_tx(tx3)
        self.run_to_completion()

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance - 100))

    def test_balance_update7(self):
        # Tx2 spends Tx1 output
        # Tx3 is twin of Tx1 with higher acc weight, so tx1 and tx2 are voided and tx3 is the winner

        self.manager.reactor.advance(1)

        # Start balance
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance))

        address = self.manager.wallet.get_unused_address_bytes()
        value = self.blocks_tokens[0] - 100
        inputs = [WalletInputInfo(tx_id=self.tx1.hash, index=0, private_key=None)]
        outputs = [WalletOutputInfo(address=address, value=int(value), timelock=None)]
        tx2 = self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs, outputs,
                                                                        self.manager.tx_storage)
        tx2.weight = 10
        tx2.parents = [self.tx1.hash, self.tx1.parents[0]]
        tx2.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(tx2)

        # Change of parents only, so it's a twin.
        tx3 = vertex_deserializer.deserialize(self.tx1.get_struct())
        tx3.parents = [self.tx1.parents[1], self.tx1.parents[0]]
        tx3.weight = 14
        self.manager.cpu_mining_service.resolve(tx3)

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)
        self.manager.propagate_tx(tx3)
        self.run_to_completion()

        meta2 = tx2.get_metadata(force_reload=True)
        self.assertEqual(meta2.twins, [])
        self.assertEqual(meta2.voided_by, {self.tx1.hash})

        meta3 = tx3.get_metadata(force_reload=True)
        self.assertEqual(meta3.voided_by, None)
        self.assertEqual(meta3.twins, [self.tx1.hash])

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance))

    def test_balance_update_twin_tx(self):
        # Start balance
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance))

        wallet_address = self.manager.wallet.get_unused_address()

        outputs2 = [
            WalletOutputInfo(address=decode_address(wallet_address), value=500, timelock=None)
        ]

        tx2 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs2, self.manager.tx_storage)
        tx2.weight = 10
        tx2.parents = self.manager.get_new_tx_parents()
        tx2.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(tx2)
        self.manager.propagate_tx(tx2)
        self.run_to_completion()

        outputs3 = [
            WalletOutputInfo(address=decode_address(wallet_address), value=self.blocks_tokens[0], timelock=None)
        ]
        tx3 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs3, self.manager.tx_storage)
        tx3.weight = 10
        tx3.parents = self.manager.get_new_tx_parents()
        tx3.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(tx3)
        self.manager.propagate_tx(tx3)
        self.run_to_completion()

        self.clock.advance(1)
        new_address = self.manager.wallet.get_unused_address_bytes()
        inputs = [WalletInputInfo(tx_id=tx3.hash, index=0, private_key=None)]
        outputs = [WalletOutputInfo(address=new_address, value=self.blocks_tokens[0], timelock=None)]
        tx4 = self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs, outputs,
                                                                        self.manager.tx_storage)
        tx4.weight = 10
        tx4.parents = [tx3.hash, tx3.parents[0]]
        tx4.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(tx4)
        self.manager.propagate_tx(tx4)
        self.run_to_completion()

        # Change of parents only, so it's a twin.
        tx5 = vertex_deserializer.deserialize(tx4.get_struct())
        tx5.parents = [tx4.parents[1], tx4.parents[0]]
        tx5.weight = 10
        self.manager.cpu_mining_service.resolve(tx5)

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx5)
        self.run_to_completion()

        meta4 = tx4.get_metadata(force_reload=True)
        self.assertEqual(meta4.twins, [tx5.hash])

        meta5 = tx5.get_metadata(force_reload=True)
        self.assertEqual(meta5.voided_by, {tx5.hash})

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, self.initial_balance))

    def test_tokens_balance(self):
        # create tokens and check balances

        # initial tokens
        address_b58 = self.manager.wallet.get_unused_address()
        address = decode_address(address_b58)
        tx = create_tokens(self.manager, address_b58)
        token_id = tx.tokens[0]
        amount = tx.outputs[0].value

        # initial token balance
        self.assertEqual(self.manager.wallet.balance[token_id], WalletBalance(0, amount))
        # initial hathor balance
        # we don't consider HTR balance 0 because we transfer genesis tokens to this
        # wallet during token creation
        hathor_balance = self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID]

        # transfer token to another wallet and check balance again
        parents = self.manager.get_new_tx_parents()
        _input1 = TxInput(tx.hash, 0, b'')
        script = P2PKH.create_output_script(address)
        token_output1 = TxOutput(30, b'', 0b00000001)
        token_output2 = TxOutput(amount - 30, script, 0b00000001)
        tx2 = Transaction(
            weight=1,
            inputs=[_input1],
            outputs=[token_output1, token_output2],
            parents=parents,
            tokens=[token_id],
            storage=self.manager.tx_storage,
            timestamp=int(self.manager.reactor.seconds())
        )
        data_to_sign = tx2.get_sighash_all()
        public_bytes, signature = self.manager.wallet.get_input_aux_data(
                                      data_to_sign,
                                      self.manager.wallet.get_private_key(address_b58)
                                  )
        tx2.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        self.manager.cpu_mining_service.resolve(tx2)
        self.manager.propagate_tx(tx2)
        self.run_to_completion()
        # verify balance
        self.assertEqual(self.manager.wallet.balance[token_id], WalletBalance(0, amount - 30))
        # hathor balance remains the same
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID], hathor_balance)

        balances_per_address = self.manager.wallet.get_balance_per_address(self._settings.HATHOR_TOKEN_UID)
        self.assertEqual(hathor_balance.available, sum(x for x in balances_per_address.values()))
