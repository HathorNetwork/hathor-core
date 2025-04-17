from struct import error as StructError

import pytest

from hathor.crypto.util import decode_address
from hathor.exception import InvalidNewTransaction
from hathor.indexes.tokens_index import TokenUtxoInfo
from hathor.transaction import Block, Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import BlockWithTokensError, InputOutputMismatch, InvalidToken, TransactionDataError
from hathor.transaction.fee import calculate_fee
from hathor.transaction.scripts import P2PKH
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.token_info import TokenInfoVersion
from hathor.transaction.util import get_deposit_amount, get_token_amount_from_htr, get_withdraw_amount, int_to_bytes
from tests import unittest
from tests.utils import (
    add_blocks_unlock_reward,
    add_new_double_spending,
    create_fee_tokens,
    create_tokens,
    get_genesis_key,
)


class TokenTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet', unlock_wallet=True, wallet_index=True)

        self.genesis = list(self.manager.tx_storage.get_all_genesis())
        self.genesis.sort(key=lambda t: t.timestamp)
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        self.address_b58 = self.manager.wallet.get_unused_address()
        self.address = decode_address(self.address_b58)

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        # add some blocks so we can spend the genesis outputs
        add_blocks_unlock_reward(self.manager)

    def test_tokens_in_block(self):
        # a block with token index > 1 should be invalid
        parents = [tx.hash for tx in self.genesis]

        output_script = P2PKH.create_output_script(self.address)
        tx_outputs = [TxOutput(100, output_script, 1)]

        block = Block(
            nonce=100,
            outputs=tx_outputs,
            parents=parents,
            weight=1,  # low weight so we don't waste time with PoW
            storage=self.manager.tx_storage)

        self.manager.cpu_mining_service.resolve(block)
        with self.assertRaises(BlockWithTokensError):
            self.manager.verification_service.verify(block)

    def test_tx_token_outputs(self):
        genesis_block = self.genesis_blocks[0]

        _input = TxInput(genesis_block.hash, 0, b'')

        value = genesis_block.outputs[0].value
        script = P2PKH.create_output_script(self.address)
        output = TxOutput(value, script, 1)

        parents = [tx.hash for tx in self.genesis_txs]
        tx = Transaction(weight=1, inputs=[_input], outputs=[output], parents=parents, storage=self.manager.tx_storage)

        # no token uids in list
        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        self.manager.cpu_mining_service.resolve(tx)
        with self.assertRaises(InvalidToken):
            self.manager.verification_service.verify(tx)

        # with 1 token uid in list
        tx.tokens = [bytes.fromhex('0023be91834c973d6a6ddd1a0ae411807b7c8ef2a015afb5177ee64b666ce602')]
        output.token_data = 2
        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        self.manager.cpu_mining_service.resolve(tx)
        with self.assertRaises(InvalidToken):
            self.manager.verification_service.verify(tx)

        # try hathor authority UTXO
        output = TxOutput(value, script, 0b10000000)
        tx.outputs = [output]
        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        self.manager.cpu_mining_service.resolve(tx)
        with self.assertRaises(InvalidToken):
            self.manager.verification_service.verify(tx)

    def test_token_transfer(self):
        wallet = self.manager.wallet
        tx = create_tokens(self.manager, self.address_b58)
        token_uid = tx.tokens[0]
        utxo = tx.outputs[0]

        parents = self.manager.get_new_tx_parents()
        _input1 = TxInput(tx.hash, 0, b'')
        script = P2PKH.create_output_script(self.address)

        # regular transfer
        token_output = TxOutput(utxo.value, script, 1)
        tx2 = Transaction(weight=1, inputs=[_input1], outputs=[token_output], parents=parents, tokens=[token_uid],
                          storage=self.manager.tx_storage, timestamp=int(self.clock.seconds()))
        data_to_sign = tx2.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx2.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        self.manager.cpu_mining_service.resolve(tx2)
        tx2.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        self.manager.verification_service.verify(tx2)

        # missing tokens
        token_output = TxOutput(utxo.value - 1, script, 1)
        tx3 = Transaction(weight=1, inputs=[_input1], outputs=[token_output], parents=parents, tokens=[token_uid],
                          storage=self.manager.tx_storage, timestamp=int(self.clock.seconds()))
        data_to_sign = tx3.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx3.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        self.manager.cpu_mining_service.resolve(tx3)
        with self.assertRaises(InputOutputMismatch):
            self.manager.verification_service.verify(tx3)

    def test_token_mint(self):
        wallet = self.manager.wallet
        tx = create_tokens(self.manager, self.address_b58, mint_amount=500)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # mint tokens and transfer mint authority
        mint_amount = 10000000
        deposit_amount = get_deposit_amount(self._settings, mint_amount)
        _input1 = TxInput(tx.hash, 1, b'')
        _input2 = TxInput(tx.hash, 3, b'')
        token_output1 = TxOutput(mint_amount, script, 1)
        token_output2 = TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
        deposit_output = TxOutput(tx.outputs[3].value - deposit_amount, script, 0)
        tx2 = Transaction(
            weight=1,
            inputs=[_input1, _input2],
            outputs=[token_output1, token_output2, deposit_output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx2.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx2.inputs[0].data = data
        tx2.inputs[1].data = data
        self.manager.cpu_mining_service.resolve(tx2)
        self.manager.propagate_tx(tx2)
        self.run_to_completion()

        # check tokens index
        tokens_index = self.manager.tx_storage.indexes.tokens.get_token_info(token_uid)
        mint = list(tokens_index.iter_mint_utxos())
        melt = list(tokens_index.iter_melt_utxos())
        self.assertIn(TokenUtxoInfo(tx2.hash, 1), mint)
        self.assertIn(TokenUtxoInfo(tx.hash, 2), melt)
        # there should only be one element on the indexes for the token
        self.assertEqual(1, len(mint))
        self.assertEqual(1, len(melt))
        # check total amount of tokens
        self.assertEqual(500 + mint_amount, tokens_index.get_total())

        # try to mint 1 token unit without deposit
        mint_amount = 1
        _input1 = TxInput(tx.hash, 1, b'')
        token_output1 = TxOutput(mint_amount, script, 1)
        token_output2 = TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
        tx3 = Transaction(
            weight=1,
            inputs=[_input1],
            outputs=[token_output1, token_output2],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx3.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx3.inputs[0].data = data
        self.manager.cpu_mining_service.resolve(tx3)
        with self.assertRaises(InputOutputMismatch):
            self.manager.verification_service.verify(tx3)

        # try to mint and deposit less tokens than necessary
        mint_amount = 10000000
        deposit_amount = get_deposit_amount(self._settings, mint_amount) - 1
        _input1 = TxInput(tx.hash, 1, b'')
        _input2 = TxInput(tx.hash, 3, b'')
        token_output1 = TxOutput(mint_amount, script, 1)
        token_output2 = TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
        deposit_output = TxOutput(tx.outputs[3].value - deposit_amount, script, 0)
        tx4 = Transaction(
            weight=1,
            inputs=[_input1, _input2],
            outputs=[token_output1, token_output2, deposit_output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx4.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx4.inputs[0].data = data
        tx4.inputs[1].data = data
        self.manager.cpu_mining_service.resolve(tx4)
        with self.assertRaises(InputOutputMismatch):
            self.manager.verification_service.verify(tx4)

        # try to mint using melt authority UTXO
        _input1 = TxInput(tx.hash, 2, b'')
        token_output = TxOutput(10000000, script, 1)
        tx5 = Transaction(weight=1, inputs=[_input1], outputs=[token_output], parents=parents, tokens=[token_uid],
                          storage=self.manager.tx_storage, timestamp=int(self.clock.seconds()))
        data_to_sign = tx5.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx5.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        self.manager.cpu_mining_service.resolve(tx5)
        with self.assertRaises(InputOutputMismatch):
            self.manager.verification_service.verify(tx5)

    def test_token_melt(self):
        wallet = self.manager.wallet
        tx = create_tokens(self.manager, self.address_b58)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # melt tokens and transfer melt authority
        melt_amount = 100
        new_amount = tx.outputs[0].value - melt_amount
        withdraw_amount = get_withdraw_amount(self._settings, melt_amount)
        _input1 = TxInput(tx.hash, 0, b'')
        _input2 = TxInput(tx.hash, 2, b'')
        token_output1 = TxOutput(new_amount, script, 1)
        token_output2 = TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001)
        withdraw_output = TxOutput(withdraw_amount, script, 0)
        tx2 = Transaction(
            weight=1,
            inputs=[_input1, _input2],
            outputs=[token_output1, token_output2, withdraw_output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx2.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx2.inputs[0].data = data
        tx2.inputs[1].data = data
        self.manager.cpu_mining_service.resolve(tx2)
        self.manager.propagate_tx(tx2)
        self.run_to_completion()

        # check tokens index
        tokens_index = self.manager.tx_storage.indexes.tokens.get_token_info(token_uid)
        mint = list(tokens_index.iter_mint_utxos())
        melt = list(tokens_index.iter_melt_utxos())
        self.assertIn(TokenUtxoInfo(tx.hash, 1), mint)
        self.assertIn(TokenUtxoInfo(tx2.hash, 1), melt)
        # there should only be one element on the indexes for the token
        self.assertEqual(1, len(mint))
        self.assertEqual(1, len(melt))
        # check total amount of tokens
        self.assertEqual(new_amount, tokens_index.get_total())

        # melt tokens and withdraw more than what's allowed
        melt_amount = 100
        withdraw_amount = get_withdraw_amount(self._settings, melt_amount)
        _input1 = TxInput(tx.hash, 0, b'')
        _input2 = TxInput(tx.hash, 2, b'')
        token_output1 = TxOutput(tx.outputs[0].value - melt_amount, script, 1)
        token_output2 = TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001)
        withdraw_output = TxOutput(withdraw_amount + 1, script, 0)
        tx3 = Transaction(
            weight=1,
            inputs=[_input1, _input2],
            outputs=[token_output1, token_output2, withdraw_output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx3.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx3.inputs[0].data = data
        tx3.inputs[1].data = data
        self.manager.cpu_mining_service.resolve(tx3)
        with self.assertRaises(InputOutputMismatch):
            self.manager.verification_service.verify(tx3)

        # try to melt using mint authority UTXO
        _input1 = TxInput(tx.hash, 0, b'')
        _input2 = TxInput(tx.hash, 1, b'')
        token_output = TxOutput(tx.outputs[0].value - 1, script, 1)
        tx4 = Transaction(weight=1, inputs=[_input1, _input2], outputs=[token_output], parents=parents,
                          tokens=[token_uid], storage=self.manager.tx_storage, timestamp=int(self.clock.seconds()))
        data_to_sign = tx4.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx4.inputs[0].data = data
        tx4.inputs[1].data = data
        self.manager.cpu_mining_service.resolve(tx4)
        with self.assertRaises(InputOutputMismatch):
            self.manager.verification_service.verify(tx4)

    def test_fee_token_melt(self):
        htr_change_utxo_index = 3
        initial_mint_amount = 500
        tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # melt tokens and transfer melt authority
        melt_amount = 100
        new_token_amount = tx.outputs[0].value - melt_amount

        inputs = [
            # token amount
            TxInput(tx.hash, 0, b''),
            # Melt authority
            TxInput(tx.hash, 2, b''),
            # HTR for fee
            TxInput(tx.hash, 3, b'')
        ]

        outputs = [
            # New token amount
            TxOutput(new_token_amount, script, 1),
            # Melt authority
            TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001)
        ]

        tx2 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        # pick the last tip tx output in HTR then subtracts the fee
        tx_fee = calculate_fee(self.manager._settings, tx2.get_complete_token_info())
        change_value = tx.outputs[htr_change_utxo_index].value - tx_fee
        outputs.append(TxOutput(change_value, script, 0))

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        self.resolve_and_propagate(tx2)
        self.check_tokens_index(token_uid, tx.hash, 1, tx2.hash, 1, new_token_amount)  # check total amount of tokens

    def test_fee_token_melt_paid_with_deposit(self):
        initial_mint_amount = 500
        tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount)
        deposit_tx = create_tokens(self.manager, self.address_b58, initial_mint_amount, use_genesis=False)
        fee_token_uid = tx.tokens[0]
        deposit_token_uid = deposit_tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # melt tokens and transfer melt authority
        melt_amount = 100
        new_token_amount = tx.outputs[0].value - melt_amount

        inputs = [
            # token amount
            TxInput(tx.hash, 0, b''),
            # Melt authority
            TxInput(tx.hash, 2, b''),
            # Deposit token to pay the fee
            TxInput(deposit_tx.hash, 0, b'')
        ]

        outputs = [
            # New token amount
            TxOutput(new_token_amount, script, 1),
            # Melt authority
            TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001),
        ]

        tx2 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            parents=parents,
            tokens=[fee_token_uid, deposit_token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )

        tx_fee = calculate_fee(self.manager._settings, tx2.get_complete_token_info())
        change_value = deposit_tx.outputs[0].value - get_token_amount_from_htr(self.manager._settings, tx_fee)
        outputs.append(TxOutput(change_value, script, 2))

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        self.resolve_and_propagate(tx2)

        # check total amount of tokens
        self.check_tokens_index(fee_token_uid, tx.hash, 1, tx2.hash, 1, new_token_amount)
        tokens_index = self.manager.tx_storage.indexes.tokens.get_token_info(deposit_token_uid)
        self.assertEqual(change_value, tokens_index.get_total())

    def test_fee_and_deposit_token_melt_paid_with_deposit(self):
        initial_mint_amount = 500
        tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount)
        deposit_tx = create_tokens(self.manager, self.address_b58, initial_mint_amount, use_genesis=False)
        fee_token_uid = tx.tokens[0]
        deposit_token_uid = deposit_tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # melt tokens and transfer melt authority
        melt_amount = 100
        new_token_amount = tx.outputs[0].value - melt_amount

        inputs = [
            # token amount
            TxInput(tx.hash, 0, b''),
            # Fee token melt authority
            TxInput(tx.hash, 2, b''),
            # Deposit token melt authority
            TxInput(deposit_tx.hash, 2, b''),
            # Deposit token to pay the fee
            TxInput(deposit_tx.hash, 0, b'')
        ]
        deposit_token_melt_amount = 200
        outputs = [
            # New token amount
            TxOutput(new_token_amount, script, 1),
            # Melt authority
            TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001),
            # HTR change output
            TxOutput(get_withdraw_amount(self.manager._settings, deposit_token_melt_amount), script, 0),
        ]

        tx2 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            parents=parents,
            tokens=[fee_token_uid, deposit_token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )

        tx_fee = calculate_fee(self.manager._settings, tx2.get_complete_token_info())
        # Deposit token change and melt in the same
        deposit_token_change_value = (
            deposit_tx.outputs[0].value
            - get_token_amount_from_htr(self.manager._settings, tx_fee)
            - deposit_token_melt_amount)
        outputs.append(TxOutput(deposit_token_change_value, script, 2))

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        self.resolve_and_propagate(tx2)

        # check total amount of tokens
        self.check_tokens_index(fee_token_uid, tx.hash, 1, tx2.hash, 1, new_token_amount)
        tokens_index = self.manager.tx_storage.indexes.tokens.get_token_info(deposit_token_uid)
        self.assertEqual(deposit_token_change_value, tokens_index.get_total())

    def test_fee_token_tx_paid_with_htr_and_deposit(self):
        initial_mint_amount = 500
        htr_amount = 5
        tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount, genesis_output_amount=htr_amount)
        deposit_tx = create_tokens(self.manager, self.address_b58, initial_mint_amount, use_genesis=False)
        fee_token_uid = tx.tokens[0]
        deposit_token_uid = deposit_tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        inputs = [
            # token amount
            TxInput(tx.hash, 0, b''),
            # Deposit token to pay the fee
            TxInput(deposit_tx.hash, 0, b''),
            # HTR
            TxInput(tx.hash, 4, b'')
        ]

        outputs = [
            # New token amount
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            # Deposit token change
            TxOutput(initial_mint_amount - get_token_amount_from_htr(
                self.manager._settings, 2 * self.manager._settings.FEE_PER_OUTPUT), script, 2),
            TxOutput(htr_amount - (3 * self.manager._settings.FEE_PER_OUTPUT), script)
        ]

        tx2 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            parents=parents,
            tokens=[fee_token_uid, deposit_token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        self.resolve_and_propagate(tx2)

    def test_fee_token_melt_and_deposit_token_to_pay_the_fee_without_melt_authority(self):
        initial_mint_amount = 500
        tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount)
        deposit_tx = create_tokens(self.manager, self.address_b58, initial_mint_amount, use_genesis=False)
        fee_token_uid = tx.tokens[0]
        deposit_token_uid = deposit_tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # melt tokens and transfer melt authority
        melt_amount = 100
        new_token_amount = tx.outputs[0].value - melt_amount

        inputs = [
            # token amount
            TxInput(tx.hash, 0, b''),
            # Fee token melt authority
            TxInput(tx.hash, 2, b''),
            # Deposit token to pay the fee
            TxInput(deposit_tx.hash, 0, b'')
        ]
        deposit_token_melt_amount = 200
        outputs = [
            # New token amount
            TxOutput(new_token_amount, script, 1),
            # Melt authority
            TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001),
            # HTR change output
            TxOutput(get_withdraw_amount(self.manager._settings, deposit_token_melt_amount), script, 0),
        ]

        tx2 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            parents=parents,
            tokens=[fee_token_uid, deposit_token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )

        tx_fee = calculate_fee(self.manager._settings, tx2.get_complete_token_info())
        # Deposit token change and melt in the same
        deposit_token_change_value = (
            deposit_tx.outputs[0].value
            - get_token_amount_from_htr(self.manager._settings, tx_fee)
            - deposit_token_melt_amount)
        outputs.append(TxOutput(deposit_token_change_value, script, 2))

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        with pytest.raises(InvalidNewTransaction) as e:
            self.resolve_and_propagate(tx2)
        assert isinstance(e.value.__cause__, InputOutputMismatch)

        # check total amount of tokens
        self.check_tokens_index(fee_token_uid, tx.hash, 1, tx.hash, 2, initial_mint_amount)
        self.check_tokens_index(deposit_token_uid, deposit_tx.hash, 1, deposit_tx.hash, 2,
                                initial_mint_amount)

    def test_fee_token_mint(self):
        htr_change_utxo_index = 3
        initial_mint_amount = 500
        tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # mint tokens and transfer mint authority
        mint_amount = 100
        inputs = [
            # Token Input
            TxInput(tx.hash, 1, b''),
            # HTR input
            TxInput(tx.hash, 3, b'')
        ]
        outputs = [
            # Token minted output
            TxOutput(mint_amount, script, 1),
            # Token mint authority
            TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
        ]

        tx2 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        # pick the last tip tx output in HTR then subtracts the fee
        tx_fee = calculate_fee(self.manager._settings, tx2.get_complete_token_info())
        change_value = tx.outputs[htr_change_utxo_index].value - tx_fee
        outputs.append(TxOutput(change_value, script, 0))

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)

        self.resolve_and_propagate(tx2)

        # check tokens index
        expected_mint_amount = initial_mint_amount + mint_amount
        self.check_tokens_index(token_uid, tx2.hash, 1, tx.hash, 2, expected_mint_amount)

    def test_fee_token_tx_without_paying(self):
        initial_mint_amount = 500
        tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount, genesis_output_amount=1)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        inputs = [
            # Token Input
            TxInput(tx.hash, 1, b''),
            # HTR input
            TxInput(tx.hash, 4, b'')
        ]
        outputs = [
            # Token output
            TxOutput(250, script, 1),
            # Token output
            TxOutput(250, script, 1),
            # HTR
            TxOutput(1, script, 0)
        ]

        tx2 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)

        with pytest.raises(InvalidNewTransaction) as e:
            self.resolve_and_propagate(tx2)
        assert isinstance(e.value.__cause__, InputOutputMismatch)

    def test_fee_token_burn_authority(self):
        initial_mint_amount = 500
        tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()

        inputs = [
            # Melt authority
            TxInput(tx.hash, 2, b''),
        ]

        outputs = []

        tx2 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        # pick the last tip tx output in HTR then subtracts the fee
        tx_fee = calculate_fee(self.manager._settings, tx2.get_complete_token_info())
        self.assertEqual(tx_fee, 0)

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        self.resolve_and_propagate(tx2)

    def check_tokens_index(self, token_uid: bytes, mint_tx_hash: bytes, mint_output: int, melt_tx_hash: bytes,
                           melt_output: int, token_amount: int) -> None:
        # check tokens index
        tokens_index = self.manager.tx_storage.indexes.tokens.get_token_info(token_uid)
        mint = list(tokens_index.iter_mint_utxos())
        melt = list(tokens_index.iter_melt_utxos())
        self.assertIn(TokenUtxoInfo(mint_tx_hash, mint_output), mint)
        self.assertIn(TokenUtxoInfo(melt_tx_hash, melt_output), melt)
        # there should only be one element on the indexes for the token
        self.assertEqual(1, len(mint))
        self.assertEqual(1, len(melt))
        # check total amount of tokens
        self.assertEqual(token_amount, tokens_index.get_total())

    def sign_inputs(self, tx: Transaction) -> None:
        wallet = self.manager.wallet
        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        signature_data = P2PKH.create_input_data(public_bytes, signature)

        for _input in tx.inputs:
            _input.data = signature_data

    def resolve_and_propagate(self, tx: Transaction) -> None:
        self.manager.cpu_mining_service.resolve(tx)
        self.manager.propagate_tx(tx, fails_silently=False)
        self.run_to_completion()

    def test_token_transfer_authority(self):
        wallet = self.manager.wallet
        tx = create_tokens(self.manager, self.address_b58)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # input with mint and output with melt
        _input1 = TxInput(tx.hash, 1, b'')
        token_output = TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001)
        tx2 = Transaction(weight=1, inputs=[_input1], outputs=[token_output], parents=parents, tokens=[token_uid],
                          storage=self.manager.tx_storage, timestamp=int(self.clock.seconds()))
        data_to_sign = tx2.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx2.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        self.manager.cpu_mining_service.resolve(tx2)
        with self.assertRaises(InvalidToken):
            self.manager.verification_service.verify(tx2)

        # input with melt and output with mint
        _input1 = TxInput(tx.hash, 2, b'')
        token_output = TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
        tx3 = Transaction(weight=1, inputs=[_input1], outputs=[token_output], parents=parents, tokens=[token_uid],
                          storage=self.manager.tx_storage, timestamp=int(self.clock.seconds()))
        data_to_sign = tx3.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx3.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        self.manager.cpu_mining_service.resolve(tx3)
        with self.assertRaises(InvalidToken):
            self.manager.verification_service.verify(tx3)

    def test_token_index_with_conflict(self, mint_amount=0):
        # create a new token and have a mint operation done. The tx that mints the
        # tokens has the following outputs:
        # 0. minted tokens
        # 1. mint authority;
        # 2. melt authority
        # 3. HTR deposit change
        tx = create_tokens(self.manager, self.address_b58, mint_amount=100)
        token_uid = tx.tokens[0]
        tokens_index = self.manager.tx_storage.indexes.tokens.get_token_info(tx.tokens[0])
        mint = list(tokens_index.iter_mint_utxos())
        melt = list(tokens_index.iter_melt_utxos())
        self.assertIn(TokenUtxoInfo(tx.hash, 1), mint)
        self.assertIn(TokenUtxoInfo(tx.hash, 2), melt)
        # there should only be one element on the indexes for the token
        self.assertEqual(1, len(mint))
        self.assertEqual(1, len(melt))
        # check total amount of tokens
        self.assertEqual(100, tokens_index.get_total())

        # new tx minting tokens
        mint_amount = 300
        deposit_amount = get_deposit_amount(self._settings, mint_amount)
        script = P2PKH.create_output_script(self.address)
        # inputs
        mint_input = TxInput(tx.hash, 1, b'')
        melt_input = TxInput(tx.hash, 2, b'')
        deposit_input = TxInput(tx.hash, 3, b'')
        # outputs
        mint_output = TxOutput(mint_amount, script, 1)
        authority_output1 = TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
        authority_output2 = TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001)
        deposit_output = TxOutput(tx.outputs[3].value - deposit_amount, script, 0)
        tx2 = Transaction(
            weight=1,
            inputs=[mint_input, melt_input, deposit_input],
            outputs=[authority_output1, authority_output2, mint_output, deposit_output],
            parents=self.manager.get_new_tx_parents(),
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        # sign inputs
        wallet = self.manager.wallet
        data_to_sign = tx2.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx2.inputs[0].data = data
        tx2.inputs[1].data = data
        tx2.inputs[2].data = data
        self.manager.cpu_mining_service.resolve(tx2)
        self.manager.propagate_tx(tx2)
        self.run_to_completion()

        # there should only be one element on the indexes for the token
        tokens_index = self.manager.tx_storage.indexes.tokens.get_token_info(tx.tokens[0])
        mint = list(tokens_index.iter_mint_utxos())
        melt = list(tokens_index.iter_melt_utxos())
        self.assertEqual(1, len(mint))
        self.assertEqual(1, len(melt))
        self.assertIn(TokenUtxoInfo(tx2.hash, 0), mint)
        self.assertIn(TokenUtxoInfo(tx2.hash, 1), melt)
        # check total amount of tokens has been updated
        self.assertEqual(400, tokens_index.get_total())

        # create conflicting tx by changing parents
        tx3 = Transaction.create_from_struct(tx2.get_struct())
        tx3.parents = [tx.parents[1], tx.parents[0]]
        tx3.weight = 3
        self.manager.cpu_mining_service.resolve(tx3)
        self.assertNotEqual(tx3.hash, tx2.hash)
        self.assertTrue(tx3.weight > tx2.weight)
        self.manager.propagate_tx(tx3)
        self.run_to_completion()

        # new tx should be on tokens index. Old tx should not be present
        tokens_index = self.manager.tx_storage.indexes.tokens.get_token_info(tx.tokens[0])
        mint = list(tokens_index.iter_mint_utxos())
        melt = list(tokens_index.iter_melt_utxos())
        self.assertIn(TokenUtxoInfo(tx3.hash, 0), mint)
        self.assertIn(TokenUtxoInfo(tx3.hash, 1), melt)
        # there should only be one element on the indexes for the token
        self.assertEqual(1, len(mint))
        self.assertEqual(1, len(melt))
        # should have same amount of tokens
        self.assertEqual(400, tokens_index.get_total())

    def test_token_info(self):
        def update_tx(tx):
            """ sighash_all data changes with token name or symbol, so we have to compute signature again
            """
            data_to_sign = tx.get_sighash_all()
            public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
            tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
            self.manager.cpu_mining_service.resolve(tx)

        # test token name and symbol
        tx = create_tokens(self.manager, self.address_b58)

        # max token name length
        tx.token_name = 'a' * self._settings.MAX_LENGTH_TOKEN_NAME
        update_tx(tx)
        self.manager.verification_service.verify(tx)

        # max token symbol length
        tx.token_symbol = 'a' * self._settings.MAX_LENGTH_TOKEN_SYMBOL
        update_tx(tx)
        self.manager.verification_service.verify(tx)

        # long token name
        tx.token_name = 'a' * (self._settings.MAX_LENGTH_TOKEN_NAME + 1)
        update_tx(tx)
        with self.assertRaises(TransactionDataError):
            self.manager.verification_service.verify(tx)

        # long token symbol
        tx.token_name = 'ValidName'
        tx.token_symbol = 'a' * (self._settings.MAX_LENGTH_TOKEN_SYMBOL + 1)
        update_tx(tx)
        with self.assertRaises(TransactionDataError):
            self.manager.verification_service.verify(tx)

        # Hathor token name
        tx.token_name = self._settings.HATHOR_TOKEN_NAME
        tx.token_symbol = 'TST'
        update_tx(tx)
        with self.assertRaises(TransactionDataError):
            self.manager.verification_service.verify(tx)

        # Hathor token symbol
        tx.token_name = 'Test'
        tx.token_symbol = self._settings.HATHOR_TOKEN_SYMBOL
        update_tx(tx)
        with self.assertRaises(TransactionDataError):
            self.manager.verification_service.verify(tx)

        # Token name unicode
        tx.token_name = 'Test ∞'
        tx.token_symbol = 'TST'
        token_info = tx.serialize_token_info()
        TokenCreationTransaction.deserialize_token_info(self.manager._settings, token_info)
        update_tx(tx)
        self.manager.verification_service.verify(tx)

        # Token symbol unicode
        tx.token_name = 'Test Token'
        tx.token_symbol = 'TST∞'
        token_info = tx.serialize_token_info()
        TokenCreationTransaction.deserialize_token_info(self.manager._settings, token_info)
        update_tx(tx)
        self.manager.verification_service.verify(tx)

    def test_token_mint_zero(self):
        # try to mint 0 tokens
        with pytest.raises(InvalidNewTransaction) as e:
            create_tokens(self.manager, self.address_b58, mint_amount=0)

        assert isinstance(e.value.__cause__, InvalidToken)

    def test_token_struct(self):
        tx = create_tokens(self.manager, self.address_b58, mint_amount=500)
        tx2 = TokenCreationTransaction.create_from_struct(tx.get_struct())
        self.assertEqual(tx.hash, tx2.hash)

    def test_unknown_authority(self):
        wallet = self.manager.wallet
        tx = create_tokens(self.manager, self.address_b58, mint_amount=500)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # try an unknown authority
        input1 = TxInput(tx.hash, 1, b'')
        input2 = TxInput(tx.hash, 2, b'')
        output = TxOutput((TxOutput.ALL_AUTHORITIES << 1), script, 0b10000001)
        tx2 = Transaction(
            weight=1,
            inputs=[input1, input2],
            outputs=[output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx2.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx2.inputs[0].data = data
        tx2.inputs[1].data = data
        self.manager.cpu_mining_service.resolve(tx2)
        with self.assertRaises(InvalidToken):
            self.manager.verification_service.verify(tx2)

    def test_token_info_serialization(self):
        tx = create_tokens(self.manager, self.address_b58, mint_amount=500)
        info = tx.serialize_token_info()

        def generate_invalid_enum_value(start: int = 1) -> int:
            valid_values = {item.value for item in TokenInfoVersion}
            candidate = start
            while candidate in valid_values:
                candidate += 1
            return candidate

        # try with a version outsite the enum
        invalid_version = generate_invalid_enum_value(1)
        info2 = bytes(int_to_bytes(invalid_version, 1)) + info[1:]

        with self.assertRaises(ValueError):
            TokenCreationTransaction.deserialize_token_info(self.manager._settings, info2)

    def test_token_info_not_utf8(self):
        token_name = 'TestCoin'
        token_symbol = 'TST'
        token_info_version = 1

        # Token version 1; Name length; Name; Symbol length; Symbol
        bytes1 = (int_to_bytes(token_info_version, 1) + int_to_bytes(len(token_name), 1) + token_name.encode('utf-8')
                  + int_to_bytes(len(token_symbol), 1) + token_symbol.encode('utf-8'))

        name, symbol, info_version, _ = TokenCreationTransaction.deserialize_token_info(self.manager._settings, bytes1)

        self.assertEqual(name, token_name)
        self.assertEqual(symbol, token_symbol)
        self.assertEqual(token_info_version, info_version)

        encoded_name = token_name.encode('utf-16')
        bytes2 = (int_to_bytes(token_info_version, 1) + int_to_bytes(len(encoded_name), 1) + encoded_name
                  + int_to_bytes(len(token_symbol), 1) + token_symbol.encode('utf-8'))

        with self.assertRaises(StructError):
            TokenCreationTransaction.deserialize_token_info(self.manager._settings, bytes2)

        encoded_symbol = token_symbol.encode('utf-16')
        bytes3 = (bytes([0x01]) + int_to_bytes(len(token_name), 1) + token_name.encode('utf-8')
                  + int_to_bytes(len(encoded_symbol), 1) + encoded_symbol)

        with self.assertRaises(StructError):
            TokenCreationTransaction.deserialize_token_info(self.manager._settings, bytes3)

    def test_block_with_htr_authority(self):
        parents = [tx.hash for tx in self.genesis]

        output_script = P2PKH.create_output_script(self.address)
        output = TxOutput(0b11, output_script, 0b10000000)
        self.assertTrue(output.is_token_authority())

        block = Block(
            nonce=100,
            outputs=[output],
            parents=parents,
            weight=1,  # low weight so we don't waste time with PoW
            storage=self.manager.tx_storage)

        self.manager.cpu_mining_service.resolve(block)
        with self.assertRaises(InvalidToken):
            self.manager.verification_service.verify(block)

    def test_voided_token_creation(self):
        tx1 = create_tokens(self.manager, self.address_b58, mint_amount=500, use_genesis=False)
        token_uid = tx1.tokens[0]

        # check tokens index
        tokens_index = self.manager.tx_storage.indexes.tokens.get_token_info(token_uid)
        mint = list(tokens_index.iter_mint_utxos())
        melt = list(tokens_index.iter_melt_utxos())
        self.assertEqual(1, len(mint))
        self.assertEqual(1, len(melt))

        # add simple tx that will void the token created above
        tx2 = add_new_double_spending(self.manager, tx=tx1, weight=(tx1.weight + 3), use_same_parents=True)
        self.assertFalse(bool(tx2.get_metadata().voided_by))
        self.assertTrue(bool(tx1.get_metadata().voided_by))
        mint = list(tokens_index.iter_mint_utxos())
        melt = list(tokens_index.iter_melt_utxos())
        self.assertEqual(1, len(mint))
        self.assertEqual(1, len(melt))
        tokens_index = self.manager.tx_storage.indexes.tokens.get_token_info(token_uid)
        print(tokens_index)
