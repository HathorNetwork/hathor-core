from unittest.mock import patch

import pytest

from hathor.crypto.util import decode_address
from hathor.exception import InvalidNewTransaction
from hathor.indexes.tokens_index import TokenUtxoInfo
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import InputOutputMismatch, TransactionDataError
from hathor.transaction.fee import calculate_fee
from hathor.transaction.scripts import P2PKH
from hathor.transaction.util import get_deposit_token_amount_from_htr, get_deposit_token_withdraw_amount
from tests import unittest
from tests.utils import add_blocks_unlock_reward, create_fee_tokens, create_tokens, get_genesis_key


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

        #  It's the tx item output signature
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        self.resolve_and_propagate(tx2)
        self.check_tokens_index(token_uid, tx.hash, 1, tx2.hash, 1, new_token_amount)  # check total amount of tokens

    def test_fee_token_melt_without_output(self):
        htr_change_utxo_index = 3
        initial_mint_amount = 500
        tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # melt tokens and transfer melt authority
        inputs = [
            # token amount
            TxInput(tx.hash, 0, b''),
            # Melt authority
            TxInput(tx.hash, 2, b''),
            # HTR for fee
            TxInput(tx.hash, 3, b'')
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
        # check if only the melting operation was considered
        self.assertEqual(tx_fee, 1)
        change_value = tx.outputs[htr_change_utxo_index].value - tx_fee
        tx2.outputs.append(TxOutput(change_value, script, 0))

        self.sign_inputs(tx2)
        self.resolve_and_propagate(tx2)

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
        change_value = deposit_tx.outputs[0].value - get_deposit_token_amount_from_htr(self.manager._settings, tx_fee)
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
            TxOutput(get_deposit_token_withdraw_amount(self.manager._settings, deposit_token_melt_amount), script, 0),
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
            - get_deposit_token_amount_from_htr(self.manager._settings, tx_fee)
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
        tx_output_value = initial_mint_amount - get_deposit_token_amount_from_htr(
            self.manager._settings, 2 * self.manager._settings.FEE_PER_OUTPUT)
        outputs = [
            # New token amount
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            # Deposit token change
            TxOutput(tx_output_value, script, 2),
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
            TxOutput(get_deposit_token_withdraw_amount(self.manager._settings, deposit_token_melt_amount), script, 0),
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
            - get_deposit_token_amount_from_htr(self.manager._settings, tx_fee)
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

    def test_fee_token_activation(self):
        with patch(
            'hathor.verification.token_creation_transaction_verifier.should_charge_fee',
            return_value=False
        ):
            with pytest.raises(InvalidNewTransaction) as e:
                create_fee_tokens(self.manager, self.address_b58)
            assert isinstance(e.value.__cause__, TransactionDataError)

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
