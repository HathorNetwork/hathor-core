import pytest

from hathor.crypto.util import decode_address
from hathor.exception import InvalidNewTransaction
from hathor.indexes.tokens_index import TokenUtxoInfo
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import ForbiddenMelt, InputOutputMismatch, TransactionDataError
from hathor.transaction.scripts import P2PKH
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.token_info import TokenVersion
from hathor.transaction.util import get_deposit_token_withdraw_amount
from tests import unittest
from tests.utils import (
    add_blocks_unlock_reward,
    create_fee_tokens,
    create_tokens,
    get_deposit_token_amount_from_htr,
    get_genesis_key,
)


class FeeTokenTest(unittest.TestCase):
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

    def test_fee_token_melt(self) -> None:
        initial_mint_amount = 500
        htr_amount = 100
        fee_tx = create_fee_tokens(
            self.manager,
            self.address_b58,
            initial_mint_amount,
            genesis_output_amount=htr_amount
        )
        fee_tx2 = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount, 'FBT2', 'FFB')
        fee_tx3 = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount, 'FBT3', 'FFF')
        fee_token_uid = fee_tx.tokens[0]
        fee_token2_uid = fee_tx2.tokens[0]
        fee_token3_uid = fee_tx3.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        inputs = [
            # token amount
            TxInput(fee_tx.hash, 0, b''),
            # Melt authority
            TxInput(fee_tx.hash, 2, b''),
            # HTR for fee
            TxInput(fee_tx.hash, 4, b'')
        ]

        outputs = [
            # New token amount
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            # Melt authority
            TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001),
        ]

        tx2 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            parents=parents,
            tokens=[fee_token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        # Melt 100 tokens from fee_token and add 4 outputs, should charge only by the outputs count
        tx_fee = tx2.get_complete_token_info().calculate_fee(self.manager._settings)
        self.assertEqual(tx_fee, 4)
        change_value = htr_amount - tx_fee
        # 100 htr - 4 htr (fee)
        self.assertEqual(change_value, 96)
        outputs.append(TxOutput(change_value, script, 0))

        #  It's the tx item output signature
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        self.resolve_and_propagate(tx2)

        inputs = [
            TxInput(tx2.hash, 0, b''),
            TxInput(tx2.hash, 1, b''),
            TxInput(tx2.hash, 2, b''),
            TxInput(tx2.hash, 3, b''),
            # melt authority
            TxInput(tx2.hash, 4, b''),
            # HTR
            TxInput(tx2.hash, 5, b''),
            # fee token 2 - amount
            TxInput(fee_tx2.hash, 0, b''),
            # fee token 2 Melt authority
            TxInput(fee_tx2.hash, 2, b''),
            # fee token 3 - amount
            TxInput(fee_tx3.hash, 0, b''),
            # fee token 3 Melt authority
            TxInput(fee_tx3.hash, 2, b''),
        ]

        outputs = [
            TxOutput(100, script, 2),
            TxOutput(100, script, 2),
            TxOutput(100, script, 2)
        ]

        tx3 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            parents=self.manager.get_new_tx_parents(),
            tokens=[fee_token_uid, fee_token2_uid, fee_token3_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )

        # melting 2 tokens without outputs, should charge FEE_PER_OUT * 2 = 2
        # melting 1 token with outputs, should charge 1 per non-authority output = 3
        tx3_fee = tx3.get_complete_token_info().calculate_fee(self.manager._settings)
        # Multiple inputs should be only charge once per token when no outputs are present
        self.assertEqual(tx3_fee, 5)
        tx3_change_value = change_value - tx3_fee
        # tx2 change value - fee: 96 - 5
        self.assertEqual(tx3_change_value, 91)
        tx3.outputs.append(TxOutput(tx3_change_value, script, 0))

        self.sign_inputs(tx3)
        self.resolve_and_propagate(tx3)

    def test_fee_token_melt_without_authority(self) -> None:
        htr_amount = 5
        initial_mint_amount = 500
        tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount, genesis_output_amount=htr_amount)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # melt tokens and transfer melt authority
        melt_amount = 100
        new_token_amount = tx.outputs[0].value - melt_amount

        inputs = [
            # token amount
            TxInput(tx.hash, 0, b''),
            # HTR for fee
            TxInput(tx.hash, 4, b'')
        ]

        outputs = [
            # New token amount
            TxOutput(new_token_amount, script, 1),
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
        tx_fee = tx2.get_complete_token_info().calculate_fee(self.manager._settings)
        self.assertEqual(tx_fee, 1)
        change_value = htr_amount - tx_fee
        self.assertEqual(change_value, 4)
        outputs.append(TxOutput(change_value, script, 0))

        #  It's the tx item output signature
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        with pytest.raises(InvalidNewTransaction) as e:
            self.resolve_and_propagate(tx2)
        assert isinstance(e.value.__cause__, ForbiddenMelt)
        assert 'tokens melted, but there is no melt authority input' in str(e.value)

    def test_fee_token_melt_without_output(self) -> None:
        htr_amount = 5
        initial_mint_amount = 500
        tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount, genesis_output_amount=htr_amount)
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
            TxInput(tx.hash, 4, b'')
        ]

        tx2 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=[],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        # pick the last tip tx output in HTR then subtracts the fee
        tx_fee = tx2.get_complete_token_info().calculate_fee(self.manager._settings)
        # check if only the melting operation was considered
        self.assertEqual(tx_fee, 1)
        change_value = htr_amount - tx_fee
        self.assertEqual(change_value, 4)
        tx2.outputs.append(TxOutput(change_value, script, 0))

        self.sign_inputs(tx2)
        self.resolve_and_propagate(tx2)

    def test_fee_token_melt_paid_with_deposit(self) -> None:
        # fbt -> Fee based token
        # dbt -> deposit based token
        initial_mint_amount = 500
        fbt_tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount)
        dbt_tx = create_tokens(self.manager, self.address_b58, initial_mint_amount, use_genesis=False)
        fee_token_uid = fbt_tx.tokens[0]
        deposit_token_uid = dbt_tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # melt tokens and transfer melt authority
        melt_amount = 100
        new_token_amount = initial_mint_amount - melt_amount  # 500 - 100 = 400

        inputs = [
            # token amount
            TxInput(fbt_tx.hash, 0, b''),
            # Melt authority
            TxInput(fbt_tx.hash, 2, b''),
            # Deposit token to pay the fee
            TxInput(dbt_tx.hash, 0, b'')
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

        tx_fee = tx2.get_complete_token_info().calculate_fee(self.manager._settings)
        self.assertEqual(tx_fee, 1)
        change_value = initial_mint_amount - get_deposit_token_amount_from_htr(tx_fee)
        # 500 from initial mint amount - 100 fee
        self.assertEqual(change_value, 400)
        outputs.append(TxOutput(change_value, script, 2))

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        self.resolve_and_propagate(tx2)

        # check total amount of tokens
        self.check_tokens_index(
            token_uid=fee_token_uid,
            mint_tx_hash=fbt_tx.hash,
            mint_output=1,
            melt_tx_hash=tx2.hash,
            melt_output=1,
            token_amount=new_token_amount
        )
        tokens_index = self.manager.tx_storage.indexes.tokens.get_token_info(deposit_token_uid)
        self.assertEqual(change_value, tokens_index.get_total())

    def test_fee_and_deposit_token_melt_paid_with_deposit(self) -> None:
        # fbt -> Fee based token
        # dbt -> deposit based token
        initial_mint_amount = 500
        fbt_tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount)
        dbt_tx = create_tokens(self.manager, self.address_b58, initial_mint_amount, use_genesis=False)
        fee_token_uid = fbt_tx.tokens[0]
        deposit_token_uid = dbt_tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # melt tokens and transfer melt authority
        melt_amount = 100
        new_token_amount = initial_mint_amount - melt_amount  # 500 - 100 = 400

        inputs = [
            # token amount
            TxInput(fbt_tx.hash, 0, b''),
            # Fee token melt authority
            TxInput(fbt_tx.hash, 2, b''),
            # Deposit token melt authority
            TxInput(dbt_tx.hash, 2, b''),
            # Deposit token to pay the fee
            TxInput(dbt_tx.hash, 0, b'')
        ]
        dbt_melt_amount = 200
        htr_change_value = get_deposit_token_withdraw_amount(self.manager._settings, dbt_melt_amount)
        # 200 dbt -> 2 htr
        self.assertEqual(htr_change_value, 2)
        outputs = [
            # New token amount
            TxOutput(new_token_amount, script, 1),
            # Melt authority
            TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001),
            # HTR change output
            TxOutput(htr_change_value, script, 0),
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

        tx_fee = tx2.get_complete_token_info().calculate_fee(self.manager._settings)
        self.assertEqual(tx_fee, 1)
        # Deposit token change and melt in the same
        deposit_token_change_value = (
            initial_mint_amount
            - get_deposit_token_amount_from_htr(tx_fee)
            - dbt_melt_amount)
        # 500 - 100 - 200 = 200
        self.assertEqual(deposit_token_change_value, 200)
        outputs.append(TxOutput(deposit_token_change_value, script, 2))

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        self.resolve_and_propagate(tx2)

        # check total amount of tokens
        self.check_tokens_index(
            token_uid=fee_token_uid,
            mint_tx_hash=fbt_tx.hash,
            mint_output=1,
            melt_tx_hash=tx2.hash,
            melt_output=1,
            token_amount=new_token_amount
        )
        tokens_index = self.manager.tx_storage.indexes.tokens.get_token_info(deposit_token_uid)
        self.assertEqual(deposit_token_change_value, tokens_index.get_total())

    def test_fee_token_tx_paid_with_htr_and_deposit(self) -> None:
        # fbt -> Fee based token
        # dbt -> deposit based token
        initial_mint_amount = 500
        htr_amount = 5
        fbt_tx = create_fee_tokens(
            self.manager,
            self.address_b58,
            initial_mint_amount,
            genesis_output_amount=htr_amount
        )
        dbt_tx = create_tokens(self.manager, self.address_b58, initial_mint_amount, use_genesis=False)
        fee_token_uid = fbt_tx.tokens[0]
        deposit_token_uid = dbt_tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        inputs = [
            # token amount
            TxInput(fbt_tx.hash, 0, b''),
            # Deposit token to pay the fee
            TxInput(dbt_tx.hash, 0, b''),
            # HTR
            TxInput(fbt_tx.hash, 4, b'')
        ]

        outputs = [
            # New token amount
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            TxOutput(100, script, 1),
            # Deposit token change
            TxOutput(300, script, 2),  # 500 - 200
            TxOutput(2, script)  # 5 - 3
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
        fee = tx2.get_complete_token_info().calculate_fee(self.manager._settings)
        self.assertEqual(fee, 5)

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        self.resolve_and_propagate(tx2)

    def test_fee_token_melt_and_deposit_token_to_pay_the_fee_without_melt_authority(self) -> None:
        # fbt -> Fee based token
        # dbt -> deposit based token
        initial_mint_amount = 500
        fbt_tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount)
        dbt_tx = create_tokens(self.manager, self.address_b58, initial_mint_amount, use_genesis=False)
        fbt_token_uid = fbt_tx.tokens[0]
        dbt_token_uid = dbt_tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # melt tokens and transfer melt authority
        melt_amount = 100
        new_fbt_amount = initial_mint_amount - melt_amount

        inputs = [
            # token amount
            TxInput(fbt_tx.hash, 0, b''),
            # Fee token melt authority
            TxInput(fbt_tx.hash, 2, b''),
            # Deposit token to pay the fee
            TxInput(dbt_tx.hash, 0, b''),
        ]

        outputs = [
            # New fbt token amount
            TxOutput(new_fbt_amount, script, 1),
            # Melt authority
            fbt_tx.outputs[2],
            # HTR change output
            TxOutput(4, script, 0)
        ]

        tx2 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            parents=parents,
            tokens=[fbt_token_uid, dbt_token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )

        tx_fee = tx2.get_complete_token_info().calculate_fee(self.manager._settings)
        self.assertEqual(tx_fee, 1)
        dbt_melt_amount = 100
        # Deposit token change and melt in the same
        dbt_change_value = (
            initial_mint_amount
            - get_deposit_token_amount_from_htr(tx_fee)
            - dbt_melt_amount)
        # 500 - 100 - 100 = 300
        self.assertEqual(dbt_change_value, 300)
        outputs.append(TxOutput(dbt_change_value, script, 2))

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        with pytest.raises(InvalidNewTransaction) as e:
            self.resolve_and_propagate(tx2)
        assert 'Melting tokens without a melt authority is forbidden' in str(e.value)

        # check total amount of tokens
        self.check_tokens_index(
            token_uid=fbt_token_uid,
            mint_tx_hash=fbt_tx.hash,
            mint_output=1,
            melt_tx_hash=fbt_tx.hash,
            melt_output=2,
            token_amount=initial_mint_amount
        )
        self.check_tokens_index(
            token_uid=dbt_token_uid,
            mint_tx_hash=dbt_tx.hash,
            mint_output=1,
            melt_tx_hash=dbt_tx.hash,
            melt_output=2,
            token_amount=initial_mint_amount
        )

    def test_fee_token_melt_deposit_token_with_invalid_amount(self) -> None:
        # fbt -> Fee based token
        # dbt -> deposit based token
        initial_mint_amount = 500
        fbt_tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount)
        dbt_tx = create_tokens(self.manager, self.address_b58, initial_mint_amount, use_genesis=False)
        fbt_token_uid = fbt_tx.tokens[0]
        dbt_token_uid = dbt_tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # melt tokens and transfer melt authority
        melt_amount = 100
        new_fbt_amount = initial_mint_amount - melt_amount

        inputs = [
            # token amount
            TxInput(fbt_tx.hash, 0, b''),
            # Fee token melt authority
            TxInput(fbt_tx.hash, 2, b''),
            # Deposit token to pay the fee
            TxInput(dbt_tx.hash, 0, b''),
        ]

        outputs = [
            # New fbt token amount
            TxOutput(new_fbt_amount, script, 1),
            # Melt authority
            fbt_tx.outputs[2]
        ]

        tx2 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            parents=parents,
            tokens=[fbt_token_uid, dbt_token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )

        tx_fee = tx2.get_complete_token_info().calculate_fee(self.manager._settings)
        self.assertEqual(tx_fee, 1)
        dbt_invalid_melt_amount = 99
        # Deposit token change and melt in the same
        dbt_change_value = (
            initial_mint_amount
            - get_deposit_token_amount_from_htr(tx_fee)
            - dbt_invalid_melt_amount)
        # 500 - 100 - 99 = 301
        self.assertEqual(dbt_change_value, 301)
        outputs.append(TxOutput(dbt_change_value, script, 2))

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        with pytest.raises(InvalidNewTransaction) as e:
            self.resolve_and_propagate(tx2)
        assert 'Paying fees with non integer amount is forbidden' in str(e.value)

        # check total amount of tokens
        self.check_tokens_index(
            token_uid=fbt_token_uid,
            mint_tx_hash=fbt_tx.hash,
            mint_output=1,
            melt_tx_hash=fbt_tx.hash,
            melt_output=2,
            token_amount=initial_mint_amount
        )
        self.check_tokens_index(
            token_uid=dbt_token_uid,
            mint_tx_hash=dbt_tx.hash,
            mint_output=1,
            melt_tx_hash=dbt_tx.hash,
            melt_output=2,
            token_amount=initial_mint_amount
        )

    def test_fee_token_mint(self) -> None:
        # fbt -> Fee based token
        initial_mint_amount = 500
        htr_amount = 5
        fbt_tx = create_fee_tokens(
            self.manager,
            self.address_b58,
            initial_mint_amount,
            genesis_output_amount=htr_amount
        )
        token_uid = fbt_tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # mint tokens and transfer mint authority
        mint_amount = 100
        inputs = [
            # Mint authority
            TxInput(fbt_tx.hash, 1, b''),
            # HTR input
            TxInput(fbt_tx.hash, 4, b'')
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
        tx_fee = tx2.get_complete_token_info().calculate_fee(self.manager._settings)
        self.assertEqual(tx_fee, 1)
        change_value = htr_amount - tx_fee
        self.assertEqual(change_value, 4)
        outputs.append(TxOutput(change_value, script, 0))

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)

        self.resolve_and_propagate(tx2)

        # check tokens index
        expected_mint_amount = initial_mint_amount + mint_amount
        self.assertEqual(expected_mint_amount, 600)
        self.check_tokens_index(
            token_uid=token_uid,
            mint_tx_hash=tx2.hash,
            mint_output=1,
            melt_tx_hash=fbt_tx.hash,
            melt_output=2,
            token_amount=expected_mint_amount
        )

    def test_fee_token_tx_without_paying(self) -> None:
        initial_mint_amount = 500
        tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount, genesis_output_amount=1)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        inputs = [
            # Token Input
            TxInput(tx.hash, 1, b''),
        ]
        outputs = [
            # Token output
            TxOutput(250, script, 1),
            # Token output
            TxOutput(250, script, 1),
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
        fee = tx2.get_complete_token_info().calculate_fee(self.manager._settings)
        self.assertEqual(fee, 2)

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)

        with pytest.raises(InvalidNewTransaction) as e:
            self.resolve_and_propagate(tx2)
        assert isinstance(e.value.__cause__, InputOutputMismatch)
        assert "HTR balance is different than expected. (amount=0, expected=-2)" in str(e.value)

    def test_fee_token_burn_authority(self) -> None:
        initial_mint_amount = 500
        tx = create_fee_tokens(self.manager, self.address_b58, initial_mint_amount)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()

        inputs = [
            # Melt authority
            TxInput(tx.hash, 2, b''),
        ]

        tx2 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=[],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )

        tx_fee = tx2.get_complete_token_info().calculate_fee(self.manager._settings)
        self.assertEqual(tx_fee, 0)

        #  It's the signature of the output of the tx item
        #  this signature_data allows the tx output to be spent by the tx2 inputs
        self.sign_inputs(tx2)
        self.resolve_and_propagate(tx2)

    def test_fee_token_activation(self) -> None:
        custom_manager = self.create_peer(
            'testnet',
            unlock_wallet=True,
            wallet_index=True,
            settings=self._settings._replace(ENABLE_FEE_TOKEN=False)
        )
        with pytest.raises(InvalidNewTransaction) as e:
            create_fee_tokens(custom_manager, self.address_b58)
        assert isinstance(e.value.__cause__, TransactionDataError)
        # 2 is the TokenVersion.FEE enum value
        assert "full validation failed: Invalid token version (2)" in str(e.value)

    def test_verify_token_info(self) -> None:
        """
        By adding the TokenVersion enum as an argument of create token transaction
        we should assert the validation when some invalid token data is propagated
        """
        script = P2PKH.create_output_script(self.address)

        parents = self.manager.get_new_tx_parents()

        deposit_input = [TxInput(self.genesis_blocks[0].hash, 0, b'')]
        timestamp = int(self.manager.reactor.seconds())

        outputs = [
            # mint output
            TxOutput(500, script, 0b00000001),
            # authority outputs
            TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001),
            TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001),
            # deposit output
            TxOutput(self.genesis_blocks[0].outputs[0].value, script, 0)
        ]

        # Invalid token_version
        tx = TokenCreationTransaction(
            weight=1,
            parents=parents,
            storage=self.manager.tx_storage,
            inputs=deposit_input,
            outputs=outputs,
            token_name='ValidName',
            token_symbol='VNA',
            timestamp=timestamp,
            token_version=TokenVersion.NATIVE
        )
        self.sign_inputs(tx)

        # Invalid token_name
        tx2 = TokenCreationTransaction(
            weight=1,
            parents=parents,
            storage=self.manager.tx_storage,
            inputs=deposit_input,
            outputs=outputs,
            token_name='Hathor',
            token_symbol='ITK',
            timestamp=timestamp,
            token_version=TokenVersion.DEPOSIT
        )
        self.sign_inputs(tx2)

        # Invalid token_symbol
        tx3 = TokenCreationTransaction(
            weight=1,
            parents=parents,
            storage=self.manager.tx_storage,
            inputs=deposit_input,
            outputs=outputs,
            token_name='ValidName',
            token_symbol='HTR',
            timestamp=timestamp,
            token_version=TokenVersion.FEE
        )

        self.sign_inputs(tx3)

        with pytest.raises(InvalidNewTransaction) as e:
            self.resolve_and_propagate(tx)
        assert 'Invalid token version (0)' in str(e.value)

        with pytest.raises(InvalidNewTransaction) as e:
            self.resolve_and_propagate(tx2)
        assert 'Invalid token name (Hathor)' in str(e.value)

        with pytest.raises(InvalidNewTransaction) as e:
            self.resolve_and_propagate(tx3)
        assert 'Invalid token symbol (HTR)' in str(e.value)

    def check_tokens_index(
        self,
        *,
        token_uid: bytes,
        mint_tx_hash: bytes,
        mint_output: int,
        melt_tx_hash: bytes,
        melt_output: int,
        token_amount: int
    ) -> None:
        # check tokens index
        tokens_index = self.manager.tx_storage.indexes.tokens.get_token_info(token_uid)
        mint = list(tokens_index.iter_mint_utxos())
        melt = list(tokens_index.iter_melt_utxos())
        # there should only be one element on the indexes for the token
        self.assertEqual(1, len(mint))
        self.assertEqual(1, len(melt))
        self.assertEqual(TokenUtxoInfo(mint_tx_hash, mint_output), mint[0])
        self.assertEqual(TokenUtxoInfo(melt_tx_hash, melt_output), melt[0])

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
        self.manager.propagate_tx(tx)
        self.run_to_completion()
