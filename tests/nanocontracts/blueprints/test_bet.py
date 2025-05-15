import os
from typing import NamedTuple, Optional

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.nanocontracts.blueprints.bet import (
    DepositNotAllowed,
    InsufficientBalance,
    InvalidOracleSignature,
    InvalidToken,
    Result,
    ResultAlreadySet,
    ResultNotAvailable,
    TooLate,
    WithdrawalNotAllowed,
)
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import (
    Address,
    Amount,
    BlueprintId,
    ContractId,
    NCDepositAction,
    NCWithdrawalAction,
    SignedData,
)
from hathor.transaction.scripts import P2PKH
from hathor.util import not_none
from hathor.wallet import KeyPair
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase

settings = HathorSettings()


class BetInfo(NamedTuple):
    key: KeyPair
    address: Address
    amount: Amount
    score: str


class NCBetBlueprintTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()
        self.token_uid = settings.HATHOR_TOKEN_UID
        self.nc_id = ContractId(b'1' * 32)
        self.blueprint_id = BlueprintId(
            bytes.fromhex('3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595')
        )
        self.initialize_contract()
        self.nc_storage = self.runner.get_storage(self.nc_id)

    def _get_any_tx(self):
        genesis = self.manager.tx_storage.get_all_genesis()
        tx = list(genesis)[0]
        return tx

    def _get_any_address(self):
        password = os.urandom(12)
        key = KeyPair.create(password)
        address_b58 = key.address
        address_bytes = decode_address(not_none(address_b58))
        return address_bytes, key

    def get_current_timestamp(self):
        return int(self.clock.seconds())

    def _make_a_bet(self, amount: int, score: str, *, timestamp: Optional[int] = None) -> BetInfo:
        (address_bytes, key) = self._get_any_address()
        tx = self._get_any_tx()
        action = NCDepositAction(token_uid=self.token_uid, amount=amount)
        if timestamp is None:
            timestamp = self.get_current_timestamp()
        context = Context([action], tx, address_bytes, timestamp=timestamp)
        self.runner.call_public_method(self.nc_id, 'bet', context, address_bytes, score)
        return BetInfo(key=key, address=Address(address_bytes), amount=Amount(amount), score=score)

    def _set_result(self, result: Result, oracle_key: Optional[KeyPair] = None) -> None:
        signed_result = SignedData[Result](result, b'')

        if oracle_key is None:
            oracle_key = self.oracle_key

        result_bytes = signed_result.get_data_bytes(self.nc_id)
        signed_result.script_input = oracle_key.p2pkh_create_input_data(b'123', result_bytes)

        tx = self._get_any_tx()
        context = Context([], tx, Address(b''), timestamp=self.get_current_timestamp())
        self.runner.call_public_method(self.nc_id, 'set_result', context, signed_result)
        self.assertEqual(self.nc_storage.get('final_result'), '2x2')

    def _withdraw(self, address: Address, amount: int) -> None:
        tx = self._get_any_tx()
        action = NCWithdrawalAction(token_uid=self.token_uid, amount=amount)
        context = Context([action], tx, address, timestamp=self.get_current_timestamp())
        self.runner.call_public_method(self.nc_id, 'withdraw', context)

    def initialize_contract(self):
        runner = self.runner

        self.oracle_key = KeyPair.create(b'123')
        assert self.oracle_key.address is not None
        p2pkh = P2PKH(self.oracle_key.address)
        oracle_script = p2pkh.get_script()
        self.date_last_bet = self.get_current_timestamp() + 3600 * 24

        tx = self._get_any_tx()
        context = Context([], tx, b'', timestamp=self.get_current_timestamp())
        runner.create_contract(
            self.nc_id,
            self.blueprint_id,
            context,
            oracle_script,
            self.token_uid,
            self.date_last_bet,
        )

        storage = runner.get_storage(self.nc_id)
        self.assertEqual(storage.get('oracle_script'), oracle_script)
        self.assertEqual(storage.get('token_uid'), self.token_uid)
        self.assertEqual(storage.get('date_last_bet'), self.date_last_bet)

    def test_basic_flow(self) -> None:
        runner = self.runner

        tx = self._get_any_tx()

        ###
        # Make some bets.
        ###
        self._make_a_bet(100, '1x1')
        self._make_a_bet(200, '1x1')
        self._make_a_bet(300, '1x1')
        bet1 = self._make_a_bet(500, '2x2')

        ###
        # Set the final result.
        ###
        self._set_result('2x2')

        ###
        # Single winner withdraws all funds.
        ###
        self.assertEqual(1100, runner.call_view_method(self.nc_id, 'get_max_withdrawal', bet1.address))

        self._withdraw(bet1.address, 100)
        self.assertEqual(1000, runner.call_view_method(self.nc_id, 'get_max_withdrawal', bet1.address))

        self._withdraw(bet1.address, 1000)
        self.assertEqual(0, runner.call_view_method(self.nc_id, 'get_max_withdrawal', bet1.address))

        # Out of funds! Any withdrawal must fail from now on...
        amount = 1
        action = NCWithdrawalAction(token_uid=self.token_uid, amount=amount)
        context = Context([action], tx, bet1.address, timestamp=self.get_current_timestamp())
        with self.assertRaises(InsufficientBalance):
            runner.call_public_method(self.nc_id, 'withdraw', context)

    def test_make_a_bet_with_withdrawal(self):
        self._make_a_bet(100, '1x1')

        (address_bytes, _) = self._get_any_address()
        tx = self._get_any_tx()
        action = NCWithdrawalAction(token_uid=self.token_uid, amount=1)
        context = Context([action], tx, address_bytes, timestamp=self.get_current_timestamp())
        score = '1x1'
        with self.assertRaises(WithdrawalNotAllowed):
            self.runner.call_public_method(self.nc_id, 'bet', context, address_bytes, score)

    def test_make_a_bet_after_result(self):
        self._make_a_bet(100, '1x1')
        self._set_result('2x2')
        with self.assertRaises(ResultAlreadySet):
            self._make_a_bet(100, '1x1')

    def test_make_a_bet_after_date_last_bet(self):
        with self.assertRaises(TooLate):
            self._make_a_bet(100, '1x1', timestamp=self.date_last_bet + 1)

    def test_set_results_two_times(self):
        self._set_result('2x2')
        with self.assertRaises(ResultAlreadySet):
            self._set_result('5x1')

    def test_set_results_wrong_signature(self):
        wrong_oracle_key = KeyPair.create(b'123')
        with self.assertRaises(InvalidOracleSignature):
            self._set_result('3x2', oracle_key=wrong_oracle_key)

    def test_withdraw_before_result(self):
        bet1 = self._make_a_bet(100, '1x1')
        with self.assertRaises(ResultNotAvailable):
            self._withdraw(bet1.address, 100)

    def test_withdraw_with_deposits(self):
        (address_bytes, _) = self._get_any_address()
        tx = self._get_any_tx()
        action = NCDepositAction(token_uid=self.token_uid, amount=1)
        context = Context([action], tx, address_bytes, timestamp=self.get_current_timestamp())
        with self.assertRaises(DepositNotAllowed):
            self.runner.call_public_method(self.nc_id, 'withdraw', context)

    def test_make_a_bet_wrong_token(self):

        (address_bytes, _) = self._get_any_address()
        tx = self._get_any_tx()
        token_uid = b'xxx'
        self.assertNotEqual(token_uid, self.token_uid)
        action = NCDepositAction(token_uid=token_uid, amount=1)
        context = Context([action], tx, address_bytes, timestamp=self.get_current_timestamp())
        score = '1x1'
        with self.assertRaises(InvalidToken):
            self.runner.call_public_method(self.nc_id, 'bet', context, address_bytes, score)

    def test_withdraw_wrong_token(self):
        bet1 = self._make_a_bet(100, '1x1')

        tx = self._get_any_tx()
        token_uid = b'xxx'
        self.assertNotEqual(token_uid, self.token_uid)
        action = NCWithdrawalAction(token_uid=token_uid, amount=1)
        context = Context([action], tx, bet1.address, timestamp=self.get_current_timestamp())
        with self.assertRaises(InvalidToken):
            self.runner.call_public_method(self.nc_id, 'withdraw', context)
