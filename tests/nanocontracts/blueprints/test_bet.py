import os
from typing import Any, NamedTuple, Optional

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.nanocontracts.blueprints.bet import (
    Bet,
    DepositNotAllowed,
    InvalidOracleSignature,
    InvalidToken,
    Result,
    ResultAlreadySet,
    ResultNotAvailable,
    TooLate,
    WithdrawalNotAllowed,
)
from hathor.nanocontracts.exception import NCInsufficientFunds
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.storage import NCMemoryStorage
from hathor.nanocontracts.types import Context, NCAction, NCActionType, SignedData
from hathor.transaction.scripts import P2PKH
from hathor.util import not_none
from hathor.wallet import KeyPair
from tests import unittest

settings = HathorSettings()


class MyRunner(Runner):
    def call_public_method(self, method_name: str, ctx: Context, *args: Any) -> None:
        method = getattr(self.blueprint_class, method_name)
        parser = NCMethodParser(method)

        serialized_args = parser.serialize_args(list(args))
        deserialized_args = parser.parse_args_bytes(serialized_args)
        assert tuple(args) == tuple(deserialized_args)

        super().call_public_method(method_name, ctx, *args)


class BetInfo(NamedTuple):
    key: KeyPair
    address: bytes
    amount: int
    score: str


class NCBetBlueprintTestCase(unittest.TestCase):
    _enable_sync_v1 = True
    _enable_sync_v2 = True
    use_memory_storage = True

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet')
        self.token_uid = settings.HATHOR_TOKEN_UID
        self.nc_storage = NCMemoryStorage()
        self.runner = self.get_runner(Bet, self.nc_storage)

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
        action = NCAction(NCActionType.DEPOSIT, self.token_uid, amount)
        if timestamp is None:
            timestamp = self.get_current_timestamp()
        context = Context([action], tx, address_bytes, timestamp=timestamp)
        self.runner.call_public_method('bet', context, address_bytes, score)
        return BetInfo(key=key, address=address_bytes, amount=amount, score=score)

    def get_runner(self, blueprint, storage):
        runner = MyRunner(blueprint, b'', storage)
        return runner

    def _set_result(self, result: Result, oracle_key: Optional[KeyPair] = None) -> None:
        signed_result: SignedData[Result] = SignedData(result, b'')

        if oracle_key is None:
            oracle_key = self.oracle_key

        signed_result.script_input = oracle_key.p2pkh_create_input_data(b'123', signed_result.get_data_bytes())

        tx = self._get_any_tx()
        context = Context([], tx, b'', timestamp=self.get_current_timestamp())
        self.runner.call_public_method('set_result', context, signed_result)
        self.assertEqual(self.nc_storage.get('final_result'), '2x2')

    def _withdraw(self, address: bytes, amount: int) -> None:
        tx = self._get_any_tx()
        action = NCAction(NCActionType.WITHDRAWAL, self.token_uid, amount)
        context = Context([action], tx, address, timestamp=self.get_current_timestamp())
        self.runner.call_public_method('withdraw', context)

    def initialize_contract(self):
        runner = self.runner
        storage = self.nc_storage

        self.oracle_key = KeyPair.create(b'123')
        assert self.oracle_key.address is not None
        p2pkh = P2PKH(self.oracle_key.address)
        oracle_script = p2pkh.get_script()
        self.date_last_bet = self.get_current_timestamp() + 3600 * 24

        tx = self._get_any_tx()
        context = Context([], tx, b'', timestamp=self.get_current_timestamp())
        runner.call_public_method('initialize', context, oracle_script, self.token_uid, self.date_last_bet)
        self.assertEqual(storage.get('oracle_script'), oracle_script)
        self.assertEqual(storage.get('token_uid'), self.token_uid)
        self.assertEqual(storage.get('date_last_bet'), self.date_last_bet)

    def test_basic_flow(self) -> None:
        runner = self.runner
        self.initialize_contract()

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
        self.assertEqual(1100, runner.call_private_method('get_max_withdrawal', bet1.address))

        self._withdraw(bet1.address, 100)
        self.assertEqual(1000, runner.call_private_method('get_max_withdrawal', bet1.address))

        self._withdraw(bet1.address, 1000)
        self.assertEqual(0, runner.call_private_method('get_max_withdrawal', bet1.address))

        # Out of funds! Any withdrawal must fail from now on...
        amount = 1
        action = NCAction(NCActionType.WITHDRAWAL, self.token_uid, amount)
        context = Context([action], tx, bet1.address, timestamp=self.get_current_timestamp())
        with self.assertRaises(NCInsufficientFunds):
            runner.call_public_method('withdraw', context)

    def test_make_a_bet_with_withdrawal(self):
        self.initialize_contract()
        self._make_a_bet(100, '1x1')

        (address_bytes, _) = self._get_any_address()
        tx = self._get_any_tx()
        action = NCAction(NCActionType.WITHDRAWAL, self.token_uid, 1)
        context = Context([action], tx, address_bytes, timestamp=self.get_current_timestamp())
        score = '1x1'
        with self.assertRaises(WithdrawalNotAllowed):
            self.runner.call_public_method('bet', context, address_bytes, score)

    def test_make_a_bet_after_result(self):
        self.initialize_contract()
        self._make_a_bet(100, '1x1')
        self._set_result('2x2')
        with self.assertRaises(ResultAlreadySet):
            self._make_a_bet(100, '1x1')

    def test_make_a_bet_after_date_last_bet(self):
        self.initialize_contract()
        with self.assertRaises(TooLate):
            self._make_a_bet(100, '1x1', timestamp=self.date_last_bet + 1)

    def test_set_results_two_times(self):
        self.initialize_contract()
        self._set_result('2x2')
        with self.assertRaises(ResultAlreadySet):
            self._set_result('5x1')

    def test_set_results_wrong_signature(self):
        self.initialize_contract()
        wrong_oracle_key = KeyPair.create(b'123')
        with self.assertRaises(InvalidOracleSignature):
            self._set_result('3x2', oracle_key=wrong_oracle_key)

    def test_withdraw_before_result(self):
        self.initialize_contract()
        bet1 = self._make_a_bet(100, '1x1')
        with self.assertRaises(ResultNotAvailable):
            self._withdraw(bet1.address, 100)

    def test_withdraw_with_deposits(self):
        self.initialize_contract()
        (address_bytes, _) = self._get_any_address()
        tx = self._get_any_tx()
        action = NCAction(NCActionType.DEPOSIT, self.token_uid, 1)
        context = Context([action], tx, address_bytes, timestamp=self.get_current_timestamp())
        with self.assertRaises(DepositNotAllowed):
            self.runner.call_public_method('withdraw', context)

    def test_make_a_bet_wrong_token(self):
        self.initialize_contract()

        (address_bytes, _) = self._get_any_address()
        tx = self._get_any_tx()
        token_uid = b'xxx'
        self.assertNotEqual(token_uid, self.token_uid)
        action = NCAction(NCActionType.DEPOSIT, token_uid, 1)
        context = Context([action], tx, address_bytes, timestamp=self.get_current_timestamp())
        score = '1x1'
        with self.assertRaises(InvalidToken):
            self.runner.call_public_method('bet', context, address_bytes, score)

    def test_withdraw_wrong_token(self):
        self.initialize_contract()
        bet1 = self._make_a_bet(100, '1x1')

        tx = self._get_any_tx()
        token_uid = b'xxx'
        self.assertNotEqual(token_uid, self.token_uid)
        action = NCAction(NCActionType.WITHDRAWAL, token_uid, 1)
        context = Context([action], tx, bet1.address, timestamp=self.get_current_timestamp())
        # We can't really reach the InvalidToken exception because the contract will not have balance
        # and its execution will fail before executing the withdraw method.
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method('withdraw', context)
