import inspect
import os
import re
from typing import NamedTuple, Optional

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.nanocontracts.nc_types import NCType, make_nc_type_for_arg_type as make_nc_type
from hathor.nanocontracts.types import (
    Address,
    Amount,
    ContractId,
    NCDepositAction,
    NCWithdrawalAction,
    SignedData,
    Timestamp,
    TokenUid,
    TxOutputScript,
    VertexId,
)
from hathor.transaction.scripts import P2PKH
from hathor.util import not_none
from hathor.wallet import KeyPair
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.test_blueprints import bet

settings = HathorSettings()

TX_OUTPUT_SCRIPT_NC_TYPE = make_nc_type(TxOutputScript)
RESULT_NC_TYPE: NCType[str | None] = make_nc_type(str | None)  # type: ignore[arg-type]
TIMESTAMP_NC_TYPE = make_nc_type(Timestamp)
TOKEN_UID_NC_TYPE = make_nc_type(TokenUid)


class BetInfo(NamedTuple):
    key: KeyPair
    address: Address
    amount: Amount
    score: str


class NCBetBlueprintTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()
        self.blueprint_id = self.register_blueprint_file(inspect.getfile(bet))
        self.token_uid = TokenUid(settings.HATHOR_TOKEN_UID)
        self.nc_id = ContractId(VertexId(b'1' * 32))
        self.initialize_contract()
        self.nc_storage = self.runner.get_storage(self.nc_id)

    def _get_any_address(self) -> tuple[Address, KeyPair]:
        password = os.urandom(12)
        key = KeyPair.create(password)
        address_b58 = key.address
        address_bytes = Address(decode_address(not_none(address_b58)))
        return address_bytes, key

    def get_current_timestamp(self) -> int:
        return int(self.clock.seconds())

    def _make_a_bet(self, amount: int, score: str, *, timestamp: Optional[int] = None) -> BetInfo:
        (address_bytes, key) = self._get_any_address()
        action = NCDepositAction(token_uid=self.token_uid, amount=amount)
        context = self.create_context(caller_id=address_bytes, actions=[action], timestamp=timestamp)
        self.runner.call_public_method(self.nc_id, 'bet', context, address_bytes, score)
        return BetInfo(key=key, address=Address(address_bytes), amount=Amount(amount), score=score)

    def _set_result(self, result: str, oracle_key: Optional[KeyPair] = None) -> None:
        signed_result = SignedData[str](result, b'')

        if oracle_key is None:
            oracle_key = self.oracle_key

        result_bytes = signed_result.get_data_bytes(self.nc_id)
        signed_result.script_input = oracle_key.p2pkh_create_input_data(b'123', result_bytes)

        context = self.create_context()
        self.runner.call_public_method(self.nc_id, 'set_result', context, signed_result)
        final_result = self.nc_storage.get_obj(b'final_result', RESULT_NC_TYPE)
        self.assertEqual(final_result, '2x2')

    def _withdraw(self, address: Address, amount: int) -> None:
        action = NCWithdrawalAction(token_uid=self.token_uid, amount=amount)
        context = self.create_context(caller_id=address, actions=[action])
        self.runner.call_public_method(self.nc_id, 'withdraw', context)

    def initialize_contract(self) -> None:
        self.oracle_key = KeyPair.create(b'123')
        assert self.oracle_key.address is not None
        self.oracle_script = P2PKH(self.oracle_key.address).get_script()
        self.date_last_bet = self.get_current_timestamp() + 3600 * 24
        self.runner.create_contract(
            self.nc_id,
            self.blueprint_id,
            self.create_context(),
            self.oracle_script,
            self.token_uid,
            self.date_last_bet,
        )

    def test_blueprint_initialization(self) -> None:
        # if initialization was correct we should be able to observe these in the nc_storage:
        self.assertEqual(self.nc_storage.get_obj(b'oracle_script', TX_OUTPUT_SCRIPT_NC_TYPE), self.oracle_script)
        self.assertEqual(self.nc_storage.get_obj(b'token_uid', TOKEN_UID_NC_TYPE), self.token_uid)
        self.assertEqual(self.nc_storage.get_obj(b'date_last_bet', TIMESTAMP_NC_TYPE), self.date_last_bet)

    def test_basic_flow(self) -> None:
        runner = self.runner

        ###
        # Make some bets.
        ###
        self._make_a_bet(100, '1x1')
        self._make_a_bet(200, '1x1')
        self._make_a_bet(300, '1x1')
        self._make_a_bet(300, '2x2')
        bet1 = self._make_a_bet(500, '2x2')

        ###
        # Set the final result.
        ###
        self._set_result('2x2')

        ###
        # Single winner withdraws all funds.
        ###
        self.assertEqual(875, runner.call_view_method(self.nc_id, 'get_max_withdrawal', bet1.address))

        self._withdraw(bet1.address, 100)
        self.assertEqual(775, runner.call_view_method(self.nc_id, 'get_max_withdrawal', bet1.address))

        self._withdraw(bet1.address, 775)
        self.assertEqual(0, runner.call_view_method(self.nc_id, 'get_max_withdrawal', bet1.address))

        # Out of funds! Any withdrawal must fail from now on...
        amount = 1
        action = NCWithdrawalAction(token_uid=self.token_uid, amount=amount)
        context = self.create_context(caller_id=bet1.address, actions=[action])
        with self.assertNCFail('InsufficientBalance', 'withdrawal amount is greater than available (max: 0)'):
            runner.call_public_method(self.nc_id, 'withdraw', context)

    def test_make_a_bet_with_withdrawal(self) -> None:
        self._make_a_bet(100, '1x1')

        (address_bytes, _) = self._get_any_address()
        action = NCWithdrawalAction(token_uid=self.token_uid, amount=1)
        context = self.create_context(caller_id=address_bytes, actions=[action])
        score = '1x1'
        with self.assertNCFail('NCForbiddenAction', 'action WITHDRAWAL is forbidden on method `bet`'):
            self.runner.call_public_method(self.nc_id, 'bet', context, address_bytes, score)

    def test_make_a_bet_after_result(self) -> None:
        self._make_a_bet(100, '1x1')
        self._set_result('2x2')
        with self.assertNCFail('ResultAlreadySet', ''):
            self._make_a_bet(100, '1x1')

    def test_make_a_bet_after_date_last_bet(self) -> None:
        with self.assertNCFail('TooLate', re.compile(r'cannot place bets after \d+')):
            self._make_a_bet(100, '1x1', timestamp=self.date_last_bet + 1)

    def test_set_results_two_times(self) -> None:
        self._set_result('2x2')
        with self.assertNCFail('ResultAlreadySet', ''):
            self._set_result('5x1')

    def test_set_results_wrong_signature(self) -> None:
        wrong_oracle_key = KeyPair.create(b'123')
        with self.assertNCFail('InvalidOracleSignature', ''):
            self._set_result('3x2', oracle_key=wrong_oracle_key)

    def test_withdraw_before_result(self) -> None:
        bet1 = self._make_a_bet(100, '1x1')
        with self.assertNCFail('ResultNotAvailable', ''):
            self._withdraw(bet1.address, 100)

    def test_withdraw_with_deposits(self) -> None:
        (address_bytes, _) = self._get_any_address()
        action = NCDepositAction(token_uid=self.token_uid, amount=1)
        context = self.create_context(caller_id=address_bytes, actions=[action])
        with self.assertNCFail('NCForbiddenAction', 'action DEPOSIT is forbidden on method `withdraw`'):
            self.runner.call_public_method(self.nc_id, 'withdraw', context)

    def test_make_a_bet_wrong_token(self) -> None:
        (address_bytes, _) = self._get_any_address()
        token_uid = TokenUid(b'xxx')
        self.assertNotEqual(token_uid, self.token_uid)
        action = NCDepositAction(token_uid=token_uid, amount=1)
        context = self.create_context(caller_id=address_bytes, actions=[action])
        score = '1x1'
        with self.assertNCFail('InvalidToken', 'token different from 00'):
            self.runner.call_public_method(self.nc_id, 'bet', context, address_bytes, score)

    def test_withdraw_wrong_token(self) -> None:
        bet1 = self._make_a_bet(100, '1x1')

        token_uid = TokenUid(b'xxx')
        self.assertNotEqual(token_uid, self.token_uid)
        action = NCWithdrawalAction(token_uid=token_uid, amount=1)
        context = self.create_context(caller_id=bet1.address, actions=[action])
        with self.assertNCFail('InvalidToken', 'token different from 00'):
            self.runner.call_public_method(self.nc_id, 'withdraw', context)
