import os
import re
from typing import Any, NamedTuple, Optional

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address, get_address_b58_from_public_key_bytes
from hathor.nanocontracts import OnChainBlueprint
from hathor.nanocontracts.nc_types import NCType, make_nc_type_for_arg_type as make_nc_type
from hathor.nanocontracts.types import (
    NC_INITIALIZE_METHOD,
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
from hathor.nanocontracts.utils import load_builtin_blueprint_for_ocb, sign_pycoin
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Transaction
from hathor.util import initialize_hd_wallet, not_none
from hathor.wallet import KeyPair
from hathorlib.scripts import P2PKH

from ...utils import DEFAULT_WORDS
from .. import test_blueprints
from ..blueprints.unittest import BlueprintTestCase
from .utils import get_ocb_private_key

settings = HathorSettings()

ON_CHAIN_BET_NC_CODE: str = load_builtin_blueprint_for_ocb('bet.py', 'Bet', test_blueprints)
TX_OUTPUT_SCRIPT_NC_TYPE = make_nc_type(TxOutputScript)
RESULT_NC_TYPE: NCType[str | None] = make_nc_type(str | None)  # type: ignore[arg-type]
TIMESTAMP_NC_TYPE = make_nc_type(Timestamp)
TOKEN_UID_NC_TYPE = make_nc_type(TokenUid)


class BetInfo(NamedTuple):
    key: KeyPair
    address: Address
    amount: Amount
    score: str


class OnChainBetBlueprintTestCase(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('unittests')
        self.wallet = initialize_hd_wallet(DEFAULT_WORDS)
        self.token_uid = TokenUid(settings.HATHOR_TOKEN_UID)
        self.initialize_contract()  # will set self.nc_id, self.runner, self.nc_storage

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

    def _create_on_chain_blueprint(self, nc_code: str) -> OnChainBlueprint:
        from hathor.nanocontracts.on_chain_blueprint import Code
        code = Code.from_python_code(nc_code, self._settings)
        timestamp = self.manager.tx_storage.latest_timestamp + 1
        parents = self.manager.get_new_tx_parents(timestamp)
        blueprint = OnChainBlueprint(
            weight=1,
            inputs=[],
            outputs=[],
            parents=parents,
            storage=self.manager.tx_storage,
            timestamp=timestamp,
            code=code,
        )
        blueprint.weight = self.manager.daa.minimum_tx_weight(blueprint)
        blueprint.sign(get_ocb_private_key())
        self.manager.cpu_mining_service.resolve(blueprint)
        self.manager.reactor.advance(2)
        return blueprint

    def _gen_nc_initialize_tx(self, blueprint: OnChainBlueprint, nc_args: list[Any]) -> Transaction:
        method_parser = blueprint.get_method(NC_INITIALIZE_METHOD)
        timestamp = int(self.manager.reactor.seconds())
        parents = self.manager.get_new_tx_parents()

        nc = Transaction(timestamp=timestamp, parents=parents)

        nc_id = blueprint.blueprint_id()
        nc_method = NC_INITIALIZE_METHOD
        nc_args_bytes = method_parser.serialize_args_bytes(nc_args)

        # sign
        address = self.wallet.get_unused_address()
        private_key = self.wallet.get_private_key(address)

        from hathor.transaction.headers import NanoHeader
        nano_header = NanoHeader(
            tx=nc,
            nc_seqnum=1,
            nc_id=nc_id,
            nc_method=nc_method,
            nc_args_bytes=nc_args_bytes,
            nc_address=b'',
            nc_script=b'',
            nc_actions=[],
        )
        nc.headers.append(nano_header)

        sign_pycoin(nano_header, private_key)

        # mine
        nc.weight = self.manager.daa.minimum_tx_weight(nc)
        self.manager.cpu_mining_service.resolve(nc)

        # advance
        self.manager.reactor.advance(2)
        return nc

    def initialize_contract(self) -> None:
        # create on-chain Bet nanocontract
        blueprint = self._create_on_chain_blueprint(ON_CHAIN_BET_NC_CODE)

        related_addresses = set(blueprint.get_related_addresses())
        address = get_address_b58_from_public_key_bytes(blueprint.nc_pubkey)
        self.assertIn(address, related_addresses)

        assert self.manager.vertex_handler.on_new_relayed_vertex(blueprint)
        add_new_blocks(self.manager, 1, advance_clock=30)  # confirm the on-chain blueprint vertex
        assert blueprint.get_metadata().first_block is not None

        self.oracle_key = KeyPair.create(b'123')
        assert self.oracle_key.address is not None
        self.oracle_script = P2PKH(self.oracle_key.address).get_script()
        self.date_last_bet = self.get_current_timestamp() + 3600 * 24

        # initialize an on-chain Bet nanocontract
        nc_init_tx = self._gen_nc_initialize_tx(blueprint, [self.oracle_script, self.token_uid, self.date_last_bet])
        assert self.manager.vertex_handler.on_new_relayed_vertex(nc_init_tx)
        block, = add_new_blocks(self.manager, 1, advance_clock=30)  # confirm the initialization nc transaction
        assert nc_init_tx.get_metadata().first_block is not None

        # set expected self objects:
        self.nc_id = ContractId(VertexId(nc_init_tx.hash))
        self.runner = self.manager.get_nc_runner(block)
        self.nc_storage = self.runner.get_storage(self.nc_id)

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
