import sys

import pytest

from hathor.nanocontracts import Blueprint, Context, NCFail, public, view
from hathor.nanocontracts.exception import (
    NCInsufficientFunds,
    NCInvalidContractId,
    NCInvalidInitializeMethodCall,
    NCNumberOfCallsExceeded,
    NCRecursionError,
    NCUninitializedContractError,
    NCViewMethodError,
)
from hathor.nanocontracts.nc_types import NCType, make_nc_type_for_arg_type as make_nc_type
from hathor.nanocontracts.storage.contract_storage import Balance
from hathor.nanocontracts.types import (
    Address,
    ContractId,
    NCAction,
    NCDepositAction,
    NCWithdrawalAction,
    TokenUid,
    VertexId,
)
from hathor.transaction.token_info import TokenVersion
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase

COUNTER_NC_TYPE = make_nc_type(int)
CONTRACT_NC_TYPE: NCType[ContractId | None] = make_nc_type(ContractId | None)  # type: ignore[arg-type]
MOCK_ADDRESS = Address(b'')


class ZeroedCounterFail(NCFail):
    pass


class MyBlueprint(Blueprint):
    counter: int
    contract: ContractId | None

    @public(allow_deposit=True)
    def initialize(self, ctx: Context, initial: int) -> None:
        self.counter = initial
        self.contract = None

    @public
    def set_contract(self, ctx: Context, contract: ContractId) -> None:
        self.contract = contract

    @public(allow_deposit=True)
    def split_balance(self, ctx: Context) -> None:
        if self.contract is None:
            return

        actions = []
        for action in ctx.__all_actions__:
            assert isinstance(action, NCDepositAction)
            amount = 1 + action.amount // 2
            actions.append(NCDepositAction(token_uid=action.token_uid, amount=amount))
        self.syscall.get_contract(self.contract, blueprint_id=None).public(*actions).split_balance()

    @public(allow_withdrawal=True)
    def get_tokens_from_another_contract(self, ctx: Context) -> None:
        if self.contract is None:
            return

        actions = []
        for action in ctx.__all_actions__:
            assert isinstance(action, NCWithdrawalAction)
            balance = self.syscall.get_balance_before_current_call(action.token_uid)
            diff = balance - action.amount
            if diff < 0:
                actions.append(NCWithdrawalAction(token_uid=action.token_uid, amount=-diff))

        if actions:
            self.syscall.get_contract(self.contract, blueprint_id=None) \
                .public(*actions) \
                .get_tokens_from_another_contract()

    @public(allow_reentrancy=True)
    def dec(self, ctx: Context, fail_on_zero: bool) -> None:
        if self.counter == 0:
            if fail_on_zero:
                raise ZeroedCounterFail
            else:
                return
        self.counter -= 1
        if self.contract:
            self.syscall.get_contract(self.contract, blueprint_id=None).public().dec(fail_on_zero=fail_on_zero)

    @public
    def non_stop_call(self, ctx: Context) -> None:
        assert self.contract is not None
        while True:
            self.syscall.get_contract(self.contract, blueprint_id=None).public().dec(fail_on_zero=False)

    @view
    def get_total_counter(self) -> int:
        mine = self.counter
        other = 0
        if self.contract:
            other = self.syscall.get_contract(self.contract, blueprint_id=None).view().get_counter()
        return mine + other

    @public
    def dec_and_get_counter(self, ctx: Context) -> int:
        assert self.contract is not None
        self.dec(ctx, fail_on_zero=True)
        other = self.syscall.get_contract(self.contract, blueprint_id=None).view().get_counter()
        return self.counter + other

    @view
    def get_counter(self) -> int:
        return self.counter

    @public
    def invalid_call_initialize(self, ctx: Context) -> None:
        assert self.contract is not None
        self.syscall.get_contract(self.contract, blueprint_id=None).public().initialize()

    @view
    def invalid_call_public_from_view(self) -> None:
        assert self.contract is not None
        self.syscall.get_contract(self.contract, blueprint_id=None).public().dec()

    @view
    def invalid_call_view_itself(self) -> int:
        return self.syscall.get_contract(self.syscall.get_contract_id(), blueprint_id=None).view().get_counter()


class NCBlueprintTestCase(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.genesis = self.manager.tx_storage.get_all_genesis()
        self.tx = [t for t in self.genesis if t.is_transaction][0]
        self.blueprint_id = self._register_blueprint_class(MyBlueprint)

        self.nc1_id = ContractId(VertexId(b'1' * 32))
        self.nc2_id = ContractId(VertexId(b'2' * 32))
        self.nc3_id = ContractId(VertexId(b'3' * 32))

    def test_failing(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 5)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 1)
        self.runner.create_contract(self.nc3_id, self.blueprint_id, ctx, 3)

        self.runner.call_public_method(self.nc2_id, 'set_contract', ctx, self.nc1_id)
        self.runner.call_public_method(self.nc3_id, 'set_contract', ctx, self.nc2_id)

        storage1 = self.runner.get_storage(self.nc1_id)
        self.assertEqual(storage1.get_obj(b'counter', COUNTER_NC_TYPE), 5)
        self.assertEqual(storage1.get_obj(b'contract', CONTRACT_NC_TYPE), None)

        storage2 = self.runner.get_storage(self.nc2_id)
        self.assertEqual(storage2.get_obj(b'counter', COUNTER_NC_TYPE), 1)
        self.assertEqual(storage2.get_obj(b'contract', CONTRACT_NC_TYPE), self.nc1_id)

        storage3 = self.runner.get_storage(self.nc3_id)
        self.assertEqual(storage3.get_obj(b'counter', COUNTER_NC_TYPE), 3)
        self.assertEqual(storage3.get_obj(b'contract', CONTRACT_NC_TYPE), self.nc2_id)

        self.runner.call_public_method(self.nc3_id, 'dec', ctx, fail_on_zero=True)
        self.assertEqual(storage1.get_obj(b'counter', COUNTER_NC_TYPE), 4)
        self.assertEqual(storage2.get_obj(b'counter', COUNTER_NC_TYPE), 0)
        self.assertEqual(storage3.get_obj(b'counter', COUNTER_NC_TYPE), 2)

        with self.assertRaises(ZeroedCounterFail):
            self.runner.call_public_method(self.nc3_id, 'dec', ctx, fail_on_zero=True)

        self.assertEqual(storage1.get_obj(b'counter', COUNTER_NC_TYPE), 4)
        self.assertEqual(storage2.get_obj(b'counter', COUNTER_NC_TYPE), 0)
        self.assertEqual(storage3.get_obj(b'counter', COUNTER_NC_TYPE), 2)

    def test_call_itself(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 10)
        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc1_id)

        with pytest.raises(NCInvalidContractId, match='a contract cannot call itself'):
            self.runner.call_public_method(self.nc1_id, 'dec', ctx, fail_on_zero=True)

    def test_call_itself_view(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 10)

        with pytest.raises(NCInvalidContractId, match='a contract cannot call itself'):
            self.runner.call_view_method(self.nc1_id, 'invalid_call_view_itself')

    def test_call_initialize(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 10)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 10)
        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)

        with self.assertRaises(NCInvalidInitializeMethodCall):
            self.runner.call_public_method(self.nc1_id, 'invalid_call_initialize', ctx)

    def test_call_public_from_view(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 10)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 10)
        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)

        with self.assertRaises(NCViewMethodError):
            self.runner.call_view_method(self.nc1_id, 'invalid_call_public_from_view')

    def test_call_uninitialize_contract(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 10)
        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)

        with self.assertRaises(NCUninitializedContractError):
            self.runner.call_public_method(self.nc1_id, 'dec', ctx, fail_on_zero=True)

    def test_recursion_error(self) -> None:
        # Each call to `self.call_public_method()` in the blueprint adds 8 frames to the call stack.
        # To trigger an NCRecursionError (instead of Python's built-in RecursionError),
        # we need to increase the recursion limit accordingly.
        sys.setrecursionlimit(5000)

        ctx = self.create_context()
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 100_000)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 100_000)

        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)
        self.runner.call_public_method(self.nc2_id, 'set_contract', ctx, self.nc1_id)

        with self.assertRaises(NCRecursionError):
            self.runner.call_public_method(self.nc1_id, 'dec', ctx, fail_on_zero=True)
        trace = self.runner.get_last_call_info()
        assert trace.calls is not None
        self.assertEqual(len(trace.calls), self.runner.MAX_RECURSION_DEPTH)

    def test_max_calls_exceeded(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 0)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 0)
        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)

        with self.assertRaises(NCNumberOfCallsExceeded):
            self.runner.call_public_method(self.nc1_id, 'non_stop_call', ctx)
        trace = self.runner.get_last_call_info()
        assert trace.calls is not None
        self.assertEqual(len(trace.calls), self.runner.MAX_CALL_COUNTER)

    def test_getting_funds_from_another_contract(self) -> None:
        token1_uid = TokenUid(self._settings.HATHOR_TOKEN_UID)
        token2_uid = TokenUid(b'b' * 32)
        token3_uid = TokenUid(b'c' * 32)

        actions: list[NCAction] = [
            NCDepositAction(token_uid=token1_uid, amount=11),
            NCDepositAction(token_uid=token2_uid, amount=12),
            NCDepositAction(token_uid=token3_uid, amount=13),
        ]
        self.runner.create_contract(
            self.nc1_id,
            self.blueprint_id,
            self.create_context(actions, self.tx, MOCK_ADDRESS),
            0
        )

        self.create_token(token2_uid, 'tk2', 'tk2', TokenVersion.DEPOSIT)
        self.create_token(token3_uid, 'tk3', 'tk3', TokenVersion.DEPOSIT)

        self.assertEqual(
            Balance(value=11, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc1_id, token1_uid)
        )
        self.assertEqual(
            Balance(value=12, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc1_id, token2_uid)
        )
        self.assertEqual(
            Balance(value=13, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc1_id, token3_uid)
        )

        actions = [
            NCDepositAction(token_uid=token1_uid, amount=21),
            NCDepositAction(token_uid=token2_uid, amount=22),
            NCDepositAction(token_uid=token3_uid, amount=23),
        ]
        ctx = self.create_context(actions, self.tx, MOCK_ADDRESS)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 0)
        self.assertEqual(
            Balance(value=21, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc2_id, token1_uid)
        )
        self.assertEqual(
            Balance(value=22, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc2_id, token2_uid)
        )
        self.assertEqual(
            Balance(value=23, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc2_id, token3_uid)
        )

        actions = [
            NCDepositAction(token_uid=token1_uid, amount=31),
            NCDepositAction(token_uid=token2_uid, amount=32),
            NCDepositAction(token_uid=token3_uid, amount=33),
        ]
        ctx = self.create_context(actions, self.tx, MOCK_ADDRESS)
        self.runner.create_contract(self.nc3_id, self.blueprint_id, ctx, 0)
        self.assertEqual(
            Balance(value=31, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc3_id, token1_uid)
        )
        self.assertEqual(
            Balance(value=32, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc3_id, token2_uid)
        )
        self.assertEqual(
            Balance(value=33, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc3_id, token3_uid)
        )

        ctx = self.create_context()
        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)
        self.runner.call_public_method(self.nc2_id, 'set_contract', ctx, self.nc3_id)

        actions = [
            NCWithdrawalAction(token_uid=token1_uid, amount=7),
            NCWithdrawalAction(token_uid=token2_uid, amount=18),
            NCWithdrawalAction(token_uid=token3_uid, amount=65),
        ]
        ctx = self.create_context(actions, self.tx, MOCK_ADDRESS)
        self.runner.call_public_method(self.nc1_id, 'get_tokens_from_another_contract', ctx)

        self.assertEqual(
            Balance(value=4, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc1_id, token1_uid)
        )
        self.assertEqual(
            Balance(value=0, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc1_id, token2_uid)
        )
        self.assertEqual(
            Balance(value=0, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc1_id, token3_uid)
        )

        self.assertEqual(
            Balance(value=21, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc2_id, token1_uid)
        )
        self.assertEqual(
            Balance(value=16, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc2_id, token2_uid)
        )
        self.assertEqual(
            Balance(value=0, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc2_id, token3_uid)
        )

        self.assertEqual(
            Balance(value=31, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc3_id, token1_uid)
        )
        self.assertEqual(
            Balance(value=32, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc3_id, token2_uid)
        )
        self.assertEqual(
            Balance(value=4, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc3_id, token3_uid)
        )

        ctx = self.create_context(
            [NCWithdrawalAction(token_uid=token1_uid, amount=100)],
            self.tx,
            MOCK_ADDRESS,
            timestamp=0,
        )
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method(self.nc1_id, 'get_tokens_from_another_contract', ctx)

    def test_transfer_between_contracts(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 1)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 20)
        self.runner.create_contract(self.nc3_id, self.blueprint_id, ctx, 300)

        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)
        self.runner.call_public_method(self.nc2_id, 'set_contract', ctx, self.nc3_id)

        total_counter = self.runner.call_view_method(self.nc1_id, 'get_total_counter')
        self.assertEqual(total_counter, 21)

        total_counter = self.runner.call_view_method(self.nc2_id, 'get_total_counter')
        self.assertEqual(total_counter, 320)

        token1_uid = TokenUid(self._settings.HATHOR_TOKEN_UID)
        token2_uid = TokenUid(b'b' * 32)
        token3_uid = TokenUid(b'c' * 32)

        self.create_token(token2_uid, 'tk2', 'tk2', TokenVersion.DEPOSIT)
        self.create_token(token3_uid, 'tk3', 'tk3', TokenVersion.DEPOSIT)

        actions = [
            NCDepositAction(token_uid=token1_uid, amount=100),
            NCDepositAction(token_uid=token2_uid, amount=50),
            NCDepositAction(token_uid=token3_uid, amount=25),
        ]
        ctx = self.create_context(actions, self.tx, MOCK_ADDRESS)
        self.runner.call_public_method(self.nc1_id, 'split_balance', ctx)

        self.assertEqual(
            Balance(value=49, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc1_id, token1_uid)
        )
        self.assertEqual(
            Balance(value=24, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc1_id, token2_uid)
        )
        self.assertEqual(
            Balance(value=12, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc1_id, token3_uid)
        )

        self.assertEqual(
            Balance(value=25, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc2_id, token1_uid)
        )
        self.assertEqual(
            Balance(value=12, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc2_id, token2_uid)
        )
        self.assertEqual(
            Balance(value=6, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc2_id, token3_uid)
        )

        self.assertEqual(
            Balance(value=26, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc3_id, token1_uid)
        )
        self.assertEqual(
            Balance(value=14, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc3_id, token2_uid)
        )
        self.assertEqual(
            Balance(value=7, can_mint=False, can_melt=False), self.runner.get_current_balance(self.nc3_id, token3_uid)
        )

    def test_loop(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 8)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 3)
        self.runner.create_contract(self.nc3_id, self.blueprint_id, ctx, 6)

        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)
        self.runner.call_public_method(self.nc2_id, 'set_contract', ctx, self.nc3_id)
        self.runner.call_public_method(self.nc3_id, 'set_contract', ctx, self.nc1_id)

        storage1 = self.runner.get_storage(self.nc1_id)
        self.assertEqual(storage1.get_obj(b'counter', COUNTER_NC_TYPE), 8)
        self.assertEqual(storage1.get_obj(b'contract', CONTRACT_NC_TYPE), self.nc2_id)

        storage2 = self.runner.get_storage(self.nc2_id)
        self.assertEqual(storage2.get_obj(b'counter', COUNTER_NC_TYPE), 3)
        self.assertEqual(storage2.get_obj(b'contract', CONTRACT_NC_TYPE), self.nc3_id)

        storage3 = self.runner.get_storage(self.nc3_id)
        self.assertEqual(storage3.get_obj(b'counter', COUNTER_NC_TYPE), 6)
        self.assertEqual(storage3.get_obj(b'contract', CONTRACT_NC_TYPE), self.nc1_id)

        self.runner.call_public_method(self.nc1_id, 'dec', ctx, fail_on_zero=False)
        self.assertEqual(storage1.get_obj(b'counter', COUNTER_NC_TYPE), 4)
        self.assertEqual(storage2.get_obj(b'counter', COUNTER_NC_TYPE), 0)
        self.assertEqual(storage3.get_obj(b'counter', COUNTER_NC_TYPE), 3)

    def test_call_view_after_public(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 8)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 3)

        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)

        storage1 = self.runner.get_storage(self.nc1_id)
        self.assertEqual(storage1.get_obj(b'counter', COUNTER_NC_TYPE), 8)
        self.assertEqual(storage1.get_obj(b'contract', CONTRACT_NC_TYPE), self.nc2_id)

        storage2 = self.runner.get_storage(self.nc2_id)
        self.assertEqual(storage2.get_obj(b'counter', COUNTER_NC_TYPE), 3)
        self.assertEqual(storage2.get_obj(b'contract', CONTRACT_NC_TYPE), None)

        result = self.runner.call_public_method(self.nc1_id, 'dec_and_get_counter', ctx)
        self.assertEqual(storage1.get_obj(b'counter', COUNTER_NC_TYPE), 7)
        self.assertEqual(storage2.get_obj(b'counter', COUNTER_NC_TYPE), 2)
        self.assertEqual(result, 9)
