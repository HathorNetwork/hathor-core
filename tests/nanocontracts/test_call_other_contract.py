import sys
from typing import Optional

from hathor.nanocontracts import Blueprint, Context, NCFail, public, view
from hathor.nanocontracts.exception import (
    NCInsufficientFunds,
    NCInvalidContractId,
    NCInvalidInitializeMethodCall,
    NCInvalidPublicMethodCallFromView,
    NCNumberOfCallsExceeded,
    NCRecursionError,
    NCUninitializedContractError,
)
from hathor.nanocontracts.storage import NCBlockStorage, NCMemoryStorageFactory
from hathor.nanocontracts.storage.backends import MemoryNodeTrieStore
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.types import BlueprintId, ContractId, NCAction, NCActionType
from tests import unittest
from tests.nanocontracts.utils import TestRunner


class ZeroedCounterFail(NCFail):
    pass


class MyBlueprint(Blueprint):
    counter: int
    contract: Optional[ContractId]

    @public
    def initialize(self, ctx: Context, initial: int) -> None:
        self.counter = initial
        self.contract = None

    @public
    def set_contract(self, ctx: Context, contract: ContractId) -> None:
        self.contract = contract

    @public
    def split_balance(self, ctx: Context) -> None:
        if self.contract is None:
            return

        actions = []
        for action in ctx.actions.values():
            amount = 1 + action.amount // 2
            actions.append(NCAction(NCActionType.DEPOSIT, action.token_uid, amount))
        self.syscall.call_public_method(self.contract, 'split_balance', actions)

    @public
    def get_tokens_from_another_contract(self, ctx: Context) -> None:
        if self.contract is None:
            return

        actions = []
        for action in ctx.actions.values():
            balance = self.syscall.get_balance(action.token_uid)
            diff = balance - action.amount
            if diff < 0:
                actions.append(NCAction(NCActionType.WITHDRAWAL, action.token_uid, -diff))

        if actions:
            self.syscall.call_public_method(self.contract, 'get_tokens_from_another_contract', actions)

    @public
    def dec(self, ctx: Context, fail_on_zero: bool = True) -> None:
        if self.counter == 0:
            if fail_on_zero:
                raise ZeroedCounterFail
            else:
                return
        self.counter -= 1
        if self.contract:
            actions: list[NCAction] = []
            self.syscall.call_public_method(self.contract, 'dec', actions, fail_on_zero=fail_on_zero)

    @public
    def non_stop_call(self, ctx: Context) -> None:
        assert self.contract is not None
        while True:
            actions: list[NCAction] = []
            self.syscall.call_public_method(self.contract, 'dec', actions, fail_on_zero=False)

    @view
    def get_total_counter(self) -> int:
        mine = self.counter
        other = 0
        if self.contract:
            other = self.syscall.call_view_method(self.contract, 'get_counter')
        return mine + other

    @public
    def dec_and_get_counter(self, ctx: Context) -> int:
        assert self.contract is not None
        self.dec(ctx)
        other = self.syscall.call_view_method(self.contract, 'get_counter')
        return self.counter + other

    @view
    def get_counter(self) -> int:
        return self.counter

    @public
    def invalid_call_initialize(self, ctx: Context) -> None:
        assert self.contract is not None
        self.syscall.call_public_method(self.contract, 'initialize', [])

    @view
    def invalid_call_public_from_view(self):
        assert self.contract is not None
        self.syscall.call_public_method(self.contract, 'dec', [])


class NCBlueprintTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.manager = self.create_peer('testnet')
        self.genesis = self.manager.tx_storage.get_all_genesis()
        self.tx = list(self.genesis)[0]

        nc_storage_factory = NCMemoryStorageFactory()
        store = MemoryNodeTrieStore()
        block_trie = PatriciaTrie(store)
        block_storage = NCBlockStorage(block_trie=block_trie)
        self.runner = TestRunner(
            self.manager.tx_storage, nc_storage_factory, block_storage, settings=self._settings, reactor=self.reactor
        )

        self.blueprint_id = BlueprintId(b'a' * 32)

        nc_catalog = self.manager.tx_storage.nc_catalog
        nc_catalog.blueprints[self.blueprint_id] = MyBlueprint

        self.nc1_id = ContractId(b'1' * 32)
        self.nc2_id = ContractId(b'2' * 32)
        self.nc3_id = ContractId(b'3' * 32)

    def test_failing(self):
        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 5)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 1)
        self.runner.create_contract(self.nc3_id, self.blueprint_id, ctx, 3)

        self.runner.call_public_method(self.nc2_id, 'set_contract', ctx, self.nc1_id)
        self.runner.call_public_method(self.nc3_id, 'set_contract', ctx, self.nc2_id)

        storage1 = self.runner.get_storage(self.nc1_id)
        self.assertEqual(storage1.get('counter'), 5)
        self.assertEqual(storage1.get('contract'), None)

        storage2 = self.runner.get_storage(self.nc2_id)
        self.assertEqual(storage2.get('counter'), 1)
        self.assertEqual(storage2.get('contract'), self.nc1_id)

        storage3 = self.runner.get_storage(self.nc3_id)
        self.assertEqual(storage3.get('counter'), 3)
        self.assertEqual(storage3.get('contract'), self.nc2_id)

        self.runner.call_public_method(self.nc3_id, 'dec', ctx)
        self.assertEqual(storage1.get('counter'), 4)
        self.assertEqual(storage2.get('counter'), 0)
        self.assertEqual(storage3.get('counter'), 2)

        with self.assertRaises(ZeroedCounterFail):
            self.runner.call_public_method(self.nc3_id, 'dec', ctx)

        self.assertEqual(storage1.get('counter'), 4)
        self.assertEqual(storage2.get('counter'), 0)
        self.assertEqual(storage3.get('counter'), 2)

    def test_call_itself(self):
        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 10)
        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc1_id)

        with self.assertRaises(NCInvalidContractId):
            self.runner.call_public_method(self.nc1_id, 'dec', ctx)

    def test_call_initialize(self):
        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 10)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 10)
        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)

        with self.assertRaises(NCInvalidInitializeMethodCall):
            self.runner.call_public_method(self.nc1_id, 'invalid_call_initialize', ctx)

    def test_call_public_from_view(self):
        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 10)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 10)
        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)

        with self.assertRaises(NCInvalidPublicMethodCallFromView):
            self.runner.call_view_method(self.nc1_id, 'invalid_call_public_from_view')

    def test_call_uninitialize_contract(self):
        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 10)
        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)

        with self.assertRaises(NCUninitializedContractError):
            self.runner.call_public_method(self.nc1_id, 'dec', ctx)

    def test_recursion_error(self):
        # Each call to `self.call_public_method()` in the blueprint adds 8 frames to the call stack.
        # To trigger an NCRecursionError (instead of Python's built-in RecursionError),
        # we need to increase the recursion limit accordingly.
        sys.setrecursionlimit(5000)

        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 100_000)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 100_000)

        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)
        self.runner.call_public_method(self.nc2_id, 'set_contract', ctx, self.nc1_id)

        self.runner.enable_call_trace()
        with self.assertRaises(NCRecursionError):
            self.runner.call_public_method(self.nc1_id, 'dec', ctx)
        trace = self.runner.get_last_call_info()
        self.assertEqual(len(trace.calls), self.runner.MAX_RECURSION_DEPTH)

    def test_max_calls_exceeded(self):
        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 0)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 0)
        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)

        self.runner.enable_call_trace()
        with self.assertRaises(NCNumberOfCallsExceeded):
            self.runner.call_public_method(self.nc1_id, 'non_stop_call', ctx)
        trace = self.runner.get_last_call_info()
        self.assertEqual(len(trace.calls), self.runner.MAX_CALL_COUNTER)

    def test_getting_funds_from_another_contract(self):
        token1_uid = self._settings.HATHOR_TOKEN_UID
        token2_uid = b'b' * 32
        token3_uid = b'c' * 32

        actions = [
            NCAction(NCActionType.DEPOSIT, token1_uid, 11),
            NCAction(NCActionType.DEPOSIT, token2_uid, 12),
            NCAction(NCActionType.DEPOSIT, token3_uid, 13),
        ]
        ctx = Context(actions, self.tx, b'', timestamp=0)
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 0)
        self.assertEqual(11, self.runner.get_balance(self.nc1_id, token1_uid))
        self.assertEqual(12, self.runner.get_balance(self.nc1_id, token2_uid))
        self.assertEqual(13, self.runner.get_balance(self.nc1_id, token3_uid))

        actions = [
            NCAction(NCActionType.DEPOSIT, token1_uid, 21),
            NCAction(NCActionType.DEPOSIT, token2_uid, 22),
            NCAction(NCActionType.DEPOSIT, token3_uid, 23),
        ]
        ctx = Context(actions, self.tx, b'', timestamp=0)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 0)
        self.assertEqual(21, self.runner.get_balance(self.nc2_id, token1_uid))
        self.assertEqual(22, self.runner.get_balance(self.nc2_id, token2_uid))
        self.assertEqual(23, self.runner.get_balance(self.nc2_id, token3_uid))

        actions = [
            NCAction(NCActionType.DEPOSIT, token1_uid, 31),
            NCAction(NCActionType.DEPOSIT, token2_uid, 32),
            NCAction(NCActionType.DEPOSIT, token3_uid, 33),
        ]
        ctx = Context(actions, self.tx, b'', timestamp=0)
        self.runner.create_contract(self.nc3_id, self.blueprint_id, ctx, 0)
        self.assertEqual(31, self.runner.get_balance(self.nc3_id, token1_uid))
        self.assertEqual(32, self.runner.get_balance(self.nc3_id, token2_uid))
        self.assertEqual(33, self.runner.get_balance(self.nc3_id, token3_uid))

        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)
        self.runner.call_public_method(self.nc2_id, 'set_contract', ctx, self.nc3_id)

        actions = [
            NCAction(NCActionType.WITHDRAWAL, token1_uid, 7),
            NCAction(NCActionType.WITHDRAWAL, token2_uid, 18),
            NCAction(NCActionType.WITHDRAWAL, token3_uid, 65),
        ]
        ctx = Context(actions, self.tx, b'', timestamp=0)
        self.runner.call_public_method(self.nc1_id, 'get_tokens_from_another_contract', ctx)

        self.assertEqual(4, self.runner.get_balance(self.nc1_id, token1_uid))
        self.assertEqual(0, self.runner.get_balance(self.nc1_id, token2_uid))
        self.assertEqual(0, self.runner.get_balance(self.nc1_id, token3_uid))

        self.assertEqual(21, self.runner.get_balance(self.nc2_id, token1_uid))
        self.assertEqual(16, self.runner.get_balance(self.nc2_id, token2_uid))
        self.assertEqual(0, self.runner.get_balance(self.nc2_id, token3_uid))

        self.assertEqual(31, self.runner.get_balance(self.nc3_id, token1_uid))
        self.assertEqual(32, self.runner.get_balance(self.nc3_id, token2_uid))
        self.assertEqual(4, self.runner.get_balance(self.nc3_id, token3_uid))

        actions = [
            NCAction(NCActionType.WITHDRAWAL, token1_uid, 100),
        ]
        ctx = Context(actions, self.tx, b'', timestamp=0)
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method(self.nc1_id, 'get_tokens_from_another_contract', ctx)

    def test_transfer_between_contracts(self):
        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 1)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 20)
        self.runner.create_contract(self.nc3_id, self.blueprint_id, ctx, 300)

        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)
        self.runner.call_public_method(self.nc2_id, 'set_contract', ctx, self.nc3_id)

        total_counter = self.runner.call_view_method(self.nc1_id, 'get_total_counter')
        self.assertEqual(total_counter, 21)

        total_counter = self.runner.call_view_method(self.nc2_id, 'get_total_counter')
        self.assertEqual(total_counter, 320)

        token1_uid = self._settings.HATHOR_TOKEN_UID
        token2_uid = b'b' * 32
        token3_uid = b'c' * 32

        actions = [
            NCAction(NCActionType.DEPOSIT, token1_uid, 100),
            NCAction(NCActionType.DEPOSIT, token2_uid, 50),
            NCAction(NCActionType.DEPOSIT, token3_uid, 25),
        ]
        ctx = Context(actions, self.tx, b'', timestamp=0)
        self.runner.call_public_method(self.nc1_id, 'split_balance', ctx)

        self.assertEqual(49, self.runner.get_balance(self.nc1_id, token1_uid))
        self.assertEqual(24, self.runner.get_balance(self.nc1_id, token2_uid))
        self.assertEqual(12, self.runner.get_balance(self.nc1_id, token3_uid))

        self.assertEqual(25, self.runner.get_balance(self.nc2_id, token1_uid))
        self.assertEqual(12, self.runner.get_balance(self.nc2_id, token2_uid))
        self.assertEqual(6, self.runner.get_balance(self.nc2_id, token3_uid))

        self.assertEqual(26, self.runner.get_balance(self.nc3_id, token1_uid))
        self.assertEqual(14, self.runner.get_balance(self.nc3_id, token2_uid))
        self.assertEqual(7, self.runner.get_balance(self.nc3_id, token3_uid))

    def test_loop(self):
        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 8)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 3)
        self.runner.create_contract(self.nc3_id, self.blueprint_id, ctx, 6)

        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)
        self.runner.call_public_method(self.nc2_id, 'set_contract', ctx, self.nc3_id)
        self.runner.call_public_method(self.nc3_id, 'set_contract', ctx, self.nc1_id)

        storage1 = self.runner.get_storage(self.nc1_id)
        self.assertEqual(storage1.get('counter'), 8)
        self.assertEqual(storage1.get('contract'), self.nc2_id)

        storage2 = self.runner.get_storage(self.nc2_id)
        self.assertEqual(storage2.get('counter'), 3)
        self.assertEqual(storage2.get('contract'), self.nc3_id)

        storage3 = self.runner.get_storage(self.nc3_id)
        self.assertEqual(storage3.get('counter'), 6)
        self.assertEqual(storage3.get('contract'), self.nc1_id)

        self.runner.enable_call_trace()
        self.runner.call_public_method(self.nc1_id, 'dec', ctx, fail_on_zero=False)
        self.assertEqual(storage1.get('counter'), 4)
        self.assertEqual(storage2.get('counter'), 0)
        self.assertEqual(storage3.get('counter'), 3)

    def test_call_view_after_public(self):
        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.create_contract(self.nc1_id, self.blueprint_id, ctx, 8)
        self.runner.create_contract(self.nc2_id, self.blueprint_id, ctx, 3)

        self.runner.call_public_method(self.nc1_id, 'set_contract', ctx, self.nc2_id)

        storage1 = self.runner.get_storage(self.nc1_id)
        self.assertEqual(storage1.get('counter'), 8)
        self.assertEqual(storage1.get('contract'), self.nc2_id)

        storage2 = self.runner.get_storage(self.nc2_id)
        self.assertEqual(storage2.get('counter'), 3)
        self.assertEqual(storage2.get('contract'), None)

        result = self.runner.call_public_method(self.nc1_id, 'dec_and_get_counter', ctx)
        self.assertEqual(storage1.get('counter'), 7)
        self.assertEqual(storage2.get('counter'), 2)
        self.assertEqual(result, 9)
