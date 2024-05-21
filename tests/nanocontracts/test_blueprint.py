from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.exception import NCFail, NCInsufficientFunds, NCPrivateMethodError, UnknownFieldType
from hathor.nanocontracts.storage import NCMemoryStorageFactory
from hathor.nanocontracts.storage.backends import MemoryNodeTrieStore
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.storage.storage import BalanceKey
from hathor.nanocontracts.types import Context, ContractId, NCAction, NCActionType, public
from tests import unittest
from tests.nanocontracts.utils import TestRunner


class SimpleFields(Blueprint):
    a: str
    b: bytes
    c: int
    d: bool
    e: float

    @public
    def initialize(self, ctx: Context, a: str, b: bytes, c: int, d: bool, e: float) -> None:
        self.a = a
        self.b = b
        self.c = c
        self.d = d
        self.e = e

        # Read the content of the variable.
        if self.a:
            pass


class ContainerFields(Blueprint):
    a: dict[str, str]
    b: dict[bytes, bytes]
    c: dict[int, int]
    d: dict[str, float]

    def _set(self, _dict, key, value):
        _dict[key] = value
        assert key in _dict
        assert _dict[key] == value
        del _dict[key]
        assert key not in _dict
        _dict[key] = value

    @public
    def initialize(self, ctx: Context, items: list[tuple[str, str, bytes, int, float]]) -> None:
        for key, va, vb, vc, vd in items:
            self._set(self.a, key, va)
            self._set(self.b, key, vb)
            self._set(self.c, key, vc)
            self._set(self.d, key, vd)


class MyBlueprint(Blueprint):
    a: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.a = 1

    @public
    def nop(self, ctx: Context) -> None:
        pass

    @public
    def fail(self, ctx: Context) -> None:
        self.a = 2
        raise NCFail()
        self.a = 3

    def my_private_method_fail(self) -> None:
        # This operation is not permitted because private methods
        # cannot change the transaction state.
        self.a = 2

    def my_private_method_nop(self) -> int:
        return 1


class NCBlueprintTestCase(unittest.TestCase):
    _enable_sync_v1 = True
    _enable_sync_v2 = True

    def setUp(self) -> None:
        super().setUp()
        self.simple_fields_id = ContractId(b'1' * 32)
        self.container_fields_id = ContractId(b'2' * 32)
        self.my_blueprint_id = ContractId(b'3' * 32)

        nc_storage_factory = NCMemoryStorageFactory()
        store = MemoryNodeTrieStore()
        block_trie = PatriciaTrie(store)
        self.manager = self.create_peer('testnet', use_memory_storage=True)
        self.runner = TestRunner(self.manager.tx_storage, nc_storage_factory, block_trie)

        self.runner.register_contract(SimpleFields, self.simple_fields_id)
        self.runner.register_contract(ContainerFields, self.container_fields_id)
        self.runner.register_contract(MyBlueprint, self.my_blueprint_id)

        genesis = self.manager.tx_storage.get_all_genesis()
        self.tx = list(genesis)[0]

    def test_simple_fields(self):
        nc_id = self.simple_fields_id
        storage = self.runner.get_storage(nc_id)

        ctx = Context([], self.tx, b'', timestamp=0)
        a = 'str'
        b = b'bytes'
        c = 123
        d = True
        e = 1.25
        self.runner.call_public_method(nc_id, 'initialize', ctx, a, b, c, d, e)
        self.assertEqual(storage.get('a'), a)
        self.assertEqual(storage.get('b'), b)
        self.assertEqual(storage.get('c'), c)
        self.assertEqual(storage.get('d'), d)
        self.assertEqual(storage.get('e'), e)

    def test_container_fields(self):
        nc_id = self.container_fields_id
        storage = self.runner.get_storage(nc_id)

        ctx = Context([], self.tx, b'', timestamp=0)
        items = [
            ('a', '1', b'1', 1, 1.25),
            ('b', '2', b'2', 2, 2.25),
            ('c', '3', b'3', 3, 3.25),
        ]
        self.runner.call_public_method(nc_id, 'initialize', ctx, items)
        self.assertEqual(storage.get('a:a'), '1')
        self.assertEqual(storage.get('a:b'), '2')
        self.assertEqual(storage.get('a:c'), '3')

    def test_public_method_fails(self):
        nc_id = self.my_blueprint_id
        storage = self.runner.get_storage(nc_id)

        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'initialize', ctx)
        self.assertEqual(1, storage.get('a'))
        with self.assertRaises(NCFail):
            self.runner.call_public_method(nc_id, 'fail', ctx)
        self.assertEqual(1, storage.get('a'))

    def test_private_method_change_state(self):
        nc_id = self.my_blueprint_id
        with self.assertRaises(NCPrivateMethodError):
            self.runner.call_private_method(nc_id, 'my_private_method_fail')

    def test_private_method_success(self):
        nc_id = self.my_blueprint_id
        self.assertEqual(1, self.runner.call_private_method(nc_id, 'my_private_method_nop'))

    def test_initial_balance(self):
        nc_id = self.my_blueprint_id
        storage = self.runner.get_storage(nc_id)
        self.assertEqual(0, storage.get_balance(b''))

    def test_nop(self):
        nc_id = self.my_blueprint_id
        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)

    def test_withdrawal_fail(self):
        nc_id = self.my_blueprint_id
        action = NCAction(NCActionType.WITHDRAWAL, b'\0', 1)
        ctx = Context([action], self.tx, b'', timestamp=0)
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method(nc_id, 'nop', ctx)

    def test_deposits_and_withdrawals(self):
        nc_id = self.my_blueprint_id
        storage = self.runner.get_storage(nc_id)

        token_uid = b'\0'
        action = NCAction(NCActionType.DEPOSIT, token_uid, 100)
        ctx = Context([action], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(100, storage.get_balance(token_uid))

        action = NCAction(NCActionType.WITHDRAWAL, token_uid, 1)
        ctx = Context([action], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(99, storage.get_balance(token_uid))

        action = NCAction(NCActionType.WITHDRAWAL, token_uid, 50)
        ctx = Context([action], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(49, storage.get_balance(token_uid))

        action = NCAction(NCActionType.WITHDRAWAL, token_uid, 50)
        ctx = Context([action], self.tx, b'', timestamp=0)
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method(nc_id, 'nop', ctx)

    def test_withdraw_wrong_token(self):
        nc_id = self.my_blueprint_id
        storage = self.runner.get_storage(nc_id)

        token_uid = b'\0'
        wrong_token_uid = b'\1'

        action = NCAction(NCActionType.DEPOSIT, token_uid, 100)
        ctx = Context([action], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(100, storage.get_balance(token_uid))

        action = NCAction(NCActionType.WITHDRAWAL, wrong_token_uid, 1)
        ctx = Context([action], self.tx, b'', timestamp=0)
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(100, storage.get_balance(token_uid))

    def test_invalid_field(self) -> None:
        with self.assertRaises(UnknownFieldType):
            class WrongBlueprint(Blueprint):
                a: list[int]

                @public
                def initialize(self, ctx: Context) -> None:
                    self.a = [1, 2, 3]

    def test_balances(self):
        nc_id = self.my_blueprint_id
        storage = self.runner.get_storage(nc_id)

        token_uid = b'\0'
        action = NCAction(NCActionType.DEPOSIT, token_uid, 100)
        ctx = Context([action], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(100, storage.get_balance(token_uid))

        token_uid2 = b'\1'
        action = NCAction(NCActionType.DEPOSIT, token_uid2, 200)
        ctx = Context([action], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(200, storage.get_balance(token_uid2))

        all_balances = storage.get_all_balances()
        key1 = BalanceKey(nc_id, token_uid)
        key2 = BalanceKey(nc_id, token_uid2)

        self.assertEqual(all_balances, {key1: 100, key2: 200})
