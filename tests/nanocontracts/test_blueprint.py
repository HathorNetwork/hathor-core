from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCFail, NCInsufficientFunds, NCPrivateMethodError
from hathor.nanocontracts.storage import NCBlockStorage, NCMemoryStorageFactory
from hathor.nanocontracts.storage.backends import MemoryNodeTrieStore
from hathor.nanocontracts.storage.contract_storage import Balance, BalanceKey
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.types import ContractId, NCDepositAction, NCWithdrawalAction, VertexId, public, view
from tests import unittest
from tests.nanocontracts.utils import TestRunner


class SimpleFields(Blueprint):
    a: str
    b: bytes
    c: int
    d: bool

    @public
    def initialize(self, ctx: Context, a: str, b: bytes, c: int, d: bool) -> None:
        self.a = a
        self.b = b
        self.c = c
        self.d = d

        # Read the content of the variable.
        if self.a:
            pass


class ContainerFields(Blueprint):
    a: dict[str, str]
    b: dict[bytes, bytes]
    c: dict[int, int]

    def _set(self, _dict, key, value):
        _dict[key] = value
        assert key in _dict
        assert _dict[key] == value
        del _dict[key]
        assert key not in _dict
        _dict[key] = value

    @public
    def initialize(self, ctx: Context, items: list[tuple[str, str, bytes, int]]) -> None:
        for key, va, vb, vc in items:
            self._set(self.a, key, va)
            self._set(self.b, key, vb)
            self._set(self.c, key, vc)


class MyBlueprint(Blueprint):
    a: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.a = 1

    @public(allow_deposit=True, allow_withdrawal=True)
    def nop(self, ctx: Context) -> None:
        pass

    @public
    def fail(self, ctx: Context) -> None:
        self.a = 2
        raise NCFail()
        self.a = 3

    @view
    def my_private_method_fail(self) -> None:
        # This operation is not permitted because private methods
        # cannot change the transaction state.
        self.a = 2

    @view
    def my_private_method_nop(self) -> int:
        return 1


class NCBlueprintTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.simple_fields_id = ContractId(VertexId(b'1' * 32))
        self.container_fields_id = ContractId(VertexId(b'2' * 32))
        self.my_blueprint_id = ContractId(VertexId(b'3' * 32))

        nc_storage_factory = NCMemoryStorageFactory()
        store = MemoryNodeTrieStore()
        block_trie = PatriciaTrie(store)
        block_storage = NCBlockStorage(block_trie)
        self.manager = self.create_peer('testnet')
        self.runner = TestRunner(
            self.manager.tx_storage, nc_storage_factory, block_storage, settings=self._settings, reactor=self.reactor
        )

        self.blueprint_ids = {
            'simple_fields': b'a' * 32,
            'container_fields': b'b' * 32,
            'my_blueprint': b'c' * 32,
        }

        nc_catalog = self.manager.tx_storage.nc_catalog
        nc_catalog.blueprints[self.blueprint_ids['simple_fields']] = SimpleFields
        nc_catalog.blueprints[self.blueprint_ids['container_fields']] = ContainerFields
        nc_catalog.blueprints[self.blueprint_ids['my_blueprint']] = MyBlueprint

        genesis = self.manager.tx_storage.get_all_genesis()
        self.tx = list(genesis)[0]

    def test_simple_fields(self):
        blueprint_id = self.blueprint_ids['simple_fields']
        nc_id = self.simple_fields_id

        ctx = Context([], self.tx, b'', timestamp=0)
        a = 'str'
        b = b'bytes'
        c = 123
        d = True
        self.runner.create_contract(nc_id, blueprint_id, ctx, a, b, c, d)

        storage = self.runner.get_storage(nc_id)
        self.assertEqual(storage.get('a'), a)
        self.assertEqual(storage.get('b'), b)
        self.assertEqual(storage.get('c'), c)
        self.assertEqual(storage.get('d'), d)

    def test_container_fields(self):
        blueprint_id = self.blueprint_ids['container_fields']
        nc_id = self.container_fields_id

        ctx = Context([], self.tx, b'', timestamp=0)
        items = [
            ('a', '1', b'1', 1),
            ('b', '2', b'2', 2),
            ('c', '3', b'3', 3),
        ]
        self.runner.create_contract(nc_id, blueprint_id, ctx, items)

        storage = self.runner.get_storage(nc_id)
        self.assertEqual(storage.get('a:a'), '1')
        self.assertEqual(storage.get('a:b'), '2')
        self.assertEqual(storage.get('a:c'), '3')

    def _create_my_blueprint_contract(self):
        blueprint_id = self.blueprint_ids['my_blueprint']
        nc_id = self.my_blueprint_id
        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.create_contract(nc_id, blueprint_id, ctx)

    def test_public_method_fails(self):
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id

        storage = self.runner.get_storage(nc_id)
        self.assertEqual(1, storage.get('a'))
        with self.assertRaises(NCFail):
            ctx = Context([], self.tx, b'', timestamp=0)
            self.runner.call_public_method(nc_id, 'fail', ctx)
        self.assertEqual(1, storage.get('a'))

    def test_private_method_change_state(self):
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        with self.assertRaises(NCPrivateMethodError):
            self.runner.call_view_method(nc_id, 'my_private_method_fail')

    def test_private_method_success(self):
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        self.assertEqual(1, self.runner.call_view_method(nc_id, 'my_private_method_nop'))

    def test_initial_balance(self):
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        storage = self.runner.get_storage(nc_id)
        self.assertEqual(Balance(value=0, can_mint=False, can_melt=False), storage.get_balance(b''))

    def test_nop(self):
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        ctx = Context([], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)

    def test_withdrawal_fail(self):
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        action = NCWithdrawalAction(token_uid=b'\0', amount=1)
        ctx = Context([action], self.tx, b'', timestamp=0)
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method(nc_id, 'nop', ctx)

    def test_deposits_and_withdrawals(self):
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        storage = self.runner.get_storage(nc_id)

        token_uid = b'\0'
        action = NCDepositAction(token_uid=token_uid, amount=100)
        ctx = Context([action], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(Balance(value=100, can_mint=False, can_melt=False), storage.get_balance(token_uid))

        action = NCWithdrawalAction(token_uid=token_uid, amount=1)
        ctx = Context([action], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(Balance(value=99, can_mint=False, can_melt=False), storage.get_balance(token_uid))

        action = NCWithdrawalAction(token_uid=token_uid, amount=50)
        ctx = Context([action], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(Balance(value=49, can_mint=False, can_melt=False), storage.get_balance(token_uid))

        action = NCWithdrawalAction(token_uid=token_uid, amount=50)
        ctx = Context([action], self.tx, b'', timestamp=0)
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method(nc_id, 'nop', ctx)

    def test_withdraw_wrong_token(self):
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        storage = self.runner.get_storage(nc_id)

        token_uid = b'\0'
        wrong_token_uid = b'\1'

        action = NCDepositAction(token_uid=token_uid, amount=100)
        ctx = Context([action], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(Balance(value=100, can_mint=False, can_melt=False), storage.get_balance(token_uid))

        action = NCWithdrawalAction(token_uid=wrong_token_uid, amount=1)
        ctx = Context([action], self.tx, b'', timestamp=0)
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(Balance(value=100, can_mint=False, can_melt=False), storage.get_balance(token_uid))

    def test_balances(self):
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        storage = self.runner.get_storage(nc_id)

        token_uid = b'\0'  # HTR
        action = NCDepositAction(token_uid=token_uid, amount=100)
        ctx = Context([action], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(Balance(value=100, can_mint=False, can_melt=False), storage.get_balance(token_uid))

        token_uid2 = b'\0' + b'\1' * 31
        action = NCDepositAction(token_uid=token_uid2, amount=200)
        ctx = Context([action], self.tx, b'', timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(Balance(value=200, can_mint=False, can_melt=False), storage.get_balance(token_uid2))

        all_balances = storage.get_all_balances()
        key1 = BalanceKey(nc_id, token_uid)
        key2 = BalanceKey(nc_id, token_uid2)

        self.assertEqual(
            all_balances,
            {
                key1: Balance(value=100, can_mint=False, can_melt=False),
                key2: Balance(value=200, can_mint=False, can_melt=False),
            }
        )
