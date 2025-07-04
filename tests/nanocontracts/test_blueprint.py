from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import BlueprintSyntaxError, NCFail, NCInsufficientFunds, NCViewMethodError
from hathor.nanocontracts.nc_types import make_nc_type_for_arg_type as make_nc_type
from hathor.nanocontracts.storage import NCBlockStorage, NCMemoryStorageFactory
from hathor.nanocontracts.storage.backends import MemoryNodeTrieStore
from hathor.nanocontracts.storage.contract_storage import Balance, BalanceKey
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.types import (
    Address,
    BlueprintId,
    ContractId,
    NCDepositAction,
    NCWithdrawalAction,
    TokenUid,
    VertexId,
    public,
    view,
)
from tests import unittest
from tests.nanocontracts.utils import TestRunner

STR_NC_TYPE = make_nc_type(str)
BYTES_NC_TYPE = make_nc_type(bytes)
INT_NC_TYPE = make_nc_type(int)
BOOL_NC_TYPE = make_nc_type(bool)

MOCK_ADDRESS = Address(b'')


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
    b: dict[str, bytes]
    c: dict[str, int]

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

        self.blueprint_ids: dict[str, BlueprintId] = {
            'simple_fields': BlueprintId(VertexId(b'a' * 32)),
            'container_fields': BlueprintId(VertexId(b'b' * 32)),
            'my_blueprint': BlueprintId(VertexId(b'c' * 32)),
        }

        nc_catalog = self.manager.tx_storage.nc_catalog
        nc_catalog.blueprints[self.blueprint_ids['simple_fields']] = SimpleFields
        nc_catalog.blueprints[self.blueprint_ids['container_fields']] = ContainerFields
        nc_catalog.blueprints[self.blueprint_ids['my_blueprint']] = MyBlueprint

        genesis = self.manager.tx_storage.get_all_genesis()
        self.tx = [t for t in genesis if t.is_transaction][0]

    def test_simple_fields(self) -> None:
        blueprint_id = self.blueprint_ids['simple_fields']
        nc_id = self.simple_fields_id

        ctx = Context([], self.tx, MOCK_ADDRESS, timestamp=0)
        a = 'str'
        b = b'bytes'
        c = 123
        d = True
        self.runner.create_contract(nc_id, blueprint_id, ctx, a, b, c, d)

        storage = self.runner.get_storage(nc_id).unwrap_or_raise()
        self.assertEqual(storage.get_obj(b'a', STR_NC_TYPE), a)
        self.assertEqual(storage.get_obj(b'b', BYTES_NC_TYPE), b)
        self.assertEqual(storage.get_obj(b'c', INT_NC_TYPE), c)
        self.assertEqual(storage.get_obj(b'd', BOOL_NC_TYPE), d)

    def test_container_fields(self) -> None:
        blueprint_id = self.blueprint_ids['container_fields']
        nc_id = self.container_fields_id

        ctx = Context([], self.tx, MOCK_ADDRESS, timestamp=0)
        items = [
            ('a', '1', b'1', 1),
            ('b', '2', b'2', 2),
            ('c', '3', b'3', 3),
        ]
        self.runner.create_contract(nc_id, blueprint_id, ctx, items)

        storage = self.runner.get_storage(nc_id).unwrap_or_raise()
        self.assertEqual(storage.get_obj(b'a:\x01a', STR_NC_TYPE), '1')
        self.assertEqual(storage.get_obj(b'a:\x01b', STR_NC_TYPE), '2')
        self.assertEqual(storage.get_obj(b'a:\x01c', STR_NC_TYPE), '3')

    def _create_my_blueprint_contract(self) -> None:
        blueprint_id = self.blueprint_ids['my_blueprint']
        nc_id = self.my_blueprint_id
        ctx = Context([], self.tx, MOCK_ADDRESS, timestamp=0)
        self.runner.create_contract(nc_id, blueprint_id, ctx)

    def test_public_method_fails(self) -> None:
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        storage = self.runner.get_storage(nc_id).unwrap_or_raise()

        with self.assertRaises(NCFail):
            ctx = Context([], self.tx, MOCK_ADDRESS, timestamp=0)
            self.runner.call_public_method(nc_id, 'fail', ctx)
        self.assertEqual(1, storage.get_obj(b'a', INT_NC_TYPE))

    def test_private_method_change_state(self) -> None:
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        with self.assertRaises(NCViewMethodError):
            self.runner.call_view_method(nc_id, 'my_private_method_fail')

    def test_private_method_success(self) -> None:
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        self.assertEqual(1, self.runner.call_view_method(nc_id, 'my_private_method_nop'))

    def test_initial_balance(self) -> None:
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        storage = self.runner.get_storage(nc_id).unwrap_or_raise()
        self.assertEqual(Balance(value=0, can_mint=False, can_melt=False), storage.get_balance(MOCK_ADDRESS))

    def test_nop(self) -> None:
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        ctx = Context([], self.tx, MOCK_ADDRESS, timestamp=0)
        self.runner.call_public_method(nc_id, 'nop', ctx)

    def test_withdrawal_fail(self) -> None:
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        token_uid = TokenUid(b'\0')
        ctx = Context(
            [NCWithdrawalAction(token_uid=token_uid, amount=1)],
            self.tx,
            MOCK_ADDRESS,
            timestamp=0,
        )
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method(nc_id, 'nop', ctx)

    def test_deposits_and_withdrawals(self) -> None:
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        storage = self.runner.get_storage(nc_id).unwrap_or_raise()
        token_uid = TokenUid(b'\0')
        ctx = Context(
            [NCDepositAction(token_uid=token_uid, amount=100)],
            self.tx,
            MOCK_ADDRESS,
            timestamp=0,
        )
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(Balance(value=100, can_mint=False, can_melt=False), storage.get_balance(token_uid))

        ctx = Context(
            [NCWithdrawalAction(token_uid=token_uid, amount=1)],
            self.tx,
            MOCK_ADDRESS,
            timestamp=0,
        )
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(Balance(value=99, can_mint=False, can_melt=False), storage.get_balance(token_uid))

        ctx = Context(
            [NCWithdrawalAction(token_uid=token_uid, amount=50)],
            self.tx,
            MOCK_ADDRESS,
            timestamp=0,
        )
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(Balance(value=49, can_mint=False, can_melt=False), storage.get_balance(token_uid))

        ctx = Context(
            [NCWithdrawalAction(token_uid=token_uid, amount=50)],
            self.tx,
            MOCK_ADDRESS,
            timestamp=0,
        )
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method(nc_id, 'nop', ctx)

    def test_withdraw_wrong_token(self) -> None:
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        storage = self.runner.get_storage(nc_id).unwrap_or_raise()

        token_uid = TokenUid(b'\0')
        wrong_token_uid = TokenUid(b'\1')

        ctx = Context(
            [NCDepositAction(token_uid=token_uid, amount=100)],
            self.tx,
            MOCK_ADDRESS,
            timestamp=0,
        )
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(Balance(value=100, can_mint=False, can_melt=False), storage.get_balance(token_uid))

        ctx = Context(
            [NCWithdrawalAction(token_uid=wrong_token_uid, amount=1)],
            self.tx,
            MOCK_ADDRESS,
            timestamp=0,
        )
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(Balance(value=100, can_mint=False, can_melt=False), storage.get_balance(token_uid))

    def test_invalid_field(self) -> None:
        with self.assertRaises(BlueprintSyntaxError):
            class WrongBlueprint(Blueprint):
                a: float

                @public
                def initialize(self, ctx: Context) -> None:
                    self.a = 1.2

    def test_balances(self) -> None:
        self._create_my_blueprint_contract()
        nc_id = self.my_blueprint_id
        storage = self.runner.get_storage(nc_id).unwrap_or_raise()

        token_uid = TokenUid(b'\0')  # HTR
        ctx = Context(
            [NCDepositAction(token_uid=token_uid, amount=100)],
            self.tx,
            MOCK_ADDRESS,
            timestamp=0,
        )
        self.runner.call_public_method(nc_id, 'nop', ctx)
        self.assertEqual(Balance(value=100, can_mint=False, can_melt=False), storage.get_balance(token_uid))

        token_uid2 = TokenUid(b'\0' + b'\1' * 31)
        ctx = Context(
            [NCDepositAction(token_uid=token_uid2, amount=200)],
            self.tx,
            MOCK_ADDRESS,
            timestamp=0,
        )
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
