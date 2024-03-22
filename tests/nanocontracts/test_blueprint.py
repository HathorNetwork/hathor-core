from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.exception import NCFail, NCInsufficientFunds, NCPrivateMethodError, UnknownFieldType
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.storage import NCMemoryStorage
from hathor.nanocontracts.types import Context, NCAction, NCActionType, public
from tests import unittest


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

    def test_simple_fields(self):
        storage = NCMemoryStorage()
        nc_id = b''
        runner = Runner(SimpleFields, nc_id, storage)

        manager = self.create_peer('testnet')
        genesis = manager.tx_storage.get_all_genesis()
        tx = list(genesis)[0]

        ctx = Context([], tx, b'', timestamp=0)
        a = 'str'
        b = b'bytes'
        c = 123
        d = True
        e = 1.25
        runner.call_public_method('initialize', ctx, a, b, c, d, e)
        self.assertEqual(storage.get('a'), a)
        self.assertEqual(storage.get('b'), b)
        self.assertEqual(storage.get('c'), c)
        self.assertEqual(storage.get('d'), d)
        self.assertEqual(storage.get('e'), e)

    def test_container_fields(self):
        storage = NCMemoryStorage()
        nc_id = b''
        runner = Runner(ContainerFields, nc_id, storage)

        manager = self.create_peer('testnet')
        genesis = manager.tx_storage.get_all_genesis()
        tx = list(genesis)[0]

        ctx = Context([], tx, b'', timestamp=0)
        items = [
            ('a', '1', b'1', 1, 1.25),
            ('b', '2', b'2', 2, 2.25),
            ('c', '3', b'3', 3, 3.25),
        ]
        runner.call_public_method('initialize', ctx, items)
        self.assertEqual(storage.get('a:a'), '1')
        self.assertEqual(storage.get('a:b'), '2')
        self.assertEqual(storage.get('a:c'), '3')

    def test_public_method_fails(self):
        storage = NCMemoryStorage()
        nc_id = b''
        runner = Runner(MyBlueprint, nc_id, storage)

        ctx = Context([], None, b'', timestamp=0)
        runner.call_public_method('initialize', ctx)
        self.assertEqual(1, storage.get('a'))
        with self.assertRaises(NCFail):
            runner.call_public_method('fail', ctx)
        self.assertEqual(1, storage.get('a'))

    def test_private_method_change_state(self):
        storage = NCMemoryStorage()
        nc_id = b''
        runner = Runner(MyBlueprint, nc_id, storage)
        with self.assertRaises(NCPrivateMethodError):
            runner.call_private_method('my_private_method_fail')

    def test_private_method_success(self):
        storage = NCMemoryStorage()
        nc_id = b''
        runner = Runner(MyBlueprint, nc_id, storage)
        self.assertEqual(1, runner.call_private_method('my_private_method_nop'))

    def test_initial_balance(self):
        storage = NCMemoryStorage()
        self.assertEqual(0, storage.get_balance(b''))

    def test_nop(self):
        storage = NCMemoryStorage()
        nc_id = b''
        runner = Runner(MyBlueprint, nc_id, storage)
        ctx = Context([], None, b'', timestamp=0)
        runner.call_public_method('nop', ctx)

    def test_withdrawal_fail(self):
        storage = NCMemoryStorage()
        nc_id = b''
        runner = Runner(MyBlueprint, nc_id, storage)
        action = NCAction(NCActionType.WITHDRAWAL, b'\0', 1)
        ctx = Context([action], None, b'', timestamp=0)
        with self.assertRaises(NCInsufficientFunds):
            runner.call_public_method('nop', ctx)

    def test_deposits_and_withdrawals(self):
        storage = NCMemoryStorage()
        nc_id = b''
        runner = Runner(MyBlueprint, nc_id, storage)

        token_uid = b'\0'
        action = NCAction(NCActionType.DEPOSIT, token_uid, 100)
        ctx = Context([action], None, b'', timestamp=0)
        runner.call_public_method('nop', ctx)
        self.assertEqual(100, storage.get_balance(token_uid))

        action = NCAction(NCActionType.WITHDRAWAL, token_uid, 1)
        ctx = Context([action], None, b'', timestamp=0)
        runner.call_public_method('nop', ctx)
        self.assertEqual(99, storage.get_balance(token_uid))

        action = NCAction(NCActionType.WITHDRAWAL, token_uid, 50)
        ctx = Context([action], None, b'', timestamp=0)
        runner.call_public_method('nop', ctx)
        self.assertEqual(49, storage.get_balance(token_uid))

        action = NCAction(NCActionType.WITHDRAWAL, token_uid, 50)
        ctx = Context([action], None, b'', timestamp=0)
        with self.assertRaises(NCInsufficientFunds):
            runner.call_public_method('nop', ctx)

    def test_withdraw_wrong_token(self):
        storage = NCMemoryStorage()
        nc_id = b''
        runner = Runner(MyBlueprint, nc_id, storage)

        token_uid = b'\0'
        wrong_token_uid = b'\1'

        action = NCAction(NCActionType.DEPOSIT, token_uid, 100)
        ctx = Context([action], None, b'', timestamp=0)
        runner.call_public_method('nop', ctx)
        self.assertEqual(100, storage.get_balance(token_uid))

        action = NCAction(NCActionType.WITHDRAWAL, wrong_token_uid, 1)
        ctx = Context([action], None, b'', timestamp=0)
        with self.assertRaises(NCInsufficientFunds):
            runner.call_public_method('nop', ctx)
        self.assertEqual(100, storage.get_balance(token_uid))

    def test_invalid_field(self) -> None:
        with self.assertRaises(UnknownFieldType):
            class WrongBlueprint(Blueprint):
                a: list[int]

                @public
                def initialize(self, ctx: Context) -> None:
                    self.a = [1, 2, 3]
