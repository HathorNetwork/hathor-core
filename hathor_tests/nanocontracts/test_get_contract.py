import os

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.nanocontracts import Blueprint, Context, public, view
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.types import Address, Amount, ContractId, TokenUid, VertexId
from hathor.transaction import BaseTransaction
from hathor.util import not_none
from hathor.wallet import KeyPair
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase

settings = HathorSettings()


class MyBlueprint(Blueprint):
    counter: int
    totals: dict[Address, Amount]

    @public
    def initialize(self, ctx: Context) -> None:
        self.totals = {}
        self.counter = 0

    @view
    def get_total(self, address: Address) -> int:
        return self.totals.get(address, 0)

    @public(allow_deposit=True)
    def address_add(self, ctx: Context, address: Address, amount: Amount) -> None:
        self.counter += 1
        # XXX: mypy complains when doing +=
        self.totals[address] = Amount(self.totals[address] + amount)

    @public(allow_withdrawal=True)
    def address_subtract(self, ctx: Context, address: Address, amount: Amount) -> None:
        self.counter += 1
        if self.totals[address] < amount:
            raise NCFail('cannot subtract')
        # XXX: mypy complains when doing -=
        self.totals[address] = Amount(self.totals[address] - amount)


class NCGetContractTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()
        self.token_uid = TokenUid(settings.HATHOR_TOKEN_UID)
        self.nc_id = ContractId(VertexId(b'1' * 32))
        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.initialize_contract()
        self.nc_storage = self.runner.get_storage(self.nc_id)

    def get_any_tx(self) -> BaseTransaction:
        genesis = self.manager.tx_storage.get_all_genesis()
        tx = [t for t in genesis if t.is_transaction][0]
        return tx

    def get_any_address(self) -> tuple[Address, KeyPair]:
        password = os.urandom(12)
        key = KeyPair.create(password)
        address_b58 = key.address
        address_bytes = Address(decode_address(not_none(address_b58)))
        return address_bytes, key

    def get_current_timestamp(self) -> int:
        return int(self.clock.seconds())

    def initialize_contract(self) -> None:
        self.runner.create_contract(self.nc_id, self.blueprint_id, self.create_context())

    def test_get_readonly_contract(self) -> None:
        contract = self.get_readonly_contract(self.nc_id)
        assert isinstance(contract, MyBlueprint)

        # counter was initialized with 0
        self.assertEqual(contract.counter, 0)

        # view method works
        address, _ = self.get_any_address()
        self.assertEqual(contract.get_total(address), 0)

        # no write, direct or indirect is allowed:

        with self.assertRaises(RuntimeError):
            contract.counter = 5

        with self.assertRaises(RuntimeError):
            contract.counter += 1

        ctx = self.create_context()

        with self.assertRaises(RuntimeError):
            contract.totals[address] = Amount(5)

        with self.assertRaises(RuntimeError):
            contract.address_add(ctx, address, 10)

    def test_get_readwrite_contract(self) -> None:
        contract = self.get_readwrite_contract(self.nc_id)
        assert isinstance(contract, MyBlueprint)

        # counter was initialized with 0
        self.assertEqual(contract.counter, 0)

        # incrementing works
        contract.counter += 2
        self.assertEqual(contract.counter, 2)

        # one more tim to check it added to 2 (and not to 0)
        contract.counter += 3
        self.assertEqual(contract.counter, 5)

        # wrong type fails immediately
        with self.assertRaises(TypeError):
            contract.counter = "7"  # type: ignore[assignment]

        # no effect on actual stored value
        self.assertEqual(contract.counter, 5)

        ctx = self.create_context()
        address, _ = self.get_any_address()

        # direct view call works:
        contract.totals[address] = Amount(5)
        self.assertEqual(contract.get_total(address), 5)

        # dict values also fail immediately if either key or value type is wrong:
        with self.assertRaises(TypeError):
            contract.totals[address] = "7"  # type: ignore[assignment]
        with self.assertRaises(TypeError):
            contract.totals["myaddress"] = Amount(5)  # type: ignore[index]

        # also no effect on stored value
        self.assertEqual(contract.get_total(address), 5)

        # view call method also works:
        total_address = self.runner.call_view_method(self.nc_id, 'get_total', address)
        self.assertEqual(total_address, 5)

        # direct public call works:
        contract.address_add(ctx, address, 7)
        self.assertEqual(contract.get_total(address), 12)

        # public call method also works:
        self.runner.call_public_method(self.nc_id, 'address_subtract', ctx, address, 2)
        self.assertEqual(contract.totals[address], 10)
