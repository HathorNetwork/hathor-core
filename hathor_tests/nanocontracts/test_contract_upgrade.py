import pytest

from hathor.nanocontracts import Blueprint, Context, fallback, public
from hathor.nanocontracts.exception import BlueprintDoesNotExist, NCFail, NCInvalidSyscall, NCMethodNotFound
from hathor.nanocontracts.types import BlueprintId, ContractId, NCArgs
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class ProxyBlueprint(Blueprint):
    counter: int
    contract: ContractId

    @public
    def initialize(self, ctx: Context, contract: ContractId) -> None:
        self.counter = 0
        self.contract = contract

    @public
    def set_contract(self, ctx: Context, contract: ContractId) -> None:
        self.contract = contract

    @public
    def upgrade_no_cb(self, ctx: Context, blueprint_id: BlueprintId) -> None:
        self.syscall.change_blueprint(blueprint_id)

    @public
    def upgrade(self, ctx: Context, blueprint_id: BlueprintId, method_name: str) -> None:
        contract_id = self.syscall.get_contract_id()
        self.syscall.change_blueprint(blueprint_id)
        self.syscall.get_contract(self.contract, blueprint_id=None).public().on_upgrade(contract_id, method_name)

    @public
    def on_upgrade(self, ctx: Context) -> None:
        raise NCFail('oops')

    @public
    def inc(self, ctx: Context) -> None:
        blueprint_id = self.syscall.get_contract(self.contract, blueprint_id=None).get_blueprint_id()
        self.syscall.get_proxy(blueprint_id).public().inc()

    @fallback
    def fallback(self, ctx: Context, method_name: str, nc_args: NCArgs) -> None:
        blueprint_id = self.syscall.get_contract(self.contract, blueprint_id=None).get_blueprint_id()
        self.syscall.get_proxy(blueprint_id) \
            .get_public_method(method_name, *ctx.actions_list) \
            .call_with_nc_args(nc_args)


class CodeBlueprint1(Blueprint):
    counter: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.counter = 0

    @public
    def inc(self, ctx: Context) -> None:
        self.counter += 1

    @public
    def dec(self, ctx: Context) -> None:
        self.counter -= 1


class CodeBlueprint2(Blueprint):
    counter: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.counter = 0

    @public
    def inc(self, ctx: Context) -> None:
        self.counter += 2

    @public
    def on_upgrade(self, ctx: Context, contract: ContractId, method_name: str) -> None:
        self.syscall \
            .get_contract(contract, blueprint_id=None) \
            .get_public_method(method_name) \
            .call()


class CodeBlueprint3(Blueprint):
    counter: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.counter = 0

    @public
    def inc(self, ctx: Context) -> None:
        self.counter += 3

    @public(allow_reentrancy=True)
    def on_upgrade_inc(self, ctx: Context) -> None:
        self.counter += 100

    @public
    def on_upgrade_fail(self, ctx: Context) -> None:
        self.counter += 200
        raise NCFail('revert it all')


class NCDelegateCallTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()
        self.proxy_bp_id = self._register_blueprint_class(ProxyBlueprint)
        self.code1_bp_id = self._register_blueprint_class(CodeBlueprint1)
        self.code2_bp_id = self._register_blueprint_class(CodeBlueprint2)
        self.code3_bp_id = self._register_blueprint_class(CodeBlueprint3)

    def test_basic(self) -> None:
        code1_id = self.gen_random_contract_id()
        code2_id = self.gen_random_contract_id()
        proxy_id = self.gen_random_contract_id()

        tx = self.get_genesis_tx()
        address = self.gen_random_address()
        ctx = self.create_context(actions=[], vertex=tx, caller_id=address)

        self.runner.create_contract(code1_id, self.code1_bp_id, ctx)
        self.runner.create_contract(code2_id, self.code2_bp_id, ctx)
        self.runner.create_contract(proxy_id, self.proxy_bp_id, ctx, code1_id)

        proxy_storage = self.runner.get_storage(proxy_id)

        code1_contract = self.get_readonly_contract(code1_id)
        assert isinstance(code1_contract, CodeBlueprint1)
        code2_contract = self.get_readonly_contract(code2_id)
        assert isinstance(code2_contract, CodeBlueprint2)
        proxy_contract = self.get_readonly_contract(proxy_id)
        assert isinstance(proxy_contract, ProxyBlueprint)

        self.runner.call_public_method(proxy_id, 'set_contract', ctx, proxy_id)
        with pytest.raises(NCInvalidSyscall, match='cannot call the same blueprint'):
            self.runner.call_public_method(proxy_id, 'inc', ctx)

        self.runner.call_public_method(proxy_id, 'set_contract', ctx, code1_id)
        self.runner.call_public_method(proxy_id, 'inc', ctx)
        assert proxy_storage.get_blueprint_id() == self.proxy_bp_id
        assert proxy_contract.contract == code1_id
        assert code1_contract.counter == 0
        assert code2_contract.counter == 0
        assert proxy_contract.counter == 1

        # it should invoke the fallback method which will call `dec()` from code1's blueprint.
        self.runner.call_public_method(proxy_id, 'dec', ctx)
        assert proxy_storage.get_blueprint_id() == self.proxy_bp_id
        assert proxy_contract.contract == code1_id
        assert code1_contract.counter == 0
        assert code2_contract.counter == 0
        assert proxy_contract.counter == 0

        self.runner.call_public_method(proxy_id, 'set_contract', ctx, code1_id)
        self.runner.call_public_method(proxy_id, 'inc', ctx)
        assert proxy_storage.get_blueprint_id() == self.proxy_bp_id
        assert proxy_contract.contract == code1_id
        assert code1_contract.counter == 0
        assert code2_contract.counter == 0
        assert proxy_contract.counter == 1

        with pytest.raises(NCFail):
            self.runner.call_public_method(proxy_id, 'upgrade', ctx, self.code3_bp_id, 'on_upgrade_fail')
        assert proxy_storage.get_blueprint_id() == self.proxy_bp_id
        assert proxy_contract.counter == 1

        self.runner.call_public_method(proxy_id, 'set_contract', ctx, code2_id)
        self.runner.call_public_method(proxy_id, 'inc', ctx)
        assert proxy_storage.get_blueprint_id() == self.proxy_bp_id
        assert proxy_contract.contract == code2_id
        assert code1_contract.counter == 0
        assert code2_contract.counter == 0
        assert proxy_contract.counter == 3

        # it should invoke the fallback method which will fail calling `dec()` from code2's blueprint.
        with pytest.raises(NCMethodNotFound, match='method `dec` not found and no fallback is provided'):
            self.runner.call_public_method(proxy_id, 'dec', ctx)
        assert proxy_storage.get_blueprint_id() == self.proxy_bp_id
        assert proxy_contract.contract == code2_id
        assert code1_contract.counter == 0
        assert code2_contract.counter == 0
        assert proxy_contract.counter == 3

        unknown_bp_id = self.gen_random_blueprint_id()
        with pytest.raises(BlueprintDoesNotExist):
            self.runner.call_public_method(proxy_id, 'upgrade_no_cb', ctx, unknown_bp_id)

        self.runner.call_public_method(proxy_id, 'upgrade', ctx, self.code3_bp_id, 'on_upgrade_inc')
        assert proxy_storage.get_blueprint_id() == self.code3_bp_id
        assert proxy_contract.counter == 103

        self.runner.call_public_method(proxy_id, 'inc', ctx)
        # Even though 'contract' field does not exist in CodeBlueprint3, its value still exists in the storage.
        assert proxy_contract.contract == code2_id
        assert code1_contract.counter == 0
        assert code2_contract.counter == 0
        assert proxy_contract.counter == 106
