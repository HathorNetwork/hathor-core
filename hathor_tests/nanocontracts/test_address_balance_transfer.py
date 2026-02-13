from hathor import HATHOR_TOKEN_UID, Address, Amount, Blueprint, Context, public
from hathor.nanocontracts.types import TokenUid
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class AddressTransferBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def transfer(self, ctx: Context, to_address: Address, amount: Amount) -> None:
        self.syscall.transfer_to_address(to_address, amount)


class TestAddressBalanceTransfer(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = self._register_blueprint_class(AddressTransferBlueprint)
        self.contract_id = self.gen_random_contract_id()
        self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context())

    def test_transfer_to_address_persists_in_block_storage(self) -> None:
        destination = self.gen_random_address()
        self.runner.call_public_method(self.contract_id, 'transfer', self.create_context(), destination, 7)

        token_uid = TokenUid(HATHOR_TOKEN_UID)
        balance = self.runner.block_storage.get_address_balance(destination, token_uid)
        # Phase 2 expectation: this should become 7 once commit-time transfer persistence is enabled.
        assert balance == 7
