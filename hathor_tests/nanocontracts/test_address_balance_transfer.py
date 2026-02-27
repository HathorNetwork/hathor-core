import pytest

from hathor import HATHOR_TOKEN_UID, Address, Amount, Blueprint, Context, ContractId, public
from hathor.nanocontracts.exception import NCInvalidSyscall
from hathor.nanocontracts.types import TokenUid
from hathor.transaction.token_info import TokenVersion
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class AddressTransferBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def transfer(self, ctx: Context, to_address: Address, amount: Amount, token: TokenUid) -> None:
        self.syscall.transfer_to_address(to_address, amount, token)

    @public
    def transfer_to_contract_id(self, ctx: Context, contract_id: ContractId, amount: Amount, token: TokenUid) -> None:
        self.syscall.transfer_to_address(Address(contract_id), amount, token)


class TestAddressBalanceTransfer(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = self._register_blueprint_class(AddressTransferBlueprint)
        self.contract_id = self.gen_random_contract_id()
        self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context())

    def test_transfer_to_address_persists_in_block_storage(self) -> None:
        destination = self.gen_random_address()
        token_uid = TokenUid(HATHOR_TOKEN_UID)
        self.runner.call_public_method(self.contract_id, 'transfer', self.create_context(), destination, 7, token_uid)

        balance = self.runner.block_storage.get_address_balance(destination, token_uid)
        # Phase 2 expectation: this should become 7 once commit-time transfer persistence is enabled.
        assert balance == 7

    def test_transfer_to_address_rejects_contract_id(self) -> None:
        destination_contract = self.gen_random_contract_id()
        token_uid = TokenUid(HATHOR_TOKEN_UID)

        with pytest.raises(NCInvalidSyscall, match='address'):
            self.runner.call_public_method(
                self.contract_id,
                'transfer_to_contract_id',
                self.create_context(),
                destination_contract,
                7,
                token_uid,
            )

    def test_transfer_to_address_supports_custom_token(self) -> None:
        destination = self.gen_random_address()
        custom_token_uid = self.gen_random_token_uid()
        self.create_token(custom_token_uid, 'Custom Token', 'CTK', TokenVersion.DEPOSIT)

        self.runner.call_public_method(
            self.contract_id,
            'transfer',
            self.create_context(),
            destination,
            7,
            custom_token_uid,
        )

        custom_balance = self.runner.block_storage.get_address_balance(destination, custom_token_uid)
        assert custom_balance == 7

        htr_balance = self.runner.block_storage.get_address_balance(destination, TokenUid(HATHOR_TOKEN_UID))
        assert htr_balance == 0

    def test_transfer_to_address_rejects_unknown_token(self) -> None:
        destination = self.gen_random_address()
        unknown_token_uid = self.gen_random_token_uid()

        with pytest.raises(NCInvalidSyscall, match='could not find'):
            self.runner.call_public_method(
                self.contract_id,
                'transfer',
                self.create_context(),
                destination,
                7,
                unknown_token_uid,
            )
