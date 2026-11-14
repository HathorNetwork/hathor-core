from typing import cast

import pytest

from hathor import HATHOR_TOKEN_UID, Address, Amount, Blueprint, Context, ContractId, public
from hathor.nanocontracts.exception import NCInsufficientFunds, NCInvalidSyscall
from hathor.nanocontracts.types import TokenUid
from hathor.transaction.token_info import TokenVersion
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class AddressTransferBlueprint(Blueprint):
    before_balance: Amount
    current_balance: Amount

    @public
    def initialize(self, ctx: Context) -> None:
        self.before_balance = Amount(0)
        self.current_balance = Amount(0)

    @public
    def transfer(self, ctx: Context, to_address: Address, amount: Amount, token: TokenUid) -> None:
        self.syscall.transfer_to_address(to_address, amount, token)

    @public
    def transfer_to_contract_id(self, ctx: Context, contract_id: ContractId, amount: Amount, token: TokenUid) -> None:
        self.syscall.transfer_to_address(Address(contract_id), amount, token)

    @public
    def observe(self, ctx: Context, address: Address, token: TokenUid) -> None:
        self.before_balance = self.syscall.get_address_balance_before_current_call(address, token)
        self.current_balance = self.syscall.get_address_balance(address, token)

    @public
    def transfer_and_observe(self, ctx: Context, address: Address, amount: Amount, token: TokenUid) -> None:
        self.syscall.transfer_to_address(address, amount, token)
        self.before_balance = self.syscall.get_address_balance_before_current_call(address, token)
        self.current_balance = self.syscall.get_address_balance(address, token)


class TestAddressBalanceTransfer(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = self._register_blueprint_class(AddressTransferBlueprint)
        self.contract_id = self.gen_random_contract_id()
        self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context())

    def _seed_contract_balance(self, token_uid: TokenUid, amount: int) -> None:
        storage = self.runner.get_storage(self.contract_id)
        storage.unlock()
        storage.add_balance(token_uid, amount)
        storage.commit()
        storage.lock()
        self.runner.get_block_storage().update_contract_trie(self.contract_id, storage.get_root_id())

    def _set_before_current_call_snapshot(self) -> None:
        runner = self.runner._runner
        root_id = runner.block_storage.get_root_id()
        runner._before_current_call_block_storage = runner.storage_factory.get_block_storage(root_id)
        runner.block_storage = runner.storage_factory.get_block_storage(root_id)

    def test_transfer_to_address_persists_in_block_storage(self) -> None:
        destination = self.gen_random_address()
        token_uid = TokenUid(HATHOR_TOKEN_UID)
        self._seed_contract_balance(token_uid, 10)
        self.runner.call_public_method(self.contract_id, 'transfer', self.create_context(), destination, 7, token_uid)

        balance = self.runner.get_block_storage().get_address_balance(destination, token_uid)
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
        self._seed_contract_balance(custom_token_uid, 10)

        self.runner.call_public_method(
            self.contract_id,
            'transfer',
            self.create_context(),
            destination,
            7,
            custom_token_uid,
        )

        custom_balance = self.runner.get_block_storage().get_address_balance(destination, custom_token_uid)
        assert custom_balance == 7

        htr_balance = self.runner.get_block_storage().get_address_balance(destination, TokenUid(HATHOR_TOKEN_UID))
        assert htr_balance == 0

    def test_transfer_to_address_rejects_when_contract_balance_is_insufficient(self) -> None:
        destination = self.gen_random_address()
        token_uid = TokenUid(HATHOR_TOKEN_UID)
        self._seed_contract_balance(token_uid, 3)

        with pytest.raises(NCInsufficientFunds):
            self.runner.call_public_method(
                self.contract_id,
                'transfer',
                self.create_context(),
                destination,
                7,
                token_uid,
            )

        balance = self.runner.get_block_storage().get_address_balance(destination, token_uid)
        assert balance == 0

    def test_observe_reads_before_current_call_and_current_global_balance(self) -> None:
        address = self.gen_random_address()
        token_uid = TokenUid(HATHOR_TOKEN_UID)

        self.runner.get_block_storage().add_address_balance(address, 10, token_uid)
        self.runner.get_block_storage().commit()
        self._set_before_current_call_snapshot()
        self.runner.get_block_storage().add_address_balance(address, -4, token_uid)

        self.runner.call_public_method(self.contract_id, 'observe', self.create_context(), address, token_uid)

        contract = cast(AddressTransferBlueprint, self.get_readonly_contract(self.contract_id))
        assert contract.before_balance == 10
        assert contract.current_balance == 6

    def test_observe_current_balance_includes_prior_transfer_to_address_calls(self) -> None:
        address = self.gen_random_address()
        token_uid = TokenUid(HATHOR_TOKEN_UID)
        self._seed_contract_balance(token_uid, 10)
        self.runner.get_block_storage().add_address_balance(address, 2, token_uid)
        self.runner.get_block_storage().commit()
        self._set_before_current_call_snapshot()

        self.runner.call_public_method(
            self.contract_id,
            'transfer_and_observe',
            self.create_context(),
            address,
            3,
            token_uid,
        )

        contract = cast(AddressTransferBlueprint, self.get_readonly_contract(self.contract_id))
        assert contract.before_balance == 2
        assert contract.current_balance == 5

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


class ReentrantAddressTransferBlueprint(Blueprint):
    observed_balance: Amount

    @public
    def initialize(self, ctx: Context) -> None:
        self.observed_balance = Amount(0)

    @public
    def transfer_and_delegate(
        self,
        ctx: Context,
        to_address: Address,
        amount: Amount,
        token: TokenUid,
        delegate: ContractId,
    ) -> None:
        self.syscall.transfer_to_address(to_address, amount, token)
        origin = self.syscall.get_contract_id()
        self.syscall.get_contract(delegate, blueprint_id=None).public().delegate_observe(
            origin=origin, address=to_address, token=token,
        )

    @public
    def delegate_observe(
        self,
        ctx: Context,
        origin: ContractId,
        address: Address,
        token: TokenUid,
    ) -> None:
        self.syscall.get_contract(origin, blueprint_id=None).public().observe(
            address=address, token=token,
        )

    @public(allow_reentrancy=True)
    def observe(self, ctx: Context, address: Address, token: TokenUid) -> None:
        self.observed_balance = self.syscall.get_address_balance(address, token)


class TestReentrantAddressBalanceReads(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = self._register_blueprint_class(ReentrantAddressTransferBlueprint)
        self.origin_id = self.gen_random_contract_id()
        self.delegate_id = self.gen_random_contract_id()
        self.runner.create_contract(self.origin_id, self.blueprint_id, self.create_context())
        self.runner.create_contract(self.delegate_id, self.blueprint_id, self.create_context())

    def _seed_contract_balance(self, contract_id: ContractId, token_uid: TokenUid, amount: int) -> None:
        storage = self.runner.get_storage(contract_id)
        storage.unlock()
        storage.add_balance(token_uid, amount)
        storage.commit()
        storage.lock()
        self.runner.get_block_storage().update_contract_trie(contract_id, storage.get_root_id())

    @pytest.mark.xfail(
        strict=True,
        reason=(
            'get_address_balance only folds change_trackers[-1] per contract, so diffs from '
            'outer reentrant frames are lost. Out of scope for this PR; to be fixed alongside '
            'broader reentrancy support.'
        ),
    )
    def test_reentrant_observer_sees_outer_frame_transfer_diff(self) -> None:
        # Call path: origin.transfer_and_delegate -> delegate.delegate_observe -> origin.observe.
        # The outer `origin` frame performs the transfer, so its changes tracker holds the diff.
        # The inner `origin.observe` frame must see that diff when reading get_address_balance.
        to_address = self.gen_random_address()
        token_uid = TokenUid(HATHOR_TOKEN_UID)
        self._seed_contract_balance(self.origin_id, token_uid, 10)

        self.runner.call_public_method(
            self.origin_id,
            'transfer_and_delegate',
            self.create_context(),
            to_address,
            7,
            token_uid,
            self.delegate_id,
        )

        contract = cast(
            ReentrantAddressTransferBlueprint, self.get_readonly_contract(self.origin_id)
        )
        assert contract.observed_balance == 7
