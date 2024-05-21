# Copyright 2023 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from collections import defaultdict
from typing import Any, Type

from typing_extensions import assert_never

from hathor.conf.settings import HATHOR_TOKEN_UID, HathorSettings
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import (
    NCAlreadyInitializedContractError,
    NCInvalidContext,
    NCInvalidContractId,
    NCInvalidInitializeMethodCall,
    NCInvalidPublicMethodCallFromView,
    NCInvalidSyscall,
    NCUninitializedContractError,
)
from hathor.nanocontracts.metered_exec import MeteredExecutor
from hathor.nanocontracts.rng import NanoRNG
from hathor.nanocontracts.runner.single import _SingleCallRunner
from hathor.nanocontracts.runner.types import CallInfo, CallRecord, CallType
from hathor.nanocontracts.storage import NCBlockStorage, NCChangesTracker, NCContractStorage, NCStorageFactory
from hathor.nanocontracts.storage.contract_storage import Balance
from hathor.nanocontracts.types import (
    BaseTokenAction,
    BlueprintId,
    ContractId,
    NCAction,
    NCDepositAction,
    NCGrantAuthorityAction,
    NCInvokeAuthorityAction,
    NCWithdrawalAction,
)
from hathor.nanocontracts.utils import derive_child_contract_id
from hathor.reactor import ReactorProtocol
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.util import get_deposit_amount, get_withdraw_amount
from hathor.types import TokenUid


class Runner:
    """Runner with support for call between contracts.
    """
    MAX_RECURSION_DEPTH: int = 100
    MAX_CALL_COUNTER: int = 250

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        settings: HathorSettings,
        tx_storage: TransactionStorage,
        storage_factory: NCStorageFactory,
        block_storage: NCBlockStorage,
        seed: bytes | None,
    ) -> None:
        self.tx_storage = tx_storage
        self.storage_factory = storage_factory
        self.block_storage = block_storage
        self._storages: dict[ContractId, NCContractStorage] = {}
        self._settings = settings
        self.reactor = reactor

        # For tracking fuel and memory usage
        self._initial_fuel = self._settings.NC_INITIAL_FUEL_TO_CALL_METHOD
        self._memory_limit = self._settings.NC_MEMORY_LIMIT_TO_CALL_METHOD
        self._metered_executor: MeteredExecutor | None = None

        # Flag indicating to keep record of all calls.
        self._enable_call_trace = False

        # Information about the last call.
        self._last_call_info: CallInfo | None = None

        # Information about the current call.
        self._call_info: CallInfo | None = None

        self._rng: NanoRNG | None = NanoRNG(seed) if seed is not None else None

        # Information about minted and melted tokens in the current call via syscalls.
        self._mint_melt_totals: defaultdict[TokenUid, int] = defaultdict(int)

    def enable_call_trace(self) -> None:
        """Enable call trace for debugging."""
        self._enable_call_trace = True

    def disable_call_trace(self) -> None:
        """Disable call trace."""
        self._enable_call_trace = False

    def get_last_call_info(self) -> CallInfo:
        """Get last call information."""
        assert self._last_call_info is not None
        return self._last_call_info

    def has_contract_been_initialized(self, nanocontract_id: ContractId) -> bool:
        """Check whether a contract has been initialized or not."""
        if nanocontract_id in self._storages:
            return True
        return self.block_storage.has_contract(nanocontract_id)

    def get_storage(self, nanocontract_id: ContractId) -> NCContractStorage:
        """Return the storage for a contract.

        If no storage has been created, then one will be created."""
        storage = self._storages.get(nanocontract_id)
        if storage is None:
            storage = self.block_storage.get_contract_storage(nanocontract_id)
            storage.lock()
            self._storages[nanocontract_id] = storage
        return storage

    def _create_changes_tracker(self, nanocontract_id: ContractId) -> NCChangesTracker:
        """Return the latest change tracker for a contract."""
        assert self._call_info is not None
        change_trackers = self._call_info.change_trackers[nanocontract_id]
        storage: NCContractStorage
        if len(change_trackers) > 0:
            storage = change_trackers[-1]
        else:
            storage = self.get_storage(nanocontract_id)
        change_tracker = NCChangesTracker(nanocontract_id, storage)
        return change_tracker

    def get_blueprint_id(self, nanocontract_id: ContractId) -> BlueprintId:
        """Return the blueprint id of a contract."""
        storage = self.get_storage(nanocontract_id)
        return storage.get_blueprint_id()

    def get_blueprint_class(self, nanocontract_id: ContractId) -> Type[Blueprint]:
        """Return the blueprint class of a contract."""
        blueprint_id = self.get_blueprint_id(nanocontract_id)
        return self.tx_storage.get_blueprint_class(blueprint_id)

    def _create_single_runner(
        self,
        nanocontract_id: ContractId,
        change_tracker: NCChangesTracker,
    ) -> _SingleCallRunner:
        """Return a single runner for a contract."""
        assert self._metered_executor is not None
        assert self._call_info is not None
        blueprint_class = self.get_blueprint_class(nanocontract_id)
        metered_executor = self._metered_executor
        nc_logger = self._call_info.nc_logger
        return _SingleCallRunner(
            self, blueprint_class, nanocontract_id, change_tracker, metered_executor, nc_logger
        )

    def _build_call_info(self, nanocontract_id: ContractId) -> CallInfo:
        from hathor.nanocontracts.nc_exec_logs import NCLogger
        return CallInfo(
            MAX_RECURSION_DEPTH=self.MAX_RECURSION_DEPTH,
            MAX_CALL_COUNTER=self.MAX_CALL_COUNTER,
            enable_call_trace=self._enable_call_trace,
            nc_logger=NCLogger(__reactor__=self.reactor, __nc_id__=nanocontract_id),
        )

    def call_public_method(
        self,
        nanocontract_id: ContractId,
        method_name: str,
        ctx: Context,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Call a contract public method."""
        from hathor.transaction.headers import NC_INITIALIZE_METHOD
        if method_name == NC_INITIALIZE_METHOD:
            raise NCInvalidInitializeMethodCall(
                'Cannot call initialize from call_public_method(); use create_contract() instead.'
            )
        try:
            ret = self._unsafe_call_public_method(nanocontract_id, method_name, ctx, *args, **kwargs)
        finally:
            self._reset_all_change_trackers()
        return ret

    def _unsafe_call_public_method(
        self,
        nanocontract_id: ContractId,
        method_name: str,
        ctx: Context,
        *args: Any,
        **kwargs: Any
    ) -> Any:
        """Invoke a public method without running the usual guard‑safety checks.

        Used by call_public_method() and create_contract()."""

        assert self._call_info is None
        self._call_info = self._build_call_info(nanocontract_id)

        if not self.has_contract_been_initialized(nanocontract_id):
            raise NCUninitializedContractError('cannot call methods from uninitialized contracts')

        self._metered_executor = MeteredExecutor(fuel=self._initial_fuel, memory_limit=self._memory_limit)

        ret = self._execute_public_method_call(nanocontract_id, method_name, ctx, *args, **kwargs)

        self._validate_balances(ctx)
        self._commit_all_changes_to_storage()

        # Reset the mint/melt counters so this Runner can be reused (in blueprint tests, for example).
        self._mint_melt_totals = defaultdict(int)
        return ret

    def call_another_contract_public_method(
        self,
        nanocontract_id: ContractId,
        method_name: str,
        actions: list[NCAction],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Call another contract's public method. This method must be called by a blueprint during an execution."""
        from hathor.transaction.headers import NC_INITIALIZE_METHOD
        if method_name == NC_INITIALIZE_METHOD:
            raise NCInvalidInitializeMethodCall('cannot call initialize from another contract')
        return self._unsafe_call_another_contract_public_method(nanocontract_id, method_name, actions, *args, **kwargs)

    def _unsafe_call_another_contract_public_method(
        self,
        nanocontract_id: ContractId,
        method_name: str,
        actions: list[NCAction],
        *args: Any,
        **kwargs: Any
    ) -> Any:
        """Invoke another contract's public method without running the usual guard‑safety checks.

        Used by call_another_contract_public_method() and create_another_contract()."""
        assert self._call_info is not None

        # The caller is always the last element in the stack. So we need to use it as the `address` in the subsequent
        # call.
        last_call_record = self._call_info.stack[-1]

        if last_call_record.nanocontract_id == nanocontract_id:
            raise NCInvalidContractId('a contract cannot call itself')

        if not self.has_contract_been_initialized(nanocontract_id):
            raise NCUninitializedContractError('cannot call a method from an uninitialized contract')

        if last_call_record.type is CallType.VIEW:
            raise NCInvalidPublicMethodCallFromView('cannot call a public method from a view method')

        # Validate actions.
        for action in actions:
            if isinstance(action, BaseTokenAction) and action.amount < 0:
                raise NCInvalidContext('amount must be positive')

        first_ctx = self._call_info.stack[0].ctx
        assert first_ctx is not None

        # Call the other contract method.
        ctx = Context(
            actions=actions,
            vertex=first_ctx.vertex,
            address=last_call_record.nanocontract_id,
            timestamp=first_ctx.timestamp,
        )
        ret = self._execute_public_method_call(nanocontract_id, method_name, ctx, *args, **kwargs)

        # Execute the transfer on the caller side. The callee side is executed by the `_execute_public_method_call()`
        # call above, if it succeeds.
        previous_changes_tracker = last_call_record.changes_tracker
        for action in actions:
            match action:
                case NCDepositAction():
                    previous_changes_tracker.add_balance(action.token_uid, -action.amount)
                case NCWithdrawalAction():
                    previous_changes_tracker.add_balance(action.token_uid, action.amount)
                # TODO: implement new actions here.
                case NCGrantAuthorityAction():
                    raise NotImplementedError
                case NCInvokeAuthorityAction():
                    raise NotImplementedError
                case _:
                    assert_never(action)

        return ret

    def _reset_all_change_trackers(self) -> None:
        """Reset all changes and prepare for next call."""
        assert self._call_info is not None
        for change_trackers in self._call_info.change_trackers.values():
            for change_tracker in change_trackers:
                if not change_tracker.has_been_commited:
                    change_tracker.block()
        self._last_call_info = self._call_info
        self._call_info = None

    def _validate_balances(self, ctx: Context) -> None:
        """Validate that all balances are non-negative and assert that the total diffs match the actions."""
        assert self._call_info is not None
        # total_diffs sums the balance differences for all contracts called by this execution
        total_diffs: defaultdict[TokenUid, int] = defaultdict(int)

        for change_trackers in self._call_info.change_trackers.values():
            assert len(change_trackers) == 1
            change_tracker = change_trackers[0]
            change_tracker.validate_balances()

            for (_, token_uid), balance in change_tracker.get_balance_diff().items():
                total_diffs[token_uid] += balance

        for token_uid, amount in self._mint_melt_totals.items():
            total_diffs[token_uid] -= amount

        for action in ctx.__all_actions__:
            match action:
                case NCDepositAction():
                    total_diffs[action.token_uid] -= action.amount

                case NCWithdrawalAction():
                    total_diffs[action.token_uid] += action.amount

                case NCGrantAuthorityAction() | NCInvokeAuthorityAction():
                    # These actions don't affect the tx balance,
                    # so no need to account for them.
                    pass

                case _:
                    assert_never(action)

        assert all(diff == 0 for diff in total_diffs.values()), (
            f'change tracker diffs do not match actions: {total_diffs}'
        )

    def _commit_all_changes_to_storage(self) -> None:
        """Commit all change trackers."""
        assert self._call_info is not None
        for nc_id, change_trackers in self._call_info.change_trackers.items():
            assert len(change_trackers) == 1
            change_tracker = change_trackers[0]

            nc_storage = self._storages[nc_id]
            assert change_tracker.storage == nc_storage
            nc_storage.unlock()
            change_tracker.commit()
            nc_storage.lock()
            self.block_storage.update_contract_trie(nc_id, nc_storage.get_root_id())

    def commit(self) -> None:
        """Commit all storages and update block trie."""
        for nc_id, nc_storage in self._storages.items():
            nc_storage.unlock()
            nc_storage.commit()
            nc_storage.lock()

    def _execute_public_method_call(
        self,
        nanocontract_id: ContractId,
        method_name: str,
        ctx: Context,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """An internal method that actually execute the public method call.
        It is also used when a contract calls another contract.
        """
        assert self._call_info is not None

        changes_tracker = self._create_changes_tracker(nanocontract_id)

        blueprint_id = self.get_blueprint_id(nanocontract_id)
        call_record = CallRecord(
            type=CallType.PUBLIC,
            depth=self._call_info.depth,
            nanocontract_id=nanocontract_id,
            blueprint_id=blueprint_id,
            method_name=method_name,
            ctx=ctx,
            args=args,
            kwargs=kwargs,
            changes_tracker=changes_tracker,
        )

        self._call_info.pre_call(call_record)
        single_runner = self._create_single_runner(nanocontract_id, changes_tracker)
        ret = single_runner.call_public_method(method_name, ctx, *args, **kwargs)
        if len(self._call_info.change_trackers[nanocontract_id]) > 1:
            call_record.changes_tracker.commit()
        self._call_info.post_call(call_record)
        return ret

    def call_view_method(self, nanocontract_id: ContractId, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """Call a contract view method."""
        if not self.has_contract_been_initialized(nanocontract_id):
            raise NCUninitializedContractError('cannot call methods from uninitialized contracts')

        if self._call_info is None:
            self._call_info = self._build_call_info(nanocontract_id)
        if self._metered_executor is None:
            self._metered_executor = MeteredExecutor(fuel=self._initial_fuel, memory_limit=self._memory_limit)

        assert self._call_info is not None
        assert self._metered_executor is not None

        changes_tracker = self._create_changes_tracker(nanocontract_id)

        blueprint_id = self.get_blueprint_id(nanocontract_id)
        call_record = CallRecord(
            type=CallType.VIEW,
            depth=self._call_info.depth,
            nanocontract_id=nanocontract_id,
            blueprint_id=blueprint_id,
            method_name=method_name,
            ctx=None,
            args=args,
            kwargs=kwargs,
            changes_tracker=changes_tracker,
        )

        self._call_info.pre_call(call_record)
        single_runner = self._create_single_runner(nanocontract_id, changes_tracker)
        ret = single_runner.call_view_method(method_name, *args, **kwargs)
        self._call_info.post_call(call_record)

        assert changes_tracker.is_empty()

        if not self._call_info.stack:
            self._call_info = None

        return ret

    def get_balance(self, nanocontract_id: ContractId | None, token_uid: TokenUid | None) -> Balance:
        """Return a contract balance for a given token."""
        if nanocontract_id is None:
            assert self._call_info is not None
            nanocontract_id = self.get_current_contract_id()
        if token_uid is None:
            token_uid = self._settings.HATHOR_TOKEN_UID

        storage: NCContractStorage
        if self._call_info is None:
            storage = self.get_storage(nanocontract_id)
        else:
            storage = self.get_current_changes_tracker(nanocontract_id)

        return storage.get_balance(token_uid)

    def get_current_contract_id(self) -> ContractId:
        """Return the contract id for the current method being executed."""
        assert self._call_info is not None
        return self._call_info.stack[-1].nanocontract_id

    def get_current_changes_tracker(self, nanocontract_id: ContractId) -> NCChangesTracker:
        """Return the NCChangesTracker for the current method being executed."""
        assert self._call_info is not None
        change_trackers = self._call_info.change_trackers[nanocontract_id]
        assert len(change_trackers) > 0
        return change_trackers[-1]

    def get_rng(self) -> NanoRNG:
        """Return the RNG for the current contract being executed."""
        if self._rng is None:
            raise ValueError('no seed was provided')
        return self._rng

    def _internal_create_contract(self, nanocontract_id: ContractId, blueprint_id: BlueprintId) -> None:
        """Create a new contract without calling the initialize() method."""
        assert not self.has_contract_been_initialized(nanocontract_id)
        assert nanocontract_id not in self._storages
        nc_storage = self.storage_factory.get_empty_contract_storage(nanocontract_id)
        nc_storage.set_blueprint_id(blueprint_id)
        self._storages[nanocontract_id] = nc_storage

    def create_contract(self,
                        nanocontract_id: ContractId,
                        blueprint_id: BlueprintId,
                        ctx: Context,
                        *args: Any,
                        **kwargs: Any) -> Any:
        """Create contract and call its initialize() method."""
        from hathor.transaction.headers import NC_INITIALIZE_METHOD

        if self.has_contract_been_initialized(nanocontract_id):
            raise NCAlreadyInitializedContractError(nanocontract_id)

        self._internal_create_contract(nanocontract_id, blueprint_id)
        try:
            ret = self._unsafe_call_public_method(nanocontract_id, NC_INITIALIZE_METHOD, ctx, *args, **kwargs)
        finally:
            self._reset_all_change_trackers()
        return ret

    def create_another_contract(self,
                                blueprint_id: BlueprintId,
                                salt: bytes,
                                actions: list[NCAction],
                                *args: Any,
                                **kwargs: Any) -> tuple[ContractId, Any]:
        """Create a contract from another contract."""
        from hathor.transaction.headers import NC_INITIALIZE_METHOD

        if not salt:
            raise Exception('invalid salt')

        assert self._call_info is not None
        last_call_record = self._call_info.stack[-1]
        parent_id = last_call_record.nanocontract_id
        child_id = derive_child_contract_id(parent_id, salt, blueprint_id)

        if self.has_contract_been_initialized(child_id):
            raise NCAlreadyInitializedContractError(child_id)

        self._internal_create_contract(child_id, blueprint_id)
        ret = self._unsafe_call_another_contract_public_method(
            child_id,
            NC_INITIALIZE_METHOD,
            actions,
            *args,
            **kwargs
        )
        return child_id, ret

    def revoke_authorities(self, token_uid: TokenUid, *, revoke_mint: bool, revoke_melt: bool) -> None:
        """Revoke authorities from this nano contract."""
        contract_id = self.get_current_contract_id()
        if token_uid == HATHOR_TOKEN_UID:
            raise NCInvalidSyscall(f'contract {contract_id.hex()} cannot revoke authorities from HTR token')

        changes_tracker = self.get_current_changes_tracker(contract_id)
        changes_tracker.revoke_authorities(
            token_uid,
            revoke_mint=revoke_mint,
            revoke_melt=revoke_melt,
        )

    def mint_tokens(self, token_uid: TokenUid, amount: int) -> None:
        """Mint tokens and add them to the balance of this nano contract."""
        contract_id = self.get_current_contract_id()
        if token_uid == HATHOR_TOKEN_UID:
            raise NCInvalidSyscall(f'contract {contract_id.hex()} cannot mint HTR tokens')

        changes_tracker = self.get_current_changes_tracker(contract_id)
        assert changes_tracker.nc_id == contract_id
        balance = changes_tracker.get_balance(token_uid)

        if not balance.can_mint:
            raise NCInvalidSyscall(f'contract {contract_id.hex()} cannot mint {token_uid.hex()} tokens')

        token_amount = amount
        htr_amount = -get_deposit_amount(self._settings, token_amount)
        changes_tracker.add_balance(token_uid, token_amount)
        changes_tracker.add_balance(HATHOR_TOKEN_UID, htr_amount)

        self._mint_melt_totals[token_uid] += token_amount
        self._mint_melt_totals[TokenUid(HATHOR_TOKEN_UID)] += htr_amount

    def melt_tokens(self, token_uid: TokenUid, amount: int) -> None:
        """Melt tokens by removing them from the balance of this nano contract."""
        contract_id = self.get_current_contract_id()
        if token_uid == HATHOR_TOKEN_UID:
            raise NCInvalidSyscall(f'contract {contract_id.hex()} cannot melt HTR tokens')

        changes_tracker = self.get_current_changes_tracker(contract_id)
        assert changes_tracker.nc_id == contract_id
        balance = changes_tracker.get_balance(token_uid)

        if not balance.can_melt:
            raise NCInvalidSyscall(f'contract {contract_id.hex()} cannot melt {token_uid.hex()} tokens')

        token_amount = -amount
        htr_amount = get_withdraw_amount(self._settings, token_amount)
        changes_tracker.add_balance(token_uid, token_amount)
        changes_tracker.add_balance(HATHOR_TOKEN_UID, htr_amount)

        self._mint_melt_totals[token_uid] += token_amount
        self._mint_melt_totals[TokenUid(HATHOR_TOKEN_UID)] += htr_amount


class RunnerFactory:
    __slots__ = ('reactor', 'settings', 'tx_storage', 'nc_storage_factory')

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        settings: HathorSettings,
        tx_storage: TransactionStorage,
        nc_storage_factory: NCStorageFactory,
    ) -> None:
        self.reactor = reactor
        self.settings = settings
        self.tx_storage = tx_storage
        self.nc_storage_factory = nc_storage_factory

    def create(self, *, block_storage: NCBlockStorage, seed: bytes | None = None) -> Runner:
        return Runner(
            reactor=self.reactor,
            settings=self.settings,
            tx_storage=self.tx_storage,
            storage_factory=self.nc_storage_factory,
            block_storage=block_storage,
            seed=seed,
        )
