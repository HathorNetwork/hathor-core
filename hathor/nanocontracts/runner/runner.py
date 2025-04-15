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

from collections import defaultdict
from typing import Any, Type

from typing_extensions import assert_never

from hathor.conf.get_settings import get_global_settings
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import (
    NCAlreadyInitializedContractError,
    NCInvalidContext,
    NCInvalidContractId,
    NCInvalidInitializeMethodCall,
    NCInvalidPublicMethodCallFromView,
    NCUninitializedContractError,
)
from hathor.nanocontracts.metered_exec import MeteredExecutor
from hathor.nanocontracts.rng import NanoRNG
from hathor.nanocontracts.runner.single import _SingleCallRunner
from hathor.nanocontracts.runner.types import CallInfo, CallRecord, CallType
from hathor.nanocontracts.storage import NCChangesTracker, NCStorage, NCStorageFactory
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.types import ContractId, NCAction, NCActionType
from hathor.transaction.storage import TransactionStorage
from hathor.types import Amount, TokenUid


class Runner:
    """Runner with support for call between contracts.
    """
    MAX_RECURSION_DEPTH: int = 100
    MAX_CALL_COUNTER: int = 250

    def __init__(
        self,
        tx_storage: TransactionStorage,
        storage_factory: NCStorageFactory,
        block_trie: PatriciaTrie,
        *,
        seed: bytes | None = None,
    ) -> None:
        self.tx_storage = tx_storage
        self.storage_factory = storage_factory
        self.block_trie = block_trie
        self._storages: dict[ContractId, NCStorage] = {}
        self._settings = get_global_settings()

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

    def enable_call_trace(self) -> None:
        """Enable call trace for debugging."""
        self._enable_call_trace = True

    def disable_call_trace(self) -> None:
        """Disable call trace."""
        self._enable_call_trace = False
        self._last_call_info = None

    def get_last_call_info(self) -> CallInfo | None:
        """Get last call information."""
        return self._last_call_info

    def has_contract_been_initialized(self, nanocontract_id: ContractId) -> bool:
        """Check whether a contract has been initialized or not."""
        try:
            self.block_trie.get(nanocontract_id)
        except KeyError:
            return False
        else:
            return True

    def get_storage(self, nanocontract_id: ContractId) -> NCStorage:
        """Return the storage for a contract.

        If no storage has been created, then one will be created."""
        storage = self._storages.get(nanocontract_id)
        if storage is None:
            try:
                nc_root_id = self.block_trie.get(nanocontract_id)
            except KeyError:
                nc_root_id = None
            storage = self.storage_factory(nanocontract_id, nc_root_id)
            storage.lock()
            self._storages[nanocontract_id] = storage
        return storage

    def _create_changes_tracker(self, nanocontract_id: ContractId) -> NCChangesTracker:
        """Return the latest change tracker for a contract."""
        assert self._call_info is not None
        change_trackers = self._call_info.change_trackers[nanocontract_id]
        storage: NCStorage
        if len(change_trackers) > 0:
            storage = change_trackers[-1]
        else:
            storage = self.get_storage(nanocontract_id)
        change_tracker = NCChangesTracker(nanocontract_id, storage)
        return change_tracker

    def get_blueprint_class(self, nanocontract_id: ContractId) -> Type[Blueprint]:
        """Return the blueprint class of a contract."""
        from hathor.nanocontracts.utils import get_nano_contract_creation
        nc = get_nano_contract_creation(self.tx_storage, nanocontract_id, allow_mempool=True)
        nano_header = nc.get_nano_header()
        return nano_header.get_blueprint_class()

    def _create_single_runner(
        self,
        nanocontract_id: ContractId,
        change_tracker: NCChangesTracker
    ) -> _SingleCallRunner:
        """Return a single runner for a contract."""
        assert self._metered_executor is not None
        blueprint_class = self.get_blueprint_class(nanocontract_id)
        metered_executor = self._metered_executor
        return _SingleCallRunner(self, blueprint_class, nanocontract_id, change_tracker, metered_executor)

    def _build_call_info(self) -> CallInfo:
        return CallInfo(
            MAX_RECURSION_DEPTH=self.MAX_RECURSION_DEPTH,
            MAX_CALL_COUNTER=self.MAX_CALL_COUNTER,
            enable_call_trace=self._enable_call_trace,
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
        **kwargs: Any,
    ) -> Any:
        from hathor.transaction.headers import NC_INITIALIZE_METHOD
        assert self._call_info is None
        self._call_info = self._build_call_info()

        if method_name == NC_INITIALIZE_METHOD:
            if self.has_contract_been_initialized(nanocontract_id):
                raise NCAlreadyInitializedContractError(nanocontract_id)
        else:
            if not self.has_contract_been_initialized(nanocontract_id):
                raise NCUninitializedContractError('cannot call methods from uninitialized contracts')

        self._metered_executor = MeteredExecutor(fuel=self._initial_fuel, memory_limit=self._memory_limit)

        ret = self._internal_call_public_method(nanocontract_id, method_name, ctx, *args, **kwargs)

        self._validate_balances(ctx)
        self._commit_all_changes_to_storage()
        return ret

    def call_another_contract_public_method(self,
                                            nanocontract_id: ContractId,
                                            method_name: str,
                                            actions: list[NCAction],
                                            *args: Any,
                                            **kwargs: Any) -> Any:
        assert self._call_info is not None

        # The caller is always the last element in the stack. So we need to use it as the `address` in the subsequent
        # call.
        last_call_record = self._call_info.stack[-1]

        if last_call_record.nanocontract_id == nanocontract_id:
            raise NCInvalidContractId('a contract cannot call itself')

        from hathor.transaction.headers import NC_INITIALIZE_METHOD
        if method_name == NC_INITIALIZE_METHOD:
            raise NCInvalidInitializeMethodCall('cannot call initialize from another contract')

        if not self.has_contract_been_initialized(nanocontract_id):
            raise NCUninitializedContractError('cannot call a method from an uninitialized contract')

        if last_call_record.type is CallType.VIEW:
            raise NCInvalidPublicMethodCallFromView('cannot call a public method from a view method')

        # Validate actions.
        for action in actions:
            if action.amount < 0:
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
        ret = self._internal_call_public_method(nanocontract_id, method_name, ctx, *args, **kwargs)

        # Execute the transfer on the caller side. The callee side is executed by the `_internal_call_public_method()`
        # call above, if it succeeds.
        previous_changes_tracker = last_call_record.changes_tracker
        for action in actions:
            match action.type:
                case NCActionType.DEPOSIT:
                    previous_changes_tracker.add_balance(action.token_uid, -action.amount)
                case NCActionType.WITHDRAWAL:
                    previous_changes_tracker.add_balance(action.token_uid, action.amount)
                case _:
                    assert_never(action.type)

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

            for (_, token_uid), balance in change_tracker.balance_diff.items():
                total_diffs[token_uid] += balance

        for token_uid, action in ctx.actions.items():
            match action.type:
                case NCActionType.DEPOSIT:
                    total_diffs[token_uid] -= action.amount
                case NCActionType.WITHDRAWAL:
                    total_diffs[token_uid] += action.amount
                case _:
                    assert_never(action.type)

        assert all(diff == 0 for diff in total_diffs.values()), 'change tracker diffs do not match actions'

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
            self.block_trie.update(nc_id, nc_storage.get_root_id())

    def commit(self) -> None:
        """Commit all storages and update block trie."""
        for nc_id, nc_storage in self._storages.items():
            nc_storage.unlock()
            nc_storage.commit()
            nc_storage.lock()

    def _internal_call_public_method(self,
                                     nanocontract_id: ContractId,
                                     method_name: str,
                                     ctx: Context,
                                     *args: Any,
                                     **kwargs: Any) -> Any:
        """An internal method that actually execute the public method call.
        It is also used when a contract calls another contract.
        """
        assert self._call_info is not None

        changes_tracker = self._create_changes_tracker(nanocontract_id)

        call_record = CallRecord(
            type=CallType.PUBLIC,
            depth=self._call_info.depth,
            nanocontract_id=nanocontract_id,
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
        if self._call_info is None:
            self._call_info = self._build_call_info()
        if self._metered_executor is None:
            self._metered_executor = MeteredExecutor(fuel=self._initial_fuel, memory_limit=self._memory_limit)

        assert self._call_info is not None
        assert self._metered_executor is not None

        changes_tracker = self._create_changes_tracker(nanocontract_id)

        call_record = CallRecord(
            type=CallType.VIEW,
            depth=self._call_info.depth,
            nanocontract_id=nanocontract_id,
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

    def get_balance(self, nanocontract_id: ContractId | None, token_uid: TokenUid | None) -> Amount:
        """Return a contract balance for a given token."""
        if nanocontract_id is None:
            assert self._call_info is not None
            nanocontract_id = self.get_current_nanocontract_id()
        if token_uid is None:
            token_uid = self._settings.HATHOR_TOKEN_UID

        storage: NCStorage
        if self._call_info is None:
            storage = self.get_storage(nanocontract_id)
        else:
            change_trackers = self._call_info.change_trackers[nanocontract_id]
            assert len(change_trackers) > 0
            storage = change_trackers[-1]

        return storage.get_balance(token_uid)

    def get_current_nanocontract_id(self) -> ContractId:
        """Return the contract id for the current method being executed."""
        assert self._call_info is not None
        return self._call_info.stack[-1].nanocontract_id

    def get_rng(self) -> NanoRNG:
        """Return the RNG for the current contract being executed."""
        if self._rng is None:
            raise ValueError('no seed was provided')
        return self._rng
