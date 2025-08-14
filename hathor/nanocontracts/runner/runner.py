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
from typing import Any, Callable, Concatenate, ParamSpec, Sequence, TypeVar

from typing_extensions import assert_never

from hathor.conf.settings import HATHOR_TOKEN_UID, HathorSettings
from hathor.nanocontracts.balance_rules import BalanceRules
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.blueprint_env import BlueprintEnvironment
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import (
    NCAlreadyInitializedContractError,
    NCFail,
    NCForbiddenAction,
    NCInvalidContext,
    NCInvalidContractId,
    NCInvalidInitializeMethodCall,
    NCInvalidMethodCall,
    NCInvalidPublicMethodCallFromView,
    NCInvalidSyscall,
    NCMethodNotFound,
    NCUninitializedContractError,
    NCViewMethodError,
)
from hathor.nanocontracts.faux_immutable import create_with_shell
from hathor.nanocontracts.metered_exec import MeteredExecutor
from hathor.nanocontracts.method import Method, ReturnOnly
from hathor.nanocontracts.rng import NanoRNG
from hathor.nanocontracts.runner.types import (
    CallInfo,
    CallRecord,
    CallType,
    IndexUpdateRecordType,
    SyscallCreateContractRecord,
    SyscallUpdateTokensRecord,
    UpdateAuthoritiesRecord,
    UpdateAuthoritiesRecordType,
)
from hathor.nanocontracts.storage import NCBlockStorage, NCChangesTracker, NCContractStorage, NCStorageFactory
from hathor.nanocontracts.storage.contract_storage import Balance
from hathor.nanocontracts.types import (
    NC_ALLOWED_ACTIONS_ATTR,
    NC_FALLBACK_METHOD,
    NC_INITIALIZE_METHOD,
    Address,
    BaseTokenAction,
    BlueprintId,
    ContractId,
    NCAcquireAuthorityAction,
    NCAction,
    NCActionType,
    NCArgs,
    NCDepositAction,
    NCGrantAuthorityAction,
    NCParsedArgs,
    NCRawArgs,
    NCWithdrawalAction,
    TokenUid,
    VertexId,
)
from hathor.nanocontracts.utils import (
    derive_child_contract_id,
    derive_child_token_id,
    is_nc_fallback_method,
    is_nc_public_method,
    is_nc_view_method,
)
from hathor.reactor import ReactorProtocol
from hathor.transaction import Transaction
from hathor.transaction.exceptions import TransactionDataError
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.util import (
    clean_token_string,
    get_deposit_amount,
    get_withdraw_amount,
    validate_token_name_and_symbol,
)

P = ParamSpec('P')
T = TypeVar('T')

MAX_SEQNUM_JUMP_SIZE: int = 10


def _forbid_syscall_from_view(
    display_name: str,
) -> Callable[[Callable[Concatenate['Runner', P], T]], Callable[Concatenate['Runner', P], T]]:
    """Mark a syscall method as forbidden to be called from @view methods."""
    def decorator(fn: Callable[Concatenate['Runner', P], T]) -> Callable[Concatenate['Runner', P], T]:
        def wrapper(self: Runner, /, *args: P.args, **kwargs: P.kwargs) -> T:
            current_call_record = self.get_current_call_record()
            if current_call_record.type is CallType.VIEW:
                raise NCViewMethodError(f'@view method cannot call `syscall.{display_name}`')
            return fn(self, *args, **kwargs)
        return wrapper
    return decorator


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
        self._enable_call_trace = True

        # Information about the last call.
        self._last_call_info: CallInfo | None = None

        # Information about the current call.
        self._call_info: CallInfo | None = None

        self._rng: NanoRNG | None = NanoRNG(seed) if seed is not None else None
        self._rng_per_contract: dict[ContractId, NanoRNG] = {}

        # Information about updated tokens in the current call via syscalls.
        self._updated_tokens_totals: defaultdict[TokenUid, int] = defaultdict(int)

    def execute_from_tx(self, tx: Transaction) -> None:
        """Execute the contract's method call."""
        # Check seqnum.
        nano_header = tx.get_nano_header()

        if nano_header.is_creating_a_new_contract():
            contract_id = ContractId(VertexId(tx.hash))
        else:
            contract_id = ContractId(VertexId(nano_header.nc_id))

        assert nano_header.nc_seqnum >= 0
        current_seqnum = self.block_storage.get_address_seqnum(Address(nano_header.nc_address))
        diff = nano_header.nc_seqnum - current_seqnum
        if diff <= 0 or diff > MAX_SEQNUM_JUMP_SIZE:
            # Fail execution if seqnum is invalid.
            self._last_call_info = self._build_call_info(contract_id)
            # TODO: Set the seqnum in this case?
            raise NCFail(f'invalid seqnum (diff={diff})')
        self.block_storage.set_address_seqnum(Address(nano_header.nc_address), nano_header.nc_seqnum)

        vertex_metadata = tx.get_metadata()
        assert vertex_metadata.first_block is not None, 'execute must only be called after first_block is updated'

        context = nano_header.get_context()
        assert context.vertex.block.hash == vertex_metadata.first_block

        nc_args = NCRawArgs(nano_header.nc_args_bytes)
        if nano_header.is_creating_a_new_contract():
            blueprint_id = BlueprintId(VertexId(nano_header.nc_id))
            self.create_contract_with_nc_args(contract_id, blueprint_id, context, nc_args)
        else:
            self.call_public_method_with_nc_args(contract_id, nano_header.nc_method, context, nc_args)

    def disable_call_trace(self) -> None:
        """Disable call trace. Useful when the runner is only used to call view methods, for example in APIs."""
        self._enable_call_trace = False

    def get_last_call_info(self) -> CallInfo:
        """Get last call information."""
        assert self._last_call_info is not None
        return self._last_call_info

    def has_contract_been_initialized(self, contract_id: ContractId) -> bool:
        """Check whether a contract has been initialized or not."""
        if contract_id in self._storages:
            return True
        return self.block_storage.has_contract(contract_id)

    def get_storage(self, contract_id: ContractId) -> NCContractStorage:
        """Return the storage for a contract.

        If no storage has been created, then one will be created."""
        storage = self._storages.get(contract_id)
        if storage is None:
            storage = self.block_storage.get_contract_storage(contract_id)
            storage.lock()
            self._storages[contract_id] = storage
        return storage

    def _create_changes_tracker(self, contract_id: ContractId) -> NCChangesTracker:
        """Return the latest change tracker for a contract."""
        nc_storage = self.get_current_changes_tracker_or_storage(contract_id)
        change_tracker = NCChangesTracker(contract_id, nc_storage)
        return change_tracker

    def get_blueprint_id(self, contract_id: ContractId) -> BlueprintId:
        """Return the blueprint id of a contract."""
        nc_storage = self.get_current_changes_tracker_or_storage(contract_id)
        return nc_storage.get_blueprint_id()

    def _build_call_info(self, contract_id: ContractId) -> CallInfo:
        from hathor.nanocontracts.nc_exec_logs import NCLogger
        return CallInfo(
            MAX_RECURSION_DEPTH=self.MAX_RECURSION_DEPTH,
            MAX_CALL_COUNTER=self.MAX_CALL_COUNTER,
            enable_call_trace=self._enable_call_trace,
            nc_logger=NCLogger(__reactor__=self.reactor, __nc_id__=contract_id),
        )

    def call_public_method(
        self,
        contract_id: ContractId,
        method_name: str,
        ctx: Context,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Call a contract public method."""
        nc_args = NCParsedArgs(args, kwargs)
        return self.call_public_method_with_nc_args(contract_id, method_name, ctx, nc_args)

    def call_public_method_with_nc_args(
        self,
        contract_id: ContractId,
        method_name: str,
        ctx: Context,
        nc_args: NCArgs,
    ) -> Any:
        """Call a contract public method with pre-constructed NCArgs."""
        if method_name == NC_INITIALIZE_METHOD:
            raise NCInvalidInitializeMethodCall(
                'Cannot call initialize from call_public_method(); use create_contract() instead.'
            )
        try:
            ret = self._unsafe_call_public_method(contract_id, method_name, ctx, nc_args)
        finally:
            self._reset_all_change_trackers()
        return ret

    def _unsafe_call_public_method(
        self,
        contract_id: ContractId,
        method_name: str,
        ctx: Context,
        nc_args: NCArgs,
    ) -> Any:
        """Invoke a public method without running the usual guard‑safety checks.

        Used by call_public_method() and create_contract()."""

        assert self._call_info is None
        self._call_info = self._build_call_info(contract_id)

        if not self.has_contract_been_initialized(contract_id):
            raise NCUninitializedContractError('cannot call methods from uninitialized contracts')

        self._metered_executor = MeteredExecutor(fuel=self._initial_fuel, memory_limit=self._memory_limit)

        blueprint_id = self.get_blueprint_id(contract_id)

        ret = self._execute_public_method_call(
            contract_id=contract_id,
            blueprint_id=blueprint_id,
            method_name=method_name,
            ctx=ctx,
            nc_args=nc_args,
        )

        self._validate_balances(ctx)
        self._commit_all_changes_to_storage()

        # Reset the tokens counters so this Runner can be reused (in blueprint tests, for example).
        self._updated_tokens_totals = defaultdict(int)
        return ret

    @_forbid_syscall_from_view('call_public_method')
    def syscall_call_another_contract_public_method(
        self,
        contract_id: ContractId,
        method_name: str,
        actions: Sequence[NCAction],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        """Call another contract's public method. This method must be called by a blueprint during an execution."""
        if method_name == NC_INITIALIZE_METHOD:
            raise NCInvalidInitializeMethodCall('cannot call initialize from another contract')

        if self.get_current_contract_id() == contract_id:
            raise NCInvalidContractId('a contract cannot call itself')

        if not self.has_contract_been_initialized(contract_id):
            raise NCUninitializedContractError('cannot call a method from an uninitialized contract')

        blueprint_id = self.get_blueprint_id(contract_id)
        nc_args = NCParsedArgs(args, kwargs)
        return self._unsafe_call_another_contract_public_method(
            contract_id=contract_id,
            blueprint_id=blueprint_id,
            method_name=method_name,
            actions=actions,
            nc_args=nc_args,
        )

    @_forbid_syscall_from_view('proxy_call_public_method')
    def syscall_proxy_call_public_method(
        self,
        blueprint_id: BlueprintId,
        method_name: str,
        actions: Sequence[NCAction],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        """Execute a proxy call to another blueprint's public method (similar to a DELEGATECALL).
        This method must be called by a blueprint during an execution.

        When using delegatecall:
        - The code from the target blueprint runs as if it were part of the calling contract
        - For all purposes, it is a call to the calling contract
        - The storage context remains that of the calling contract
        """
        nc_args = NCParsedArgs(args, kwargs)
        return self.syscall_proxy_call_public_method_nc_args(blueprint_id, method_name, actions, nc_args)

    @_forbid_syscall_from_view('proxy_call_public_method_nc_args')
    def syscall_proxy_call_public_method_nc_args(
        self,
        blueprint_id: BlueprintId,
        method_name: str,
        actions: Sequence[NCAction],
        nc_args: NCArgs,
    ) -> Any:
        if method_name == NC_INITIALIZE_METHOD:
            raise NCInvalidInitializeMethodCall('cannot call initialize from another contract')

        contract_id = self.get_current_contract_id()

        if blueprint_id == self.get_blueprint_id(contract_id):
            raise NCInvalidSyscall('cannot call the same blueprint')

        return self._unsafe_call_another_contract_public_method(
            contract_id=contract_id,
            blueprint_id=blueprint_id,
            method_name=method_name,
            actions=actions,
            nc_args=nc_args,
        )

    def _unsafe_call_another_contract_public_method(
        self,
        contract_id: ContractId,
        blueprint_id: BlueprintId,
        method_name: str,
        actions: Sequence[NCAction],
        nc_args: NCArgs,
    ) -> Any:
        """Invoke another contract's public method without running the usual guard‑safety checks.

        Used by call_another_contract_public_method() and create_another_contract()."""
        assert self._call_info is not None

        last_call_record = self.get_current_call_record()

        if last_call_record.type is CallType.VIEW:
            raise NCInvalidPublicMethodCallFromView('cannot call a public method from a view method')

        # Validate actions.
        for action in actions:
            if isinstance(action, BaseTokenAction) and action.amount < 0:
                raise NCInvalidContext('amount must be positive')

        first_ctx = self._call_info.stack[0].ctx
        assert first_ctx is not None

        # Execute the actions on the caller side. The callee side is executed by the `_execute_public_method_call()`
        # call below, if it succeeds.
        previous_changes_tracker = last_call_record.changes_tracker
        for action in actions:
            rules = BalanceRules.get_rules(self._settings, action)
            rules.nc_caller_execution_rule(previous_changes_tracker)

        # Call the other contract method.
        ctx = Context(
            actions=actions,
            vertex=first_ctx.vertex,
            caller_id=last_call_record.contract_id,
            timestamp=first_ctx.timestamp,
        )
        return self._execute_public_method_call(
            contract_id=contract_id,
            blueprint_id=blueprint_id,
            method_name=method_name,
            ctx=ctx,
            nc_args=nc_args,
        )

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
        """
        Validate that all balances are non-negative and assert that
        the total diffs match the actions from the main call.
        """
        assert self._call_info is not None
        assert self._call_info.calls is not None

        # total_diffs accumulates the balance differences for all contracts called during this execution.
        total_diffs: defaultdict[TokenUid, int] = defaultdict(int)

        # Each list of change trackers account for a single call in a contract.
        for change_trackers in self._call_info.change_trackers.values():
            assert len(change_trackers) == 1, 'after execution, each contract must have exactly one change tracker'
            change_tracker = change_trackers[0]
            change_tracker.validate_balances_are_positive()

            # Update total_diffs according to the diffs caused by each call, for each token.
            for balance_key, balance in change_tracker.get_balance_diff().items():
                total_diffs[TokenUid(balance_key.token_uid)] += balance

        # Accumulate tokens totals from syscalls to compare with the totals from this runner.
        calculated_tokens_totals: defaultdict[TokenUid, int] = defaultdict(int)
        for call in self._call_info.calls:
            if call.index_updates is None:
                assert call.type is CallType.VIEW
                continue
            for record in call.index_updates:
                match record:
                    case SyscallCreateContractRecord() | UpdateAuthoritiesRecord():
                        # Nothing to do here.
                        pass
                    case SyscallUpdateTokensRecord():
                        calculated_tokens_totals[record.token_uid] += record.token_amount
                        calculated_tokens_totals[TokenUid(HATHOR_TOKEN_UID)] += record.htr_amount
                    case _:
                        assert_never(record)

        assert calculated_tokens_totals == self._updated_tokens_totals, (
            f'conflicting updated tokens totals: {calculated_tokens_totals, self._updated_tokens_totals}'
        )

        # Update total_diffs according to syscalls caused by each call.
        for token_uid, amount in self._updated_tokens_totals.items():
            total_diffs[token_uid] -= amount

        # Now we do the inverse, accounting for all actions in the main call.
        for action in ctx.__all_actions__:
            match action:
                case NCDepositAction():
                    total_diffs[action.token_uid] -= action.amount

                case NCWithdrawalAction():
                    total_diffs[action.token_uid] += action.amount

                case NCGrantAuthorityAction() | NCAcquireAuthorityAction():
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
        *,
        contract_id: ContractId,
        blueprint_id: BlueprintId,
        method_name: str,
        ctx: Context,
        nc_args: NCArgs,
    ) -> Any:
        """An internal method that actually execute the public method call.
        It is also used when a contract calls another contract.
        """
        assert self._metered_executor is not None
        assert self._call_info is not None

        self._validate_context(ctx)
        changes_tracker = self._create_changes_tracker(contract_id)
        blueprint = self._create_blueprint_instance(blueprint_id, changes_tracker)
        method = getattr(blueprint, method_name, None)

        called_method_name: str = method_name
        parser: Method | ReturnOnly
        args: tuple[Any, ...]
        if method is None:
            assert method_name != NC_INITIALIZE_METHOD
            fallback_method = getattr(blueprint, NC_FALLBACK_METHOD, None)
            if fallback_method is None:
                raise NCMethodNotFound(f'method `{method_name}` not found and no fallback is provided')
            method = fallback_method
            assert is_nc_fallback_method(method)
            parser = ReturnOnly.from_callable(method)
            called_method_name = NC_FALLBACK_METHOD
            args = method_name, nc_args
        else:
            if not is_nc_public_method(method):
                raise NCInvalidMethodCall(f'method `{method_name}` is not a public method')
            parser = Method.from_callable(method)
            args = self._validate_nc_args_for_method(parser, nc_args)

        call_record = CallRecord(
            type=CallType.PUBLIC,
            depth=self._call_info.depth,
            contract_id=contract_id,
            blueprint_id=blueprint_id,
            method_name=called_method_name,
            ctx=ctx,
            args=args,
            changes_tracker=changes_tracker,
            index_updates=[],
        )
        self._call_info.pre_call(call_record)

        self._validate_actions(method, called_method_name, ctx)
        for action in ctx.__all_actions__:
            rules = BalanceRules.get_rules(self._settings, action)
            rules.nc_callee_execution_rule(changes_tracker)
            self._handle_index_update(action)

        try:
            # Although the context is immutable, we're passing a copy to the blueprint method as an added precaution.
            # This ensures that, even if the blueprint method attempts to exploit or alter the context, it cannot
            # impact the original context. Since the runner relies on the context for other critical checks, any
            # unauthorized modification would pose a serious security risk.
            ret = self._metered_executor.call(method, args=(ctx.copy(), *args))
        except NCFail:
            raise
        except Exception as e:
            # Convert any other exception to NCFail.
            raise NCFail from e

        if len(self._call_info.change_trackers[contract_id]) > 1:
            call_record.changes_tracker.commit()

        self._call_info.post_call(call_record)
        return self._validate_return_type_for_method(parser, ret)

    @staticmethod
    def _validate_nc_args_for_method(method: Method, nc_args: NCArgs) -> tuple[Any, ...]:
        """
        Given a method and its NCArgs, return the merged args and kwargs,
        while validating their types and cloning the objects.
        """
        args_bytes: bytes
        match nc_args:
            case NCParsedArgs():
                # Even though we could simply validate the type with `check_value/isinstance` and return the args,
                # we do a round-trip to create a new instance and secure mutation of objects across contracts.
                args_bytes = method.serialize_args_bytes(nc_args.args, nc_args.kwargs)
            case NCRawArgs(args_bytes):
                # Nothing to do, we can just deserialize the bytes directly.
                pass
            case _:
                assert_never(nc_args)

        return method.deserialize_args_bytes(args_bytes)

    @staticmethod
    def _validate_return_type_for_method(method: Method | ReturnOnly, return_value: Any) -> Any:
        """
        Given a method and its return value, return that value, while validating its type and cloning the object.
        """
        # Even though we could simply validate the type with `check_value/isinstance` and return the value,
        # we do a round-trip to create a new instance and secure mutation of objects across contracts.
        return_bytes = method.serialize_return_bytes(return_value)
        return method.deserialize_return_bytes(return_bytes)

    def call_view_method(self, contract_id: ContractId, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """Call a contract view method."""
        assert self._call_info is None
        self._call_info = self._build_call_info(contract_id)
        try:
            return self._unsafe_call_view_method(contract_id, method_name, args, kwargs)
        finally:
            self._reset_all_change_trackers()

    def _handle_index_update(self, action: NCAction) -> None:
        """For each action in a public method call, create the appropriate index update records."""
        call_record = self.get_current_call_record()
        assert call_record.index_updates is not None

        match action:
            case NCDepositAction() | NCWithdrawalAction():
                # Since these actions only affect indexes when used via a transaction call
                # (not when used across contracts), they are handled only once when the tx
                # is added to indexes (more specifically, to the tokens index).
                pass
            case NCGrantAuthorityAction() | NCAcquireAuthorityAction():
                # Since these actions "duplicate" authorities, they must be
                # handled everytime they're used, even across contracts.
                # That's why they account for index update records.
                record = UpdateAuthoritiesRecord(
                    token_uid=action.token_uid,
                    sub_type=UpdateAuthoritiesRecordType.GRANT,
                    mint=action.mint,
                    melt=action.melt,
                )
                call_record.index_updates.append(record)
            case _:
                assert_never(action)

    def syscall_call_another_contract_view_method(
        self,
        contract_id: ContractId,
        method_name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        """Call the view method of another contract."""
        assert self._call_info is not None
        if self.get_current_contract_id() == contract_id:
            raise NCInvalidContractId('a contract cannot call itself')
        return self._unsafe_call_view_method(contract_id, method_name, args, kwargs)

    def _unsafe_call_view_method(
        self,
        contract_id: ContractId,
        method_name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        """Call a contract view method without handling resets."""
        assert self._call_info is not None
        if not self.has_contract_been_initialized(contract_id):
            raise NCUninitializedContractError('cannot call methods from uninitialized contracts')

        if self._metered_executor is None:
            self._metered_executor = MeteredExecutor(fuel=self._initial_fuel, memory_limit=self._memory_limit)

        changes_tracker = self._create_changes_tracker(contract_id)
        blueprint_id = self.get_blueprint_id(contract_id)
        blueprint = self._create_blueprint_instance(blueprint_id, changes_tracker)
        method = getattr(blueprint, method_name, None)

        if method is None:
            raise NCMethodNotFound(method_name)
        if not is_nc_view_method(method):
            raise NCInvalidMethodCall('not a view method')

        parser = Method.from_callable(method)
        args = self._validate_nc_args_for_method(parser, NCParsedArgs(args, kwargs))

        call_record = CallRecord(
            type=CallType.VIEW,
            depth=self._call_info.depth,
            contract_id=contract_id,
            blueprint_id=blueprint_id,
            method_name=method_name,
            ctx=None,
            args=args,
            changes_tracker=changes_tracker,
            index_updates=None,
        )
        self._call_info.pre_call(call_record)

        ret = self._metered_executor.call(method, args=args)

        if not changes_tracker.is_empty():
            raise NCViewMethodError('view methods cannot change the state')

        self._call_info.post_call(call_record)
        return self._validate_return_type_for_method(parser, ret)

    def get_balance_before_current_call(self, contract_id: ContractId | None, token_uid: TokenUid | None) -> Balance:
        """
        Return the contract balance for a given token before the current call, that is,
        excluding any actions and changes in the current call.
        """
        return self._get_balance(contract_id=contract_id, token_uid=token_uid, before_current_call=True)

    def get_current_balance(self, contract_id: ContractId | None, token_uid: TokenUid | None) -> Balance:
        """
        Return the current contract balance for a given token,
        which includes all actions and changes in the current call.
        """
        return self._get_balance(contract_id=contract_id, token_uid=token_uid, before_current_call=False)

    def _get_balance(
        self,
        *,
        contract_id: ContractId | None,
        token_uid: TokenUid | None,
        before_current_call: bool,
    ) -> Balance:
        """Internal implementation of get_balance."""
        if contract_id is None:
            contract_id = self.get_current_contract_id()
        if token_uid is None:
            token_uid = TokenUid(HATHOR_TOKEN_UID)

        storage: NCContractStorage
        if self._call_info is None:
            storage = self.get_storage(contract_id)
        else:
            changes_tracker = self.get_current_changes_tracker(contract_id)
            storage = changes_tracker.storage if before_current_call else changes_tracker

        return storage.get_balance(bytes(token_uid))

    def get_current_call_record(self) -> CallRecord:
        """Return the call record for the current method being executed."""
        assert self._call_info is not None
        return self._call_info.stack[-1]

    def get_current_contract_id(self) -> ContractId:
        """Return the contract id for the current method being executed."""
        call_record = self.get_current_call_record()
        return call_record.contract_id

    def get_current_changes_tracker(self, contract_id: ContractId) -> NCChangesTracker:
        """Return the NCChangesTracker for the current method being executed."""
        assert self._call_info is not None
        change_trackers = self._call_info.change_trackers[contract_id]
        assert len(change_trackers) > 0
        return change_trackers[-1]

    def get_current_changes_tracker_or_storage(self, contract_id: ContractId) -> NCContractStorage:
        """Return the current NCChangesTracker if it exists or NCContractStorage otherwise."""
        if self._call_info is not None and contract_id in self._call_info.change_trackers:
            change_trackers = self._call_info.change_trackers[contract_id]
            assert len(change_trackers) > 0
            return change_trackers[-1]
        else:
            return self.get_storage(contract_id)

    @_forbid_syscall_from_view('rng')
    def syscall_get_rng(self) -> NanoRNG:
        """Return the RNG for the current contract being executed."""
        if self._rng is None:
            raise ValueError('no seed was provided')
        contract_id = self.get_current_contract_id()
        if contract_id not in self._rng_per_contract:
            self._rng_per_contract[contract_id] = create_with_shell(NanoRNG, seed=self._rng.randbytes(32))
        return self._rng_per_contract[contract_id]

    def _internal_create_contract(self, contract_id: ContractId, blueprint_id: BlueprintId) -> None:
        """Create a new contract without calling the initialize() method."""
        assert not self.has_contract_been_initialized(contract_id)
        assert contract_id not in self._storages
        nc_storage = self.block_storage.get_empty_contract_storage(contract_id)
        nc_storage.set_blueprint_id(blueprint_id)
        self._storages[contract_id] = nc_storage

    def create_contract(
        self,
        contract_id: ContractId,
        blueprint_id: BlueprintId,
        ctx: Context,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Create contract and call its initialize() method."""
        nc_args = NCParsedArgs(args, kwargs)
        return self.create_contract_with_nc_args(contract_id, blueprint_id, ctx, nc_args)

    def create_contract_with_nc_args(
        self,
        contract_id: ContractId,
        blueprint_id: BlueprintId,
        ctx: Context,
        nc_args: NCArgs,
    ) -> Any:
        """Create contract and call its initialize() method with pre-constructed NCArgs."""
        if self.has_contract_been_initialized(contract_id):
            raise NCAlreadyInitializedContractError(contract_id)

        self._internal_create_contract(contract_id, blueprint_id)
        try:
            ret = self._unsafe_call_public_method(contract_id, NC_INITIALIZE_METHOD, ctx, nc_args)
        finally:
            self._reset_all_change_trackers()
        return ret

    @_forbid_syscall_from_view('create_contract')
    def syscall_create_another_contract(
        self,
        blueprint_id: BlueprintId,
        salt: bytes,
        actions: Sequence[NCAction],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> tuple[ContractId, Any]:
        """Create a contract from another contract."""
        if not salt:
            raise Exception('invalid salt')

        assert self._call_info is not None
        last_call_record = self.get_current_call_record()
        parent_id = last_call_record.contract_id
        child_id = derive_child_contract_id(parent_id, salt, blueprint_id)

        if self.has_contract_been_initialized(child_id):
            raise NCAlreadyInitializedContractError(child_id)

        self._internal_create_contract(child_id, blueprint_id)
        nc_args = NCParsedArgs(args, kwargs)
        ret = self._unsafe_call_another_contract_public_method(
            child_id,
            blueprint_id,
            NC_INITIALIZE_METHOD,
            actions,
            nc_args,
        )

        assert last_call_record.index_updates is not None
        syscall_record = SyscallCreateContractRecord(blueprint_id=blueprint_id, contract_id=child_id)
        last_call_record.index_updates.append(syscall_record)
        return child_id, ret

    @_forbid_syscall_from_view('revoke_authorities')
    def syscall_revoke_authorities(self, token_uid: TokenUid, *, revoke_mint: bool, revoke_melt: bool) -> None:
        """Revoke authorities from this nano contract."""
        call_record = self.get_current_call_record()
        contract_id = call_record.contract_id
        if token_uid == HATHOR_TOKEN_UID:
            raise NCInvalidSyscall(f'contract {contract_id.hex()} cannot revoke authorities from HTR token')

        changes_tracker = self.get_current_changes_tracker(contract_id)
        assert changes_tracker.nc_id == call_record.contract_id
        balance = changes_tracker.get_balance(token_uid)

        if revoke_mint and not balance.can_mint:
            raise NCInvalidSyscall(f'contract {call_record.contract_id.hex()} cannot mint {token_uid.hex()} tokens')

        if revoke_melt and not balance.can_melt:
            raise NCInvalidSyscall(f'contract {call_record.contract_id.hex()} cannot melt {token_uid.hex()} tokens')

        changes_tracker.revoke_authorities(
            token_uid,
            revoke_mint=revoke_mint,
            revoke_melt=revoke_melt,
        )

        assert call_record.index_updates is not None
        syscall_record = UpdateAuthoritiesRecord(
            token_uid=token_uid,
            sub_type=UpdateAuthoritiesRecordType.REVOKE,
            mint=revoke_mint,
            melt=revoke_melt,
        )
        call_record.index_updates.append(syscall_record)

    @_forbid_syscall_from_view('mint_tokens')
    def syscall_mint_tokens(self, token_uid: TokenUid, amount: int) -> None:
        """Mint tokens and add them to the balance of this nano contract."""
        call_record = self.get_current_call_record()
        if token_uid == HATHOR_TOKEN_UID:
            raise NCInvalidSyscall(f'contract {call_record.contract_id.hex()} cannot mint HTR tokens')

        changes_tracker = self.get_current_changes_tracker(call_record.contract_id)
        assert changes_tracker.nc_id == call_record.contract_id
        balance = changes_tracker.get_balance(token_uid)

        if not balance.can_mint:
            raise NCInvalidSyscall(f'contract {call_record.contract_id.hex()} cannot mint {token_uid.hex()} tokens')

        token_amount = amount
        htr_amount = -get_deposit_amount(self._settings, token_amount)

        changes_tracker.add_balance(token_uid, token_amount)
        changes_tracker.add_balance(HATHOR_TOKEN_UID, htr_amount)

        self._updated_tokens_totals[token_uid] += token_amount
        self._updated_tokens_totals[TokenUid(HATHOR_TOKEN_UID)] += htr_amount

        assert call_record.index_updates is not None
        syscall_record = SyscallUpdateTokensRecord(
            type=IndexUpdateRecordType.MINT_TOKENS,
            token_uid=token_uid,
            token_amount=token_amount,
            htr_amount=htr_amount,
        )
        call_record.index_updates.append(syscall_record)

    @_forbid_syscall_from_view('melt_tokens')
    def syscall_melt_tokens(self, token_uid: TokenUid, amount: int) -> None:
        """Melt tokens by removing them from the balance of this nano contract."""
        call_record = self.get_current_call_record()
        if token_uid == HATHOR_TOKEN_UID:
            raise NCInvalidSyscall(f'contract {call_record.contract_id.hex()} cannot melt HTR tokens')

        changes_tracker = self.get_current_changes_tracker(call_record.contract_id)
        assert changes_tracker.nc_id == call_record.contract_id
        balance = changes_tracker.get_balance(token_uid)

        if not balance.can_melt:
            raise NCInvalidSyscall(f'contract {call_record.contract_id.hex()} cannot melt {token_uid.hex()} tokens')

        token_amount = -amount
        htr_amount = get_withdraw_amount(self._settings, token_amount)

        changes_tracker.add_balance(token_uid, token_amount)
        changes_tracker.add_balance(HATHOR_TOKEN_UID, htr_amount)

        self._updated_tokens_totals[token_uid] += token_amount
        self._updated_tokens_totals[TokenUid(HATHOR_TOKEN_UID)] += htr_amount

        assert call_record.index_updates is not None
        syscall_record = SyscallUpdateTokensRecord(
            type=IndexUpdateRecordType.MELT_TOKENS,
            token_uid=token_uid,
            token_amount=token_amount,
            htr_amount=htr_amount,
        )
        call_record.index_updates.append(syscall_record)

    def _validate_context(self, ctx: Context) -> None:
        """Check whether the context is valid."""
        for token_uid, actions in ctx.actions.items():
            for action in actions:
                if token_uid != action.token_uid:
                    raise NCInvalidContext('token_uid mismatch')
                if isinstance(action, BaseTokenAction) and action.amount < 0:
                    raise NCInvalidContext('amount must be positive')

    def _validate_actions(self, method: Any, method_name: str, ctx: Context) -> None:
        """Check whether actions are allowed."""
        allowed_actions: set[NCActionType] = getattr(method, NC_ALLOWED_ACTIONS_ATTR, set())
        assert isinstance(allowed_actions, set)

        for actions in ctx.actions.values():
            for action in actions:
                if action.type not in allowed_actions:
                    raise NCForbiddenAction(f'action {action.name} is forbidden on method `{method_name}`')

    def _create_blueprint_instance(self, blueprint_id: BlueprintId, changes_tracker: NCChangesTracker) -> Blueprint:
        """Create a new blueprint instance."""
        assert self._call_info is not None
        env = BlueprintEnvironment(self, self._call_info.nc_logger, changes_tracker)
        blueprint_class = self.tx_storage.get_blueprint_class(blueprint_id)
        return blueprint_class(env)

    @_forbid_syscall_from_view('create_token')
    def syscall_create_child_token(
        self,
        token_name: str,
        token_symbol: str,
        amount: int,
        mint_authority: bool,
        melt_authority: bool,
    ) -> TokenUid:
        """Create a child token from a contract."""
        try:
            validate_token_name_and_symbol(self._settings, token_name, token_symbol)
        except TransactionDataError as e:
            raise NCInvalidSyscall('invalid token description') from e

        last_call_record = self.get_current_call_record()
        parent_id = last_call_record.contract_id
        cleaned_token_symbol = clean_token_string(token_symbol)
        token_id = derive_child_token_id(parent_id, cleaned_token_symbol)

        token_amount = amount
        htr_amount = get_deposit_amount(self._settings, token_amount)

        changes_tracker = self.get_current_changes_tracker(parent_id)
        changes_tracker.create_token(token_id, token_name, token_symbol)
        changes_tracker.grant_authorities(
            token_id,
            grant_mint=mint_authority,
            grant_melt=melt_authority,
        )
        changes_tracker.add_balance(token_id, amount)
        changes_tracker.add_balance(HATHOR_TOKEN_UID, -htr_amount)
        self._updated_tokens_totals[token_id] += amount
        self._updated_tokens_totals[TokenUid(HATHOR_TOKEN_UID)] -= htr_amount

        assert last_call_record.index_updates is not None
        syscall_record = SyscallUpdateTokensRecord(
            type=IndexUpdateRecordType.CREATE_TOKEN,
            token_uid=token_id,
            token_amount=token_amount,
            htr_amount=-htr_amount,
            token_symbol=token_symbol,
            token_name=token_name,
        )
        last_call_record.index_updates.append(syscall_record)

        return token_id

    @_forbid_syscall_from_view('emit_event')
    def syscall_emit_event(self, data: bytes) -> None:
        """Emit a custom event from a Nano Contract."""
        assert self._call_info is not None
        self._call_info.nc_logger.__emit_event__(data)

    @_forbid_syscall_from_view('change_blueprint')
    def syscall_change_blueprint(self, blueprint_id: BlueprintId) -> None:
        """Change the blueprint of a contract."""
        assert self._call_info is not None
        last_call_record = self.get_current_call_record()
        if last_call_record.type is CallType.VIEW:
            raise NCInvalidPublicMethodCallFromView('forbidden')

        # The blueprint must exist. If an unknown blueprint is provided, it will raise an BlueprintDoesNotExist
        # exception.
        self.tx_storage.get_blueprint_class(blueprint_id)

        nc_storage = self.get_current_changes_tracker(last_call_record.contract_id)
        nc_storage.set_blueprint_id(blueprint_id)


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
