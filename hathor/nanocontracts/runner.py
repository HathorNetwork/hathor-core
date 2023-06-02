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

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Type

from hathor.conf.get_settings import get_global_settings
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.exception import (
    NCError,
    NCFail,
    NCInvalidContext,
    NCInvalidContractId,
    NCInvalidMethodCall,
    NCMethodNotFound,
    NCNumberOfCallsExceeded,
    NCPrivateMethodError,
    NCRecursionError,
    NCUninitializedContractError,
)
from hathor.nanocontracts.storage import NCChangesTracker, NCStorage, NCStorageFactory
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.types import Context, ContractId, NCAction, NCActionType
from hathor.transaction.storage import TransactionStorage
from hathor.types import Amount, TokenUid


class CallType(Enum):
    PUBLIC = 'public'
    PRIVATE = 'private'


@dataclass
class CallRecord:
    type: CallType
    depth: int
    nanocontract_id: ContractId
    method_name: str
    ctx: Context | None
    args: tuple[Any]
    kwargs: dict[str, Any]

    def print_dump(self):
        prefix = '    ' * self.depth
        print(prefix, self.nanocontract_id.hex(), self.method_name, self.args, self.kwargs)


@dataclass(kw_only=True)
class CallInfo:
    MAX_RECURSION_DEPTH: int
    MAX_CALL_COUNTER: int
    enable_call_trace: bool

    stack: list[CallRecord] = field(default_factory=list)
    calls: list[CallRecord] = field(default_factory=list)
    depth: int = 0
    call_counter: int = 0

    def print_dump(self):
        for item in self.trace:
            item.print_dump()

    def pre_call(self, call_record: CallRecord) -> None:
        if self.depth >= self.MAX_RECURSION_DEPTH:
            raise NCRecursionError

        if self.call_counter >= self.MAX_CALL_COUNTER:
            raise NCNumberOfCallsExceeded

        if self.enable_call_trace:
            self.calls.append(call_record)

        assert self.depth == len(self.stack)
        self.call_counter += 1
        self.depth += 1
        self.stack.append(call_record)

    def post_call(self, call_record: CallRecord) -> None:
        assert call_record == self.stack.pop()
        self.depth -= 1


class _SingleCallRunner:
    """This class is used to run a single method in a blueprint.

    You should not use this class unless you know what you are doing.
    """

    def __init__(self,
                 blueprint_class: Type[Blueprint],
                 nanocontract_id: bytes,
                 changes_tracker: NCChangesTracker) -> None:
        self.blueprint_class = blueprint_class
        self.nanocontract_id = nanocontract_id
        self.changes_tracker = changes_tracker
        self._has_been_called = False

    def get_nc_balance(self, token_id: bytes) -> int:
        """Return a Nano Contract balance for a given token."""
        return self.changes_tracker.get_balance(token_id)

    def add_nc_balance(self, token_uid: bytes, amount: int) -> None:
        """Add balance to a token. Notice that the amount might be negative."""
        self.changes_tracker.add_balance(token_uid, amount)

    def validate_context(self, ctx: Context) -> None:
        """Validate if the context is valid."""
        for token_uid, action in ctx.actions.items():
            if token_uid != action.token_uid:
                raise NCInvalidContext('token_uid mismatch')
            if action.amount < 0:
                raise NCInvalidContext('amount must be positive')

    def update_deposits_and_withdrawals(self, ctx: Context) -> None:
        """Update the contract balance according to deposits and withdrawals."""
        for action in ctx.actions.values():
            self.update_balance(action)

    def update_balance(self, action: NCAction) -> None:
        """Update the contract balance according to the given action."""
        if action.type == NCActionType.WITHDRAWAL:
            self.add_nc_balance(action.token_uid, -action.amount)
        else:
            assert action.type == NCActionType.DEPOSIT
            self.add_nc_balance(action.token_uid, action.amount)

    def call_public_method(self, method_name: str, ctx: Context, *args: Any, **kwargs: Any) -> Any:
        """Call a contract public method. If it fails, no change is saved."""
        if self._has_been_called:
            raise RuntimeError('only one call to a public method per instance')
        self._has_been_called = True

        from hathor.nanocontracts.utils import is_nc_public_method
        self.validate_context(ctx)

        blueprint = self.blueprint_class(self.changes_tracker)
        method = getattr(blueprint, method_name)
        if method is None:
            raise NCMethodNotFound(method_name)
        if not is_nc_public_method(method):
            raise NCError('not a public method')

        try:
            ret = method(ctx, *args, **kwargs)
        except NCFail:
            raise
        except Exception as e:
            # Convert any other exception to NCFail.
            raise NCFail from e

        self.update_deposits_and_withdrawals(ctx)
        return ret

    def call_private_method(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """Call a contract private method. It cannot change the state."""
        from hathor.nanocontracts.utils import is_nc_public_method
        blueprint = self.blueprint_class(self.changes_tracker)
        method = getattr(blueprint, method_name)
        if method is None:
            raise NCMethodNotFound(method_name)
        if is_nc_public_method(method):
            raise NCError('not a private method')
        ret = method(*args, **kwargs)
        if not self.changes_tracker.is_empty():
            raise NCPrivateMethodError('private methods cannot change the state')
        return ret


class Runner:
    """Runner with support for call between contracts.
    """
    MAX_RECURSION_DEPTH: int = 100
    MAX_CALL_COUNTER: int = 250

    def __init__(self,
                 tx_storage: TransactionStorage,
                 storage_factory: NCStorageFactory,
                 block_trie: PatriciaTrie) -> None:
        self.tx_storage = tx_storage
        self.storage_factory = storage_factory
        self.block_trie = block_trie
        self._storages: dict[ContractId, NCStorage] = {}
        self._change_trackers: dict[ContractId, NCChangesTracker] = {}
        self._settings = get_global_settings()

        # Flag indicating to keep record of all calls.
        self._enable_call_trace = False

        # Information about the last call.
        self._last_call_info: CallInfo | None = None

        # Information about the current call.
        self._call_info: CallInfo | None = None

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
            self._storages[nanocontract_id] = storage
        return storage

    def _get_changes_tracker(self, nanocontract_id: ContractId) -> NCChangesTracker:
        """Return the change tracker for a contract.

        If no change tracker has been created for the contract, then one will be created."""
        change_tracker = self._change_trackers.get(nanocontract_id)
        if change_tracker is None:
            storage = self.get_storage(nanocontract_id)
            change_tracker = NCChangesTracker(nanocontract_id, storage)
            self._change_trackers[nanocontract_id] = change_tracker
        return change_tracker

    def get_blueprint_class(self, nanocontract_id: ContractId) -> Type[Blueprint]:
        """Return the blueprint class of a contract."""
        from hathor.nanocontracts.utils import get_nano_contract_creation
        nc = get_nano_contract_creation(self.tx_storage, nanocontract_id, allow_mempool=True)
        return nc.get_blueprint_class()

    def _get_single_runner(self, nanocontract_id: ContractId) -> _SingleCallRunner:
        """Return a single runner for a contract."""
        blueprint_class = self.get_blueprint_class(nanocontract_id)
        change_tracker = self._get_changes_tracker(nanocontract_id)
        return _SingleCallRunner(blueprint_class, nanocontract_id, change_tracker)

    def _build_call_info(self) -> CallInfo:
        return CallInfo(
            MAX_RECURSION_DEPTH=self.MAX_RECURSION_DEPTH,
            MAX_CALL_COUNTER=self.MAX_CALL_COUNTER,
            enable_call_trace=self._enable_call_trace,
        )

    def call_public_method(self,
                           nanocontract_id: ContractId,
                           method_name: str,
                           ctx: Context,
                           *args: Any,
                           **kwargs: Any) -> Any:
        """Call a contract public method."""
        assert self._call_info is None
        self._call_info = self._build_call_info()
        try:
            ret = self._internal_call_public_method(nanocontract_id, method_name, ctx, *args, **kwargs)
        except NCFail:
            self._reset_all_change_trackers()
            raise

        self._validate_balances()
        self._commit_all_changes_to_storage()
        return ret

    def call_another_contract_public_method(self,
                                            nanocontract_id: ContractId,
                                            method_name: str,
                                            actions: list[NCAction],
                                            *args: Any,
                                            **kwargs: Any) -> Any:
        assert self._call_info is not None
        first_ctx = self._call_info.stack[0].ctx
        assert first_ctx is not None
        last_nanocontract_id = self._call_info.stack[-1].nanocontract_id
        changes_tracker = self._get_changes_tracker(last_nanocontract_id)

        if last_nanocontract_id == nanocontract_id:
            raise NCInvalidContractId('a contract cannot call itself')

        from hathor.nanocontracts.nanocontract import NC_INITIALIZE_METHOD
        if method_name == NC_INITIALIZE_METHOD:
            raise NCInvalidMethodCall('cannot call initialize from another contract')

        if not self.has_contract_been_initialized(nanocontract_id):
            raise NCUninitializedContractError('cannot call a method from an uninitialized contract')

        # Validate actions.
        for action in actions:
            if action.amount < 0:
                raise NCInvalidContext('amount must be positive')

        # Call the other contract method.
        ctx = Context(
            actions=actions,
            tx=first_ctx.tx,
            address=last_nanocontract_id,
            timestamp=first_ctx.timestamp,
        )
        ret = self._internal_call_public_method(nanocontract_id, method_name, ctx, *args, **kwargs)

        # Execute the transfers between contracts.
        for action in actions:
            match action.type:
                case NCActionType.DEPOSIT:
                    changes_tracker.add_balance(action.token_uid, -action.amount)
                case NCActionType.WITHDRAWAL:
                    changes_tracker.add_balance(action.token_uid, action.amount)
                case _:
                    assert False, 'should never happen'

        return ret

    def _reset_all_change_trackers(self) -> None:
        """Reset all changes and prepare for next call."""
        for change_tracker in self._change_trackers.values():
            change_tracker.reset()
        self._change_trackers = {}
        self._last_call_info = self._call_info
        self._call_info = None

    def _validate_balances(self) -> None:
        """Validate that all balances are non-negative."""
        for change_tracker in self._change_trackers.values():
            change_tracker.validate_balances()

    def _commit_all_changes_to_storage(self) -> None:
        """Commit all change trackers."""
        for change_tracker in self._change_trackers.values():
            change_tracker.commit()
        for nc_id, nc_storage in self._storages.items():
            self.block_trie.update(nc_id, nc_storage.get_root_id())
        self._reset_all_change_trackers()

    def commit(self) -> None:
        """Commit all storages and update block trie."""
        for nc_id, nc_storage in self._storages.items():
            nc_storage.commit()

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
        assert ctx._runner is None

        call_record = CallRecord(
            type=CallType.PUBLIC,
            depth=self._call_info.depth,
            nanocontract_id=nanocontract_id,
            method_name=method_name,
            ctx=ctx,
            args=args,
            kwargs=kwargs,
        )

        ctx._runner = self
        self._call_info.pre_call(call_record)
        single_runner = self._get_single_runner(nanocontract_id)
        ret = single_runner.call_public_method(method_name, ctx, *args, **kwargs)
        self._call_info.post_call(call_record)
        ctx._runner = None
        return ret

    def call_private_method(self, nanocontract_id: ContractId, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """Call a contract private method."""
        if self._call_info is None:
            self._call_info = self._build_call_info()

        assert self._call_info is not None

        call_record = CallRecord(
            type=CallType.PRIVATE,
            depth=self._call_info.depth,
            nanocontract_id=nanocontract_id,
            method_name=method_name,
            ctx=None,
            args=args,
            kwargs=kwargs,
        )

        self._call_info.pre_call(call_record)
        single_runner = self._get_single_runner(nanocontract_id)
        ret = single_runner.call_private_method(method_name, *args, **kwargs)
        self._call_info.post_call(call_record)

        if not self._call_info.stack:
            self._call_info = None

        return ret

    def get_balance(self, nanocontract_id: ContractId | None, token_uid: TokenUid | None) -> Amount:
        """Return a contract balance for a given token."""
        if nanocontract_id is None:
            assert self._call_info is not None
            nanocontract_id = self._call_info.stack[-1].nanocontract_id
        if token_uid is None:
            token_uid = self._settings.HATHOR_TOKEN_UID
        change_tracker = self._get_changes_tracker(nanocontract_id)
        return change_tracker.get_balance(token_uid)

    def get_current_nanocontract_id(self) -> ContractId:
        """Return the contract id for the current method being executed."""
        assert self._call_info is not None
        return self._call_info.stack[-1].nanocontract_id
