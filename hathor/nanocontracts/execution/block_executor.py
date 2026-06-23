#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""NCBlockExecutor - Pure execution of nano contract transactions in a block."""

from __future__ import annotations

import hashlib
import traceback
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Iterator, Mapping, TypeAlias, cast

from hathor.feature_activation.utils import Features
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.nano_runtime_version import NanoRuntimeVersion
from hathor.transaction import Block, Transaction
from hathorlib.nanocontracts.runner.call_info import CallInfo
from hathorlib.nanocontracts.runner.runner import MAX_SEQNUM_JUMP_SIZE
from hathorlib.nanocontracts.types import Address, BlueprintId, ContractId, NCRawArgs, VertexId

# Type alias for the skip predicate
ShouldSkipPredicate = Callable[[Transaction], bool]

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.feature_activation.feature_service import FeatureService
    from hathor.nanocontracts.runner import Runner
    from hathor.nanocontracts.runner.runner import RunnerFactory
    from hathor.nanocontracts.sorter.types import NCSorterCallable
    from hathor.nanocontracts.storage import NCBlockStorage, NCStorageFactory
    from hathor.nanocontracts.types import TokenUid
    from hathor.transaction.token_info import TokenDescription


# Transaction execution result types (also used as block execution effects)
@dataclass(slots=True, frozen=True)
class NCTxExecutionSuccess:
    """Result type for successful NC execution."""
    tx: Transaction
    runner: 'Runner'


@dataclass(slots=True, frozen=True)
class NCTxExecutionFailure:
    """Result type for failed NC execution.

    `call_info` is None for cyclic-dependency failures, which never run a Runner.
    """
    tx: Transaction
    call_info: CallInfo | None
    exception: NCFail
    traceback: str


@dataclass(slots=True, frozen=True)
class NCTxExecutionSkipped:
    """Result type for skipped NC execution (voided transactions)."""
    tx: Transaction


NCTxExecutionResult: TypeAlias = NCTxExecutionSuccess | NCTxExecutionFailure | NCTxExecutionSkipped


# Block execution lifecycle effect types for generator-based execution
@dataclass(slots=True, frozen=True)
class NCBeginBlock:
    """Effect yielded at the start of block execution."""
    block: Block
    parent_root_id: bytes
    block_storage: 'NCBlockStorage'
    nc_sorted_calls: tuple[Transaction, ...]
    nc_cyclic_fails: tuple[Transaction, ...]


@dataclass(slots=True, frozen=True)
class NCBeginTransaction:
    """Effect yielded at the start of transaction execution."""
    tx: Transaction
    rng_seed: bytes


@dataclass(slots=True, frozen=True)
class NCEndTransaction:
    """Effect yielded at the end of transaction processing."""
    tx: Transaction


@dataclass(slots=True, frozen=True)
class NCEndBlock:
    """Effect yielded at the end of block execution."""
    block: Block
    block_storage: 'NCBlockStorage'
    final_root_id: bytes


NCBlockEffect: TypeAlias = (
    NCBeginBlock | NCBeginTransaction | NCTxExecutionResult |
    NCEndTransaction | NCEndBlock
)


class _UncommittedRestrictedBlockProxy:
    """Read-only token overlay for pre-commit validation."""

    def __init__(
        self,
        block_storage: 'NCBlockStorage',
        *,
        created_tokens: Mapping['TokenUid', 'TokenDescription'],
    ) -> None:
        self._block_storage = block_storage
        self._created_tokens = created_tokens

    def has_token(self, token_id: 'TokenUid') -> bool:
        if token_id in self._created_tokens:
            return True
        return self._block_storage.has_token(token_id)

    def get_token_description(self, token_id: 'TokenUid') -> 'TokenDescription':
        token_description = self._created_tokens.get(token_id)
        if token_description is not None:
            return token_description
        return self._block_storage.get_token_description(token_id)


class NCBlockExecutor:
    """
    Pure execution of nano contract transactions in a block.

    This class contains the core NC execution logic without any side effects.
    It yields execution events that can be processed by a caller to apply
    state changes.
    """

    def __init__(
        self,
        *,
        settings: 'HathorSettings',
        runner_factory: 'RunnerFactory',
        nc_storage_factory: 'NCStorageFactory',
        nc_calls_sorter: 'NCSorterCallable',
        feature_service: FeatureService,
    ) -> None:
        """
        Initialize the block executor.

        Args:
            settings: Hathor settings.
            runner_factory: Factory to create Runner instances.
            nc_storage_factory: Factory to create NC storage instances.
            nc_calls_sorter: Function to sort NC transactions for deterministic execution order.
        """
        self._settings = settings
        self._runner_factory = runner_factory
        self._nc_storage_factory = nc_storage_factory
        self._nc_calls_sorter = nc_calls_sorter
        self._feature_service = feature_service

    def execute_block(
        self,
        block: Block,
        *,
        should_skip: ShouldSkipPredicate,
    ) -> Iterator[NCBlockEffect]:
        """Execute block as generator, yielding effects without applying them.

        This is the pure execution method that yields lifecycle events as it processes
        each transaction. The caller decides whether to apply the side effects.

        Args:
            block: The block to execute.
            should_skip: A predicate function that determines if a transaction should be skipped.
                This allows the caller to provide context-specific voided state tracking.

        Yields:
            NCBlockEffect instances representing each step of execution.
        """
        assert self._settings.ENABLE_NANO_CONTRACTS
        assert not block.is_genesis, "Genesis blocks should be handled separately"

        meta = block.get_metadata()
        assert not meta.voided_by

        parent = block.get_block_parent()
        parent_meta = parent.get_metadata()
        parent_root_id = parent_meta.nc_block_root_id
        assert parent_root_id is not None

        nc_calls: list[Transaction] = []
        for tx in block.iter_transactions_in_this_block():
            if not tx.is_nano_contract():
                continue
            nc_calls.append(tx)

        sorted_txs = self._nc_calls_sorter(block, nc_calls) if nc_calls else None
        nc_sorted_calls = sorted_txs.sorted if sorted_txs else tuple()
        nc_cyclic_txs = sorted_txs.cyclic if sorted_txs else tuple()
        block_storage = self._nc_storage_factory.get_block_storage(parent_root_id)
        assert block_storage.get_root_id() == parent_root_id
        features = Features.from_vertex(settings=self._settings, feature_service=self._feature_service, vertex=block)

        yield NCBeginBlock(
            block=block,
            parent_root_id=parent_root_id,
            block_storage=block_storage,
            nc_sorted_calls=nc_sorted_calls,
            nc_cyclic_fails=nc_cyclic_txs,
        )

        for tx in nc_cyclic_txs:
            yield NCBeginTransaction(tx=tx, rng_seed=b'')
            try:
                # Dummy raise just to create an exception context and convert
                # into the failure effect, analogous to seqnum failures.
                raise NCFail('cyclic failure detected')
            except NCFail as e:
                yield NCTxExecutionFailure(
                    tx=tx,
                    call_info=None,
                    exception=e,
                    traceback=traceback.format_exc(),
                )
            yield NCEndTransaction(tx=tx)

        seed_hasher = hashlib.sha256(block.hash)

        for tx in nc_sorted_calls:
            # Compute RNG seed for this transaction
            seed_hasher.update(tx.hash)
            seed_hasher.update(block_storage.get_root_id())
            rng_seed = seed_hasher.digest()

            yield NCBeginTransaction(tx=tx, rng_seed=rng_seed)

            # Execute transaction and yield the result directly
            result = self.execute_transaction(
                runtime_version=features.nano_runtime_version,
                tx=tx,
                block_storage=block_storage,
                rng_seed=rng_seed,
                should_skip=should_skip,
            )
            yield result

            yield NCEndTransaction(tx=tx)

        # Compute final root ID without committing
        final_root_id = block_storage.get_root_id()
        if not nc_sorted_calls:
            assert final_root_id == parent_root_id
        yield NCEndBlock(
            block=block,
            block_storage=block_storage,
            final_root_id=final_root_id,
        )

    def execute_transaction(
        self,
        *,
        runtime_version: NanoRuntimeVersion,
        tx: Transaction,
        block_storage: 'NCBlockStorage',
        rng_seed: bytes,
        should_skip: ShouldSkipPredicate,
    ) -> NCTxExecutionResult:
        """Execute a single NC transaction.

        On success, changes are committed to block_storage before returning.
        Does not call callbacks. Returns all information needed by the caller
        to handle success/failure cases.

        Args:
            tx: The transaction to execute.
            block_storage: The block storage for this execution context.
            rng_seed: The RNG seed for this transaction.
            should_skip: Predicate to determine if transaction should be skipped.
        """
        if should_skip(tx):
            # Skip transactions based on the caller-provided predicate.
            # Check if seqnum needs to be updated.
            nc_header = tx.get_nano_header()
            nc_address = Address(nc_header.nc_address)
            seqnum = block_storage.get_address_seqnum(nc_address)
            if nc_header.nc_seqnum > seqnum:
                block_storage.set_address_seqnum(nc_address, nc_header.nc_seqnum)
            return NCTxExecutionSkipped(tx=tx)

        runner = self._runner_factory.create(
            runtime_version=runtime_version,
            token_amount_version=tx.get_token_amount_version(),
            block_storage=block_storage,
            seed=rng_seed,
        )

        try:
            assert isinstance(tx, Transaction)

            # Check seqnum.
            nano_header = tx.get_nano_header()

            if nano_header.is_creating_a_new_contract():
                contract_id = ContractId(VertexId(tx.hash))
            else:
                contract_id = ContractId(VertexId(nano_header.nc_id))

            assert nano_header.nc_seqnum >= 0
            current_seqnum = runner.block_storage.get_address_seqnum(
                Address(nano_header.nc_address)
            )
            diff = nano_header.nc_seqnum - current_seqnum
            if diff <= 0 or diff > MAX_SEQNUM_JUMP_SIZE:
                # Fail execution if seqnum is invalid.
                runner._last_call_info = runner._build_call_info(contract_id)
                # TODO: Set the seqnum in this case?
                raise NCFail(f'invalid seqnum (diff={diff})')
            runner.block_storage.set_address_seqnum(
                Address(nano_header.nc_address), nano_header.nc_seqnum
            )

            vertex_metadata = tx.get_metadata()
            assert vertex_metadata.first_block is not None, (
                "execute must only be called after first_block is updated"
            )

            context = nano_header.get_context()
            assert context.block.hash == vertex_metadata.first_block

            nc_args = NCRawArgs(nano_header.nc_args_bytes)
            if nano_header.is_creating_a_new_contract():
                blueprint_id = BlueprintId(VertexId(nano_header.nc_id))
                runner.create_contract_with_nc_args(contract_id, blueprint_id, context, nc_args)
            else:
                runner.call_public_method_with_nc_args(
                    contract_id, nano_header.nc_method, context, nc_args
                )

            # after the execution we have the latest state in the storage + changes tracker
            # and at this point no tokens pending creation, so we can validate the balances
            self._verify_transparent_balance_after_execution(tx, block_storage, runner)
        except NCFail as e:
            runner.discard_pending_changes()
            return NCTxExecutionFailure(
                tx=tx,
                call_info=runner.get_last_call_info(),
                exception=e,
                traceback=traceback.format_exc(),
            )

        # Commit is intentionally outside the NCFail handling path.
        # A failure here indicates critical state corruption and must propagate.
        runner.commit_pending_changes()

        return NCTxExecutionSuccess(tx=tx, runner=runner)

    def _verify_transparent_balance_after_execution(
        self,
        tx: Transaction,
        block_storage: 'NCBlockStorage',
        runner: 'Runner',
    ) -> None:
        """Run strict verify_sum after execution using uncommitted token overlay visibility."""
        from hathor.transaction.exceptions import TokenNotFound
        from hathor.verification.transaction_verifier import TransactionVerifier

        created_tokens = runner.collect_created_tokens_from_uncommitted_changes()
        block_proxy = _UncommittedRestrictedBlockProxy(block_storage, created_tokens=created_tokens)
        block_proxy_as_storage = cast('NCBlockStorage', block_proxy)

        try:
            token_dict = tx.get_complete_token_info(block_proxy_as_storage)
            TransactionVerifier.verify_transparent_balance(self._settings, tx, token_dict)
        except TokenNotFound as e:
            # Missing tokens should have failed in earlier validation paths.
            raise AssertionError from e
        except Exception as e:
            raise NCFail from e
