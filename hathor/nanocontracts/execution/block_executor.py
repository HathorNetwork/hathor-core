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
from typing import TYPE_CHECKING, Callable, Iterator

from hathor.nanocontracts.exception import NCFail
from hathor.transaction import Block, Transaction
from hathor.transaction.exceptions import TokenNotFound

# Type alias for the skip predicate
ShouldSkipPredicate = Callable[[Transaction], bool]

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.nanocontracts.runner import Runner
    from hathor.nanocontracts.runner.runner import RunnerFactory
    from hathor.nanocontracts.sorter.types import NCSorterCallable
    from hathor.nanocontracts.storage import NCBlockStorage, NCStorageFactory


# Transaction execution result types (also used as block execution effects)
@dataclass(slots=True, frozen=True)
class NCTxExecutionSuccess:
    """Result type for successful NC execution."""
    tx: Transaction
    runner: 'Runner'


@dataclass(slots=True, frozen=True)
class NCTxExecutionFailure:
    """Result type for failed NC execution."""
    tx: Transaction
    runner: 'Runner'
    exception: NCFail
    traceback: str


@dataclass(slots=True, frozen=True)
class NCTxExecutionSkipped:
    """Result type for skipped NC execution (voided transactions)."""
    tx: Transaction


NCTxExecutionResult = NCTxExecutionSuccess | NCTxExecutionFailure | NCTxExecutionSkipped


# Block execution lifecycle effect types for generator-based execution
@dataclass(slots=True, frozen=True)
class NCBeginBlock:
    """Effect yielded at the start of block execution."""
    block: Block
    parent_root_id: bytes
    block_storage: 'NCBlockStorage'
    nc_sorted_calls: list[Transaction]


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


NCBlockEffect = (
    NCBeginBlock | NCBeginTransaction | NCTxExecutionResult |
    NCEndTransaction | NCEndBlock
)


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

    def execute_block(
        self,
        block: Block,
        *,
        should_skip: ShouldSkipPredicate,
        nc_txs: list[Transaction],
        parent_root_id: bytes,
    ) -> Iterator[NCBlockEffect]:
        """Execute block as generator, yielding effects without applying them.

        This is the pure execution method that yields lifecycle events as it processes
        each transaction. The caller decides whether to apply the side effects.

        Args:
            block: The block to execute.
            should_skip: A predicate function that determines if a transaction should be skipped.
                This allows the caller to provide context-specific voided state tracking.
            nc_txs: List of NC transactions to execute.
            parent_root_id: NC block root ID from parent block's metadata.

        Yields:
            NCBlockEffect instances representing each step of execution.
        """
        assert self._settings.ENABLE_NANO_CONTRACTS
        assert not block.is_genesis, "Genesis blocks should be handled separately"

        nc_calls = [tx for tx in nc_txs if tx.is_nano_contract()]

        nc_sorted_calls = self._nc_calls_sorter(block, nc_calls) if nc_calls else []
        block_storage = self._nc_storage_factory.get_block_storage(parent_root_id)

        yield NCBeginBlock(
            block=block,
            parent_root_id=parent_root_id,
            block_storage=block_storage,
            nc_sorted_calls=nc_sorted_calls,
        )

        seed_hasher = hashlib.sha256(block.hash)

        for tx in nc_sorted_calls:
            # Compute RNG seed for this transaction
            seed_hasher.update(tx.hash)
            seed_hasher.update(block_storage.get_root_id())
            rng_seed = seed_hasher.digest()

            yield NCBeginTransaction(tx=tx, rng_seed=rng_seed)

            # Execute transaction and yield the result directly
            result = self.execute_transaction(
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
        tx: Transaction,
        block_storage: 'NCBlockStorage',
        rng_seed: bytes,
        should_skip: ShouldSkipPredicate,
    ) -> NCTxExecutionResult:
        """Execute a single NC transaction.

        This method is pure and side-effect free. It does not persist anything,
        does not call callbacks, and returns all information needed by the caller
        to handle success/failure cases.

        Args:
            tx: The transaction to execute.
            block_storage: The block storage for this execution context.
            rng_seed: The RNG seed for this transaction.
            should_skip: Predicate to determine if transaction should be skipped.
        """
        from hathor.nanocontracts.types import Address

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
            block_storage=block_storage,
            seed=rng_seed,
        )

        try:
            runner.execute_from_tx(tx)

            # after the execution we have the latest state in the storage
            # and at this point no tokens pending creation
            self._verify_sum_after_execution(tx, block_storage)

        except NCFail as e:
            return NCTxExecutionFailure(
                tx=tx,
                runner=runner,
                exception=e,
                traceback=traceback.format_exc(),
            )

        return NCTxExecutionSuccess(tx=tx, runner=runner)

    def _verify_sum_after_execution(self, tx: Transaction, block_storage: 'NCBlockStorage') -> None:
        """Verify token sums after execution for dynamically created tokens."""
        from hathor.verification.transaction_verifier import TransactionVerifier
        try:
            token_dict = tx.get_complete_token_info(block_storage)
            TransactionVerifier.verify_sum(self._settings, tx, token_dict)
        except TokenNotFound as e:
            # At this point, any nonexistent token would have made a prior validation fail. For example, if there
            # was a withdrawal of a nonexistent token, it would have failed in the balance validation before.
            raise AssertionError from e
        except Exception as e:
            raise NCFail from e
