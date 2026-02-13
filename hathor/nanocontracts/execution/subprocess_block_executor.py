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

"""Subprocess-based block executor for NC execution.

This module provides NCSubprocessBlockExecutor which has the same interface as
NCBlockExecutor but runs the execution in a subprocess with controlled
PYTHONHASHSEED for deterministic hash ordering.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator

from structlog import get_logger

from hathor.nanocontracts.execution.block_executor import (
    NCBeginBlock,
    NCBeginTransaction,
    NCEndBlock,
    NCEndTransaction,
    NCTxExecutionSkipped,
    ShouldSkipPredicate,
)
from hathor.nanocontracts.execution.effect_serialization import (
    SerializedNCBeginBlock,
    SerializedNCBeginTransaction,
    SerializedNCBlockEffect,
    SerializedNCEndBlock,
    SerializedNCEndTransaction,
    SerializedNCTxExecutionFailure,
    SerializedNCTxExecutionSkipped,
    SerializedNCTxExecutionSuccess,
    SerializedRunner,
)

if TYPE_CHECKING:
    from hathor.nanocontracts.execution.subprocess_pool import NCSubprocessPool
    from hathor.nanocontracts.storage import NCBlockStorage, NCStorageFactory
    from hathor.transaction import Block, Transaction
    from hathor.transaction.storage import TransactionStorage

logger = get_logger()


@dataclass(slots=True, frozen=True)
class NCTxExecutionSuccessSerialized:
    """Execution success with serialized runner data instead of full Runner.

    This is used when execution happened in a subprocess and we only have
    the serialized runner state, not the full Runner object.
    """
    tx: 'Transaction'
    serialized_runner: SerializedRunner


@dataclass(slots=True, frozen=True)
class NCTxExecutionFailureSerialized:
    """Execution failure with serialized runner data instead of full Runner.

    This is used when execution happened in a subprocess and we only have
    the serialized runner state, not the full Runner object.
    """
    tx: 'Transaction'
    serialized_runner: SerializedRunner
    exception_repr: str
    exception_cause_repr: str
    traceback: str


# Extended effect type that includes serialized variants
NCBlockEffectExtended = (
    NCBeginBlock | NCBeginTransaction |
    NCTxExecutionSuccessSerialized | NCTxExecutionFailureSerialized | NCTxExecutionSkipped |
    NCEndTransaction | NCEndBlock
)


class NCSubprocessBlockExecutor:
    """Block executor that runs NC execution in a subprocess.

    This executor has the same interface as NCBlockExecutor.execute_block()
    but delegates execution to a subprocess pool. This allows running with
    a controlled PYTHONHASHSEED for deterministic hash ordering.

    The executor:
    1. Collects transaction hashes that should be skipped (voided)
    2. Sends block execution request to subprocess pool
    3. Receives serialized effects from subprocess
    4. "Hydrates" effects by loading full objects from tx_storage
    5. Yields hydrated effects for processing by NCConsensusBlockExecutor

    Note: Transaction execution results (success/failure) contain
    NCTxExecutionSuccessSerialized/NCTxExecutionFailureSerialized instead of
    the regular NCTxExecutionSuccess/NCTxExecutionFailure with full Runner.
    The NCConsensusBlockExecutor must handle both variants.
    """

    def __init__(
        self,
        *,
        subprocess_pool: 'NCSubprocessPool',
        tx_storage: 'TransactionStorage',
        nc_storage_factory: 'NCStorageFactory',
    ) -> None:
        """Initialize the subprocess block executor.

        Args:
            subprocess_pool: Pool of worker processes for execution
            tx_storage: Transaction storage for hydrating objects (used for
                hydrating effects, not passed to subprocess)
            nc_storage_factory: Factory for NC storage instances
        """
        self._pool = subprocess_pool
        self._tx_storage = tx_storage
        self._nc_storage_factory = nc_storage_factory
        self._log = logger.new()

    def execute_block(
        self,
        block: 'Block',
        *,
        should_skip: ShouldSkipPredicate,
        nc_txs: list['Transaction'],
        parent_root_id: bytes,
    ) -> Iterator[NCBlockEffectExtended]:
        """Execute block via subprocess, yielding hydrated effects.

        This method has the same interface as NCBlockExecutor.execute_block()
        but runs the actual execution in a subprocess. The yielded effects
        have SerializedRunner instead of full Runner for transaction results.

        Args:
            block: The block to execute
            should_skip: Predicate function to determine if a tx should be skipped
            nc_txs: List of NC transactions to execute
            parent_root_id: NC block root ID from parent block's metadata

        Yields:
            NCBlockEffectExtended instances representing each step of execution
        """
        # Track which transactions should be skipped
        skip_hashes: set[bytes] = set()
        for tx in nc_txs:
            if should_skip(tx):
                skip_hashes.add(tx.hash)

        self._log.debug(
            'executing block via subprocess',
            block_hash=block.hash.hex(),
            nc_tx_count=len(nc_txs),
            skip_count=len(skip_hashes),
        )

        # Track block_storage for NCEndBlock hydration
        block_storage: NCBlockStorage | None = None

        # Execute in subprocess and hydrate effects
        for serialized_effect in self._pool.execute_block(
            block=block,
            nc_txs=nc_txs,
            should_skip_tx_hashes=frozenset(skip_hashes),
            parent_root_id=parent_root_id,
        ):
            hydrated = self._hydrate_effect(serialized_effect, block)
            if isinstance(hydrated, NCBeginBlock):
                block_storage = hydrated.block_storage
            elif isinstance(hydrated, NCEndBlock) and block_storage is not None:
                # Use the block_storage from NCBeginBlock for NCEndBlock
                hydrated = NCEndBlock(
                    block=hydrated.block,
                    block_storage=block_storage,
                    final_root_id=hydrated.final_root_id,
                )
            yield hydrated

    def _hydrate_effect(
        self,
        effect: SerializedNCBlockEffect,
        block: 'Block',
    ) -> NCBlockEffectExtended:
        """Hydrate a serialized effect by loading full objects.

        Args:
            effect: Serialized effect from subprocess
            block: The block being executed (for context)

        Returns:
            Hydrated effect with full objects where possible
        """
        if isinstance(effect, SerializedNCBeginBlock):
            # Load sorted NC calls from hashes
            nc_sorted_calls = [
                self._tx_storage.get_transaction(tx_hash)
                for tx_hash in effect.nc_sorted_call_hashes
            ]
            block_storage = self._nc_storage_factory.get_block_storage(effect.parent_root_id)
            return NCBeginBlock(
                block=block,
                parent_root_id=effect.parent_root_id,
                block_storage=block_storage,
                nc_sorted_calls=nc_sorted_calls,  # type: ignore
            )

        elif isinstance(effect, SerializedNCBeginTransaction):
            tx = self._tx_storage.get_transaction(effect.tx_hash)
            return NCBeginTransaction(
                tx=tx,  # type: ignore
                rng_seed=effect.rng_seed,
            )

        elif isinstance(effect, SerializedNCTxExecutionSuccess):
            tx = self._tx_storage.get_transaction(effect.tx_hash)
            return NCTxExecutionSuccessSerialized(
                tx=tx,  # type: ignore
                serialized_runner=effect.runner,
            )

        elif isinstance(effect, SerializedNCTxExecutionFailure):
            tx = self._tx_storage.get_transaction(effect.tx_hash)
            return NCTxExecutionFailureSerialized(
                tx=tx,  # type: ignore
                serialized_runner=effect.runner,
                exception_repr=effect.exception_repr,
                exception_cause_repr=effect.exception_cause_repr,
                traceback=effect.traceback,
            )

        elif isinstance(effect, SerializedNCTxExecutionSkipped):
            tx = self._tx_storage.get_transaction(effect.tx_hash)
            return NCTxExecutionSkipped(tx=tx)  # type: ignore

        elif isinstance(effect, SerializedNCEndTransaction):
            tx = self._tx_storage.get_transaction(effect.tx_hash)
            return NCEndTransaction(tx=tx)  # type: ignore

        elif isinstance(effect, SerializedNCEndBlock):
            # Apply trie writes from subprocess before creating block storage
            if effect.trie_writes:
                self._apply_trie_writes(effect.trie_writes)

            # block_storage will be set by the caller using NCBeginBlock's block_storage
            # Create a temporary block_storage from final_root_id for now
            block_storage = self._nc_storage_factory.get_block_storage(effect.final_root_id)
            return NCEndBlock(
                block=block,
                block_storage=block_storage,
                final_root_id=effect.final_root_id,
            )

        else:
            raise TypeError(f'Unknown serialized effect type: {type(effect)}')

    def _apply_trie_writes(self, trie_writes: dict[bytes, bytes]) -> None:
        """Apply trie writes from subprocess to main process storage.

        Args:
            trie_writes: Dictionary mapping trie keys to serialized node bytes.
        """
        from hathor.nanocontracts.storage.backends import RocksDBNodeTrieStore

        store = self._nc_storage_factory._store
        if isinstance(store, RocksDBNodeTrieStore):
            # Write directly to RocksDB
            for key, node_bytes in trie_writes.items():
                store._db.put((store._cf_key, key), node_bytes)
        else:
            # For non-RocksDB stores, deserialize and store nodes
            from hathor.nanocontracts.storage.node_nc_type import NodeNCType
            from hathor.serialization import Deserializer
            node_nc_type = NodeNCType()
            for key, node_bytes in trie_writes.items():
                deserializer = Deserializer.build_bytes_deserializer(node_bytes)
                node = node_nc_type.deserialize(deserializer)
                deserializer.finalize()
                store[key] = node
