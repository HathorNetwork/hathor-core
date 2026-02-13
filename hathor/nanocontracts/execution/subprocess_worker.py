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

"""Subprocess worker for NC execution with controlled PYTHONHASHSEED.

This module contains the worker that runs in a subprocess with PYTHONHASHSEED
set to ensure deterministic dict iteration order, which is critical for
consensus correctness in nano contract execution.

The worker receives block execution requests via a Queue, executes them using
NCBlockExecutor, and streams serialized effects back via another Queue.
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass
from multiprocessing import Queue
from typing import TYPE_CHECKING, Any

from structlog import get_logger

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.nanocontracts.runner.runner import RunnerFactory
    from hathor.nanocontracts.storage import NCStorageFactory

logger = get_logger()

# Default timeout for queue operations in seconds
DEFAULT_QUEUE_TIMEOUT = 5.0


@dataclass(slots=True, frozen=True)
class WorkerInitConfig:
    """Configuration data sent to worker for initialization.

    This contains all the parameters needed to recreate the executor
    infrastructure in the subprocess.
    """
    settings_pickle: bytes
    nc_catalog_pickle: bytes  # Pickled NCBlueprintCatalog


@dataclass(slots=True, frozen=True)
class WorkerCommand:
    """Base class for commands sent to worker."""
    pass


@dataclass(slots=True, frozen=True)
class ExecuteBlockCommand(WorkerCommand):
    """Command to execute a block.

    The block and its NC transactions are serialized and sent through the Queue
    so the worker doesn't need to read them from tx_storage. This avoids issues
    with read-only database snapshots not seeing recently written data.
    """
    block_bytes: bytes  # Serialized block
    nc_tx_bytes_list: list[bytes]  # Serialized NC transactions in execution order
    should_skip_tx_hashes: frozenset[bytes]
    parent_root_id: bytes  # NC block root ID from parent block's metadata
    block_height: int  # Block height for creating BlockStaticMetadata in subprocess


@dataclass(slots=True, frozen=True)
class ShutdownCommand(WorkerCommand):
    """Command to shutdown the worker."""
    pass


@dataclass(slots=True, frozen=True)
class WorkerResponse:
    """Base class for responses from worker."""
    pass


@dataclass(slots=True, frozen=True)
class EffectResponse(WorkerResponse):
    """Response containing a serialized effect."""
    effect_data: dict[str, Any]


@dataclass(slots=True, frozen=True)
class ErrorResponse(WorkerResponse):
    """Response indicating an error occurred."""
    error_type: str
    error_message: str
    traceback: str


@dataclass(slots=True, frozen=True)
class ReadyResponse(WorkerResponse):
    """Response indicating worker is ready."""
    pass


@dataclass(slots=True, frozen=True)
class BlockCompleteResponse(WorkerResponse):
    """Response indicating block execution is complete."""
    pass


@dataclass(slots=True, frozen=True)
class DataRequest(WorkerResponse):
    """Request from worker to main process for data.

    Used for token lookups and on-chain blueprints that require
    access to the main process's tx_storage.
    """
    request_id: int
    request_type: str  # 'token_creation_tx' or 'on_chain_blueprint'
    request_data: bytes  # token_uid or blueprint_id


@dataclass(slots=True, frozen=True)
class DataResponse(WorkerCommand):
    """Response from main process with requested data."""
    request_id: int
    response_data: bytes  # Serialized response (None if not found)


class MinimalBlockStorage:
    """Minimal storage that provides the block and transactions being executed.

    This is used to set `vertex.storage` on transactions in the subprocess so
    that Context.create_from_vertex() can access the block via storage.get_block()
    and VertexData can resolve input transactions.
    """

    def __init__(
        self,
        block: 'Any',
        settings: 'HathorSettings',
        request_func: 'Any',
        transactions: list['Any'] | None = None,
    ) -> None:
        """Initialize with the block being executed and optional transactions.

        Args:
            block: The block being executed.
            settings: HathorSettings for deserializing transactions.
            request_func: Function to request data from main process.
            transactions: Optional list of transactions to cache locally.
        """
        self._block = block
        self._settings = settings
        self._request_func = request_func
        self._transactions: dict[bytes, 'Any'] = {}
        if transactions:
            for tx in transactions:
                self._transactions[tx.hash] = tx

    def add_transaction(self, tx: 'Any') -> None:
        """Add a transaction to the storage."""
        self._transactions[tx.hash] = tx

    def get_block(self, block_hash: bytes) -> 'Any':
        """Return the block if the hash matches, otherwise raise."""
        if block_hash == self._block.hash:
            return self._block
        raise KeyError(f'Block not found: {block_hash.hex()}')

    def get_transaction(self, tx_hash: bytes) -> 'Any':
        """Return a transaction, fetching from main process if needed."""
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist
        from hathor.transaction.vertex_parser import VertexParser

        # Check local cache first
        if tx_hash in self._transactions:
            return self._transactions[tx_hash]

        # Request from main process
        response_data = self._request_func('get_transaction', tx_hash)
        if response_data is None:
            raise TransactionDoesNotExist(f'Transaction not found: {tx_hash.hex()}')

        # Deserialize and cache
        vertex_parser = VertexParser(settings=self._settings)
        tx = vertex_parser.deserialize(response_data)
        self._transactions[tx_hash] = tx
        return tx


class SubprocessTxStorageProxy:
    """Lightweight proxy for tx_storage in subprocess.

    This proxy:
    - Uses local nc_catalog for blueprint lookups
    - Sends DataRequest to main process for token creation transactions
    - Sends DataRequest to main process for on-chain blueprints (rare case)

    This avoids the need for the subprocess to have direct access to tx_storage,
    which would require read-only database access and RocksDB secondary instances.
    """

    def __init__(
        self,
        nc_catalog: 'Any',
        settings: 'HathorSettings',
        request_func: 'Any',
    ) -> None:
        """Initialize the proxy.

        Args:
            nc_catalog: The NCBlueprintCatalog for local blueprint lookups.
            settings: HathorSettings for creating transactions.
            request_func: Function to request data from main process.
                         Signature: (request_type: str, request_data: bytes) -> bytes | None
        """
        from hathor.nanocontracts.catalog import NCBlueprintCatalog

        self.nc_catalog: NCBlueprintCatalog = nc_catalog
        self._settings = settings
        self._request_func = request_func
        self._log = logger.new()

    def get_blueprint_class(self, blueprint_id: bytes) -> 'Any':
        """Get a blueprint class by ID.

        First tries the local catalog, then requests from main process.
        """
        from hathor.nanocontracts.types import BlueprintId

        # Try local catalog first
        if blueprint_class := self.nc_catalog.get_blueprint_class(BlueprintId(blueprint_id)):
            return blueprint_class

        # Request on-chain blueprint from main process
        self._log.debug('requesting on-chain blueprint from main process', blueprint_id=blueprint_id.hex())
        response_data = self._request_func('on_chain_blueprint', blueprint_id)
        if response_data is None:
            from hathor.nanocontracts.exception import BlueprintDoesNotExist
            raise BlueprintDoesNotExist(blueprint_id.hex())

        # Deserialize the on-chain blueprint from bytes
        from hathor.nanocontracts import OnChainBlueprint
        from hathor.transaction.vertex_parser import VertexParser
        vertex_parser = VertexParser(settings=self._settings)
        on_chain_blueprint = vertex_parser.deserialize(response_data)
        assert isinstance(on_chain_blueprint, OnChainBlueprint)
        return on_chain_blueprint.get_blueprint_class()

    def get_token_creation_transaction(self, token_uid: bytes) -> 'Any':
        """Get a token creation transaction by token UID.

        Always requests from main process since we don't have tx_storage.
        """
        self._log.debug('requesting token creation tx from main process', token_uid=token_uid.hex())
        response_data = self._request_func('token_creation_tx', token_uid)
        if response_data is None:
            from hathor.transaction.storage.exceptions import TransactionDoesNotExist
            raise TransactionDoesNotExist(token_uid.hex())

        # Deserialize the token creation transaction
        from hathor.transaction.vertex_parser import VertexParser
        vertex_parser = VertexParser(settings=self._settings)
        tx = vertex_parser.deserialize(response_data)
        return tx


class NCSubprocessWorker:
    """Worker that executes NC blocks in a subprocess.

    This worker runs in a subprocess with a controlled PYTHONHASHSEED value
    to ensure deterministic dict iteration order during nano contract execution.

    The worker:
    1. Initializes with NC catalog and RocksDB access (for NC state only)
    2. Receives block execution requests via input_queue with serialized block/txs
    3. Executes blocks using NCBlockExecutor (pure execution)
    4. Sends serialized effects via output_queue
    5. Requests data from main process via DataRequest/DataResponse pattern
    """

    def __init__(
        self,
        input_queue: Queue,
        output_queue: Queue,
        init_config: WorkerInitConfig,
    ) -> None:
        """Initialize the worker.

        Args:
            input_queue: Queue to receive commands from main process
            output_queue: Queue to send responses to main process
            init_config: Configuration for initializing executor infrastructure
        """
        self._input_queue = input_queue
        self._output_queue = output_queue
        self._init_config = init_config
        self._log = logger.new()
        self._settings: HathorSettings | None = None
        self._nc_catalog: Any = None  # NCBlueprintCatalog
        self._tx_storage_proxy: SubprocessTxStorageProxy | None = None
        self._nc_storage_factory: NCStorageFactory | None = None
        self._runner_factory: RunnerFactory | None = None
        self._block_executor: Any = None  # NCBlockExecutor
        self._request_id_counter: int = 0

    def _initialize(self) -> None:
        """Initialize the executor infrastructure.

        This creates a minimal execution environment without tx_storage access.
        Instead:
        - nc_catalog is deserialized from the init config
        - A tx_storage proxy handles blueprint and token lookups via DataRequest
        - NC state storage (PatriciaTrie) uses proxy storage that requests
          trie data from the main process (no RocksDB access in subprocess)
        """
        import os
        import pickle

        from hathor.nanocontracts.execution.block_executor import NCBlockExecutor
        from hathor.nanocontracts.runner.runner import RunnerFactory
        from hathor.nanocontracts.sorter.timestamp_sorter import timestamp_nc_calls_sorter
        from hathor.nanocontracts.storage.proxy_store import NCProxyStorageFactory
        from hathor.reactor import initialize_global_reactor

        self._log.info(
            'initializing subprocess worker',
            pythonhashseed=os.environ.get('PYTHONHASHSEED'),
        )

        # Deserialize settings
        self._settings = pickle.loads(self._init_config.settings_pickle)

        # Deserialize nc_catalog
        self._nc_catalog = pickle.loads(self._init_config.nc_catalog_pickle)

        # Initialize reactor for the subprocess
        reactor = initialize_global_reactor()

        # Create NC storage factory using proxy that requests data from main process
        # This avoids RocksDB locking/blocking issues in subprocess
        self._nc_storage_factory = NCProxyStorageFactory(
            request_func=self._request_data_from_main,
        )

        # Create tx_storage proxy for blueprint and token lookups
        self._tx_storage_proxy = SubprocessTxStorageProxy(
            nc_catalog=self._nc_catalog,
            settings=self._settings,
            request_func=self._request_data_from_main,
        )

        # Create runner factory with the proxy
        self._runner_factory = RunnerFactory(
            reactor=reactor,
            settings=self._settings,
            tx_storage=self._tx_storage_proxy,  # type: ignore[arg-type]
            nc_storage_factory=self._nc_storage_factory,
        )

        # Create block executor
        self._block_executor = NCBlockExecutor(
            settings=self._settings,
            runner_factory=self._runner_factory,
            nc_storage_factory=self._nc_storage_factory,
            nc_calls_sorter=timestamp_nc_calls_sorter,
        )

        self._log.info('subprocess worker initialized')

    def _request_data_from_main(self, request_type: str, request_data: bytes) -> bytes | None:
        """Request data from the main process.

        Sends a DataRequest and waits for DataResponse.

        Returns:
            The response data bytes, or None if the data was not found.

        Raises:
            TimeoutError: If the main process doesn't respond within timeout.
        """
        from queue import Empty as QueueEmpty

        self._request_id_counter += 1
        request_id = self._request_id_counter

        # Send request
        request = DataRequest(
            request_id=request_id,
            request_type=request_type,
            request_data=request_data,
        )
        self._output_queue.put(request)

        # Wait for response with timeout
        while True:
            try:
                response = self._input_queue.get(timeout=DEFAULT_QUEUE_TIMEOUT)
            except QueueEmpty:
                self._log.error(
                    'timeout waiting for data response from main process',
                    request_type=request_type,
                    request_id=request_id,
                )
                raise TimeoutError(
                    f'Timeout waiting for data response: {request_type} (request_id={request_id})'
                )

            if isinstance(response, DataResponse) and response.request_id == request_id:
                # Empty bytes means not found
                if not response.response_data:
                    return None
                return response.response_data
            elif isinstance(response, ShutdownCommand):
                raise RuntimeError('Shutdown received while waiting for data response')
            else:
                # Put other commands back and keep waiting
                self._log.warning('unexpected command while waiting for data response',
                                  command_type=type(response).__name__)
                # This shouldn't happen in normal operation
                raise RuntimeError(f'Unexpected command: {type(response).__name__}')

    def run(self) -> None:
        """Main worker loop."""
        from queue import Empty as QueueEmpty

        try:
            self._initialize()
            self._output_queue.put(ReadyResponse())

            while True:
                try:
                    command = self._input_queue.get(timeout=DEFAULT_QUEUE_TIMEOUT)
                except QueueEmpty:
                    # No command received, keep waiting
                    continue

                if isinstance(command, ShutdownCommand):
                    self._log.info('subprocess worker shutting down')
                    break
                elif isinstance(command, ExecuteBlockCommand):
                    self._execute_block(command)
                else:
                    self._log.warning('unknown command', command_type=type(command).__name__)

        except Exception as e:
            import traceback
            self._output_queue.put(ErrorResponse(
                error_type=type(e).__name__,
                error_message=str(e),
                traceback=traceback.format_exc(),
            ))
            raise
        finally:
            # Close queue references to prevent "Exception ignored in: <Finalize object, dead>"
            # errors during interpreter shutdown in the subprocess.
            if self._input_queue is not None:
                self._input_queue.close()
            if self._output_queue is not None:
                self._output_queue.close()

    def _execute_block(self, command: ExecuteBlockCommand) -> None:
        """Execute a block and stream effects.

        The block and NC transactions are deserialized from the command,
        avoiding the need to read from tx_storage.

        For NCTxExecutionSuccess and NCEndBlock, commits storage to RocksDB
        before serializing. This ensures root IDs are valid and the main
        process doesn't need to re-commit.
        """
        from hathor.nanocontracts.execution.block_executor import NCEndBlock, NCTxExecutionSuccess
        from hathor.nanocontracts.execution.effect_serialization import serialize_effect
        from hathor.transaction import Block
        from hathor.transaction.vertex_parser import VertexParser

        try:
            assert self._settings is not None
            assert self._block_executor is not None

            # Create vertex parser for deserializing block and transactions
            vertex_parser = VertexParser(settings=self._settings)

            # Deserialize the block
            block = vertex_parser.deserialize(command.block_bytes)
            assert isinstance(block, Block)

            # Set block's static metadata so get_height() works
            # We create a minimal BlockStaticMetadata with just the height
            from hathor.transaction.static_metadata import BlockStaticMetadata
            block_static_metadata = BlockStaticMetadata(
                height=command.block_height,
                min_height=0,  # Not used in NC execution
                feature_activation_bit_counts=[],  # Not used in NC execution
                feature_states={},  # Not used in NC execution
            )
            block.set_static_metadata(block_static_metadata)

            # Create minimal storage to provide the block for context creation
            # and to fetch parent transactions when needed
            minimal_storage = MinimalBlockStorage(
                block=block,
                settings=self._settings,
                request_func=self._request_data_from_main,
            )

            # Deserialize NC transactions and set their first_block metadata
            # Since we're executing a block, all NC transactions in it are being confirmed by this block
            nc_txs = []
            for tx_bytes in command.nc_tx_bytes_list:
                tx = vertex_parser.deserialize(tx_bytes)
                # Set storage so Context.create_from_vertex() can access the block
                tx.storage = minimal_storage  # type: ignore[assignment]
                # Set first_block in metadata so the runner can create proper context
                tx_meta = tx.get_metadata(use_storage=False)
                tx_meta.first_block = block.hash
                nc_txs.append(tx)

            # Create should_skip predicate from provided hashes
            skip_hashes = command.should_skip_tx_hashes

            def should_skip(tx: Any) -> bool:
                return tx.hash in skip_hashes

            # Execute block with pre-loaded transactions
            for effect in self._block_executor.execute_block(
                block,
                should_skip=should_skip,
                nc_txs=nc_txs,
                parent_root_id=command.parent_root_id,
            ):
                # Commit storage before serializing success/end effects
                # This ensures root IDs are valid for the main process
                if isinstance(effect, NCTxExecutionSuccess):
                    # Commit runner's contract storages to RocksDB
                    effect.runner.commit()
                elif isinstance(effect, NCEndBlock):
                    # Commit block storage to RocksDB
                    effect.block_storage.commit()

                effect_data = serialize_effect(effect)

                # For NCEndBlock, include the cached trie writes from proxy storage
                if isinstance(effect, NCEndBlock):
                    from hathor.nanocontracts.storage.proxy_store import NCProxyStorageFactory
                    if isinstance(self._nc_storage_factory, NCProxyStorageFactory):
                        trie_writes = self._nc_storage_factory.get_proxy_store().get_cached_writes()
                        # Convert to hex strings for JSON serialization
                        effect_data['trie_writes'] = {
                            k.hex(): v.hex() for k, v in trie_writes.items()
                        }

                self._output_queue.put(EffectResponse(effect_data=effect_data))

            self._output_queue.put(BlockCompleteResponse())

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            self._output_queue.put(ErrorResponse(
                error_type=type(e).__name__,
                error_message=str(e),
                traceback=tb,
            ))


def worker_entry_point(
    input_queue: Queue,
    output_queue: Queue,
    init_config_bytes: bytes,
) -> None:
    """Entry point for subprocess worker.

    This function is called when the subprocess starts. It unpickles the
    init config and runs the worker.

    Args:
        input_queue: Queue for receiving commands
        output_queue: Queue for sending responses
        init_config_bytes: Pickled WorkerInitConfig
    """
    init_config = pickle.loads(init_config_bytes)
    worker = NCSubprocessWorker(input_queue, output_queue, init_config)
    worker.run()
