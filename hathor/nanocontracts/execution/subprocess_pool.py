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

"""Subprocess pool for NC execution workers.

This module provides NCSubprocessPool which manages the lifecycle of NC
execution workers running in subprocesses with controlled PYTHONHASHSEED.
"""

from __future__ import annotations

import pickle
import time
from collections import defaultdict
from dataclasses import dataclass, field
from multiprocessing import Process, Queue
from queue import Empty as QueueEmpty
from typing import TYPE_CHECKING, Iterator

from structlog import get_logger

from hathor.nanocontracts.execution.effect_serialization import SerializedNCBlockEffect, deserialize_effect
from hathor.nanocontracts.execution.subprocess_worker import (
    BlockCompleteResponse,
    DataRequest,
    DataResponse,
    EffectResponse,
    ErrorResponse,
    ExecuteBlockCommand,
    ReadyResponse,
    ShutdownCommand,
    WorkerInitConfig,
    worker_entry_point,
)

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.nanocontracts.catalog import NCBlueprintCatalog
    from hathor.nanocontracts.storage import NCStorageFactory
    from hathor.transaction import Block, Transaction
    from hathor.transaction.storage import TransactionStorage

logger = get_logger()


@dataclass
class MessageRecord:
    """Record of a single message received from the worker."""
    message_type: str
    timestamp: float  # Unix timestamp when message was received
    request_data_size: int = 0  # Size of request data in bytes (for DataRequest)
    response_data_size: int = 0  # Size of response data in bytes (for DataResponse sent back)
    processing_time: float = 0.0  # Time taken to process the request in seconds


@dataclass
class CommunicationMetrics:
    """Metrics for communication between main process and worker.

    Tracks message counts, timing, and data sizes for monitoring and debugging.
    """
    # Count of each message type received from worker
    message_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Individual message records for detailed analysis
    message_records: list[MessageRecord] = field(default_factory=list)

    # Aggregated stats per request type
    total_request_data_bytes: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_response_data_bytes: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_processing_time: dict[str, float] = field(default_factory=lambda: defaultdict(float))

    def record_message(
        self,
        message_type: str,
        timestamp: float,
        request_data_size: int = 0,
        response_data_size: int = 0,
        processing_time: float = 0.0,
    ) -> None:
        """Record a message received from the worker."""
        self.message_counts[message_type] += 1
        self.message_records.append(MessageRecord(
            message_type=message_type,
            timestamp=timestamp,
            request_data_size=request_data_size,
            response_data_size=response_data_size,
            processing_time=processing_time,
        ))

        # Update aggregated stats
        if request_data_size > 0:
            self.total_request_data_bytes[message_type] += request_data_size
        if response_data_size > 0:
            self.total_response_data_bytes[message_type] += response_data_size
        if processing_time > 0:
            self.total_processing_time[message_type] += processing_time

    def reset(self) -> None:
        """Reset all metrics."""
        self.message_counts.clear()
        self.message_records.clear()
        self.total_request_data_bytes.clear()
        self.total_response_data_bytes.clear()
        self.total_processing_time.clear()

    def get_summary(self) -> dict:
        """Get a summary of the metrics."""
        return {
            'message_counts': dict(self.message_counts),
            'total_messages': sum(self.message_counts.values()),
            'total_request_bytes': dict(self.total_request_data_bytes),
            'total_response_bytes': dict(self.total_response_data_bytes),
            'total_processing_time': dict(self.total_processing_time),
            'avg_processing_time': {
                msg_type: self.total_processing_time[msg_type] / self.message_counts[msg_type]
                for msg_type in self.total_processing_time
                if self.message_counts[msg_type] > 0
            },
        }


class SubprocessExecutionError(Exception):
    """Error raised when subprocess execution fails."""

    def __init__(self, error_type: str, error_message: str, traceback: str) -> None:
        self.error_type = error_type
        self.error_message = error_message
        self.traceback_str = traceback
        super().__init__(f'{error_type}: {error_message}')


class SubprocessTimeoutError(Exception):
    """Error raised when subprocess execution times out."""
    pass


def _derive_pythonhashseed_from_block(block_hash: bytes) -> int:
    """Derive a PYTHONHASHSEED value from a block hash.

    PYTHONHASHSEED must be an integer in range [0, 2^32).
    We use SHA256 of the block hash and take the last 4 bytes because:
    - Block hashes have leading zeros due to proof-of-work mining
    - SHA256 provides uniform distribution
    - Last bytes avoid any patterns from mining

    Args:
        block_hash: 32-byte block hash

    Returns:
        Integer seed derived from block hash
    """
    import hashlib

    # Hash the block hash to get uniform distribution, then use last 4 bytes
    derived = hashlib.sha256(block_hash).digest()
    return int.from_bytes(derived[-4:], 'big')


class NCSubprocessPool:
    """Pool manager for NC execution workers.

    Manages the lifecycle of subprocess workers that execute NC blocks with
    deterministic PYTHONHASHSEED derived from block hash. The pool:

    1. Spawns a new worker process per block with PYTHONHASHSEED derived from block hash
    2. Sends block execution request to worker with serialized block and transactions
    3. Receives serialized effects from worker
    4. Handles DataRequest messages for token lookups and on-chain blueprints
    5. Handles timeouts and worker crashes

    Note: A new subprocess is spawned per block because PYTHONHASHSEED must be
    set before Python starts, and we derive it from the block hash for
    deterministic but varied execution across blocks.

    Usage:
        pool = NCSubprocessPool(settings, nc_catalog, nc_storage_factory, tx_storage)
        pool.start()

        for effect in pool.execute_block(block, nc_txs, skip_hashes):
            # process effect
            pass

        pool.shutdown()
    """

    DEFAULT_TIMEOUT = 30.0  # seconds
    DEFAULT_POOL_SIZE = 1
    DEFAULT_WORKER_STARTUP_TIMEOUT = 60.0  # seconds

    def __init__(
        self,
        *,
        settings: 'HathorSettings',
        nc_catalog: 'NCBlueprintCatalog',
        nc_storage_factory: 'NCStorageFactory',
        tx_storage: 'TransactionStorage',
        pythonhashseed: int | None = None,  # None means derive from block hash
        timeout: float = DEFAULT_TIMEOUT,
        pool_size: int = DEFAULT_POOL_SIZE,
    ) -> None:
        """Initialize the subprocess pool.

        Args:
            settings: Hathor settings to pass to workers
            nc_catalog: Blueprint catalog to pass to workers
            nc_storage_factory: Factory for NC storage (used to handle trie data requests)
            tx_storage: Transaction storage for handling DataRequest messages
            pythonhashseed: Value for PYTHONHASHSEED in worker processes.
                If None (default), derives from block hash for each block.
            timeout: Timeout in seconds for block execution
            pool_size: Number of worker processes (currently only 1 supported)
        """
        self._log = logger.new()
        self._settings = settings
        self._nc_catalog = nc_catalog
        self._nc_storage_factory = nc_storage_factory
        self._tx_storage = tx_storage
        self._pythonhashseed = pythonhashseed
        self._timeout = timeout
        self._pool_size = pool_size

        # Worker state
        self._worker: Process | None = None
        self._input_queue: Queue | None = None
        self._output_queue: Queue | None = None
        self._started = False

        # Communication metrics
        self._metrics = CommunicationMetrics()

        # Prepare init config (serialized once, reused for restarts)
        self._init_config = WorkerInitConfig(
            settings_pickle=pickle.dumps(settings),
            nc_catalog_pickle=pickle.dumps(nc_catalog),
        )
        self._init_config_bytes = pickle.dumps(self._init_config)

    def start(self) -> None:
        """Start the worker pool.

        If pythonhashseed is fixed (not None), spawns a persistent worker.
        If pythonhashseed is None (derive from block hash), workers are
        spawned per-block in execute_block().
        """
        if self._started:
            return

        self._log.info(
            'starting subprocess pool',
            pythonhashseed=self._pythonhashseed,
            derive_from_block='yes' if self._pythonhashseed is None else 'no',
            pool_size=self._pool_size,
        )

        # Only spawn persistent worker if using fixed pythonhashseed
        if self._pythonhashseed is not None:
            self._spawn_worker(self._pythonhashseed)

        self._started = True

    def shutdown(self) -> None:
        """Shutdown the worker pool gracefully."""
        if not self._started:
            return

        self._log.info('shutting down subprocess pool')
        self._terminate_worker()
        self._started = False

    def _terminate_worker(self) -> None:
        """Terminate the current worker if running."""
        if self._worker is not None and self._worker.is_alive():
            try:
                assert self._input_queue is not None
                self._input_queue.put(ShutdownCommand())
                self._worker.join(timeout=5.0)
                if self._worker.is_alive():
                    self._log.warning('worker did not shutdown gracefully, terminating')
                    self._worker.terminate()
                    self._worker.join(timeout=1.0)
            except Exception as e:
                self._log.error('error shutting down worker', error=str(e))
                if self._worker.is_alive():
                    self._worker.kill()

        # Properly close queues to prevent "Exception ignored in: <Finalize object, dead>"
        # errors during interpreter shutdown. This ensures file descriptors are closed
        # deterministically before Python starts clearing module-level variables.
        if self._input_queue is not None:
            self._input_queue.close()
            self._input_queue.join_thread()
        if self._output_queue is not None:
            self._output_queue.close()
            self._output_queue.join_thread()

        self._worker = None
        self._input_queue = None
        self._output_queue = None

    def _spawn_worker(self, pythonhashseed: int) -> None:
        """Spawn a new worker process with specified PYTHONHASHSEED."""
        self._log.info('spawning worker process', pythonhashseed=pythonhashseed)

        # Create communication queues
        self._input_queue = Queue()
        self._output_queue = Queue()

        # Spawn worker process
        # Note: We use 'spawn' start method implicitly via Process
        # The environment variable must be set before the process starts
        self._worker = Process(
            target=_worker_entry_with_env,
            args=(
                self._input_queue,
                self._output_queue,
                self._init_config_bytes,
                pythonhashseed,
            ),
        )
        self._worker.start()

        # Wait for worker to signal ready, handling DataRequests during startup
        # The worker may request trie data during initialization
        try:
            while True:
                response = self._output_queue.get(timeout=self.DEFAULT_WORKER_STARTUP_TIMEOUT)
                recv_timestamp = time.time()

                if isinstance(response, ReadyResponse):
                    self._metrics.record_message('ReadyResponse', recv_timestamp)
                    self._log.info('worker process ready', pid=self._worker.pid)
                    break
                elif isinstance(response, DataRequest):
                    # Handle data request from worker during startup
                    # Metrics are recorded inside _handle_data_request
                    self._handle_data_request(response, recv_timestamp)
                elif isinstance(response, ErrorResponse):
                    self._metrics.record_message('ErrorResponse', recv_timestamp)
                    raise SubprocessExecutionError(
                        response.error_type,
                        response.error_message,
                        response.traceback,
                    )
                else:
                    raise RuntimeError(f'Unexpected response from worker: {type(response)}')
        except QueueEmpty:
            self._worker.terminate()
            self._cleanup_queues()
            raise SubprocessTimeoutError('Worker failed to start within timeout')
        except BaseException:
            self._cleanup_queues()
            raise

    def _cleanup_queues(self) -> None:
        """Clean up queue resources without terminating worker."""
        if self._input_queue is not None:
            self._input_queue.close()
            self._input_queue.join_thread()
            self._input_queue = None
        if self._output_queue is not None:
            self._output_queue.close()
            self._output_queue.join_thread()
            self._output_queue = None

    def _ensure_worker_alive(self, pythonhashseed: int) -> None:
        """Ensure worker is alive with correct seed, respawn if needed."""
        if self._worker is None or not self._worker.is_alive():
            self._log.warning('worker died, respawning')
            self._spawn_worker(pythonhashseed)

    def execute_block(
        self,
        block: 'Block',
        nc_txs: list['Transaction'],
        should_skip_tx_hashes: frozenset[bytes],
        parent_root_id: bytes,
    ) -> Iterator[SerializedNCBlockEffect]:
        """Execute a block in the subprocess and yield effects.

        Args:
            block: The block to execute
            nc_txs: List of NC transactions in execution order
            should_skip_tx_hashes: Set of tx hashes to skip (voided transactions)
            parent_root_id: NC block root ID from parent block's metadata

        Yields:
            SerializedNCBlockEffect instances for each execution step

        Raises:
            SubprocessExecutionError: If worker reports an error
            SubprocessTimeoutError: If execution times out
        """
        if not self._started:
            raise RuntimeError('Pool not started')

        # Determine pythonhashseed: fixed or derived from block hash
        if self._pythonhashseed is not None:
            # Fixed seed: reuse existing worker
            pythonhashseed = self._pythonhashseed
            self._ensure_worker_alive(pythonhashseed)
        else:
            # Derive from block hash: spawn new worker per block
            pythonhashseed = _derive_pythonhashseed_from_block(block.hash)
            self._log.debug(
                'deriving pythonhashseed from block',
                block_hash=block.hash.hex(),
                pythonhashseed=pythonhashseed,
            )
            # Terminate existing worker (if any) and spawn new one
            self._terminate_worker()
            self._spawn_worker(pythonhashseed)

        assert self._input_queue is not None
        assert self._output_queue is not None

        # Serialize block and transactions
        block_bytes = bytes(block)
        nc_tx_bytes_list = [bytes(tx) for tx in nc_txs]

        # Send execution command
        command = ExecuteBlockCommand(
            block_bytes=block_bytes,
            nc_tx_bytes_list=nc_tx_bytes_list,
            should_skip_tx_hashes=should_skip_tx_hashes,
            parent_root_id=parent_root_id,
            block_height=block.get_height(),
        )
        self._input_queue.put(command)

        # Receive and yield effects until block complete
        while True:
            try:
                response = self._output_queue.get(timeout=self._timeout)
                recv_timestamp = time.time()
            except QueueEmpty:
                # Timeout - kill worker and raise
                self._log.error('worker timeout', block_hash=block.hash.hex())
                if self._worker is not None:
                    self._worker.terminate()
                    self._worker.join(timeout=1.0)
                    if self._worker.is_alive():
                        self._worker.kill()
                self._worker = None
                raise SubprocessTimeoutError(
                    f'Block execution timed out after {self._timeout}s'
                )

            if isinstance(response, EffectResponse):
                self._metrics.record_message('EffectResponse', recv_timestamp)
                yield deserialize_effect(response.effect_data)
            elif isinstance(response, BlockCompleteResponse):
                self._metrics.record_message('BlockCompleteResponse', recv_timestamp)
                break
            elif isinstance(response, DataRequest):
                # Handle data request from worker
                # Metrics are recorded inside _handle_data_request
                self._handle_data_request(response, recv_timestamp)
            elif isinstance(response, ErrorResponse):
                self._metrics.record_message('ErrorResponse', recv_timestamp)
                raise SubprocessExecutionError(
                    response.error_type,
                    response.error_message,
                    response.traceback,
                )
            else:
                self._log.warning('unexpected response', response_type=type(response).__name__)

    def _handle_data_request(self, request: DataRequest, recv_timestamp: float | None = None) -> None:
        """Handle a data request from the worker.

        Fetches the requested data from tx_storage or nc_storage and sends it back
        to the worker.

        Args:
            request: The data request from the worker.
            recv_timestamp: Timestamp when the request was received (for metrics).
        """
        assert self._input_queue is not None

        if recv_timestamp is None:
            recv_timestamp = time.time()

        start_time = time.time()
        response_data: bytes | None = None
        request_data_size = len(request.request_data)

        try:
            if request.request_type == 'trie_get':
                # Get serialized node from NC storage
                key = request.request_data
                try:
                    # Access the underlying store to get raw bytes
                    # The store returns Node objects, but we need the raw serialized bytes
                    from hathor.nanocontracts.storage.backends import RocksDBNodeTrieStore
                    store = self._nc_storage_factory._store
                    if isinstance(store, RocksDBNodeTrieStore):
                        # Get raw bytes directly from RocksDB
                        db = store._db
                        cf_key = store._cf_key
                        response_data = db.get((cf_key, key))
                    else:
                        # For other store types, serialize the node using NodeNCType
                        from hathor.nanocontracts.storage.node_nc_type import NodeNCType
                        from hathor.serialization import Serializer
                        node = store[key]
                        node_nc_type = NodeNCType()
                        serializer = Serializer.build_bytes_serializer()
                        node_nc_type.serialize(serializer, node)
                        response_data = bytes(serializer.finalize())
                except KeyError:
                    response_data = None

            elif request.request_type == 'trie_contains':
                # Check if key exists in NC storage
                key = request.request_data
                store = self._nc_storage_factory._store
                response_data = b'\x01' if key in store else b'\x00'

            elif request.request_type == 'token_creation_tx':
                # Get token creation transaction
                token_uid = request.request_data
                tx = self._tx_storage.get_token_creation_transaction(token_uid)
                response_data = bytes(tx)

            elif request.request_type == 'on_chain_blueprint':
                # Get on-chain blueprint - serialize as bytes, not pickle
                # (pickle fails because dynamically compiled blueprint class can't be pickled)
                from hathor.nanocontracts.types import BlueprintId
                blueprint_id = BlueprintId(request.request_data)
                blueprint = self._tx_storage.get_on_chain_blueprint(blueprint_id)
                response_data = bytes(blueprint)

            elif request.request_type == 'get_transaction':
                # Get transaction by hash (for resolving NC transaction inputs)
                tx_hash = request.request_data
                vertex = self._tx_storage.get_transaction(tx_hash)
                response_data = bytes(vertex)

            else:
                self._log.warning('unknown data request type', request_type=request.request_type)

        except Exception as e:
            self._log.debug(
                'data request failed',
                request_type=request.request_type,
                error=str(e),
            )
            response_data = None

        # Calculate processing time and response size
        processing_time = time.time() - start_time
        response_data_size = len(response_data) if response_data else 0

        # Record metrics for this data request
        message_type = f'DataRequest:{request.request_type}'
        self._metrics.record_message(
            message_type=message_type,
            timestamp=recv_timestamp,
            request_data_size=request_data_size,
            response_data_size=response_data_size,
            processing_time=processing_time,
        )

        # Send response back to worker
        response = DataResponse(
            request_id=request.request_id,
            response_data=response_data or b'',
        )
        self._input_queue.put(response)

    @property
    def is_alive(self) -> bool:
        """Check if the worker process is alive."""
        return self._worker is not None and self._worker.is_alive()

    @property
    def metrics(self) -> CommunicationMetrics:
        """Get the communication metrics."""
        return self._metrics

    def reset_metrics(self) -> None:
        """Reset the communication metrics."""
        self._metrics.reset()

    def get_metrics_summary(self) -> dict:
        """Get a summary of the communication metrics."""
        return self._metrics.get_summary()


def _worker_entry_with_env(
    input_queue: Queue,
    output_queue: Queue,
    init_config_bytes: bytes,
    pythonhashseed: int,
) -> None:
    """Worker entry point that sets PYTHONHASHSEED.

    This function is the actual target for multiprocessing.Process.
    It sets PYTHONHASHSEED in the subprocess environment before
    calling the actual worker entry point.

    Note: PYTHONHASHSEED must be set before Python interprets any code
    that depends on hash ordering. Since this function runs after the
    Python interpreter starts, setting it here won't affect all hash
    behavior. For full determinism, the subprocess should be started
    with the environment variable already set.

    Args:
        input_queue: Queue for receiving commands
        output_queue: Queue for sending responses
        init_config_bytes: Pickled WorkerInitConfig
        pythonhashseed: Value for PYTHONHASHSEED
    """
    import os
    os.environ['PYTHONHASHSEED'] = str(pythonhashseed)

    # Now call the actual worker entry point
    worker_entry_point(input_queue, output_queue, init_config_bytes)
