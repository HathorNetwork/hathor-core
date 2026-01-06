# Copyright 2021 Hathor Labs
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

import sys
import time
from cProfile import Profile
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Iterator, Optional, Union

from hathorlib.base_transaction import tx_or_block_from_bytes as lib_tx_or_block_from_bytes
from structlog import get_logger
from twisted.internet import defer
from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall
from twisted.python.threadpool import ThreadPool

from hathor.checkpoint import Checkpoint
from hathor.conf.settings import HathorSettings
from hathor.consensus import ConsensusAlgorithm
from hathor.consensus.poa import PoaBlockProducer
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.event.event_manager import EventManager
from hathor.exception import (
    BlockTemplateTimestampError,
    DoubleSpendingError,
    InitializationError,
    InvalidNewTransaction,
    NonStandardTxError,
    RewardLockedError,
    SpendingVoidedError,
)
from hathor.execution_manager import ExecutionManager
from hathor.feature_activation.bit_signaling_service import BitSignalingService
from hathor.feature_activation.feature_service import FeatureService
from hathor.mining import BlockTemplate, BlockTemplates
from hathor.mining.cpu_mining_service import CpuMiningService
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.runner.runner import RunnerFactory
from hathor.nanocontracts.storage import NCBlockStorage, NCContractStorage
from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.peer_id import PeerId
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.reactor import ReactorProtocol as Reactor
from hathor.reward_lock import is_spent_reward_locked
from hathor.stratum import StratumFactory
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, Transaction, TxVersion
from hathor.transaction.json_serializer import VertexJsonSerializer
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.transaction_storage import TransactionStorage
from hathor.transaction.storage.tx_allow_scope import TxAllowScope
from hathor.transaction.vertex_parser import VertexParser
from hathor.types import Address, VertexId
from hathor.util import EnvironmentInfo, LogDuration, Random
from hathor.utils.weight import calculate_min_significant_weight, weight_to_work
from hathor.verification.verification_service import VerificationService
from hathor.vertex_handler import VertexHandler
from hathor.wallet import BaseWallet

if TYPE_CHECKING:
    from hathor.websocket.factory import HathorAdminWebsocketFactory

logger = get_logger()


class HathorManager:
    """ HathorManager manages the node with the help of other specialized classes.

    Its primary objective is to handle DAG-related matters, ensuring that the DAG is always valid and connected.
    """

    class NodeState(Enum):
        # This node is still initializing
        INITIALIZING = 'INITIALIZING'

        # This node is ready to establish new connections, sync, and exchange transactions.
        READY = 'READY'

    class UnhealthinessReason(str, Enum):
        NO_RECENT_ACTIVITY = "Node doesn't have recent blocks"
        NO_SYNCED_PEER = "Node doesn't have a synced peer"

    # This is the interval to be used by the task to check if the node is synced
    CHECK_SYNC_STATE_INTERVAL = 30  # seconds

    def __init__(
        self,
        reactor: Reactor,
        *,
        settings: HathorSettings,
        pubsub: PubSubManager,
        consensus_algorithm: ConsensusAlgorithm,
        daa: DifficultyAdjustmentAlgorithm,
        peer: PrivatePeer,
        tx_storage: TransactionStorage,
        p2p_manager: ConnectionsManager,
        event_manager: EventManager,
        bit_signaling_service: BitSignalingService,
        verification_service: VerificationService,
        cpu_mining_service: CpuMiningService,
        execution_manager: ExecutionManager,
        vertex_handler: VertexHandler,
        vertex_parser: VertexParser,
        runner_factory: RunnerFactory,
        feature_service: FeatureService,
        vertex_json_serializer: VertexJsonSerializer,
        hostname: Optional[str] = None,
        wallet: Optional[BaseWallet] = None,
        capabilities: Optional[list[str]] = None,
        checkpoints: Optional[list[Checkpoint]] = None,
        rng: Optional[Random] = None,
        environment_info: Optional[EnvironmentInfo] = None,
        enable_event_queue: bool = False,
        poa_block_producer: PoaBlockProducer | None = None,
        # Websocket factory
        websocket_factory: Optional['HathorAdminWebsocketFactory'] = None
    ) -> None:
        """
        :param reactor: Twisted reactor which handles the mainloop and the events.
        :param peer: Peer object, with peer-id of this node.

        :param tx_storage: Required storage backend.
        :type tx_storage: :py:class:`hathor.transaction.storage.transaction_storage.TransactionStorage`
        """
        from hathor.metrics import Metrics

        if event_manager.get_event_queue_state() is True and not enable_event_queue:
            raise InitializationError(
                'Cannot start manager without event queue feature, as it was enabled in the previous startup. '
                'Either enable it, or use the reset-event-queue CLI command to remove all event-related data'
            )

        self._execution_manager = execution_manager
        self._settings = settings
        self.daa = daa
        self._cmd_path: Optional[str] = None

        self.log = logger.new()

        if rng is None:
            rng = Random()
        self.rng = rng

        self.reactor = reactor
        add_system_event_trigger = getattr(self.reactor, 'addSystemEventTrigger', None)
        if add_system_event_trigger is not None:
            add_system_event_trigger('after', 'shutdown', self.stop)

        self.state: Optional[HathorManager.NodeState] = None

        # Profiler info
        self.profiler: Optional[Profile] = None
        self.is_profiler_running: bool = False
        self.profiler_last_start_time: float = 0

        # Hostname, used to be accessed by other peers.
        self.hostname = hostname

        # Remote address, which can be different from local address.
        self.remote_address = None

        self.my_peer = peer
        self.network = settings.NETWORK_NAME

        self.is_started: bool = False

        # XXX: first checkpoint must be genesis (height=0)
        self.checkpoints: list[Checkpoint] = checkpoints or []
        self.checkpoints_ready: list[bool] = [False] * len(self.checkpoints)
        if not self.checkpoints or self.checkpoints[0].height > 0:
            self.checkpoints.insert(0, Checkpoint(0, settings.GENESIS_BLOCK_HASH))
            self.checkpoints_ready.insert(0, True)
        else:
            self.checkpoints_ready[0] = True

        # XXX Should we use a singleton or a new PeerStorage? [msbrogli 2018-08-29]
        self.pubsub = pubsub
        self.tx_storage = tx_storage
        self.tx_storage.pubsub = self.pubsub

        self._event_manager = event_manager
        self._event_manager.save_event_queue_state(enable_event_queue)
        self._enable_event_queue = enable_event_queue

        self._bit_signaling_service = bit_signaling_service
        self.verification_service = verification_service
        self.cpu_mining_service = cpu_mining_service

        self.consensus_algorithm = consensus_algorithm

        self.connections = p2p_manager
        self.vertex_handler = vertex_handler
        self.vertex_parser = vertex_parser
        self.runner_factory = runner_factory
        self.feature_service = feature_service
        self.vertex_json_serializer = vertex_json_serializer

        self.websocket_factory = websocket_factory

        self.metrics = Metrics(
            pubsub=self.pubsub,
            avg_time_between_blocks=settings.AVG_TIME_BETWEEN_BLOCKS,
            connections=self.connections,
            tx_storage=self.tx_storage,
            reactor=self.reactor,
            websocket_factory=self.websocket_factory,
        )

        self.wallet = wallet
        if self.wallet:
            self.wallet.pubsub = self.pubsub
            self.wallet.reactor = self.reactor

        # It will be inject later by the builder.
        # XXX Remove this attribute after all dependencies are cleared.
        self.stratum_factory: Optional[StratumFactory] = None

        self._allow_mining_without_peers = False

        # Thread pool used to resolve pow when sending tokens
        self.pow_thread_pool = ThreadPool(minthreads=0, maxthreads=settings.MAX_POW_THREADS, name='Pow thread pool')

        # List of whitelisted peers
        self.peers_whitelist: list[PeerId] = []

        # List of capabilities of the peer
        if capabilities is not None:
            self.capabilities = capabilities
        else:
            self.capabilities = self.get_default_capabilities()

        # This is included in some logs to provide more context
        self.environment_info = environment_info

        self.poa_block_producer = poa_block_producer

        # Task that will count the total sync time
        self.lc_check_sync_state = LoopingCall(self.check_sync_state)
        self.lc_check_sync_state.clock = self.reactor
        self.lc_check_sync_state_interval = self.CHECK_SYNC_STATE_INTERVAL

    def get_default_capabilities(self) -> list[str]:
        """Return the default capabilities for this manager."""
        default_capabilities = [
            self._settings.CAPABILITY_WHITELIST,
            self._settings.CAPABILITY_SYNC_VERSION,
            self._settings.CAPABILITY_GET_BEST_BLOCKCHAIN,
            self._settings.CAPABILITY_IPV6,
        ]
        # only include nano-state if ENABLE_NANO_CONTRACTS is true (enabled/feature_activation)
        if self._settings.ENABLE_NANO_CONTRACTS:
            default_capabilities.append(self._settings.CAPABILITY_NANO_STATE)
        return default_capabilities

    def start(self) -> None:
        """ A factory must be started only once. And it is usually automatically started.
        """
        if self.is_started:
            raise Exception('HathorManager is already started')
        self.is_started = True

        self.log.info('start manager', network=self.network)

        if self.tx_storage.is_full_node_crashed():
            self.log.error(
                'Error initializing node. The last time you executed your full node it wasn\'t stopped correctly. '
                'The storage is not reliable anymore and, because of that, you must remove your storage and do a '
                'full sync (either from scratch or from a snapshot).'
            )
            sys.exit(-1)

        # If self.tx_storage.is_running_manager() is True, the last time the node was running it had a sudden crash
        # because of that, we must run a sync from scratch or from a snapshot.
        # The metadata is the only piece of the storage that may be wrong, not the blocks and transactions.
        if self.tx_storage.is_running_manager():
            self.log.error(
                'Error initializing node. The last time you executed your full node it wasn\'t stopped correctly. '
                'The storage is not reliable anymore and, because of that you must remove your storage and do a'
                'sync from scratch or from a snapshot.'
            )
            sys.exit(-1)

        if self._enable_event_queue:
            self._event_manager.start(str(self.my_peer.id))

        self.state = self.NodeState.INITIALIZING
        self.pubsub.publish(HathorEvents.MANAGER_ON_START)
        self._event_manager.load_started()
        self.pow_thread_pool.start()

        # Disable get transaction lock when initializing components
        self.tx_storage.disable_lock()
        # Open scope for initialization.
        self.tx_storage.set_allow_scope(TxAllowScope.VALID | TxAllowScope.PARTIAL | TxAllowScope.INVALID)
        self._initialize_components()
        self.tx_storage.set_allow_scope(TxAllowScope.VALID)
        self.tx_storage.enable_lock()

        # Preferably start before self.metrics
        if self.websocket_factory:
            self.websocket_factory.start()

        # Metric starts to capture data
        self.metrics.start()

        self.connections.start()

        self.start_time = time.time()

        self.lc_check_sync_state.start(self.lc_check_sync_state_interval, now=False)

        if self.wallet:
            self.wallet.start()

        if self.stratum_factory:
            self.stratum_factory.start()

        if self.poa_block_producer:
            self.poa_block_producer.start()

        # Start running
        self.tx_storage.start_running_manager(self._execution_manager)

    def stop(self) -> Deferred:
        if not self.is_started:
            raise Exception('HathorManager is already stopped')
        self.is_started = False

        waits = []

        self.log.info('stop manager')
        self.tx_storage.stop_running_manager()
        self.connections.stop()
        self.pubsub.publish(HathorEvents.MANAGER_ON_STOP)
        if self.pow_thread_pool.started:
            self.pow_thread_pool.stop()

        # Metric stops to capture data
        self.metrics.stop()

        if self.websocket_factory:
            self.websocket_factory.stop()

        if self.lc_check_sync_state.running:
            self.lc_check_sync_state.stop()

        if self.wallet:
            self.wallet.stop()

        if self.stratum_factory:
            wait_stratum = self.stratum_factory.stop()
            if wait_stratum:
                waits.append(wait_stratum)

        if self._enable_event_queue:
            self._event_manager.stop()

        if self.poa_block_producer:
            self.poa_block_producer.stop()

        self.tx_storage.flush()

        return defer.DeferredList(waits)

    def start_profiler(self, *, reset: bool = False) -> None:
        """
        Start profiler. It can be activated from a web resource, as well.
        """
        if reset or not self.profiler:
            self.profiler = Profile()
        self.profiler.enable()
        self.is_profiler_running = True
        self.profiler_last_start_time = self.reactor.seconds()

    def stop_profiler(self, save_to: Optional[str] = None) -> None:
        """
        Stop the profile and optionally save the results for future analysis.

        :param save_to: path where the results will be saved
        :type save_to: str
        """
        assert self.profiler is not None
        self.profiler.disable()
        self.is_profiler_running = False
        if save_to:
            self.profiler.dump_stats(save_to)

    def get_nc_runner(self, block: Block) -> Runner:
        """Return a contract runner for a given block."""
        nc_storage_factory = self.consensus_algorithm.nc_storage_factory
        block_storage = nc_storage_factory.get_block_storage_from_block(block)
        return self.runner_factory.create(block_storage=block_storage)

    def get_best_block_nc_runner(self) -> Runner:
        """Return a contract runner for the best block."""
        best_block = self.tx_storage.get_best_block()
        return self.get_nc_runner(best_block)

    def get_nc_block_storage(self, block: Block) -> NCBlockStorage:
        """Return the nano block storage for a given block."""
        return self.consensus_algorithm.nc_storage_factory.get_block_storage_from_block(block)

    def get_nc_storage(self, block: Block, nc_id: VertexId) -> NCContractStorage:
        """Return a contract storage with the contract state at a given block."""
        from hathor.nanocontracts.types import ContractId, VertexId as NCVertexId
        block_storage = self.get_nc_block_storage(block)
        return block_storage.get_contract_storage(ContractId(NCVertexId(nc_id)))

    def get_best_block_nc_storage(self, nc_id: VertexId) -> NCContractStorage:
        """Return a contract storage with the contract state at the best block."""
        best_block = self.tx_storage.get_best_block()
        return self.get_nc_storage(best_block, nc_id)

    def _initialize_components(self) -> None:
        """You are not supposed to run this method manually. You should run `doStart()` to initialize the
        manager.

        This method runs through all transactions, verifying them and updating our wallet.
        """
        self.log.info('initialize')
        t0 = time.time()
        t1 = t0

        if self.wallet:
            self.wallet._manually_initialize()

        self.tx_storage.pre_init()
        assert self.tx_storage.indexes is not None

        self._bit_signaling_service.start()

        started_at = int(time.time())
        last_started_at = self.tx_storage.get_last_started_at()
        if last_started_at >= started_at:
            # XXX: although last_started_at==started_at is not _techincally_ to the future, it's strange enough to
            #      deserve a warning, but not special enough to deserve a customized message IMO
            self.log.warn('The last started time is to the future of the current time',
                          started_at=started_at, last_started_at=last_started_at)

        self._verify_soft_voided_txs()
        self.tx_storage.indexes._manually_initialize(self.tx_storage)

        # Verify if all checkpoints that exist in the database are correct
        try:
            self._verify_checkpoints()
        except InitializationError:
            self.log.exception('Initialization error when checking checkpoints, cannot continue.')
            sys.exit()

        # XXX: last step before actually starting is updating the last started at timestamps
        self.tx_storage.update_last_started_at(started_at)

        if self._enable_event_queue:
            topological_iterator = self.tx_storage.topological_iterator()
            self._event_manager.handle_load_phase_vertices(
                topological_iterator=topological_iterator,
                total_vertices=self.tx_storage.indexes.info.get_vertices_count()
            )

        self._event_manager.load_finished()
        self.state = self.NodeState.READY

        t1 = time.time()
        total_load_time = LogDuration(t1 - t0)

        environment_info = self.environment_info.as_dict() if self.environment_info else {}

        vertex_count = self.tx_storage.get_vertices_count()

        # Changing the field names in this log could impact log collectors that parse them
        self.log.info('ready', vertex_count=vertex_count,
                      total_load_time=total_load_time, **environment_info)

    def _verify_soft_voided_txs(self) -> None:
        # TODO: this could be either refactored into a migration or at least into it's own method
        # After introducing soft voided transactions we need to guarantee the full node is not using
        # a database that already has the soft voided transaction before marking them in the metadata
        # Any new sync from the beginning should work fine or starting with the latest snapshot
        # that already has the soft voided transactions marked
        for soft_voided_id in self.consensus_algorithm.soft_voided_tx_ids:
            try:
                with self.tx_storage.allow_only_valid_context():
                    soft_voided_tx = self.tx_storage.get_transaction(soft_voided_id)
            except TransactionDoesNotExist:
                # This database does not have this tx that should be soft voided
                # so it's fine, we will mark it as soft voided when we get it through sync
                pass
            else:
                soft_voided_meta = soft_voided_tx.get_metadata()
                voided_set = soft_voided_meta.voided_by or set()
                # If the tx is not marked as soft voided, then we can't continue the initialization
                if self._settings.SOFT_VOIDED_ID not in voided_set:
                    self.log.error(
                        'Error initializing node. Your database is not compatible with the current version of the'
                        ' full node. You must use the latest available snapshot or sync from the beginning.'
                    )
                    sys.exit(-1)

                assert {soft_voided_id, self._settings.SOFT_VOIDED_ID}.issubset(voided_set)

    def _verify_checkpoints(self) -> None:
        """ Method to verify if all checkpoints that exist in the database have the correct hash and are winners.

        This method needs the essential indexes to be already initialized.
        """
        assert self.tx_storage.indexes is not None
        # based on the current best-height, filter-out checkpoints that aren't expected to exist in the database
        best_height = self.tx_storage.get_height_best_block()
        expected_checkpoints = [cp for cp in self.checkpoints if cp.height <= best_height]
        for checkpoint in expected_checkpoints:
            # XXX: query the database from checkpoint.hash and verify what comes out
            try:
                block = self.tx_storage.get_block(checkpoint.hash)
            except TransactionDoesNotExist as e:
                raise InitializationError(f'Expected checkpoint does not exist in database: {checkpoint}') from e
            meta = block.get_metadata()
            height = block.static_metadata.height
            if height != checkpoint.height:
                raise InitializationError(
                    f'Expected checkpoint of hash {block.hash_hex} to have height {checkpoint.height},'
                    f'but instead it has height {height}'
                )
            if meta.voided_by:
                pretty_voided_by = list(i.hex() for i in meta.voided_by)
                raise InitializationError(
                    f'Expected checkpoint {checkpoint} to *NOT* be voided, but it is being voided by: '
                    f'{pretty_voided_by}'
                )
            # XXX: query the height index from checkpoint.height and check that the hash matches
            block_hash = self.tx_storage.indexes.height.get(checkpoint.height)
            if block_hash is None:
                raise InitializationError(
                    f'Expected checkpoint {checkpoint} to be found in the height index, but it was not found'
                )
            if block_hash != block.hash:
                raise InitializationError(
                    f'Expected checkpoint {checkpoint} to be found in the height index, but it instead the block with '
                    f'hash {block_hash.hex()} was found'
                )

    def get_timestamp_for_new_vertex(self) -> int:
        """Generate a timestamp appropriate for a new transaction."""
        timestamp_now = int(self.reactor.seconds())
        best_block = self.tx_storage.get_best_block()
        return max(timestamp_now, best_block.timestamp)

    def get_new_tx_parents(self, timestamp: Optional[float] = None) -> list[VertexId]:
        """Select which transactions will be confirmed by a new transaction.

        :return: The hashes of the parents for a new transaction.
        """
        timestamp = timestamp or self.get_timestamp_for_new_vertex()
        parent_txs = self.generate_parent_txs(timestamp)
        return list(parent_txs.get_random_parents(self.rng))

    def generate_parent_txs(self, timestamp: Optional[float]) -> 'ParentTxs':
        """Select which transactions will be confirmed by a new block or transaction.

        The result of this method depends on the current state of the blockchain and is intended to generate tx-parents
        for a new block in the current blockchain, as such if a timestamp is present it must be at least greater than
        the current best block's.
        """

        if timestamp is None:
            timestamp = self.reactor.seconds()

        best_block = self.tx_storage.get_best_block()
        assert timestamp >= best_block.timestamp

        def get_tx_parents(tx: BaseTransaction, *, with_inputs: bool = False) -> list[Transaction]:
            if tx.is_genesis:
                genesis_txs = [self._settings.GENESIS_TX1_HASH, self._settings.GENESIS_TX2_HASH]
                if tx.is_transaction:
                    other_genesis_tx, = set(genesis_txs) - {tx.hash}
                    return [self.tx_storage.get_tx(other_genesis_tx)]
                else:
                    return [self.tx_storage.get_tx(t) for t in genesis_txs]

            parents = tx.get_tx_parents()
            assert len(parents) == 2

            txs = list(parents)
            if with_inputs:
                input_tx_ids = set(i.tx_id for i in tx.inputs)
                inputs = (self.tx_storage.get_transaction(tx_id) for tx_id in input_tx_ids)
                input_txs = (tx for tx in inputs if isinstance(tx, Transaction))
                txs.extend(input_txs)

            return txs

        unconfirmed_tips = [tx for tx in self.tx_storage.iter_mempool_tips() if tx.timestamp < timestamp]
        match unconfirmed_tips:
            case []:
                # mix the blocks tx-parents, with their own tx-parents to avoid carrying one of the genesis tx over
                best_block_tx_parents = get_tx_parents(best_block)
                tx1_tx_grandparents = get_tx_parents(best_block_tx_parents[0], with_inputs=True)
                tx2_tx_grandparents = get_tx_parents(best_block_tx_parents[1], with_inputs=True)
                confirmed_tips = sorted(
                    set(best_block_tx_parents) | set(tx1_tx_grandparents) | set(tx2_tx_grandparents),
                    key=lambda tx: tx.timestamp,
                )
                self.log.debug('generate_parent_txs: empty mempool, repeat parents')
                return ParentTxs.from_txs(can_include=confirmed_tips[-2:], must_include=())
            case [tip_tx]:
                best_block_tx_parents = get_tx_parents(best_block)
                repeated_parents = get_tx_parents(tip_tx, with_inputs=True)
                confirmed_tips = sorted(
                    set(best_block_tx_parents) | set(repeated_parents),
                    key=lambda tx: tx.timestamp,
                )
                self.log.debug('generate_parent_txs: one tx in mempool, fill with one repeated parent')
                return ParentTxs.from_txs(can_include=confirmed_tips[-1:], must_include=(tip_tx,))
            case _:
                self.log.debug('generate_parent_txs: multiple unconfirmed mempool tips')
                return ParentTxs.from_txs(can_include=unconfirmed_tips, must_include=())

    def allow_mining_without_peers(self) -> None:
        """Allow mining without being synced to at least one peer.
        It should be used only for debugging purposes.
        """
        self._allow_mining_without_peers = True

    def can_start_mining(self) -> bool:
        """ Return whether we can start mining.
        """
        if self._allow_mining_without_peers:
            return True
        return self.connections.has_synced_peer()

    def get_block_templates(self, parent_block_hash: Optional[VertexId] = None,
                            timestamp: Optional[int] = None) -> BlockTemplates:
        """ Cached version of `make_block_templates`, cache is invalidated when latest_timestamp changes."""
        if parent_block_hash is not None:
            return BlockTemplates([self.make_block_template(parent_block_hash, timestamp)], storage=self.tx_storage)
        return BlockTemplates(self.make_block_templates(timestamp), storage=self.tx_storage)

    def make_block_templates(self, timestamp: Optional[int] = None) -> Iterator[BlockTemplate]:
        """ Makes block templates for all possible best tips as of the latest timestamp.

        Each block template has all the necessary info to build a block to be mined without requiring further
        information from the blockchain state. Which is ideal for use by external mining servers.
        """
        parent_block_hash = self.tx_storage.get_best_block_hash()
        yield self.make_block_template(parent_block_hash, timestamp)

    def make_block_template(self, parent_block_hash: VertexId, timestamp: Optional[int] = None) -> BlockTemplate:
        """ Makes a block template using the given parent block.
        """
        parent_block = self.tx_storage.get_transaction(parent_block_hash)
        assert isinstance(parent_block, Block)
        parent_txs = self.generate_parent_txs(parent_block.timestamp + self._settings.MAX_DISTANCE_BETWEEN_BLOCKS)
        if timestamp is None:
            current_timestamp = int(self.reactor.seconds())
        else:
            current_timestamp = timestamp
        return self._make_block_template(parent_block, parent_txs, current_timestamp)

    def make_custom_block_template(self, parent_block_hash: VertexId, parent_tx_hashes: list[VertexId],
                                   timestamp: Optional[int] = None) -> BlockTemplate:
        """ Makes a block template using the given parent block and txs.
        """
        parent_block = self.tx_storage.get_transaction(parent_block_hash)
        assert isinstance(parent_block, Block)
        parent_tx_list: list[Transaction] = []
        for tx_hash in parent_tx_hashes:
            tx = self.tx_storage.get_transaction(tx_hash)
            assert isinstance(tx, Transaction)
            parent_tx_list.append(tx)
        parent_txs = ParentTxs.from_txs(can_include=parent_tx_list, must_include=())
        if timestamp is None:
            current_timestamp = int(max(self.tx_storage.latest_timestamp, self.reactor.seconds()))
        else:
            current_timestamp = timestamp
        return self._make_block_template(parent_block, parent_txs, current_timestamp)

    def _make_block_template(self, parent_block: Block, parent_txs: 'ParentTxs', current_timestamp: int,
                             with_weight_decay: bool = False) -> BlockTemplate:
        """ Further implementation of making block template, used by make_block_template and make_custom_block_template
        """
        # the absolute minimum would be the previous timestamp + 1
        timestamp_abs_min = parent_block.timestamp + 1
        # and absolute maximum limited by max time between blocks
        if not parent_block.is_genesis:
            timestamp_abs_max = parent_block.timestamp + self._settings.MAX_DISTANCE_BETWEEN_BLOCKS - 1
        else:
            timestamp_abs_max = 0xffffffff
        assert timestamp_abs_max > timestamp_abs_min
        # actual minimum depends on the timestamps of the parent txs
        # it has to be at least the max timestamp of parents + 1
        timestamp_min = max(timestamp_abs_min, parent_txs.max_timestamp + 1)
        assert timestamp_min <= timestamp_abs_max
        # when we have weight decay, the max timestamp will be when the next decay happens
        if with_weight_decay and self._settings.WEIGHT_DECAY_ENABLED:
            # we either have passed the first decay or not, the range will vary depending on that
            if timestamp_min > timestamp_abs_min + self._settings.WEIGHT_DECAY_ACTIVATE_DISTANCE:
                timestamp_max_decay = timestamp_min + self._settings.WEIGHT_DECAY_WINDOW_SIZE
            else:
                timestamp_max_decay = timestamp_abs_min + self._settings.WEIGHT_DECAY_ACTIVATE_DISTANCE
            timestamp_max = min(timestamp_abs_max, timestamp_max_decay)
        else:
            timestamp_max = timestamp_abs_max
        timestamp_max = min(timestamp_max, int(current_timestamp + self._settings.MAX_FUTURE_TIMESTAMP_ALLOWED))
        if timestamp_max < timestamp_min:
            raise BlockTemplateTimestampError(
                f'Unable to create a block template because there is no timestamp available. '
                f'(min={timestamp_min}, max={timestamp_max}) '
                f'(current_timestamp={current_timestamp})'
            )
        timestamp = min(max(current_timestamp, timestamp_min), timestamp_max)
        parent_block_metadata = parent_block.get_metadata()
        # this is the min weight to cause an increase of twice the WEIGHT_TOL, we make sure to generate a template with
        # at least this weight (note that the user of the API can set its own weight, the block submit API will also
        # protect against a weight that is too small but using WEIGHT_TOL instead of 2*WEIGHT_TOL)
        min_significant_weight = calculate_min_significant_weight(
            parent_block_metadata.score,
            2 * self._settings.WEIGHT_TOL
        )
        weight = max(
            self.daa.calculate_next_weight(parent_block, timestamp, self.tx_storage.get_parent_block),
            min_significant_weight
        )
        height = parent_block.get_height() + 1
        parents = [parent_block.hash] + list(parent_txs.must_include)
        parents_any = parent_txs.can_include
        # simplify representation when you only have one to choose from
        if len(parents) + len(parents_any) == 3:
            parents.extend(sorted(parents_any))
            parents_any = []
        assert len(parents) + len(parents_any) >= 3, 'There should be enough parents to choose from'
        assert 1 <= len(parents) <= 3, 'Impossible number of parents'
        if __debug__ and len(parents) == 3:
            assert len(parents_any) == 0, 'Extra parents to choose from that cannot be chosen'
        score = parent_block_metadata.score + weight_to_work(weight)
        self.rng.shuffle(parents_any)  # shuffle parents_any to get rid of biases if clients don't shuffle themselves
        return BlockTemplate(
            versions={TxVersion.REGULAR_BLOCK.value, TxVersion.MERGE_MINED_BLOCK.value},
            reward=self.daa.get_tokens_issued_per_block(height),
            weight=weight,
            timestamp_now=current_timestamp,
            timestamp_min=timestamp_min,
            timestamp_max=timestamp_max,
            parents=parents,
            parents_any=parents_any,
            height=height,
            score=score,
            signal_bits=self._bit_signaling_service.generate_signal_bits(block=parent_block)
        )

    def generate_mining_block(self, timestamp: Optional[int] = None,
                              parent_block_hash: Optional[VertexId] = None,
                              data: bytes = b'', address: Optional[Address] = None,
                              merge_mined: bool = False) -> Union[Block, MergeMinedBlock]:
        """ Generates a block ready to be mined. The block includes new issued tokens,
        parents, and the weight.

        :return: A block ready to be mined
        :rtype: :py:class:`hathor.transaction.Block`
        """
        if address is None:
            if self.wallet is None:
                raise ValueError('No wallet available and no mining address given')
            address = self.wallet.get_unused_address_bytes(mark_as_used=False)
        assert address is not None
        block = self.get_block_templates(parent_block_hash, timestamp).generate_mining_block(
            rng=self.rng,
            cls=MergeMinedBlock if merge_mined else Block,
            address=address or None,  # XXX: because we allow b'' for explicit empty output script
            data=data,
        )
        return block

    def get_tokens_issued_per_block(self, height: int) -> int:
        """Return the number of tokens issued (aka reward) per block of a given height."""
        return self.daa.get_tokens_issued_per_block(height)

    def submit_block(self, blk: Block) -> bool:
        """Used by submit block from all mining APIs.
        """
        parent_hash = blk.get_block_parent_hash()
        best_block_hash = self.tx_storage.get_best_block_hash()
        if parent_hash != best_block_hash:
            self.log.warn(
                'submit_block(): Ignoring block: parent not a tip',
                submitted_block_hash=blk.hash_hex,
                submitted_parent_hash=parent_hash.hex(),
                tip_block_hash=best_block_hash.hex(),
            )
            return False
        parent_block = self.tx_storage.get_transaction(parent_hash)
        parent_block_metadata = parent_block.get_metadata()
        # this is the smallest weight that won't cause the score to increase, anything equal or smaller is bad
        min_insignificant_weight = calculate_min_significant_weight(
            parent_block_metadata.score,
            self._settings.WEIGHT_TOL
        )
        if blk.weight <= min_insignificant_weight:
            self.log.warn('submit_block(): insignificant weight? accepted anyway', blk=blk.hash_hex, weight=blk.weight)
        return self.propagate_tx(blk)

    def push_tx(self, tx: Transaction, allow_non_standard_script: bool = False,
                max_output_script_size: int | None = None) -> None:
        """Used by all APIs that accept a new transaction (like push_tx)
        """
        if self.tx_storage.transaction_exists(tx.hash):
            raise InvalidNewTransaction('Transaction already exists {}'.format(tx.hash_hex))

        if max_output_script_size is None:
            max_output_script_size = self._settings.PUSHTX_MAX_OUTPUT_SCRIPT_SIZE

        is_double_spending = tx.is_double_spending()
        if is_double_spending:
            raise DoubleSpendingError('Invalid transaction. At least one of your inputs has already been spent.')

        is_spending_voided_tx = tx.is_spending_voided_tx()
        if is_spending_voided_tx:
            raise SpendingVoidedError('Invalid transaction. At least one input is voided.')

        if is_spent_reward_locked(self._settings, tx):
            raise RewardLockedError('Spent reward is locked.')

        # We are using here the method from lib because the property
        # to identify a nft creation transaction was created on the lib
        # to be used in the full node and tx mining service
        # TODO: avoid reparsing when hathorlib is fully compatible
        tx_from_lib = lib_tx_or_block_from_bytes(bytes(tx))
        if not tx_from_lib.is_standard(max_output_script_size, not allow_non_standard_script):
            raise NonStandardTxError('Transaction is non standard.')

        self.propagate_tx(tx)

    def propagate_tx(self, tx: BaseTransaction) -> bool:
        """Push a new transaction to the network. It is used by both the wallet and the mining modules.

        :return: True if the transaction was accepted
        :rtype: bool
        """
        if tx.storage:
            assert tx.storage == self.tx_storage, 'Invalid tx storage'
        else:
            tx.storage = self.tx_storage

        return self.on_new_tx(tx, propagate_to_peers=True)

    def on_new_tx(
        self,
        vertex: BaseTransaction,
        *,
        quiet: bool = False,
        propagate_to_peers: bool = True,
        reject_locked_reward: bool = True,
    ) -> bool:
        """ New method for adding transactions or blocks that steps the validation state machine.

        :param vertex: transaction to be added
        :param quiet: if True will not log when a new tx is accepted
        :param propagate_to_peers: if True will relay the tx to other peers if it is accepted
        """
        success = self.vertex_handler.on_new_relayed_vertex(
            vertex, quiet=quiet, reject_locked_reward=reject_locked_reward
        )

        if propagate_to_peers and success:
            self.connections.send_tx_to_peers(vertex)

        return success

    def has_sync_version_capability(self) -> bool:
        return self._settings.CAPABILITY_SYNC_VERSION in self.capabilities

    def add_peer_to_whitelist(self, peer_id: PeerId) -> None:
        if not self._settings.ENABLE_PEER_WHITELIST:
            return

        if peer_id in self.peers_whitelist:
            self.log.info('peer already in whitelist', peer_id=peer_id)
        else:
            self.peers_whitelist.append(peer_id)

    def remove_peer_from_whitelist_and_disconnect(self, peer_id: PeerId) -> None:
        if not self._settings.ENABLE_PEER_WHITELIST:
            return

        if peer_id in self.peers_whitelist:
            self.peers_whitelist.remove(peer_id)
            # disconnect from node
            self.connections.drop_connection_by_peer_id(peer_id)

    def has_recent_activity(self) -> bool:
        current_timestamp = time.time()
        latest_blockchain_timestamp = self.tx_storage.latest_timestamp

        # We use the avg time between blocks as a basis to know how much time we should use to consider the fullnode
        # as not synced.
        maximum_timestamp_delta = (
            self._settings.P2P_RECENT_ACTIVITY_THRESHOLD_MULTIPLIER * self._settings.AVG_TIME_BETWEEN_BLOCKS
        )

        if current_timestamp - latest_blockchain_timestamp > maximum_timestamp_delta:
            return False

        return True

    def is_sync_healthy(self) -> tuple[bool, Optional[str]]:
        # This checks whether the last txs (blocks or transactions) we received are recent enough.
        if not self.has_recent_activity():
            return False, HathorManager.UnhealthinessReason.NO_RECENT_ACTIVITY

        if not self.connections.has_synced_peer():
            return False, HathorManager.UnhealthinessReason.NO_SYNCED_PEER

        return True, None

    def check_sync_state(self):
        now = time.time()

        if self.has_recent_activity():
            self.first_time_fully_synced = now

            total_sync_time = LogDuration(self.first_time_fully_synced - self.start_time)
            vertex_count = self.tx_storage.get_vertices_count()

            # Changing the fields in this log could impact log collectors that parse them
            self.log.info('has recent activity for the first time', total_sync_time=total_sync_time,
                          vertex_count=vertex_count, **self.environment_info.as_dict())

            self.lc_check_sync_state.stop()

    def set_cmd_path(self, path: str) -> None:
        """Set the cmd path, where sysadmins can place files to communicate with the full node."""
        self._cmd_path = path

    def get_cmd_path(self) -> Optional[str]:
        """Return the cmd path. If no cmd path is set, returns None."""
        return self._cmd_path

    def set_hostname_and_reset_connections(self, new_hostname: str) -> None:
        """Set the hostname and reset all connections."""
        old_hostname = self.hostname
        self.hostname = new_hostname
        self.connections.update_hostname_entrypoints(old_hostname=old_hostname, new_hostname=self.hostname)
        self.connections.disconnect_all_peers(force=True)


@dataclass(slots=True, frozen=True, kw_only=True)
class ParentTxs:
    """ Tuple where the `must_include` hash, when present (at most 1), must be included in a pair, and a list of hashes
    where any of them can be included. This is done in order to make sure that when there is only one tx tip, it is
    included.
    """
    max_timestamp: int
    can_include: list[VertexId]
    must_include: tuple[()] | tuple[VertexId]

    def __post_init__(self) -> None:
        assert len(self.must_include) <= 1
        if self.must_include:
            assert self.must_include[0] not in self.can_include

    @staticmethod
    def from_txs(*, can_include: list[Transaction], must_include: tuple[()] | tuple[Transaction]) -> 'ParentTxs':
        assert len(can_include) + len(must_include) >= 2
        return ParentTxs(
            max_timestamp=max(tx.timestamp for tx in (*can_include, *must_include)),
            can_include=list(tx.hash for tx in can_include),
            must_include=(must_include[0].hash,) if must_include else (),
        )

    def get_random_parents(self, rng: Random) -> tuple[VertexId, VertexId]:
        """ Get parents from self.parents plus a random choice from self.parents_any to make it 3 in total.

        Using tuple as return type to make it explicit that the length is always 2.
        """
        fill = rng.ordered_sample(self.can_include, 2 - len(self.must_include))
        p1, p2 = self.must_include + tuple(fill)
        return p1, p2
