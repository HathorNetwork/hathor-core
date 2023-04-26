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

import datetime
import sys
import time
from enum import Enum
from typing import Any, Iterable, Iterator, List, NamedTuple, Optional, Tuple, Union

from hathorlib.base_transaction import tx_or_block_from_bytes as lib_tx_or_block_from_bytes
from structlog import get_logger
from twisted.internet import defer
from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall
from twisted.python.threadpool import ThreadPool

from hathor import daa
from hathor.checkpoint import Checkpoint
from hathor.conf import HathorSettings
from hathor.consensus import ConsensusAlgorithm
from hathor.event.event_manager import EventManager
from hathor.exception import (
    DoubleSpendingError,
    HathorError,
    InitializationError,
    InvalidNewTransaction,
    NonStandardTxError,
    RewardLockedError,
    SpendingVoidedError,
)
from hathor.mining import BlockTemplate, BlockTemplates
from hathor.p2p.peer_discovery import PeerDiscovery
from hathor.p2p.peer_id import PeerId
from hathor.p2p.protocol import HathorProtocol
from hathor.profiler import get_cpu_profiler
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, Transaction, TxVersion, sum_weights
from hathor.transaction.exceptions import TxValidationError
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.util import EnvironmentInfo, LogDuration, Random, Reactor, calculate_min_significant_weight, not_none
from hathor.wallet import BaseWallet

settings = HathorSettings()
logger = get_logger()
cpu = get_cpu_profiler()


DEFAULT_CAPABILITIES = [settings.CAPABILITY_WHITELIST, settings.CAPABILITY_SYNC_VERSION]


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

    def __init__(self,
                 reactor: Reactor,
                 *,
                 pubsub: PubSubManager,
                 consensus_algorithm: ConsensusAlgorithm,
                 peer_id: PeerId,
                 tx_storage: TransactionStorage,
                 network: str,
                 hostname: Optional[str] = None,
                 wallet: Optional[BaseWallet] = None,
                 event_manager: Optional[EventManager] = None,
                 stratum_port: Optional[int] = None,
                 ssl: bool = True,
                 enable_sync_v1: bool = True,
                 enable_sync_v2: bool = False,
                 capabilities: Optional[List[str]] = None,
                 checkpoints: Optional[List[Checkpoint]] = None,
                 rng: Optional[Random] = None,
                 environment_info: Optional[EnvironmentInfo] = None,
                 full_verification: bool = False):
        """
        :param reactor: Twisted reactor which handles the mainloop and the events.
        :param peer_id: Id of this node.
        :param network: Name of the network this node participates. Usually it is either testnet or mainnet.
        :type network: string

        :param hostname: The hostname of this node. It is used to generate its entrypoints.
        :type hostname: string

        :param tx_storage: Required storage backend.
        :type tx_storage: :py:class:`hathor.transaction.storage.transaction_storage.TransactionStorage`

        :param stratum_port: Stratum server port. Stratum server will only be created if it is not None.
        :type stratum_port: Optional[int]
        """
        from hathor.metrics import Metrics
        from hathor.p2p.factory import HathorClientFactory, HathorServerFactory
        from hathor.p2p.manager import ConnectionsManager

        if not (enable_sync_v1 or enable_sync_v2):
            raise TypeError(f'{type(self).__name__}() at least one sync version is required')

        self._enable_sync_v1 = enable_sync_v1
        self._enable_sync_v2 = enable_sync_v2

        self.log = logger.new()

        if rng is None:
            rng = Random()
        self.rng = rng

        self.reactor = reactor
        add_system_event_trigger = getattr(self.reactor, 'addSystemEventTrigger', None)
        if add_system_event_trigger is not None:
            add_system_event_trigger('after', 'shutdown', self.stop)

        self.state: Optional[HathorManager.NodeState] = None
        self.profiler: Optional[Any] = None

        # Hostname, used to be accessed by other peers.
        self.hostname = hostname

        # Remote address, which can be different from local address.
        self.remote_address = None

        self.my_peer = peer_id
        self.network = network

        self.is_started: bool = False

        self.cpu = cpu

        # XXX: first checkpoint must be genesis (height=0)
        self.checkpoints: List[Checkpoint] = checkpoints or []
        self.checkpoints_ready: List[bool] = [False] * len(self.checkpoints)
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

        if enable_sync_v2:
            assert self.tx_storage.indexes is not None
            self.log.debug('enable sync-v2 indexes')
            self.tx_storage.indexes.enable_deps_index()
            self.tx_storage.indexes.enable_mempool_index()

        self.consensus_algorithm = consensus_algorithm

        self.peer_discoveries: List[PeerDiscovery] = []

        self.ssl = ssl
        self.server_factory = HathorServerFactory(self.network, self.my_peer, node=self, use_ssl=ssl)
        self.client_factory = HathorClientFactory(self.network, self.my_peer, node=self, use_ssl=ssl)
        self.connections = ConnectionsManager(self.reactor, self.my_peer, self.server_factory, self.client_factory,
                                              self.pubsub, self, ssl, whitelist_only=False, rng=self.rng,
                                              enable_sync_v1=enable_sync_v1, enable_sync_v2=enable_sync_v2)

        self.metrics = Metrics(
            pubsub=self.pubsub,
            avg_time_between_blocks=settings.AVG_TIME_BETWEEN_BLOCKS,
            connections=self.connections,
            tx_storage=self.tx_storage,
            reactor=self.reactor,
        )

        self.wallet = wallet
        if self.wallet:
            self.wallet.pubsub = self.pubsub
            self.wallet.reactor = self.reactor

        if stratum_port:
            # XXX: only import if needed
            from hathor.stratum import StratumFactory
            self.stratum_factory: Optional[StratumFactory] = StratumFactory(manager=self, port=stratum_port)
        else:
            self.stratum_factory = None
        # Set stratum factory for metrics object
        self.metrics.stratum_factory = self.stratum_factory

        self._allow_mining_without_peers = False

        # Thread pool used to resolve pow when sending tokens
        self.pow_thread_pool = ThreadPool(minthreads=0, maxthreads=settings.MAX_POW_THREADS, name='Pow thread pool')

        # List of addresses to listen for new connections (eg: [tcp:8000])
        self.listen_addresses: List[str] = []

        # Full verification execute all validations for transactions and blocks when initializing the node
        # Can be activated on the command line with --full-verification
        self._full_verification = full_verification

        # Activated with --x-enable-event-queue flag
        # It activates the event mechanism inside full node
        self.enable_event_queue = False

        # List of whitelisted peers
        self.peers_whitelist: List[str] = []

        # List of capabilities of the peer
        if capabilities is not None:
            self.capabilities = capabilities
        else:
            self.capabilities = DEFAULT_CAPABILITIES

        # This is included in some logs to provide more context
        self.environment_info = environment_info

        # Task that will count the total sync time
        self.lc_check_sync_state = LoopingCall(self.check_sync_state)
        self.lc_check_sync_state.clock = self.reactor
        self.lc_check_sync_state_interval = self.CHECK_SYNC_STATE_INTERVAL

    def start(self) -> None:
        """ A factory must be started only once. And it is usually automatically started.
        """
        if self.is_started:
            raise Exception('HathorManager is already started')
        self.is_started = True

        self.log.info('start manager', network=self.network)
        # If it's a full verification, we save on the storage that we are starting it
        # this is required because if we stop the initilization in the middle, the metadata
        # saved on the storage is not reliable anymore, only if we finish it
        if self._full_verification:
            self.tx_storage.start_full_verification()
        else:
            # If it's a fast initialization and the last time a full initialization stopped in the middle
            # we can't allow the full node to continue, so we need to remove the storage and do a full sync
            # or execute an initialization with full verification
            if self.tx_storage.is_running_full_verification():
                self.log.error(
                    'Error initializing node. The last time you started your node you did a full verification '
                    'that was stopped in the middle. The storage is not reliable anymore and, because of that, '
                    'you must initialize with a full verification again or remove your storage and do a full sync.'
                )
                sys.exit(-1)

            # If self.tx_storage.is_running_manager() is True, the last time the node was running it had a sudden crash
            # because of that, we must run a full verification because some storage data might be wrong.
            # The metadata is the only piece of the storage that may be wrong, not the blocks and transactions.
            if self.tx_storage.is_running_manager():
                self.log.error(
                    'Error initializing node. The last time you executed your full node it wasn\'t stopped correctly. '
                    'The storage is not reliable anymore and, because of that, so you must run a full verification '
                    'or remove your storage and do a full sync.'
                )
                sys.exit(-1)

        if self._event_manager:
            self._event_manager.start(not_none(self.my_peer.id))

        self.state = self.NodeState.INITIALIZING
        self.pubsub.publish(HathorEvents.MANAGER_ON_START)
        self.connections.start()
        self.pow_thread_pool.start()

        # Disable get transaction lock when initializing components
        self.tx_storage.disable_lock()
        # Initialize manager's components.
        if self._full_verification:
            self.tx_storage.reset_indexes()
            self._initialize_components()
            # Before calling self._initialize_components() I start 'full verification' mode and after that I need to
            # finish it. It's just to know if the full node has stopped a full initialization in the middle
            self.tx_storage.finish_full_verification()
        else:
            self._initialize_components_new()
        self.tx_storage.enable_lock()

        # Metric starts to capture data
        self.metrics.start()

        for description in self.listen_addresses:
            self.listen(description)

        self.do_discovery()

        self.start_time = time.time()

        self.lc_check_sync_state.start(self.lc_check_sync_state_interval, now=False)

        if self.wallet:
            self.wallet.start()

        if self.stratum_factory:
            self.stratum_factory.start()

        # Start running
        self.tx_storage.start_running_manager()

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

        if self.lc_check_sync_state.running:
            self.lc_check_sync_state.stop()

        if self.wallet:
            self.wallet.stop()

        if self.stratum_factory:
            wait_stratum = self.stratum_factory.stop()
            if wait_stratum:
                waits.append(wait_stratum)

        if self._event_manager:
            self._event_manager.stop()

        self.tx_storage.flush()

        return defer.DeferredList(waits)

    def do_discovery(self) -> None:
        """
        Do a discovery and connect on all discovery strategies.
        """
        for peer_discovery in self.peer_discoveries:
            peer_discovery.discover_and_connect(self.connections.connect_to)

    def start_profiler(self, *, reset: bool = False) -> None:
        """
        Start profiler. It can be activated from a web resource, as well.
        """
        if reset or not self.profiler:
            import cProfile
            self.profiler = cProfile.Profile()
        self.profiler.enable()

    def stop_profiler(self, save_to: Optional[str] = None) -> None:
        """
        Stop the profile and optionally save the results for future analysis.

        :param save_to: path where the results will be saved
        :type save_to: str
        """
        assert self.profiler is not None
        self.profiler.disable()
        if save_to:
            self.profiler.dump_stats(save_to)

    def _initialize_components(self) -> None:
        """You are not supposed to run this method manually. You should run `doStart()` to initialize the
        manager.

        This method runs through all transactions, verifying them and updating our wallet.
        """
        assert not self._event_manager, 'this method cannot be used if the events feature is enabled.'

        self.log.info('initialize')
        if self.wallet:
            self.wallet._manually_initialize()
        t0 = time.time()
        t1 = t0
        cnt = 0
        cnt2 = 0
        t2 = t0
        h = 0

        block_count = 0
        tx_count = 0

        self.tx_storage.pre_init()
        assert self.tx_storage.indexes is not None

        # After introducing soft voided transactions we need to guarantee the full node is not using
        # a database that already has the soft voided transaction before marking them in the metadata
        # Any new sync from the beginning should work fine or starting with the latest snapshot
        # that already has the soft voided transactions marked
        for soft_voided_id in self.consensus_algorithm.soft_voided_tx_ids:
            try:
                soft_voided_tx = self.tx_storage.get_transaction(soft_voided_id)
            except TransactionDoesNotExist:
                # This database does not have this tx that should be soft voided
                # so it's fine, we will mark it as soft voided when we get it through sync
                pass
            else:
                soft_voided_meta = soft_voided_tx.get_metadata()
                voided_set = soft_voided_meta.voided_by or set()
                # If the tx is not marked as soft voided, then we can't continue the initialization
                if settings.SOFT_VOIDED_ID not in voided_set:
                    self.log.error(
                        'Error initializing node. Your database is not compatible with the current version of the'
                        ' full node. You must use the latest available snapshot or sync from the beginning.'
                    )
                    sys.exit(-1)

                assert {soft_voided_id, settings.SOFT_VOIDED_ID}.issubset(voided_set)

        # Checkpoints as {height: hash}
        checkpoint_heights = {}
        for cp in self.checkpoints:
            checkpoint_heights[cp.height] = cp.hash

        # self.start_profiler()
        if self._full_verification:
            self.log.debug('reset all metadata')
            for tx in self.tx_storage.get_all_transactions():
                tx.reset_metadata()

        self.log.debug('load blocks and transactions')
        for tx in self.tx_storage._topological_sort_dfs():
            if self._full_verification:
                tx.update_initial_metadata()

            assert tx.hash is not None

            tx_meta = tx.get_metadata()

            t2 = time.time()
            dt = LogDuration(t2 - t1)
            dcnt = cnt - cnt2
            tx_rate = '?' if dt == 0 else dcnt / dt
            h = max(h, tx_meta.height)
            if dt > 30:
                ts_date = datetime.datetime.fromtimestamp(self.tx_storage.latest_timestamp)
                if h == 0:
                    self.log.debug('start loading transactions...')
                else:
                    self.log.info('load transactions...', tx_rate=tx_rate, tx_new=dcnt, dt=dt,
                                  total=cnt, latest_ts=ts_date, height=h)
                t1 = t2
                cnt2 = cnt
            cnt += 1

            # It's safe to skip block weight verification during initialization because
            # we trust the difficulty stored in metadata
            skip_block_weight_verification = True
            if block_count % settings.VERIFY_WEIGHT_EVERY_N_BLOCKS == 0:
                skip_block_weight_verification = False

            try:
                if self._full_verification:
                    # TODO: deal with invalid tx
                    if tx.can_validate_full():
                        self.tx_storage.add_to_indexes(tx)
                        assert tx.validate_full(skip_block_weight_verification=skip_block_weight_verification)
                        self.consensus_algorithm.update(tx)
                        self.tx_storage.indexes.update(tx)
                        if self.tx_storage.indexes.mempool_tips is not None:
                            self.tx_storage.indexes.mempool_tips.update(tx)  # XXX: move to indexes.update
                        if self.tx_storage.indexes.deps is not None:
                            self.sync_v2_step_validations([tx])
                    else:
                        assert tx.validate_basic(skip_block_weight_verification=skip_block_weight_verification)
                    self.tx_storage.save_transaction(tx, only_metadata=True)
                else:
                    # TODO: deal with invalid tx
                    if not tx_meta.validation.is_final():
                        if not tx_meta.validation.is_checkpoint():
                            assert tx_meta.validation.is_at_least_basic(), f'invalid: {tx.hash_hex}'
                    elif tx.is_transaction and tx_meta.first_block is None and not tx_meta.voided_by:
                        assert self.tx_storage.indexes is not None
                        if self.tx_storage.indexes.mempool_tips:
                            self.tx_storage.indexes.mempool_tips.update(tx)
                    self.tx_storage.add_to_indexes(tx)
                    if tx.is_transaction and tx_meta.voided_by:
                        self.tx_storage.del_from_indexes(tx)
            except (InvalidNewTransaction, TxValidationError):
                self.log.error('unexpected error when initializing', tx=tx, exc_info=True)
                raise

            if tx.is_block:
                block_count += 1

                # this works because blocks on the best chain are iterated from lower to higher height
                assert tx.hash is not None
                assert tx_meta.validation.is_at_least_basic()
                if not tx_meta.voided_by and tx_meta.validation.is_fully_connected():
                    # XXX: this might not be needed when making a full init because the consensus should already have
                    self.tx_storage.indexes.height.add_reorg(tx_meta.height, tx.hash, tx.timestamp)

                # Check if it's a checkpoint block
                if tx_meta.height in checkpoint_heights:
                    if tx.hash == checkpoint_heights[tx_meta.height]:
                        del checkpoint_heights[tx_meta.height]
                    else:
                        # If the hash is different from checkpoint hash, we stop the node
                        self.log.error('Error initializing the node. Checkpoint validation error.')
                        sys.exit()
            else:
                tx_count += 1

            if time.time() - t2 > 1:
                dt = LogDuration(time.time() - t2)
                self.log.warn('tx took too long to load', tx=tx.hash_hex, dt=dt)

        # we have to have a best_block by now
        # assert best_block is not None

        self.log.debug('done loading transactions')

        # Check if all checkpoints in database are ok
        my_best_height = self.tx_storage.get_height_best_block()
        if checkpoint_heights:
            # If I have checkpoints that were not validated I must check if they are all in a height I still don't have
            first = min(list(checkpoint_heights.keys()))
            if first <= my_best_height:
                # If the height of the first checkpoint not validated is lower than the height of the best block
                # Then it's missing this block
                self.log.error('Error initializing the node. Checkpoint validation error.')
                sys.exit()

        # restart all validations possible
        if self.tx_storage.indexes.deps and self.tx_storage.indexes.deps.has_needed_tx():
            self.log.debug('run pending validations')
            depended_final_txs: List[BaseTransaction] = []
            for tx_hash in self.tx_storage.indexes.deps.iter():
                if not self.tx_storage.transaction_exists(tx_hash):
                    continue
                tx = self.tx_storage.get_transaction(tx_hash)
                if tx.get_metadata().validation.is_final():
                    depended_final_txs.append(tx)
            if self.tx_storage.indexes.deps is not None:
                self.sync_v2_step_validations(depended_final_txs)
            self.log.debug('pending validations finished')

        best_height = self.tx_storage.get_height_best_block()
        if best_height != h:
            self.log.warn('best height doesn\'t match', best_height=best_height, max_height=h)

        # self.stop_profiler(save_to='profiles/initializing.prof')
        self.state = self.NodeState.READY

        total_load_time = LogDuration(t2 - t0)
        tx_rate = '?' if total_load_time == 0 else cnt / total_load_time

        environment_info = self.environment_info.as_dict() if self.environment_info else {}

        # Changing the field names in this log could impact log collectors that parse them
        self.log.info('ready', vertex_count=cnt, tx_rate=tx_rate, total_load_time=total_load_time, height=h,
                      blocks=block_count, txs=tx_count, **environment_info)

    def _initialize_components_new(self) -> None:
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

        started_at = int(time.time())
        last_started_at = self.tx_storage.get_last_started_at()
        if last_started_at >= started_at:
            # XXX: although last_started_at==started_at is not _techincally_ to the future, it's strange enough to
            #      deserve a warning, but not special enough to deserve a customized message IMO
            self.log.warn('The last started time is to the future of the current time',
                          started_at=started_at, last_started_at=last_started_at)

        # TODO: this could be either refactored into a migration or at least into it's own method
        # After introducing soft voided transactions we need to guarantee the full node is not using
        # a database that already has the soft voided transaction before marking them in the metadata
        # Any new sync from the beginning should work fine or starting with the latest snapshot
        # that already has the soft voided transactions marked
        for soft_voided_id in self.consensus_algorithm.soft_voided_tx_ids:
            try:
                soft_voided_tx = self.tx_storage.get_transaction(soft_voided_id)
            except TransactionDoesNotExist:
                # This database does not have this tx that should be soft voided
                # so it's fine, we will mark it as soft voided when we get it through sync
                pass
            else:
                soft_voided_meta = soft_voided_tx.get_metadata()
                voided_set = soft_voided_meta.voided_by or set()
                # If the tx is not marked as soft voided, then we can't continue the initialization
                if settings.SOFT_VOIDED_ID not in voided_set:
                    self.log.error(
                        'Error initializing node. Your database is not compatible with the current version of the'
                        ' full node. You must use the latest available snapshot or sync from the beginning.'
                    )
                    sys.exit(-1)

                assert {soft_voided_id, settings.SOFT_VOIDED_ID}.issubset(voided_set)

        # TODO: move support for full-verification here, currently we rely on the original _initialize_components
        #       method for full-verification to work, if we implement it here we'll reduce a lot of duplicate and
        #       complex code
        self.tx_storage.indexes._manually_initialize(self.tx_storage)

        # Verify if all checkpoints that exist in the database are correct
        try:
            self._verify_checkpoints()
        except InitializationError:
            self.log.exception('Initialization error when checking checkpoints, cannot continue.')
            sys.exit()

        # restart all validations possible
        if self.tx_storage.indexes.deps is not None:
            self._sync_v2_resume_validations()

        # XXX: last step before actually starting is updating the last started at timestamps
        self.tx_storage.update_last_started_at(started_at)
        self.state = self.NodeState.READY
        self.pubsub.publish(HathorEvents.LOAD_FINISHED)

        t1 = time.time()
        total_load_time = LogDuration(t1 - t0)

        environment_info = self.environment_info.as_dict() if self.environment_info else {}

        vertex_count = self.tx_storage.get_vertices_count()

        # Changing the field names in this log could impact log collectors that parse them
        self.log.info('ready', vertex_count=vertex_count,
                      total_load_time=total_load_time, **environment_info)

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
                tx = self.tx_storage.get_transaction(checkpoint.hash)
            except TransactionDoesNotExist as e:
                raise InitializationError(f'Expected checkpoint does not exist in database: {checkpoint}') from e
            assert tx.hash is not None
            tx_meta = tx.get_metadata()
            if tx_meta.height != checkpoint.height:
                raise InitializationError(
                    f'Expected checkpoint of hash {tx.hash_hex} to have height {checkpoint.height}, but instead it has'
                    f'height {tx_meta.height}'
                )
            if tx_meta.voided_by:
                pretty_voided_by = list(i.hex() for i in tx_meta.voided_by)
                raise InitializationError(
                    f'Expected checkpoint {checkpoint} to *NOT* be voided, but it is being voided by: '
                    f'{pretty_voided_by}'
                )
            # XXX: query the height index from checkpoint.height and check that the hash matches
            tx_hash = self.tx_storage.indexes.height.get(checkpoint.height)
            if tx_hash is None:
                raise InitializationError(
                    f'Expected checkpoint {checkpoint} to be found in the height index, but it was not found'
                )
            if tx_hash != tx.hash:
                raise InitializationError(
                    f'Expected checkpoint {checkpoint} to be found in the height index, but it instead the block with '
                    f'hash {tx_hash.hex()} was found'
                )

    def _sync_v2_resume_validations(self) -> None:
        """ This method will resume running validations that did not run because the node exited.
        """
        assert self.tx_storage.indexes is not None
        assert self.tx_storage.indexes.deps is not None
        if self.tx_storage.indexes.deps.has_needed_tx():
            self.log.debug('run pending validations')
            depended_final_txs: List[BaseTransaction] = []
            for tx_hash in self.tx_storage.indexes.deps.iter():
                if not self.tx_storage.transaction_exists(tx_hash):
                    continue
                tx = self.tx_storage.get_transaction(tx_hash)
                if tx.get_metadata().validation.is_final():
                    depended_final_txs.append(tx)
            self.sync_v2_step_validations(depended_final_txs)
            self.log.debug('pending validations finished')

    def add_listen_address(self, addr: str) -> None:
        self.listen_addresses.append(addr)

    def add_peer_discovery(self, peer_discovery: PeerDiscovery) -> None:
        self.peer_discoveries.append(peer_discovery)

    def get_new_tx_parents(self, timestamp: Optional[float] = None) -> List[bytes]:
        """Select which transactions will be confirmed by a new transaction.

        :return: The hashes of the parents for a new transaction.
        :rtype: List[bytes(hash)]
        """
        timestamp = timestamp or self.reactor.seconds()
        parent_txs = self.generate_parent_txs(timestamp)
        return list(parent_txs.get_random_parents(self.rng))

    def generate_parent_txs(self, timestamp: Optional[float]) -> 'ParentTxs':
        """Select which transactions will be confirmed by a new block.

        This method tries to return a stable result, such that for a given timestamp and storage state it will always
        return the same.
        """
        if timestamp is None:
            timestamp = self.reactor.seconds()
        can_include_intervals = sorted(self.tx_storage.get_tx_tips(timestamp - 1))
        assert can_include_intervals, 'tips cannot be empty'
        max_timestamp = max(int(i.begin) for i in can_include_intervals)
        must_include: List[bytes] = []
        assert len(can_include_intervals) > 0, f'invalid timestamp "{timestamp}", no tips found"'
        if len(can_include_intervals) < 2:
            # If there is only one tip, let's randomly choose one of its parents.
            must_include_interval = can_include_intervals[0]
            must_include = [must_include_interval.data]
            can_include_intervals = sorted(self.tx_storage.get_tx_tips(must_include_interval.begin - 1))
        can_include = [i.data for i in can_include_intervals]
        return ParentTxs(max_timestamp, can_include, must_include)

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

    def get_block_templates(self, parent_block_hash: Optional[bytes] = None,
                            timestamp: Optional[int] = None) -> BlockTemplates:
        """ Cached version of `make_block_templates`, cache is invalidated when latest_timestamp changes."""
        if parent_block_hash is not None:
            return BlockTemplates([self.make_block_template(parent_block_hash, timestamp)], storage=self.tx_storage)
        return BlockTemplates(self.make_block_templates(timestamp), storage=self.tx_storage)
        # FIXME: the following caching scheme breaks tests:
        # cached_timestamp: Optional[int]
        # cached_block_template: BlockTemplates
        # cached_timestamp, cached_block_template = getattr(self, '_block_templates_cache', (None, None))
        # if cached_timestamp == self.tx_storage.latest_timestamp:
        #     return cached_block_template
        # block_templates = BlockTemplates(self.make_block_templates(), storage=self.tx_storage)
        # setattr(self, '_block_templates_cache', (self.tx_storage.latest_timestamp, block_templates))
        # return block_templates

    def make_block_templates(self, timestamp: Optional[int] = None) -> Iterator[BlockTemplate]:
        """ Makes block templates for all possible best tips as of the latest timestamp.

        Each block template has all the necessary info to build a block to be mined without requiring further
        information from the blockchain state. Which is ideal for use by external mining servers.
        """
        for parent_block_hash in self.tx_storage.get_best_block_tips():
            yield self.make_block_template(parent_block_hash, timestamp)

    def make_block_template(self, parent_block_hash: bytes, timestamp: Optional[int] = None) -> BlockTemplate:
        """ Makes a block template using the given parent block.
        """
        parent_block = self.tx_storage.get_transaction(parent_block_hash)
        assert isinstance(parent_block, Block)
        parent_txs = self.generate_parent_txs(parent_block.timestamp + settings.MAX_DISTANCE_BETWEEN_BLOCKS)
        if timestamp is None:
            current_timestamp = int(max(self.tx_storage.latest_timestamp, self.reactor.seconds()))
        else:
            current_timestamp = timestamp
        return self._make_block_template(parent_block, parent_txs, current_timestamp)

    def make_custom_block_template(self, parent_block_hash: bytes, parent_tx_hashes: List[bytes],
                                   timestamp: Optional[int] = None) -> BlockTemplate:
        """ Makes a block template using the given parent block and txs.
        """
        parent_block = self.tx_storage.get_transaction(parent_block_hash)
        assert isinstance(parent_block, Block)
        # gather the actual txs to query their timestamps
        parent_tx_list: List[Transaction] = []
        for tx_hash in parent_tx_hashes:
            tx = self.tx_storage.get_transaction(tx_hash)
            assert isinstance(tx, Transaction)
            parent_tx_list.append(tx)
        max_timestamp = max(tx.timestamp for tx in parent_tx_list)
        parent_txs = ParentTxs(max_timestamp, parent_tx_hashes, [])
        if timestamp is None:
            current_timestamp = int(max(self.tx_storage.latest_timestamp, self.reactor.seconds()))
        else:
            current_timestamp = timestamp
        return self._make_block_template(parent_block, parent_txs, current_timestamp)

    def _make_block_template(self, parent_block: Block, parent_txs: 'ParentTxs', current_timestamp: int,
                             with_weight_decay: bool = False) -> BlockTemplate:
        """ Further implementation of making block template, used by make_block_template and make_custom_block_template
        """
        assert parent_block.hash is not None
        # the absolute minimum would be the previous timestamp + 1
        timestamp_abs_min = parent_block.timestamp + 1
        # and absolute maximum limited by max time between blocks
        if not parent_block.is_genesis:
            timestamp_abs_max = parent_block.timestamp + settings.MAX_DISTANCE_BETWEEN_BLOCKS - 1
        else:
            timestamp_abs_max = 0xffffffff
        assert timestamp_abs_max > timestamp_abs_min
        # actual minimum depends on the timestamps of the parent txs
        # it has to be at least the max timestamp of parents + 1
        timestamp_min = max(timestamp_abs_min, parent_txs.max_timestamp + 1)
        assert timestamp_min <= timestamp_abs_max
        # when we have weight decay, the max timestamp will be when the next decay happens
        if with_weight_decay and settings.WEIGHT_DECAY_ENABLED:
            # we either have passed the first decay or not, the range will vary depending on that
            if timestamp_min > timestamp_abs_min + settings.WEIGHT_DECAY_ACTIVATE_DISTANCE:
                timestamp_max_decay = timestamp_min + settings.WEIGHT_DECAY_WINDOW_SIZE
            else:
                timestamp_max_decay = timestamp_abs_min + settings.WEIGHT_DECAY_ACTIVATE_DISTANCE
            timestamp_max = min(timestamp_abs_max, timestamp_max_decay)
        else:
            timestamp_max = timestamp_abs_max
        timestamp = min(max(current_timestamp, timestamp_min), timestamp_max)
        parent_block_metadata = parent_block.get_metadata()
        # this is the min weight to cause an increase of twice the WEIGHT_TOL, we make sure to generate a template with
        # at least this weight (note that the user of the API can set its own weight, the block sumit API will also
        # protect agains a weight that is too small but using WEIGHT_TOL instead of 2*WEIGHT_TOL)
        min_significant_weight = calculate_min_significant_weight(parent_block_metadata.score, 2 * settings.WEIGHT_TOL)
        weight = max(daa.calculate_next_weight(parent_block, timestamp), min_significant_weight)
        height = parent_block_metadata.height + 1
        parents = [parent_block.hash] + parent_txs.must_include
        parents_any = parent_txs.can_include
        # simplify representation when you only have one to choose from
        if len(parents) + len(parents_any) == 3:
            parents.extend(sorted(parents_any))
            parents_any = []
        assert len(parents) + len(parents_any) >= 3, 'There should be enough parents to choose from'
        assert 1 <= len(parents) <= 3, 'Impossible number of parents'
        if __debug__ and len(parents) == 3:
            assert len(parents_any) == 0, 'Extra parents to choose from that cannot be chosen'
        return BlockTemplate(
            versions={TxVersion.REGULAR_BLOCK.value, TxVersion.MERGE_MINED_BLOCK.value},
            reward=daa.get_tokens_issued_per_block(height),
            weight=weight,
            timestamp_now=current_timestamp,
            timestamp_min=timestamp_min,
            timestamp_max=timestamp_max,
            parents=parents,
            parents_any=parents_any,
            height=height,
            score=sum_weights(parent_block_metadata.score, weight),
        )

    def generate_mining_block(self, timestamp: Optional[int] = None,
                              parent_block_hash: Optional[bytes] = None,
                              data: bytes = b'', address: Optional[bytes] = None,
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
            merge_mined=merge_mined,
            address=address or None,  # XXX: because we allow b'' for explicit empty output script
            data=data,
        )
        return block

    def get_tokens_issued_per_block(self, height: int) -> int:
        """Return the number of tokens issued (aka reward) per block of a given height."""
        return daa.get_tokens_issued_per_block(height)

    def submit_block(self, blk: Block, fails_silently: bool = True) -> bool:
        """Used by submit block from all mining APIs.
        """
        tips = self.tx_storage.get_best_block_tips()
        parent_hash = blk.get_block_parent_hash()
        if parent_hash not in tips:
            self.log.warn('submit_block(): Ignoring block: parent not a tip', blk=blk.hash_hex)
            return False
        parent_block = self.tx_storage.get_transaction(parent_hash)
        parent_block_metadata = parent_block.get_metadata()
        # this is the smallest weight that won't cause the score to increase, anything equal or smaller is bad
        min_insignificant_weight = calculate_min_significant_weight(parent_block_metadata.score, settings.WEIGHT_TOL)
        if blk.weight <= min_insignificant_weight:
            self.log.warn('submit_block(): insignificant weight? accepted anyway', blk=blk.hash_hex, weight=blk.weight)
        return self.propagate_tx(blk, fails_silently=fails_silently)

    def push_tx(self, tx: Transaction, allow_non_standard_script: bool = False,
                max_output_script_size: int = settings.PUSHTX_MAX_OUTPUT_SCRIPT_SIZE) -> None:
        """Used by all APIs that accept a new transaction (like push_tx)
        """
        is_double_spending = tx.is_double_spending()
        if is_double_spending:
            raise DoubleSpendingError('Invalid transaction. At least one of your inputs has already been spent.')

        is_spending_voided_tx = tx.is_spending_voided_tx()
        if is_spending_voided_tx:
            raise SpendingVoidedError('Invalid transaction. At least one input is voided.')

        is_spent_reward_locked = tx.is_spent_reward_locked()
        if is_spent_reward_locked:
            raise RewardLockedError('Spent reward is locked.')

        # We are using here the method from lib because the property
        # to identify a nft creation transaction was created on the lib
        # to be used in the full node and tx mining service
        # TODO: avoid reparsing when hathorlib is fully compatible
        tx_from_lib = lib_tx_or_block_from_bytes(bytes(tx))
        if not tx_from_lib.is_standard(max_output_script_size, not allow_non_standard_script):
            raise NonStandardTxError('Transaction is non standard.')

        # Validate tx.
        success, message = tx.validate_tx_error()
        if not success:
            raise InvalidNewTransaction(message)

        self.propagate_tx(tx, fails_silently=False)

    def propagate_tx(self, tx: BaseTransaction, fails_silently: bool = True) -> bool:
        """Push a new transaction to the network. It is used by both the wallet and the mining modules.

        :return: True if the transaction was accepted
        :rtype: bool
        """
        if tx.storage:
            assert tx.storage == self.tx_storage, 'Invalid tx storage'
        else:
            tx.storage = self.tx_storage

        return self.on_new_tx(tx, fails_silently=fails_silently, propagate_to_peers=True)

    @cpu.profiler('on_new_tx')
    def on_new_tx(self, tx: BaseTransaction, *, conn: Optional[HathorProtocol] = None,
                  quiet: bool = False, fails_silently: bool = True, propagate_to_peers: bool = True,
                  skip_block_weight_verification: bool = False, sync_checkpoints: bool = False,
                  partial: bool = False, reject_locked_reward: bool = True) -> bool:
        """ New method for adding transactions or blocks that steps the validation state machine.

        :param tx: transaction to be added
        :param conn: optionally specify the protocol instance where this tx was received from
        :param quiet: if True will not log when a new tx is accepted
        :param fails_silently: if False will raise an exception when tx cannot be added
        :param propagate_to_peers: if True will relay the tx to other peers if it is accepted
        :param skip_block_weight_verification: if True will not check the tx PoW
        :param sync_checkpoints: if True and also partial=True, will try to validate as a checkpoint and set the proper
                                 validation state, this is used for adding txs from the sync-checkpoints phase
        :param partial: if True will accept txs that can't be fully validated yet (because of missing parent/input) but
                        will run a basic validation of what can be validated (PoW and other basic fields)
        """
        assert tx.hash is not None
        if self.tx_storage.transaction_exists(tx.hash):
            self.tx_storage.compare_bytes_with_local_tx(tx)
            if not fails_silently:
                raise InvalidNewTransaction('Transaction already exists {}'.format(tx.hash_hex))
            self.log.warn('on_new_tx(): Transaction already exists', tx=tx.hash_hex)
            return False

        if tx.timestamp - self.reactor.seconds() > settings.MAX_FUTURE_TIMESTAMP_ALLOWED:
            if not fails_silently:
                raise InvalidNewTransaction('Ignoring transaction in the future {} (timestamp={})'.format(
                    tx.hash_hex, tx.timestamp))
            self.log.warn('on_new_tx(): Ignoring transaction in the future', tx=tx.hash_hex,
                          future_timestamp=tx.timestamp)
            return False

        assert self.tx_storage.indexes is not None
        tx.storage = self.tx_storage

        try:
            metadata = tx.get_metadata()
        except TransactionDoesNotExist:
            if not fails_silently:
                raise InvalidNewTransaction('missing parent')
            self.log.warn('on_new_tx(): missing parent', tx=tx.hash_hex)
            return False

        if metadata.validation.is_invalid():
            if not fails_silently:
                raise InvalidNewTransaction('previously marked as invalid')
            self.log.warn('on_new_tx(): previously marked as invalid', tx=tx.hash_hex)
            return False

        # if partial=False (the default) we don't even try to partially validate transactions
        if not partial or (metadata.validation.is_fully_connected() or tx.can_validate_full()):
            if not metadata.validation.is_fully_connected():
                try:
                    tx.validate_full(sync_checkpoints=sync_checkpoints, reject_locked_reward=reject_locked_reward)
                except HathorError as e:
                    if not fails_silently:
                        raise InvalidNewTransaction('full validation failed') from e
                    self.log.warn('on_new_tx(): full validation failed', tx=tx.hash_hex, exc_info=True)
                    return False

            # The method below adds the tx as a child of the parents
            # This needs to be called right before the save because we were adding the children
            # in the tx parents even if the tx was invalid (failing the verifications above)
            # then I would have a children that was not in the storage
            tx.update_initial_metadata(save=False)
            self.tx_storage.save_transaction(tx)
            self.tx_storage.add_to_indexes(tx)
            try:
                self.consensus_algorithm.update(tx)
            except HathorError as e:
                if not fails_silently:
                    raise InvalidNewTransaction('consensus update failed') from e
                self.log.warn('on_new_tx(): consensus update failed', tx=tx.hash_hex)
                return False
            else:
                assert tx.validate_full(skip_block_weight_verification=True, reject_locked_reward=reject_locked_reward)
                self.tx_storage.indexes.update(tx)
                if self.tx_storage.indexes.mempool_tips:
                    self.tx_storage.indexes.mempool_tips.update(tx)  # XXX: move to indexes.update
                self.tx_fully_validated(tx)
        elif sync_checkpoints:
            assert self.tx_storage.indexes.deps is not None
            metadata.children = self.tx_storage.indexes.deps.known_children(tx)
            try:
                tx.validate_checkpoint(self.checkpoints)
            except HathorError:
                if not fails_silently:
                    raise InvalidNewTransaction('checkpoint validation failed')
                self.log.warn('on_new_tx(): checkpoint validation failed', tx=tx.hash_hex, exc_info=True)
                return False
            self.tx_storage.save_transaction(tx)
        else:
            if isinstance(tx, Block) and not tx.has_basic_block_parent():
                if not fails_silently:
                    raise InvalidNewTransaction('block parent needs to be at least basic-valid')
                self.log.warn('on_new_tx(): block parent needs to be at least basic-valid', tx=tx.hash_hex)
                return False
            if not tx.validate_basic():
                if not fails_silently:
                    raise InvalidNewTransaction('basic validation failed')
                self.log.warn('on_new_tx(): basic validation failed', tx=tx.hash_hex)
                return False

            # The method below adds the tx as a child of the parents
            # This needs to be called right before the save because we were adding the children
            # in the tx parents even if the tx was invalid (failing the verifications above)
            # then I would have a children that was not in the storage
            tx.update_initial_metadata(save=False)
            self.tx_storage.save_transaction(tx)

        if tx.is_transaction and self.tx_storage.indexes.deps is not None:
            self.tx_storage.indexes.deps.remove_from_needed_index(tx.hash)

        if self.tx_storage.indexes.deps is not None:
            try:
                self.sync_v2_step_validations([tx])
            except (AssertionError, HathorError) as e:
                if not fails_silently:
                    raise InvalidNewTransaction('step validations failed') from e
                self.log.warn('on_new_tx(): step validations failed', tx=tx.hash_hex, exc_info=True)
                return False

        if not quiet:
            ts_date = datetime.datetime.fromtimestamp(tx.timestamp)
            now = datetime.datetime.fromtimestamp(self.reactor.seconds())
            if tx.is_block:
                self.log.info('new block', tx=tx, ts_date=ts_date, time_from_now=tx.get_time_from_now(now))
            else:
                self.log.info('new tx', tx=tx, ts_date=ts_date, time_from_now=tx.get_time_from_now(now))

        if propagate_to_peers:
            # Propagate to our peers.
            self.connections.send_tx_to_peers(tx)

        return True

    def sync_v2_step_validations(self, txs: Iterable[BaseTransaction]) -> None:
        """ Step all validations until none can be stepped anymore.
        """
        assert self.tx_storage.indexes is not None
        assert self.tx_storage.indexes.deps is not None
        # cur_txs will be empty when there are no more new txs that reached full
        # validation because of an initial trigger
        for ready_tx in txs:
            assert ready_tx.hash is not None
            self.tx_storage.indexes.deps.remove_ready_for_validation(ready_tx.hash)
        it_next_ready = self.tx_storage.indexes.deps.next_ready_for_validation(self.tx_storage)
        for tx in map(self.tx_storage.get_transaction, it_next_ready):
            assert tx.hash is not None
            tx.update_initial_metadata()
            try:
                # XXX: `reject_locked_reward` might not apply, partial validation is only used on sync-v2
                # TODO: deal with `reject_locked_reward` on sync-v2
                assert tx.validate_full(reject_locked_reward=True)
            except (AssertionError, HathorError):
                # TODO
                raise
            else:
                self.tx_storage.add_to_indexes(tx)
                self.consensus_algorithm.update(tx)
                self.tx_storage.indexes.update(tx)
                if self.tx_storage.indexes.mempool_tips:
                    self.tx_storage.indexes.mempool_tips.update(tx)  # XXX: move to indexes.update
                self.tx_fully_validated(tx)

    def tx_fully_validated(self, tx: BaseTransaction) -> None:
        """ Handle operations that need to happen once the tx becomes fully validated.

        This might happen immediately after we receive the tx, if we have all dependencies
        already. Or it might happen later.
        """
        assert tx.hash is not None
        assert self.tx_storage.indexes is not None

        # Publish to pubsub manager the new tx accepted, now that it's full validated
        self.pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED, tx=tx)

        if self.tx_storage.indexes.mempool_tips:
            self.tx_storage.indexes.mempool_tips.update(tx)

        if self.wallet:
            # TODO Remove it and use pubsub instead.
            self.wallet.on_new_tx(tx)

    def listen(self, description: str, use_ssl: Optional[bool] = None) -> None:
        endpoint = self.connections.listen(description, use_ssl)
        # XXX: endpoint: IStreamServerEndpoint does not intrinsically have a port, but in practice all concrete cases
        #      that we have will have a _port attribute
        port = getattr(endpoint, '_port', None)

        if self.hostname:
            proto, _, _ = description.partition(':')
            address = '{}://{}:{}'.format(proto, self.hostname, port)
            self.my_peer.entrypoints.append(address)

    def has_sync_version_capability(self) -> bool:
        return settings.CAPABILITY_SYNC_VERSION in self.capabilities

    def add_peer_to_whitelist(self, peer_id):
        if not settings.ENABLE_PEER_WHITELIST:
            return

        if peer_id in self.peers_whitelist:
            self.log.info('peer already in whitelist', peer_id=peer_id)
        else:
            self.peers_whitelist.append(peer_id)

    def remove_peer_from_whitelist_and_disconnect(self, peer_id: str) -> None:
        if not settings.ENABLE_PEER_WHITELIST:
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
        maximum_timestamp_delta = settings.P2P_RECENT_ACTIVITY_THRESHOLD_MULTIPLIER * settings.AVG_TIME_BETWEEN_BLOCKS

        if current_timestamp - latest_blockchain_timestamp > maximum_timestamp_delta:
            return False

        return True

    def is_healthy(self) -> Tuple[bool, Optional[str]]:
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


class ParentTxs(NamedTuple):
    """ Tuple where the `must_include` hash, when present (at most 1), must be included in a pair, and a list of hashes
    where any of them can be included. This is done in order to make sure that when there is only one tx tip, it is
    included.
    """
    max_timestamp: int
    can_include: List[bytes]
    must_include: List[bytes]

    def get_random_parents(self, rng: Random) -> Tuple[bytes, bytes]:
        """ Get parents from self.parents plus a random choice from self.parents_any to make it 3 in total.

        Using tuple as return type to make it explicit that the length is always 2.
        """
        assert len(self.must_include) <= 1
        fill = rng.ordered_sample(self.can_include, 2 - len(self.must_include))
        p1, p2 = self.must_include[:] + fill
        return p1, p2

    def get_all_tips(self) -> List[bytes]:
        """All generated "tips", can_include + must_include."""
        return self.must_include + self.can_include
