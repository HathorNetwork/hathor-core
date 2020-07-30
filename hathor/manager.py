"""
Copyright 2019 Hathor Labs

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import datetime
import json
import random
import time
from enum import Enum, IntFlag
from math import log
from typing import Any, List, Optional, Type, Union, cast

from structlog import get_logger
from twisted.internet import defer
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IReactorCore
from twisted.python.threadpool import ThreadPool

import hathor.util
from hathor.conf import HathorSettings
from hathor.consensus import ConsensusAlgorithm
from hathor.exception import InvalidNewTransaction
from hathor.indexes import TokensIndex, WalletIndex
from hathor.p2p.peer_discovery import PeerDiscovery
from hathor.p2p.peer_id import PeerId
from hathor.p2p.protocol import HathorProtocol
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.stratum import StratumFactory
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, TxOutput, sum_weights
from hathor.transaction.exceptions import TxValidationError
from hathor.transaction.storage import TransactionStorage
from hathor.wallet import BaseWallet

settings = HathorSettings()
logger = get_logger()


class TestMode(IntFlag):
    DISABLED = 0
    TEST_TX_WEIGHT = 1
    TEST_BLOCK_WEIGHT = 2
    TEST_ALL_WEIGHT = 3


class HathorManager:
    """ HathorManager manages the node with the help of other specialized classes.

    Its primary objective is to handle DAG-related matters, ensuring that the DAG is always valid and connected.
    """

    class NodeState(Enum):
        # This node is still initializing
        INITIALIZING = 'INITIALIZING'

        # This node is ready to establish new connections, sync, and exchange transactions.
        READY = 'READY'

    def __init__(self, reactor: IReactorCore, peer_id: Optional[PeerId] = None, network: Optional[str] = None,
                 hostname: Optional[str] = None, pubsub: Optional[PubSubManager] = None,
                 wallet: Optional[BaseWallet] = None, tx_storage: Optional[TransactionStorage] = None,
                 peer_storage: Optional[Any] = None, default_port: int = 40403, wallet_index: bool = False,
                 stratum_port: Optional[int] = None, min_block_weight: Optional[int] = None, ssl: bool = True) -> None:
        """
        :param reactor: Twisted reactor which handles the mainloop and the events.
        :param peer_id: Id of this node. If not given, a new one is created.
        :param network: Name of the network this node participates. Usually it is either testnet or mainnet.
        :type network: string

        :param hostname: The hostname of this node. It is used to generate its entrypoints.
        :type hostname: string

        :param pubsub: If not given, a new one is created.
        :type pubsub: :py:class:`hathor.pubsub.PubSubManager`

        :param tx_storage: If not given, a :py:class:`TransactionMemoryStorage` one is created.
        :type tx_storage: :py:class:`hathor.transaction.storage.transaction_storage.TransactionStorage`

        :param peer_storage: If not given, a new one is created.
        :type peer_storage: :py:class:`hathor.p2p.peer_storage.PeerStorage`

        :param default_port: Network default port. It is used when only ip addresses are discovered.
        :type default_port: int

        :param wallet_index: If should add a wallet index in the storage
        :type wallet_index: bool

        :param stratum_port: Stratum server port. Stratum server will only be created if it is not None.
        :type stratum_port: Optional[int]

        :param min_block_weight: Minimum weight for blocks.
        :type min_block_weight: Optional[int]
        """
        from hathor.p2p.factory import HathorServerFactory, HathorClientFactory
        from hathor.p2p.manager import ConnectionsManager
        from hathor.transaction.storage.memory_storage import TransactionMemoryStorage
        from hathor.metrics import Metrics

        self.log = logger.new()

        self.reactor = reactor
        if hasattr(self.reactor, 'addSystemEventTrigger'):
            self.reactor.addSystemEventTrigger('after', 'shutdown', self.stop)

        self.state: Optional[HathorManager.NodeState] = None
        self.profiler: Optional[Any] = None

        # Hostname, used to be accessed by other peers.
        self.hostname = hostname

        # Remote address, which can be different from local address.
        self.remote_address = None

        self.my_peer = peer_id or PeerId()
        self.network = network or 'testnet'

        # XXX Should we use a singleton or a new PeerStorage? [msbrogli 2018-08-29]
        self.pubsub = pubsub or PubSubManager(self.reactor)
        self.tx_storage = tx_storage or TransactionMemoryStorage()
        self.tx_storage.pubsub = self.pubsub
        if wallet_index and self.tx_storage.with_index:
            self.tx_storage.wallet_index = WalletIndex(self.pubsub)
            self.tx_storage.tokens_index = TokensIndex()

        self.avg_time_between_blocks = settings.AVG_TIME_BETWEEN_BLOCKS
        self.min_block_weight = min_block_weight or settings.MIN_BLOCK_WEIGHT

        self.metrics = Metrics(
            pubsub=self.pubsub,
            avg_time_between_blocks=self.avg_time_between_blocks,
            tx_storage=self.tx_storage,
            reactor=self.reactor,
        )

        self.consensus_algorithm = ConsensusAlgorithm()

        self.peer_discoveries: List[PeerDiscovery] = []

        self.ssl = ssl
        self.server_factory = HathorServerFactory(self.network, self.my_peer, node=self, use_ssl=ssl)
        self.client_factory = HathorClientFactory(self.network, self.my_peer, node=self, use_ssl=ssl)
        self.connections = ConnectionsManager(self.reactor, self.my_peer, self.server_factory, self.client_factory,
                                              self.pubsub, self, ssl)

        self.wallet = wallet
        if self.wallet:
            self.wallet.pubsub = self.pubsub
            self.wallet.reactor = self.reactor

        # When manager is in test mode we reduce the weight of blocks/transactions.
        self.test_mode: int = 0

        self.stratum_factory = StratumFactory(manager=self, port=stratum_port) if stratum_port else None
        # Set stratum factory for metrics object
        self.metrics.stratum_factory = self.stratum_factory

        self._allow_mining_without_peers = False

        # Thread pool used to resolve pow when sending tokens
        self.pow_thread_pool = ThreadPool(minthreads=0, maxthreads=settings.MAX_POW_THREADS, name='Pow thread pool')

        # List of addresses to listen for new connections (eg: [tcp:8000])
        self.listen_addresses: List[str] = []

    def start(self) -> None:
        """ A factory must be started only once. And it is usually automatically started.
        """
        self.log.info('Starting HathorManager...')
        self.log.info('Network: {network}', network=self.network)
        self.state = self.NodeState.INITIALIZING
        self.pubsub.publish(HathorEvents.MANAGER_ON_START)
        self.connections.start()
        self.pow_thread_pool.start()

        # Initialize manager's components.
        self._initialize_components()

        for description in self.listen_addresses:
            self.listen(description, ssl=self.ssl)

        for peer_discovery in self.peer_discoveries:
            peer_discovery.discover_and_connect(self.connections.connect_to)

        self.start_time = time.time()

        # Metric starts to capture data
        self.metrics.start()

        if self.wallet:
            self.wallet.start()

        if self.stratum_factory:
            self.stratum_factory.start()

    def stop(self) -> Deferred:
        waits = []

        self.log.info('Stopping HathorManager...')
        self.connections.stop()
        self.pubsub.publish(HathorEvents.MANAGER_ON_STOP)
        if self.pow_thread_pool.started:
            self.pow_thread_pool.stop()

        # Metric stops to capture data
        self.metrics.stop()

        if self.wallet:
            self.wallet.stop()

        if self.stratum_factory:
            wait_stratum = self.stratum_factory.stop()
            if wait_stratum:
                waits.append(wait_stratum)

        return defer.DeferredList(waits)

    def start_profiler(self) -> None:
        """
        Start profiler. It can be activated from a web resource, as well.
        """
        if not self.profiler:
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
        self.log.info('Initializing node...')
        if self.wallet:
            self.wallet._manually_initialize()
        t0 = time.time()
        t1 = t0
        cnt = 0
        cnt2 = 0

        block_count = 0

        # self.start_profiler()
        for tx in self.tx_storage._topological_sort():
            assert tx.hash is not None

            t2 = time.time()
            if t2 - t1 > 5:
                ts_date = datetime.datetime.fromtimestamp(self.tx_storage.latest_timestamp)
                self.log.info(
                    'Verifying transations in storage... avg={avg:.4f} tx/s total={total} (latest timedate: {ts})',
                    avg=(cnt - cnt2) / (t2 - t1),
                    total=cnt,
                    ts=ts_date,
                )
                t1 = t2
                cnt2 = cnt
            cnt += 1

            # It's safe to skip block weight verification during initialization because
            # we trust the difficulty stored in metadata
            skip_block_weight_verification = True
            if block_count % settings.VERIFY_WEIGHT_EVERY_N_BLOCKS == 0:
                skip_block_weight_verification = False

            try:
                assert self.on_new_tx(
                    tx,
                    quiet=True,
                    fails_silently=False,
                    skip_block_weight_verification=skip_block_weight_verification
                )
            except (InvalidNewTransaction, TxValidationError):
                pretty_json = json.dumps(tx.to_json(), indent=4)
                self.log.error('An unexpected error occurred when initializing {tx.hash_hex}\n'
                               '{pretty_json}', tx=tx, pretty_json=pretty_json)
                raise

            if tx.is_block:
                block_count += 1

            if time.time() - t2 > 1:
                self.log.warn('Warning: {} took {} seconds to be processed.'.format(tx.hash.hex(), time.time() - t2))

        # self.stop_profiler(save_to='profiles/initializing.prof')
        self.state = self.NodeState.READY
        self.log.info(
            'Node successfully initialized (total={total}, avg={avg:.2f} tx/s in {dt} seconds).',
            total=cnt,
            avg=cnt / (t2 - t0),
            dt=t2 - t0,
        )

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
        ret = list(self.tx_storage.get_tx_tips(timestamp - 1))
        random.shuffle(ret)
        ret = ret[:2]
        if len(ret) == 1:
            # If there is only one tip, let's randomly choose one of its parents.
            parents = list(self.tx_storage.get_tx_tips(ret[0].begin - 1))
            ret.append(random.choice(parents))
        assert len(ret) == 2, 'timestamp={} tips={}'.format(
            timestamp, [x.hex() for x in self.tx_storage.get_tx_tips(timestamp - 1)])
        return [x.data for x in ret]

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

    def generate_mining_block(self, timestamp: Optional[float] = None,
                              parent_block_hash: Optional[bytes] = None,
                              data: bytes = b'', address: Optional[bytes] = None,
                              merge_mined: bool = False) -> Union[Block, MergeMinedBlock]:
        """ Generates a block ready to be mined. The block includes new issued tokens,
        parents, and the weight.

        :return: A block ready to be mined
        :rtype: :py:class:`hathor.transaction.Block`
        """
        from hathor.transaction.scripts import create_output_script

        if parent_block_hash is None:
            tip_blocks = self.tx_storage.get_best_block_tips(timestamp)
        else:
            tip_blocks = [parent_block_hash]

        # We must update it after choosing the parent block, so we may benefit from cache.
        if timestamp is None:
            timestamp = max(self.tx_storage.latest_timestamp, self.reactor.seconds())

        parent_block = self.tx_storage.get_transaction(random.choice(tip_blocks))
        if not parent_block.is_genesis and timestamp - parent_block.timestamp > settings.MAX_DISTANCE_BETWEEN_BLOCKS:
            timestamp = parent_block.timestamp + settings.MAX_DISTANCE_BETWEEN_BLOCKS

        assert timestamp is not None
        tip_txs = self.get_new_tx_parents(timestamp - 1)

        assert len(tip_blocks) >= 1
        assert len(tip_txs) == 2

        parents = [parent_block.hash] + tip_txs

        parents_tx = [self.tx_storage.get_transaction(x) for x in parents]

        timestamp1 = int(timestamp)
        timestamp2 = max(x.timestamp for x in parents_tx) + 1

        if address is None:
            if self.wallet is None:
                raise ValueError('No wallet available and no mining address given')
            address = self.wallet.get_unused_address_bytes(mark_as_used=False)
        assert address is not None

        height = parent_block.get_metadata().height + 1
        amount = self.get_tokens_issued_per_block(height)
        output_script = create_output_script(address) if address else b''
        tx_outputs = [TxOutput(amount, output_script)]

        cls: Union[Type['Block'], Type['MergeMinedBlock']]
        if merge_mined:
            cls = MergeMinedBlock
        else:
            cls = Block
        blk = cls(outputs=tx_outputs, parents=parents, storage=self.tx_storage, data=data)
        blk.timestamp = max(timestamp1, timestamp2)
        blk.weight = self.calculate_block_difficulty(blk)
        blk.get_metadata(use_storage=False)
        return blk

    def get_tokens_issued_per_block(self, height: int) -> int:
        """Return the number of tokens issued (aka reward) per block of a given height."""
        return hathor.util._get_tokens_issued_per_block(height)

    def validate_new_tx(self, tx: BaseTransaction, skip_block_weight_verification: bool = False) -> bool:
        """ Process incoming transaction during initialization.
        These transactions came only from storage.
        """
        assert tx.hash is not None

        if self.state == self.NodeState.INITIALIZING:
            if tx.is_genesis:
                return True

        else:
            if tx.is_genesis:
                raise InvalidNewTransaction('Genesis? {}'.format(tx.hash.hex()))

        if tx.timestamp - self.reactor.seconds() > settings.MAX_FUTURE_TIMESTAMP_ALLOWED:
            raise InvalidNewTransaction('Ignoring transaction in the future {} (timestamp={})'.format(
                tx.hash.hex(), tx.timestamp))

        # Verify transaction and raises an TxValidationError if tx is not valid.
        tx.verify()

        if tx.is_block:
            tx = cast(Block, tx)
            assert tx.hash is not None  # XXX: it appears that after casting this assert "casting" is lost

            if not skip_block_weight_verification:
                # Validate minimum block difficulty
                block_weight = self.calculate_block_difficulty(tx)
                if tx.weight < block_weight - settings.WEIGHT_TOL:
                    raise InvalidNewTransaction(
                        'Invalid new block {}: weight ({}) is smaller than the minimum weight ({})'.format(
                            tx.hash.hex(), tx.weight, block_weight
                        )
                    )

            parent_block = tx.get_block_parent()
            tokens_issued_per_block = self.get_tokens_issued_per_block(parent_block.get_metadata().height + 1)
            if tx.sum_outputs != tokens_issued_per_block:
                raise InvalidNewTransaction(
                    'Invalid number of issued tokens tag=invalid_issued_tokens'
                    ' tx.hash={tx.hash_hex} issued={tx.sum_outputs} allowed={allowed}'.format(
                        tx=tx,
                        allowed=tokens_issued_per_block,
                    )
                )
        else:
            assert tx.hash is not None  # XXX: it appears that after casting this assert "casting" is lost

            # Validate minimum tx difficulty
            min_tx_weight = self.minimum_tx_weight(tx)
            if tx.weight < min_tx_weight - settings.WEIGHT_TOL:
                raise InvalidNewTransaction(
                    'Invalid new tx {}: weight ({}) is smaller than the minimum weight ({})'.format(
                        tx.hash.hex(), tx.weight, min_tx_weight
                    )
                )

        return True

    def propagate_tx(self, tx: BaseTransaction, fails_silently: bool = True) -> bool:
        """Push a new transaction to the network. It is used by both the wallet and the mining modules.

        :return: True if the transaction was accepted
        :rtype: bool
        """
        if tx.storage:
            assert tx.storage == self.tx_storage, 'Invalid tx storage'
        else:
            tx.storage = self.tx_storage
        return self.on_new_tx(tx, fails_silently=fails_silently)

    def on_new_tx(self, tx: BaseTransaction, *, conn: Optional[HathorProtocol] = None,
                  quiet: bool = False, fails_silently: bool = True, propagate_to_peers: bool = True,
                  skip_block_weight_verification: bool = False) -> bool:
        """This method is called when any transaction arrive.

        If `fails_silently` is False, it may raise either InvalidNewTransaction or TxValidationError.

        :return: True if the transaction was accepted
        :rtype: bool
        """
        assert tx.hash is not None
        if self.state != self.NodeState.INITIALIZING:
            if self.tx_storage.transaction_exists(tx.hash):
                if not fails_silently:
                    raise InvalidNewTransaction('Transaction already exists {}'.format(tx.hash.hex()))
                self.log.debug('on_new_tx(): Already have transaction {}'.format(tx.hash.hex()))
                return False

        try:
            assert self.validate_new_tx(tx, skip_block_weight_verification=skip_block_weight_verification) is True
        except (InvalidNewTransaction, TxValidationError) as e:
            # Discard invalid Transaction/block.
            self.log.debug('Transaction/Block discarded', tx=tx, exc=e)
            if not fails_silently:
                raise
            return False

        if self.state != self.NodeState.INITIALIZING:
            self.tx_storage.save_transaction(tx)
        else:
            tx.reset_metadata()
            self.tx_storage._add_to_cache(tx)

        try:
            tx.update_initial_metadata()
            self.consensus_algorithm.update(tx)
        except Exception:
            pretty_json = json.dumps(tx.to_json(), indent=4)
            self.log.error('An unexpected error occurred when processing {tx.hash_hex}\n'
                           '{pretty_json}', tx=tx, pretty_json=pretty_json)
            self.tx_storage.remove_transaction(tx)
            raise

        if not quiet:
            ts_date = datetime.datetime.fromtimestamp(tx.timestamp)
            if tx.is_block:
                self.log.info('New block found',
                              tag='new_block', tx=tx, ts_date=ts_date, time_from_now=tx.get_time_from_now())
            else:
                self.log.info('New transaction found',
                              tag='new_tx', tx=tx, ts_date=ts_date, time_from_now=tx.get_time_from_now())

        if propagate_to_peers:
            # Propagate to our peers.
            self.connections.send_tx_to_peers(tx)

        if self.wallet:
            # TODO Remove it and use pubsub instead.
            self.wallet.on_new_tx(tx)

        # Publish to pubsub manager the new tx accepted
        self.pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED, tx=tx)

        return True

    def get_weight_decay_amount(self, distance: int) -> float:
        """Return the amount to be reduced in the weight of the block."""
        if not settings.WEIGHT_DECAY_ENABLED:
            return 0.0
        if distance < settings.WEIGHT_DECAY_ACTIVATE_DISTANCE:
            return 0.0

        dt = distance - settings.WEIGHT_DECAY_ACTIVATE_DISTANCE

        # Calculate the number of windows.
        n_windows = 1 + (dt // settings.WEIGHT_DECAY_WINDOW_SIZE)
        return n_windows * settings.WEIGHT_DECAY_AMOUNT

    def calculate_block_difficulty(self, block: Block) -> float:
        """ Calculate block difficulty according to the ascendents of `block`, aka DAA/difficulty adjustment algorithm

        The algorithm used is described in [RFC 22](https://gitlab.com/HathorNetwork/rfcs/merge_requests/22).

        The new difficulty must not be less than `self.min_block_weight`.
        """
        # In test mode we don't validate the block difficulty
        if self.test_mode & TestMode.TEST_BLOCK_WEIGHT:
            return 1.0

        if block.is_genesis:
            return self.min_block_weight

        root = block
        parent = root.get_block_parent()
        N = min(2 * settings.BLOCK_DIFFICULTY_N_BLOCKS, parent.get_metadata().height - 1)
        K = N // 2
        T = self.avg_time_between_blocks
        S = 5
        if N < 10:
            return self.min_block_weight

        blocks: List[Block] = []
        while len(blocks) < N + 1:
            root = root.get_block_parent()
            assert isinstance(root, Block)
            assert root is not None
            blocks.append(root)

        # TODO: revise if this assertion can be safely removed
        assert blocks == sorted(blocks, key=lambda tx: -tx.timestamp)
        blocks = list(reversed(blocks))

        assert len(blocks) == N + 1
        solvetimes, weights = zip(*(
            (block.timestamp - prev_block.timestamp, block.weight)
            for prev_block, block in hathor.util.iwindows(blocks, 2)
        ))
        assert len(solvetimes) == len(weights) == N, f'got {len(solvetimes)}, {len(weights)} expected {N}'

        sum_solvetimes = 0.0
        logsum_weights = 0.0

        prefix_sum_solvetimes = [0]
        for x in solvetimes:
            prefix_sum_solvetimes.append(prefix_sum_solvetimes[-1] + x)

        # Loop through N most recent blocks. N is most recently solved block.
        for i in range(K, N):
            solvetime = solvetimes[i]
            weight = weights[i]
            x = (prefix_sum_solvetimes[i + 1] - prefix_sum_solvetimes[i - K]) / K
            ki = K * (x - T)**2 / (2 * T * T)
            ki = max(1, ki / S)
            sum_solvetimes += ki * solvetime
            logsum_weights = sum_weights(logsum_weights, log(ki, 2) + weight)

        weight = logsum_weights - log(sum_solvetimes, 2) + log(T, 2)

        # Apply weight decay
        weight -= self.get_weight_decay_amount(block.timestamp - parent.timestamp)

        # Apply minimum weight
        if weight < self.min_block_weight:
            weight = self.min_block_weight

        return weight

    def minimum_tx_weight(self, tx: BaseTransaction) -> float:
        """ Returns the minimum weight for the param tx
            The minimum is calculated by the following function:

            w = alpha * log(size, 2) +       4.0         + 4.0
                                       ----------------
                                        1 + k / amount

            :param tx: tx to calculate the minimum weight
            :type tx: :py:class:`hathor.transaction.transaction.Transaction`

            :return: minimum weight for the tx
            :rtype: float
        """
        # In test mode we don't validate the minimum weight for tx
        # We do this to allow generating many txs for testing
        if self.test_mode & TestMode.TEST_TX_WEIGHT:
            return 1

        if tx.is_genesis:
            return settings.MIN_TX_WEIGHT

        tx_size = len(tx.get_struct())

        # We need to take into consideration the decimal places because it is inside the amount.
        # For instance, if one wants to transfer 20 HTRs, the amount will be 2000.
        # Max below is preventing division by 0 when handling authority methods that have no outputs
        amount = max(1, tx.sum_outputs) / (10 ** settings.DECIMAL_PLACES)
        weight = (
            + settings.MIN_TX_WEIGHT_COEFFICIENT * log(tx_size, 2)
            + 4 / (1 + settings.MIN_TX_WEIGHT_K / amount) + 4
        )

        # Make sure the calculated weight is at least the minimum
        weight = max(weight, settings.MIN_TX_WEIGHT)

        return weight

    def listen(self, description: str, ssl: bool = False) -> None:
        endpoint = self.connections.listen(description, ssl)

        if self.hostname:
            proto, _, _ = description.partition(':')
            address = '{}://{}:{}'.format(proto, self.hostname, endpoint._port)
            self.my_peer.entrypoints.append(address)
