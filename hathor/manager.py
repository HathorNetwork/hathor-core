import datetime
import json
import random
import sys
import time
from enum import Enum, IntFlag
from math import log
from typing import Any, List, Optional, cast

from twisted.internet.interfaces import IReactorCore
from twisted.logger import Logger
from twisted.python.threadpool import ThreadPool

from hathor.conf import HathorSettings
from hathor.exception import InvalidNewTransaction
from hathor.indexes import WalletIndex
from hathor.p2p.peer_discovery import PeerDiscovery
from hathor.p2p.peer_id import PeerId
from hathor.p2p.protocol import HathorProtocol
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.stratum import StratumFactory
from hathor.transaction import BaseTransaction, Block, Transaction, TxOutput, sum_weights
from hathor.transaction.exceptions import TxValidationError
from hathor.transaction.storage import TransactionStorage
from hathor.wallet import BaseWallet

settings = HathorSettings()


class TestMode(IntFlag):
    DISABLED = 0
    TEST_TX_WEIGHT = 1
    TEST_BLOCK_WEIGHT = 2
    TEST_ALL_WEIGHT = 3


class HathorManager:
    """ HathorManager manages the node with the help of other specialized classes.

    Its primary objective is to handle DAG-related matters, ensuring that the DAG is always valid and connected.
    """
    log = Logger()

    class NodeState(Enum):
        # This node is still initializing
        INITIALIZING = 'INITIALIZING'

        # This node is ready to establish new connections, sync, and exchange transactions.
        READY = 'READY'

    def __init__(self, reactor: IReactorCore, peer_id: Optional[PeerId] = None, network: Optional[str] = None,
                 hostname: Optional[str] = None, pubsub: Optional[PubSubManager] = None,
                 wallet: Optional[BaseWallet] = None, tx_storage: Optional[TransactionStorage] = None,
                 peer_storage: Optional[Any] = None, default_port: int = 40403, wallet_index: bool = False,
                 stratum_port: Optional[int] = None, min_block_weight: Optional[int] = None) -> None:
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

        self.avg_time_between_blocks = settings.AVG_TIME_BETWEEN_BLOCKS
        self.min_block_weight = min_block_weight or settings.MIN_BLOCK_WEIGHT
        self.min_tx_weight = settings.MIN_TX_WEIGHT
        self.tokens_issued_per_block = settings.TOKENS_PER_BLOCK * (10**settings.DECIMAL_PLACES)

        self.max_future_timestamp_allowed = 3600  # in seconds

        self.metrics = Metrics(
            pubsub=self.pubsub,
            avg_time_between_blocks=self.avg_time_between_blocks,
            tx_storage=tx_storage,
            reactor=self.reactor,
        )

        self.peer_discoveries: List[PeerDiscovery] = []

        self.server_factory = HathorServerFactory(self.network, self.my_peer, node=self)
        self.client_factory = HathorClientFactory(self.network, self.my_peer, node=self)
        self.connections = ConnectionsManager(self.reactor, self.my_peer, self.server_factory, self.client_factory,
                                              self.pubsub)

        self.wallet = wallet
        if self.wallet:
            self.wallet.pubsub = self.pubsub
            self.wallet.reactor = self.reactor

        # When manager is in test mode we reduce the weight of blocks/transactions.
        self.test_mode: int = 0

        # Multiplier coefficient to adjust the minimum weight of a normal tx to 18
        self.min_tx_weight_coefficient = 1.6
        # Amount in which tx min weight reaches the middle point between the minimum and maximum weight.
        self.min_tx_weight_k = 100

        self.stratum_factory = StratumFactory(manager=self, port=stratum_port) if stratum_port else None

        self._allow_mining_without_peers = False

        # Thread pool used to resolve pow when sending tokens
        self.pow_thread_pool = ThreadPool(minthreads=0, maxthreads=settings.MAX_POW_THREADS, name='Pow thread pool')

    def start(self) -> None:
        """ A factory must be started only once. And it is usually automatically started.
        """
        self.log.info('Starting HathorManager...')
        self.state = self.NodeState.INITIALIZING
        self.pubsub.publish(HathorEvents.MANAGER_ON_START)
        self.connections.start()
        self.pow_thread_pool.start()

        # Initialize manager's components.
        self._initialize_components()

        for peer_discovery in self.peer_discoveries:
            peer_discovery.discover_and_connect(self.connections.connect_to)

        self.start_time = time.time()

        # Metric starts to capture data
        self.metrics.start()

        if self.wallet:
            self.wallet.start()

        if self.stratum_factory:
            self.stratum_factory.start()

    def stop(self) -> None:
        self.log.info('Stopping HathorManager...')
        self.connections.stop()
        self.pubsub.publish(HathorEvents.MANAGER_ON_STOP)
        if self.pow_thread_pool.started:
            self.pow_thread_pool.stop()

        # Metric stops to capture data
        self.metrics.stop()

        if self.wallet:
            self.wallet.stop()

    def start_profiler(self) -> None:
        """
        Start profiler. It can be activated from a web resource, as well.
        """
        if not self.profiler:
            import cProfile
            self.profiler = cProfile.Profile()
        self.profiler.enable()

    def stop_profiler(self, save_to=None) -> None:
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

        # self.start_profiler()
        for tx in self.tx_storage._topological_sort():
            assert tx.hash is not None

            t2 = time.time()
            if t2 - t1 > 5:
                ts_date = datetime.datetime.fromtimestamp(self.tx_storage.latest_timestamp)
                self.log.info(
                    'Verifying transations in storage... avg={avg:.4f} tx/s total={total} (latest timedate: {ts})',
                    avg=cnt / (t2 - t0),
                    total=cnt,
                    ts=ts_date,
                )
                t1 = t2
            cnt += 1

            try:
                assert self.on_new_tx(tx, quiet=True, fails_silently=False)
            except (InvalidNewTransaction, TxValidationError):
                pretty_json = json.dumps(tx.to_json(), indent=4)
                self.log.failure('An unexpected error occurred when initializing {tx.hash_hex}\n'
                                 '{pretty_json}', tx=tx, pretty_json=pretty_json)
                sys.exit(-1)

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
                              data: bytes = b'', address: Optional[bytes] = None) -> Block:
        """ Generates a block ready to be mined. The block includes new issued tokens,
        parents, and the weight.

        :return: A block ready to be mined
        :rtype: :py:class:`hathor.transaction.Block`
        """
        from hathor.transaction.scripts import create_output_script

        if address is None:
            if self.wallet is None:
                raise ValueError('No wallet available and no mining address given')
            address = self.wallet.get_unused_address_bytes(mark_as_used=False)
        amount = self.tokens_issued_per_block
        output_script = create_output_script(address)
        tx_outputs = [TxOutput(amount, output_script)]

        if not timestamp:
            timestamp = max(self.tx_storage.latest_timestamp, self.reactor.seconds())

        if parent_block_hash is None:
            tip_blocks = self.tx_storage.get_best_block_tips(timestamp)
        else:
            tip_blocks = [parent_block_hash]

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

        blk = Block(outputs=tx_outputs, parents=parents, storage=self.tx_storage, data=data)
        blk.timestamp = max(timestamp1, timestamp2)
        blk.weight = self.calculate_block_difficulty(blk)
        return blk

    def validate_new_tx(self, tx: BaseTransaction) -> bool:
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

        if tx.timestamp - self.reactor.seconds() > self.max_future_timestamp_allowed:
            raise InvalidNewTransaction('Ignoring transaction in the future {} (timestamp={})'.format(
                tx.hash.hex(), tx.timestamp))

        # Verify transaction and raises an TxValidationError if tx is not valid.
        tx.verify()

        if tx.is_block:
            tx = cast(Block, tx)
            assert tx.hash is not None  # XXX: it appears that after casting this assert "casting" is lost

            # Validate minimum block difficulty
            block_weight = self.calculate_block_difficulty(tx)
            if tx.weight < block_weight - settings.WEIGHT_TOL:
                raise InvalidNewTransaction(
                    'Invalid new block {}: weight ({}) is smaller than the minimum weight ({})'.format(
                        tx.hash.hex(), tx.weight, block_weight
                    )
                )
            if tx.sum_outputs != self.tokens_issued_per_block:
                raise InvalidNewTransaction(
                    'Invalid number of issued tokens tag=invalid_issued_tokens'
                    ' tx.hash={tx.hash_hex} issued={tx.sum_outputs} allowed={allowed}'.format(
                        tx=tx,
                        allowed=self.tokens_issued_per_block,
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
                  quiet: bool = False, fails_silently: bool = True, propagate_to_peers: bool = True) -> bool:
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
            assert self.validate_new_tx(tx) is True
        except (InvalidNewTransaction, TxValidationError) as e:
            # Discard invalid Transaction/block.
            self.log.debug('Transaction/Block discarded {tx.hash_hex}: {e}', tx=tx, e=e)
            if not fails_silently:
                raise
            return False

        if self.state != self.NodeState.INITIALIZING:
            self.tx_storage.save_transaction(tx)
        else:
            tx.reset_metadata()
            self.tx_storage._add_to_cache(tx)

        if self.wallet:
            self.wallet.on_new_tx(tx)

        tx.update_parents()

        if not quiet:
            ts_date = datetime.datetime.fromtimestamp(tx.timestamp)
            if tx.is_block:
                self.log.info(
                    'New block found tag=new_block hash={tx.hash_hex}'
                    ' weight={tx.weight} timestamp={tx.timestamp} datetime={ts_date} from_now={time_from_now}', tx=tx,
                    ts_date=ts_date, time_from_now=tx.get_time_from_now())
            else:
                self.log.info(
                    'New transaction tag=new_tx hash={tx.hash_hex}'
                    ' timestamp={tx.timestamp} datetime={ts_date} from_now={time_from_now}', tx=tx, ts_date=ts_date,
                    time_from_now=tx.get_time_from_now())

        if tx.is_block:
            assert isinstance(tx, Block)
            tx.update_voided_info()
        else:
            assert isinstance(tx, Transaction)
            tx.mark_inputs_as_used()
            tx.update_voided_info()
            tx.set_conflict_twins()

        if propagate_to_peers:
            # Propagate to our peers.
            self.connections.send_tx_to_peers(tx)

        # Publish to pubsub manager the new tx accepted
        self.pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED, tx=tx)

        return True

    def calculate_block_difficulty(self, block: Block) -> float:
        """ Calculate block difficulty according to the ascendents of `block`.

        The new difficulty is calculated so that the average time between blocks will be
        `self.avg_time_between_blocks`. If the measured time between blocks is smaller than the target,
        the weight increases. If it is higher than the target, the weight decreases.

        The new difficulty cannot be smaller than `self.min_block_weight`.
        """
        # In test mode we don't validate the block difficulty
        if self.test_mode & TestMode.TEST_BLOCK_WEIGHT:
            return 1

        if block.is_genesis:
            return self.min_block_weight

        blocks: List[Block] = []
        root = block
        while len(blocks) < settings.BLOCK_DIFFICULTY_N_BLOCKS:
            if not root.parents:
                assert root.is_genesis
                break
            root = root.get_block_parent()
            assert isinstance(root, Block)
            blocks.append(root)
        blocks.sort(key=lambda tx: tx.timestamp)

        if blocks[-1].is_genesis:
            return self.min_block_weight

        dt = blocks[-1].timestamp - blocks[0].timestamp
        assert dt > 0

        logH = 0.0
        for blk in blocks:
            logH = sum_weights(logH, blk.weight)

        weight = logH - log(dt, 2) + log(self.avg_time_between_blocks, 2)

        # Apply a maximum change in difficulty.
        max_dw = settings.BLOCK_DIFFICULTY_MAX_DW
        dw = weight - blocks[-1].weight
        if dw > max_dw:
            weight = blocks[-1].weight + max_dw
        elif dw < -max_dw:
            weight = blocks[-1].weight - max_dw

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
            return self.min_tx_weight

        tx_size = len(tx.get_struct())

        # We need to take into consideration the decimal places because it is inside the amount.
        # For instance, if one wants to transfer 20 HTRs, the amount will be 2000.
        # Max below is preventing division by 0 when handling authority methods that have no outputs
        amount = max(1, tx.sum_outputs) / (10 ** settings.DECIMAL_PLACES)
        weight = (
            + self.min_tx_weight_coefficient * log(tx_size, 2)
            + 4 / (1 + self.min_tx_weight_k / amount) + 4
        )

        # Make sure the calculated weight is at least the minimum
        weight = max(weight, self.min_tx_weight)

        return weight

    def listen(self, description: str, ssl: bool = False) -> None:
        endpoint = self.connections.listen(description, ssl)

        if self.hostname:
            proto, _, _ = description.partition(':')
            address = '{}:{}:{}'.format(proto, self.hostname, endpoint._port)
            self.my_peer.entrypoints.append(address)
