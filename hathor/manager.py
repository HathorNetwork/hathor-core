from abc import ABC, abstractmethod
from collections import defaultdict
from enum import Enum
from typing import List, Optional
import time
import random
import datetime

from twisted.logger import Logger

from hathor import protos
from hathor.p2p.peer_id import PeerId
from hathor.p2p.manager import ConnectionsManager
from hathor.transaction import Block, TxOutput
from hathor.transaction.base_transaction import BaseTransaction
from hathor.transaction.scripts import create_output_script
from hathor.transaction.storage import ITransactionStorage, TransactionRemoteStorageFactory
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage
from hathor.transaction.storage.remote_storage import TransactionStorageServicer
from hathor.p2p.factory import HathorServerFactory, HathorClientFactory
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.metrics import Metrics
from hathor.constants import TOKENS_PER_BLOCK, DECIMAL_PLACES
from hathor.validator import ValidatorSubprocessMock, Validator
from hathor.wallet.base_wallet import IWallet
from hathor.p2p.protocol import HathorLineReceiver


MyServerProtocol = HathorLineReceiver
MyClientProtocol = HathorLineReceiver

# from hathor.p2p.protocol import HathorWebSocketServerProtocol, HathorWebSocketClientProtocol
# MyServerProtocol = HathorWebSocketServerProtocol
# MyClientProtocol = HathorWebSocketClientProtocol


class IManager(ABC):
    wallet: IWallet
    tx_storage: ITransactionStorage

    @abstractmethod
    def get_new_tx_parents(self, timestamp: Optional[int] = None) -> List[bytes]:
        """Select which transactions will be confirmed by a new transaction.

        Returns the hashes of the parents for a new transaction.
        """
        raise NotImplementedError

    @abstractmethod
    def minimum_tx_weight(self, tx: BaseTransaction) -> float:
        """Returns the minimum weight for the param tx.

        The minimum is calculated by the following function:

        w = log(size, 2) + log(amount, 2) + 0.5

        Returns minimum weight for the tx.
        """
        raise NotImplementedError

    @abstractmethod
    def propagate_tx(self, tx: BaseTransaction) -> bool:
        """Push a new transaction to the network. It is used by both the wallet and the mining modules.

        Returns whether the transaction was accepted.
        """
        raise NotImplementedError


class HathorManager(IManager):
    """ HathorManager manages the node with the help of other specialized classes.

    Its primary objective is to handle DAG-related matters, ensuring that the DAG is always valid and connected.
    """
    log = Logger()

    class NodeState(Enum):
        # This node is still initializing
        INITIALIZING = 'INITIALIZING'

        # This node is ready to establish new connections, sync, and exchange transactions.
        READY = 'READY'

    def __init__(
            self,
            reactor,
            peer_id=None,
            network=None,
            hostname=None,
            pubsub=None,
            wallet=None,
            tx_storage=None,
            peer_storage=None,
            default_port=40403,
            *,
            grpc_server_port=None,
            test_mode=False,
            clock=None,
            ):
        """
        :param reactor: Twisted reactor which handles the mainloop and the events.
        :type reactor: :py:class:`twisted.internet.Reactor`

        :param peer_id: Id of this node. If not given, a new one is created.
        :type peer_id: :py:class:`hathor.p2p.peer_id.PeerId`

        :param network: Name of the network this node participates. Usually it is either testnet or mainnet.
        :type network: string

        :param hostname: The hostname of this node. It is used to generate its entrypoints.
        :type hostname: string

        :param pubsub: If not given, a new one is created.
        :type pubsub: :py:class:`hathor.pubsub.PubSubManager`

        :param tx_storage: If not given, a :py:class:`TransactionMemoryStorage` one is created.
        :type tx_storage: :py:class:`hathor.transaction.storage.ITransactionStorage`

        :param peer_storage: If not given, a new one is created.
        :type peer_storage: :py:class:`hathor.p2p.peer_storage.PeerStorage`

        :param default_port: Network default port. It is used when only ip addresses are discovered.
        :type default_port: int
        """
        from hathor.remote_manager import HathorManagerServicer, RemoteManagerFactory

        self.reactor = reactor
        self.clock = clock or self.reactor
        if hasattr(self.reactor, 'addSystemEventTrigger'):
            self.reactor.addSystemEventTrigger('after', 'shutdown', self.stop)

        self.state = None
        self.profiler = None

        # Hostname, used to be accessed by other peers.
        self.hostname = hostname

        # Remote address, which can be different from local address.
        self.remote_address = None

        self.my_peer = peer_id or PeerId()
        self.network = network or 'testnet'

        # XXX Should we use a singleton or a new PeerStorage? [msbrogli 2018-08-29]
        self.pubsub = pubsub or PubSubManager()
        self.tx_storage = tx_storage or TransactionMemoryStorage()
        self.tx_storage.pubsub = self.pubsub

        self._test_mode = test_mode

        self.avg_time_between_blocks = 64  # in seconds
        self.tokens_issued_per_block = TOKENS_PER_BLOCK * (10**DECIMAL_PLACES)

        # self.metrics = Metrics(
        #     pubsub=self.pubsub,
        #     avg_time_between_blocks=self.avg_time_between_blocks,
        #     tx_storage=tx_storage,
        #     reactor=self.reactor,
        # )

        self.peer_discoveries = []

        self.server_factory = HathorServerFactory(self.network, self.my_peer, node=self)
        self.client_factory = HathorClientFactory(self.network, self.my_peer, node=self)
        self.connections = ConnectionsManager(
            self.reactor,
            self.my_peer,
            self.server_factory,
            self.client_factory,
            self.pubsub
        )

        # Map of peer_id to the best block height reported by that peer.
        self.peer_best_heights = defaultdict(int)

        self.wallet = wallet
        self.wallet.pubsub = self.pubsub
        self.wallet.reactor = self.reactor

        self._grpc_server_port = grpc_server_port
        if grpc_server_port is not None:
            self.tx_storage_factory = TransactionRemoteStorageFactory(grpc_server_port)
            self._tx_storage_servicer = TransactionStorageServicer(self.tx_storage)
            self.manager_factory = RemoteManagerFactory(grpc_server_port, self.tx_storage_factory)
            self._manager_servicer = HathorManagerServicer(self)
            self.validator_subprocess = ValidatorSubprocessMock(
                    self.tx_storage_factory, test_mode=self._test_mode,
                    clock=clock)  # XXX: use `clock` NOT `self.clock` to propagate the None-ness
            self.validator = None
        else:
            self.validator = Validator(self.tx_storage, clock=self.clock, test_mode=self._test_mode)
            # TODO
            raise
            pass

        self.state = None

    def add_grpc_servicers_to_server(self, grpc_server):
        assert self._grpc_server_port is not None, 'No grpc_server_port given, cannot add servicers'
        assert self.state is None, 'Call manager.add_grpc_servicers_to_server before manager.start'
        protos.add_TransactionStorageServicer_to_server(self._tx_storage_servicer, grpc_server)
        protos.add_HathorManagerServicer_to_server(self._manager_servicer, grpc_server)

    def start(self):
        """ A factory must be started only once. And it is usually automatically started.
        """
        self.log.info('Starting HathorManager...')

        self.state = self.NodeState.INITIALIZING
        self.pubsub.publish(HathorEvents.MANAGER_ON_START)
        if self.validator_subprocess is not None:
            self.validator_subprocess.start()
            self.validator = self.validator_subprocess.remote_validator_factory()
        self.connections.start()

        # Initialize manager's components.
        self._initialize_components()

        for peer_discovery in self.peer_discoveries:
            peer_discovery.discover_and_connect(self.connections.connect_to)

        self.start_time = time.time()

        # Metric starts to capture data
        # self.metrics.start()

        self.wallet.start()

    def stop(self):
        self.log.info('Stopping HathorManager...')
        self.connections.stop()
        self.pubsub.publish(HathorEvents.MANAGER_ON_STOP)

        # Metric stops to capture data
        # self.metrics.stop()

        self.wallet.stop()
        if self.validator_subprocess:
            self.validator_subprocess.stop()

    def start_profiler(self):
        """
        Start profiler. It can be activated from a web resource, as well.
        """
        if not self.profiler:
            import cProfile
            self.profiler = cProfile.Profile()
        self.profiler.enable()

    def stop_profiler(self, save_to=None):
        """
        Stop the profile and optionally save the results for future analysis.

        :param save_to: path where the results will be saved
        :type save_to: str
        """
        self.profiler.disable()
        if save_to:
            self.profiler.dump_stats(save_to)

    def _initialize_components(self):
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
        for tx in self.tx_storage._topological_sort():
            t2 = time.time()
            if t2 - t1 > 5:
                # self.start_profiler()
                ts_date = datetime.datetime.fromtimestamp(self.tx_storage.latest_timestamp)
                self.log.info(
                    'Verifying transations in storage...'
                    ' avg={:.4f} tx/s total={} (latest timedate: {})'.format(cnt / (t2 - t0), cnt, ts_date)
                )
                t1 = t2
            cnt += 1
            self.on_new_tx(tx, quiet=True)
        # self.stop_profiler(save_to='initializing.prof')
        self.state = self.NodeState.READY
        self.log.info('Node successfully initialized ({} seconds).'.format(t2 - t0))

    def advance_clock(self, amount):
        # TODO: docstring
        self.clock.advance(amount)
        if self.validator_subprocess and self.validator.clock:
            self.validator.clock.advance(amount)
        # if self.wallet_subprocess and self.wallet.clock:
        #     self.wallet.clock.advance(amount)

    def add_peer_discovery(self, peer_discovery):
        self.peer_discoveries.append(peer_discovery)

    def get_new_tx_parents(self, timestamp=None):
        """Select which transactions will be confirmed by a new transaction.

        :return: The hashes of the parents for a new transaction.
        :rtype: List[bytes(hash)]
        """
        timestamp = timestamp or self.clock.seconds()
        ret = list(self.tx_storage.get_tx_tips(timestamp-1))
        random.shuffle(ret)
        ret = ret[:2]
        if len(ret) == 1:
            # If there is only one tip, let's randomly choose one of its parents.
            parents = list(self.tx_storage.get_tx_tips(ret[0].begin - 1))
            ret.append(random.choice(parents))
        assert len(ret) == 2, 'timestamp={} tips={}'.format(
            timestamp,
            [x.hex() for x in self.tx_storage.get_tx_tips(timestamp-1)]
        )
        return [x.data for x in ret]

    # XXX: this function is only used by the MiningResource class, it makes sense to make mining talk to the wallet
    #      directly instead of indirectly (through the manager), ... thinking of a "multi wallet manager"
    def generate_mining_block(self, timestamp=None):
        """ Generates a block ready to be mined. The block includes new issued tokens,
        parents, and the weight.

        :return: A block ready to be mined
        :rtype: :py:class:`hathor.transaction.Block`
        """
        address = self.wallet.get_unused_address_bytes(mark_as_used=False)
        amount = self.tokens_issued_per_block
        output_script = create_output_script(address)
        tx_outputs = [
            TxOutput(amount, output_script)
        ]

        if not timestamp:
            timestamp = max(self.tx_storage.latest_timestamp, self.clock.seconds())
        tip_blocks = [x.data for x in self.tx_storage.get_block_tips(timestamp)]
        tip_txs = self.get_new_tx_parents(timestamp)

        assert len(tip_blocks) >= 1
        assert len(tip_txs) == 2

        parents = [random.choice(tip_blocks)] + tip_txs

        parents_tx = [self.tx_storage.get_transaction(x) for x in parents]
        new_height = max(x.height for x in parents_tx) + 1

        timestamp1 = int(self.clock.seconds())
        timestamp2 = max(x.timestamp for x in parents_tx) + 1

        blk = Block(outputs=tx_outputs, parents=parents, storage=self.tx_storage, height=new_height)
        blk.timestamp = max(timestamp1, timestamp2)
        blk.weight = self.calculate_block_difficulty(blk)
        return blk

    def propagate_tx(self, tx):
        """Push a new transaction to the network. It is used by both the wallet and the mining modules.

        :return: True if the transaction was accepted
        :rtype: bool
        """
        if tx.storage:
            assert tx.storage == self.tx_storage, 'Invalid tx storage'
        else:
            tx.storage = self.tx_storage
        return self.on_new_tx(tx)

    def on_new_tx(self, tx, conn=None, quiet=False):
        """This method is called when any transaction arrive.

        :return: True if the transaction was accepted
        :rtype: bool
        """
        if not self.validate_new_tx(tx):
            # Discard invalid Transaction/block.
            self.log.debug('Transaction/Block discarded {}'.format(tx.hash_hex))
            return False

        if self.wallet:
            self.wallet.on_new_tx(tx)

        if self.state is self.NodeState.READY:
            self.tx_storage.save_transaction(tx)
            tx.update_parents()
        else:
            self.tx_storage._add_to_cache(tx)

        if not quiet:
            ts_date = datetime.datetime.fromtimestamp(tx.timestamp)
            if tx.is_block:
                self.log.info(
                    'New block found tag=new_block hash={tx.hash_hex}'
                    ' weight={tx.weight} timestamp={tx.timestamp} datetime={ts_date} from_now={time_from_now}',
                    tx=tx, ts_date=ts_date, time_from_now=tx.get_time_from_now()
                )
            else:
                self.log.info(
                    'New transaction tag=new_tx hash={tx.hash_hex}'
                    ' timestamp={tx.timestamp} datetime={ts_date} from_now={time_from_now}',
                    tx=tx,
                    ts_date=ts_date,
                    time_from_now=tx.get_time_from_now()
                )

        tx.mark_inputs_as_used()
        tx.update_voided_info()
        tx.set_conflict_twins()

        # Propagate to our peers.
        self.connections.send_tx_to_peers(tx)

        # Publish to pubsub manager the new tx accepted
        self.pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED, tx=tx)
        return True

    def validate_new_tx(self, tx):
        """ Process incoming transaction during initialization.
        These transactions came only from storage.
        """
        if self.state is self.NodeState.READY:
            if tx.is_genesis:
                self.log.debug('validate_new_tx(): Genesis? {}'.format(tx.hash.hex()))
                return False

            if self.tx_storage.transaction_exists(tx.hash):
                self.log.debug('validate_new_tx(): Already have transaction {}'.format(tx.hash.hex()))
                return False

        else:
            if tx.is_genesis:
                return True

        return self.validator.validate_new_tx(tx)

    def minimum_tx_weight(self, tx):
        return self.validator.minimum_tx_weight(tx)

    def calculate_block_difficulty(self, block):
        return self.validator.calculate_block_difficulty(block)

    def listen(self, description, ssl=False):
        endpoint = self.connections.listen(description, ssl)

        if self.hostname:
            proto, _, _ = description.partition(':')
            address = '{}:{}:{}'.format(proto, self.hostname, endpoint._port)
            self.my_peer.entrypoints.append(address)
