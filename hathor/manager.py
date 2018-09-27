# encoding: utf-8

from hathor.p2p.peer_id import PeerId
from hathor.p2p.node_sync import NodeSyncLeftToRightManager
from hathor.p2p.manager import ConnectionsManager
from hathor.transaction import Block, TxOutput
from hathor.transaction.scripts import P2PKH
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage
from hathor.p2p.factory import HathorServerFactory, HathorClientFactory
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.exception import HathorError

from collections import defaultdict, deque
from enum import Enum
from math import log
import time
import random

from hathor.p2p.protocol import HathorLineReceiver
MyServerProtocol = HathorLineReceiver
MyClientProtocol = HathorLineReceiver

# from hathor.p2p.protocol import HathorWebSocketServerProtocol, HathorWebSocketClientProtocol
# MyServerProtocol = HathorWebSocketServerProtocol
# MyClientProtocol = HathorWebSocketClientProtocol


class HathorManager(object):
    """ HathorManager manages the node with the help of other specialized classes.

    Its primary objective is to handle DAG-related matters, ensuring that the DAG is always valid and connected.
    """

    class NodeState(Enum):
        # This node is still initializing
        INITIALIZING = 'INITIALIZING'

        # This node is waiting for peers to decide whether it is sync'ed or not.
        WAITING_FOR_PEERS = 'WAITING_FOR_PEERS'

        # This node is still synchronizing with the network
        SYNCING = 'SYNCING'

        # This node is up-to-date with the network
        SYNCED = 'SYNCED'

    def __init__(self, reactor, peer_id=None, network=None, hostname=None,
                 pubsub=None, wallet=None, tx_storage=None, peer_storage=None, default_port=40403):
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
        :type tx_storage: :py:class:`hathor.transaction.storage.transaction_storage.TransactionStorage`

        :param peer_storage: If not given, a new one is created.
        :type peer_storage: :py:class:`hathor.p2p.peer_storage.PeerStorage`

        :param default_port: Network default port. It is used when only ip addresses are discovered.
        :type default_port: int
        """
        self.reactor = reactor
        self.state = None

        # Hostname, used to be accessed by other peers.
        self.hostname = hostname

        # Remote address, which can be different from local address.
        self.remote_address = None

        self.my_peer = peer_id or PeerId()
        self.network = network or 'testnet'

        # XXX Should we use a singleton or a new PeerStorage? [msbrogli 2018-08-29]
        self.tx_storage = tx_storage or TransactionMemoryStorage()
        self.pubsub = pubsub or PubSubManager()

        self.peer_discoveries = []

        self.server_factory = HathorServerFactory(self.network, self.my_peer, node=self)
        self.client_factory = HathorClientFactory(self.network, self.my_peer, node=self)
        self.connections = ConnectionsManager(self.reactor, self.my_peer, self.server_factory, self.client_factory)

        # Map of peer_id to the best block height reported by that peer.
        self.peer_best_heights = defaultdict(int)

        self.node_sync_manager = NodeSyncLeftToRightManager(self)
        self.wallet = wallet
        self.wallet.pubsub = self.pubsub

        self.blocks_per_difficulty = 5
        self.latest_blocks = deque()
        self.avg_time_between_blocks = 64  # in seconds
        self.min_block_weight = 10
        self.block_weight = 10  # starting difficulty (10 is too low for production)
        self.max_allowed_block_weight_change = 2
        self.tokens_issued_per_block = 10000

    def start(self):
        """ A factory must be started only once. And it is usually automatically started.
        """
        self.state = self.NodeState.INITIALIZING
        self.pubsub.publish(HathorEvents.MANAGER_ON_START)

        # Initialize manager's components.
        self._initialize_components()

        for peer_discovery in self.peer_discoveries:
            peer_discovery.discover_and_connect(self.connections.connect_to)

        self.start_time = time.time()

    def stop(self):
        self.connections.stop()
        self.pubsub.publish(HathorEvents.MANAGER_ON_STOP)

    def _initialize_components(self):
        """You are not supposed to run this method manually. You should run `doStart()` to initialize the
        manager.

        This method runs through all transactions, verifying them and updating our wallet.
        """
        if self.wallet:
            self.wallet._manually_initialize()
        for tx in self.tx_storage._topological_sort():
            self.on_new_tx(tx)
        self.state = self.NodeState.WAITING_FOR_PEERS

    def add_peer_discovery(self, peer_discovery):
        self.connections.start()
        self.peer_discoveries.append(peer_discovery)

    def get_new_tx_parents(self):
        """Select which transactions will be confirmed by a new transaction.

        :return: The hashes of the parents for a new transaction.
        :rtype: List[bytes(hash)]
        """
        tips = self.tx_storage.get_tip_transactions(count=2)
        ret = [x.hash for x in tips]
        if len(tips) == 1:
            # If there is only one tip, let's randomly choose one of its parents.
            ret.append(random.choice(tips[0].parents))
        return ret

    def generate_mining_block(self):
        address = self.wallet.get_unused_address_bytes(mark_as_used=False)
        amount = self.tokens_issued_per_block
        output_script = P2PKH.create_output_script(address)
        tx_outputs = [
            TxOutput(amount, output_script)
        ]
        tip_blocks = self.tx_storage.get_tip_blocks_hashes()
        tip_txs = self.get_new_tx_parents()
        parents = tip_blocks + tip_txs

        parents_tx = [self.tx_storage.get_transaction_by_hash_bytes(x) for x in parents]
        new_height = max(x.height for x in parents_tx) + 1

        return Block(weight=self.block_weight, outputs=tx_outputs, parents=parents, storage=self.tx_storage,
                     height=new_height)

    def on_tips_received(self, tip_blocks, tip_transactions, conn=None):
        self.node_sync_manager.on_tips_received(tip_blocks, tip_transactions, conn)

    def validate_new_tx(self, tx):
        """ Process incoming transaction during initialization.
        These transactions came only from storage.
        """
        if self.state != self.NodeState.INITIALIZING:
            if tx.is_genesis:
                print('validate_new_tx(): Genesis? {}'.format(tx.hash.hex()))
                return False

            if self.tx_storage.transaction_exists_by_hash_bytes(tx.hash):
                print('validate_new_tx(): Already have transaction {}'.format(tx.hash.hex()))
                return False

        for parent_hash in tx.parents:
            if not self.tx_storage.transaction_exists_by_hash_bytes(parent_hash):
                # All parents must exist.
                print('validate_new_tx(): Invalid transaction with unknown parent tx={} parent={}'.format(
                    tx.hash.hex(), parent_hash.hex()
                ))
                return False

        try:
            tx.verify()
        except HathorError as e:
            print('validate_new_tx(): Error verifying transaction {} tx={}'.format(e, tx.hash.hex()))
            return False

        if tx.is_block:
            if tx.weight < self.block_weight:
                print('Invalid new block {}: weight ({}) is smaller than the minimum block weight ({})'.format(
                    tx.hash.hex(), tx.weight, self.block_weight)
                )
                return False
            if tx.sum_outputs != self.tokens_issued_per_block:
                print('Invalid number of issued tokens: {} <> {} (tx: {})'.format(
                    tx.sum_outputs,
                    self.tokens_issued_per_block,
                    tx.hash.hex())
                )

        return True

    def propagate_tx(self, tx):
        """Push a new transaction to the network. It is used by both the wallet and the mining modules.
        """
        if tx.storage:
            assert tx.storage == self.tx_storage, 'Invalid tx storage'
        else:
            tx.storage = self.tx_storage
        self.on_new_tx(tx)

        # Only propagate transactions once we are sufficiently synced up with the rest of the network.
        # TODO Should we queue transactions?
        if self.state == self.NodeState.SYNCED:
            for conn in self.get_ready_connections():
                conn.state.send_data(tx)

    def on_new_tx(self, tx, conn=None):
        """This method is called when any transaction arrive.
        """
        if not self.validate_new_tx(tx):
            # Discard invalid Transaction/block.
            return

        if self.wallet:
            self.wallet.on_new_tx(tx)

        if self.state == self.NodeState.INITIALIZING:
            self.tx_storage._add_to_cache(tx)
        else:
            self.tx_storage.save_transaction(tx)
            self.node_sync_manager.on_new_tx(tx, conn)
            self.update_accumulated_weights(tx)

        if tx.is_block:
            self.latest_blocks.append(tx)
            while len(self.latest_blocks) > self.blocks_per_difficulty:
                self.latest_blocks.popleft()

            print('New block found: {} weight={}'.format(tx.hash_hex, tx.weight))
            count_blocks = self.tx_storage.get_block_count()
            if count_blocks % self.blocks_per_difficulty == 0:
                print('Adjusting mining difficulty...')
                avg_dt, new_weight = self.calculate_block_difficulty()
                print('Block weight updated: avg_dt={:.2f} target_avg_dt={:.2f} {:6.2f} -> {:6.2f}'.format(
                    avg_dt,
                    self.avg_time_between_blocks,
                    self.block_weight,
                    new_weight
                ))
                self.block_weight = new_weight
        else:
            print('New tx: {}'.format(tx.hash.hex()))

        # Publish to pubsub manager the new tx accepted
        self.pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED, tx=tx)

    def on_block_hashes_received(self, block_hashes, conn=None):
        """We have received a list of hashes of blocks, according to a peer."""
        self.node_sync_manager.on_block_hashes_received(block_hashes, conn)

    def on_transactions_hashes_received(self, txs_hashes, conn=None):
        """We have received a list of hashes of transactions, according to a peer."""
        self.node_sync_manager.on_transactions_hashes_received(txs_hashes, conn)

    def on_best_height(self, best_height, conn):
        raise NotImplemented

    def calculate_block_difficulty(self):
        """ Calculate block difficulty according to the latest blocks.

        The new difficulty is calculated so that the average time between blocks will be
        `self.avg_time_between_blocks`. If the measured time between blocks is smaller than the target,
        the difficulty increases. If it is higher than the target, the difficulty decreases.

        The difficulty change cannot be higher than `self.max_allowed_block_weight_change`, and
        the new difficulty cannot be smaller than `self.min_block_weight`.
        """
        blocks = self.latest_blocks
        assert len(blocks) == self.blocks_per_difficulty
        dt = blocks[-1].timestamp - blocks[0].timestamp

        if dt <= 0:
            dt = 1  # Strange situation, so, let's just increase difficulty.

        delta = (
            log(self.avg_time_between_blocks, 2)
            + log(self.blocks_per_difficulty, 2)
            - log(dt, 2)
        )

        if delta > self.max_allowed_block_weight_change:
            delta = self.max_allowed_block_weight_change
        elif delta < -self.max_allowed_block_weight_change:
            delta = -self.max_allowed_block_weight_change

        new_weight = self.block_weight + delta

        if new_weight < self.min_block_weight:
            new_weight = self.min_block_weight

        avg_dt = float(dt) / self.blocks_per_difficulty
        return avg_dt, new_weight

    def update_accumulated_weights(self, tx):
        """Update all previous transactions' accumulated weight when a new one arrives

        :param tx: the new transaction/block
        :type tx: :py:class:`hathor.transaction.Transaction` or :py:class:`hathor.transaction.Block`

        :rtype: None
        """
        for _tx in self.tx_storage.iter_bfs(tx):
            _tx.update_accumulated_weight(tx.weight)

    def listen(self, description, ssl=False):
        endpoint = self.connections.listen(description, ssl)

        if self.hostname:
            proto, _, _ = description.partition(':')
            address = '{}:{}:{}'.format(proto, self.hostname, endpoint._port)
            self.my_peer.entrypoints.append(address)
