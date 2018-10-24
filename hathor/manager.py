# encoding: utf-8

from twisted.internet.defer import inlineCallbacks

from hathor.amp_protocol import HathorAMPFactory, SendTx, GetNetworkStatus
from hathor.transaction import Block, TxOutput, sum_weights
from hathor.transaction.scripts import P2PKH
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.metrics import Metrics
from hathor.exception import HathorError

from collections import defaultdict
from enum import Enum
from math import log
import time
import random
import datetime
import pickle

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

        # This node is ready to establish new connections, sync, and exchange transactions.
        READY = 'READY'

    def __init__(self, reactor, pubsub=None, network=None, wallet=None, tx_storage=None, unix_socket=None):
        """
        :param reactor: Twisted reactor which handles the mainloop and the events.
        :type reactor: :py:class:`twisted.internet.Reactor`

        :param network: Name of the network this node participates. Usually it is either testnet or mainnet.
        :type network: string

        :param pubsub: If not given, a new one is created.
        :type pubsub: :py:class:`hathor.pubsub.PubSubManager`

        :param tx_storage: If not given, a :py:class:`TransactionMemoryStorage` one is created.
        :type tx_storage: :py:class:`hathor.transaction.storage.transaction_storage.TransactionStorage`
        """
        self.reactor = reactor
        self.state = None
        self.profiler = None
        self.network = network or 'testnet'

        # XXX Should we use a singleton or a new PeerStorage? [msbrogli 2018-08-29]
        self.tx_storage = tx_storage or TransactionMemoryStorage()
        self.pubsub = pubsub or PubSubManager(self)

        self.avg_time_between_blocks = 64  # in seconds
        self.min_block_weight = 14
        self.tokens_issued_per_block = 10000

        self.metrics = Metrics(
            pubsub=self.pubsub,
            avg_time_between_blocks=self.avg_time_between_blocks,
            tx_storage=tx_storage
        )

        # Map of peer_id to the best block height reported by that peer.
        self.peer_best_heights = defaultdict(int)

        self.wallet = wallet
        self.wallet.pubsub = self.pubsub

        self.remoteConnection = None
        self.unix_socket = unix_socket

    def start(self):
        """ A factory must be started only once. And it is usually automatically started.
        """
        self.state = self.NodeState.INITIALIZING

        self.start_time = time.time()

        self.reactor.listenUNIX(self.unix_socket, HathorAMPFactory(self))

        # Initialize manager's components.
        self._initialize_components()
        self.pubsub.publish(HathorEvents.MANAGER_ON_START)

    def stop(self):
        self.pubsub.publish(HathorEvents.MANAGER_ON_STOP)

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
        if self.wallet:
            self.wallet._manually_initialize()
        for tx in self.tx_storage._topological_sort():
            self.on_new_tx(tx)
        self.state = self.NodeState.READY

    def get_new_tx_parents(self, timestamp=None):
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
        assert len(ret) == 2
        return [x.data for x in ret]

    def generate_mining_block(self, timestamp=None):
        """ Generates a block ready to be mined. The block includes new issued tokens,
        parents, and the weight.

        :return: A block ready to be mined
        :rtype: :py:class:`hathor.transaction.Block`
        """
        address = self.wallet.get_unused_address_bytes(mark_as_used=False)
        amount = self.tokens_issued_per_block
        output_script = P2PKH.create_output_script(address)
        tx_outputs = [
            TxOutput(amount, output_script)
        ]

        timestamp = timestamp or self.reactor.seconds()
        tip_blocks = [x.data for x in self.tx_storage.get_block_tips(timestamp)]
        tip_txs = self.get_new_tx_parents(timestamp)

        assert len(tip_blocks) >= 1
        assert len(tip_txs) == 2

        parents = tip_blocks + tip_txs

        parents_tx = [self.tx_storage.get_transaction_by_hash_bytes(x) for x in parents]
        new_height = max(x.height for x in parents_tx) + 1

        timestamp1 = int(self.reactor.seconds())
        timestamp2 = max(x.timestamp for x in parents_tx) + 1

        blk = Block(outputs=tx_outputs, parents=parents, storage=self.tx_storage, height=new_height)
        blk.timestamp = max(timestamp1, timestamp2)
        blk.weight = self.calculate_block_difficulty(blk)
        return blk

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
            print('validate_new_tx(): Error verifying transaction {} tx={}'.format(repr(e), tx.hash.hex()))
            return False

        if tx.is_block:
            block_weight = self.calculate_block_difficulty(tx)
            if tx.weight < block_weight:
                print('Invalid new block {}: weight ({}) is smaller than the minimum block weight ({})'.format(
                    tx.hash.hex(), tx.weight, block_weight)
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

    def on_new_tx(self, tx, conn=None):
        """This method is called when any transaction arrive.
        """
        if not self.validate_new_tx(tx):
            # Discard invalid Transaction/block.
            return False

        if self.wallet:
            self.wallet.on_new_tx(tx)

        if self.state != self.NodeState.INITIALIZING:
            self.tx_storage.save_transaction(tx)
            tx.update_parents()
        else:
            self.tx_storage._add_to_cache(tx)

        ts_date = datetime.datetime.fromtimestamp(tx.timestamp)
        if tx.is_block:
            print('New block: {} timestamp={} ({}) ({}) weight={}'.format(
                tx.hash_hex,
                ts_date,
                tx.get_time_from_now(),
                tx.timestamp,
                tx.weight)
            )
        else:
            print('New tx: {} timestamp={} ({})'.format(tx.hash.hex(), ts_date, tx.get_time_from_now()))

        tx.mark_inputs_as_used()

        # Propagate to our peers.
        if self.remoteConnection:
            tx_type = 'block' if tx.is_block else 'tx'
            self.remoteConnection.callRemote(SendTx, tx_type=tx_type, tx_bytes=bytes(tx))

        # Publish to pubsub manager the new tx accepted
        self.pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED, tx=tx)
        return True

    def calculate_block_difficulty(self, block):
        """ Calculate block difficulty according to the ascendents of `block`.

        The new difficulty is calculated so that the average time between blocks will be
        `self.avg_time_between_blocks`. If the measured time between blocks is smaller than the target,
        the weight increases. If it is higher than the target, the weight decreases.

        The new difficulty cannot be smaller than `self.min_block_weight`.
        """
        if block.is_genesis:
            return 10

        it = self.tx_storage.iter_bfs_ascendent_blocks(block, max_depth=10)
        blocks = list(it)
        blocks.sort(key=lambda tx: tx.timestamp)

        if blocks[-1].is_genesis:
            return 10

        dt = blocks[-1].timestamp - blocks[0].timestamp

        if dt <= 0:
            dt = 1  # Strange situation, so, let's just increase difficulty.

        logH = 0
        for blk in blocks:
            logH = sum_weights(logH, blk.weight)

        weight = logH - log(dt, 2) + log(self.avg_time_between_blocks, 2)

        if weight < self.min_block_weight:
            weight = self.min_block_weight

        return weight

    @inlineCallbacks
    def get_network_status(self):
        if self.remoteConnection:
            ret = yield self.remoteConnection.callRemote(GetNetworkStatus)
            ret['status'] = pickle.loads(ret['status'])
            return ret
