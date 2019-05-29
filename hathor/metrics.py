from collections import deque
from typing import TYPE_CHECKING, Callable, Deque, NamedTuple, Optional

from twisted.internet.interfaces import IReactorCore

from hathor.pubsub import EventArguments, HathorEvents, PubSubManager
from hathor.transaction.base_transaction import sub_weights, sum_weights
from hathor.transaction.block import Block
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage

if TYPE_CHECKING:
    from hathor.websocket.factory import HathorAdminWebsocketFactory  # noqa: F401


class WeightValue(NamedTuple):
    time: int
    value: float


class Metrics:
    transactions: int
    blocks: int
    hash_rate: float
    total_block_weight: float
    total_tx_weight: float
    peers: int
    tx_hash_rate: float
    block_hash_rate: float
    best_block_weight: float
    weight_tx_deque_len: int
    weight_block_deque_len: int
    weight_tx_deque: Deque[WeightValue]
    weight_block_deque: Deque[WeightValue]
    avg_time_between_blocks: int
    pubsub: PubSubManager
    tx_storage: TransactionStorage
    reactor: IReactorCore
    is_running: bool
    exponential_alfa: float  # XXX: "alpha"?
    tx_hash_store_interval: int
    block_hash_store_interval: int
    collect_data_interval: int
    websocket_connections: int
    subscribed_addresses: int
    websocket_factory: Optional['HathorAdminWebsocketFactory']

    def __init__(
            self,
            pubsub: PubSubManager,
            avg_time_between_blocks: int,
            tx_storage: Optional[TransactionStorage] = None,
            reactor: Optional[IReactorCore] = None,
    ):
        """
        :param pubsub: If not given, a new one is created.
        :param tx_storage: If not given, a new one is created.
        :param avg_time_between_blocks: Seconds between blocks (comes from manager)
        :param tx_storage: Transaction storage
        :param reactor: Twisted reactor that handles the time and callLater
        """
        # Transactions count in the network
        self.transactions = 0

        # Blocks count in the network
        self.blocks = 0

        # Hash rate of the network
        self.hash_rate = 0.0

        # Total block weight
        self.total_block_weight = 0.0

        # Total tx weight
        self.total_tx_weight = 0.0

        # Peers connected
        self.peers = 0

        # Hash rate of tx
        self.tx_hash_rate = 0.0

        # Hash rate of block
        self.block_hash_rate = 0

        # Length of the tx deque
        self.weight_tx_deque_len = 60

        # Length of the block deque
        self.weight_block_deque_len = 450

        # Stores caculated tx weights saved in tx storage
        self.weight_tx_deque = deque(maxlen=self.weight_tx_deque_len)

        # Stores caculated block weights saved in tx storage
        self.weight_block_deque = deque(maxlen=self.weight_block_deque_len)

        self.avg_time_between_blocks = avg_time_between_blocks

        self.pubsub = pubsub

        self.tx_storage = tx_storage or TransactionMemoryStorage()

        if reactor is None:
            from twisted.internet import reactor as twisted_reactor
            reactor = twisted_reactor
        self.reactor = reactor

        # If metric capture data is running
        self.is_running = False

        # Coefficient of exponential calculus
        self.exponential_alfa = 0.7

        # Time between method call to store hash count
        self.tx_hash_store_interval = 1
        self.block_hash_store_interval = 1

        # Time between method call to collect data
        self.collect_data_interval = 5

        # Websocket data stored
        self.websocket_connections = 0
        self.subscribed_addresses = 0

        # Websocket factory
        self.websocket_factory = None

        # weight of the head of the best blockchain
        self.best_block_weight = 0

        self._initial_setup()

    def _initial_setup(self) -> None:
        """ Start metrics initial values and subscribe to necessary events in the pubsub
        """
        self._start_initial_values()
        self.subscribe()

    def _start_initial_values(self) -> None:
        """ When we start the metrics object we set the transaction and block count already in the network
        """
        self.transactions = self.tx_storage.get_tx_count()
        self.blocks = self.tx_storage.get_block_count()

        (last_block, _) = self.tx_storage.get_newest_blocks(count=1)
        if last_block:
            self.hash_rate = self.calculate_new_hashrate(last_block[0])

    def start(self) -> None:
        self.is_running = True
        self.set_current_tx_hash_rate()
        self.set_current_block_hash_rate()
        self.collect_data()

    def stop(self) -> None:
        self.is_running = False

    def subscribe(self) -> None:
        """ Subscribe to defined events for the pubsub received
        """
        events = [
            HathorEvents.NETWORK_NEW_TX_ACCEPTED,
            HathorEvents.NETWORK_PEER_CONNECTED,
            HathorEvents.NETWORK_PEER_DISCONNECTED,
        ]

        for event in events:
            self.pubsub.subscribe(event, self.handle_publish)

    def handle_publish(self, key: HathorEvents, args: EventArguments) -> None:
        """ This method is called when pubsub publishes an event that we subscribed
        """
        from hathor.p2p.protocol import HathorProtocol

        data = args.__dict__
        if key == HathorEvents.NETWORK_NEW_TX_ACCEPTED:
            if data['tx'].is_block:
                self.blocks += 1
                self.total_block_weight = sum_weights(data['tx'].weight, self.total_block_weight)
                self.hash_rate = self.calculate_new_hashrate(data['tx'])
                self.best_block_weight = self.tx_storage.get_weight_best_block()
            else:
                self.transactions += 1
                self.total_tx_weight = sum_weights(data['tx'].weight, self.total_tx_weight)
        elif key == HathorEvents.NETWORK_PEER_CONNECTED:
            self.peers += 1
        elif key == HathorEvents.NETWORK_PEER_DISCONNECTED:
            # Check if peer was ready before disconnecting
            if data['protocol'].state.state_name == HathorProtocol.PeerState.READY.name:
                self.peers -= 1
        else:
            raise ValueError('Invalid key')

    def calculate_new_hashrate(self, block: Block) -> float:
        """ Weight formula: w = log2(avg_time_between_blocks) + log2(hash_rate)
        """
        from math import log
        return 2**(block.weight - log(self.avg_time_between_blocks, 2))

    def set_current_tx_hash_rate(self) -> None:
        """ Calculate new tx hash rate
        """
        hash_rate = self.get_current_hash_rate(self.weight_tx_deque, self.total_tx_weight,
                                               self.set_current_tx_hash_rate, self.tx_hash_store_interval)
        self.tx_hash_rate = self.get_exponential_hash_rate(hash_rate, self.tx_hash_rate)

    def set_current_block_hash_rate(self) -> None:
        """ Calculate new block hash rate
        """
        hash_rate = self.get_current_hash_rate(self.weight_block_deque, self.total_block_weight,
                                               self.set_current_block_hash_rate, self.block_hash_store_interval)
        self.block_hash_rate = self.get_exponential_hash_rate(hash_rate, self.block_hash_rate)

    def get_current_hash_rate(self, deque: Deque[WeightValue], total_weight: float, fn: Callable[[], None],
                              interval: int) -> float:
        """ Calculate new hash rate and schedule next call

            :param deque: deque to get first and last hash rate values
            :type deque: deque[WeightValue]

            :param total_weight: total weight of blocks/txs
            :type total_weight: float

            :param fn: method to be called in the scheduler
            :type fn: function

            :param interval: interval (in seconds) for the next method call
            :type interval: int

            :return: new hash rate
            :rtype: float
        """
        deque.append(WeightValue(self.reactor.seconds(), total_weight))

        last = deque[-1]
        first = deque[0]
        if first.time == last.time:
            hash_rate = 0.0
        else:
            hash_rate = (2**sub_weights(last.value, first.value)) / (last.time - first.time)

        if self.is_running:
            self.reactor.callLater(interval, fn)

        return hash_rate

    def get_exponential_hash_rate(self, new_value: float, last_value: float) -> float:
        """ Using exponential moving average to calculate hash rate, so it decreases exponentially
            https://en.wikipedia.org/wiki/Moving_average#Exponential_moving_average

            :param new_value: new hash rate value
            :type new_value: float

            :param last_value: last weighted value for hash rate
            :type last_value: float

            :return: weighted value for hash rate
            :rtype: float
        """
        return new_value * self.exponential_alfa + (1 - self.exponential_alfa) * last_value

    def set_websocket_data(self) -> None:
        """ Set websocket metrics data. Connections and addresses subscribed.
        """
        if self.websocket_factory:
            self.websocket_connections = len(self.websocket_factory.connections)
            self.subscribed_addresses = len(self.websocket_factory.address_connections)

    def collect_data(self) -> None:
        """ Call methods that collect data to metrics
            If it's still running, we schedule another call
        """
        self.set_websocket_data()

        if self.is_running:
            self.reactor.callLater(self.collect_data_interval, self.collect_data)
