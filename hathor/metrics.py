from hathor.pubsub import HathorEvents
from hathor.p2p.protocol import HathorProtocol
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage
from math import log


class Metrics:
    def __init__(self, pubsub, avg_time_between_blocks, tx_storage=None):
        """
        :param pubsub: If not given, a new one is created.
        :type pubsub: :py:class:`hathor.pubsub.PubSubManager`

        :param tx_storage: If not given, a new one is created.
        :type tx_storage: :py:class:`hathor.storage.TransactionStorage`

        :param avg_time_between_blocks: Seconds between blocks (comes from manager)
        :type avg_time_between_blocks: int
        """
        # Transactions count in the network
        self.transactions = 0

        # Blocks count in the network
        self.blocks = 0

        # Hash rate of the network
        self.hash_rate = 0

        # Peers connected
        self.peers = 0

        self.avg_time_between_blocks = avg_time_between_blocks

        self.pubsub = pubsub

        self.tx_storage = tx_storage or TransactionMemoryStorage()

        self._initial_setup()

    def _initial_setup(self):
        """ Start metrics initial values and subscribe to necessary events in the pubsub
        """
        self._start_initial_values()
        self.subscribe()

    def _start_initial_values(self):
        """ When we start the metrics object we set the transaction and block count already in the network
        """
        self.transactions = self.tx_storage.get_tx_count()
        self.blocks = self.tx_storage.get_block_count()

        last_block = self.tx_storage.get_latest_blocks(count=1)
        if last_block:
            self.hash_rate = self.calculate_new_hashrate(last_block[0])

    def subscribe(self):
        """ Subscribe to defined events for the pubsub received
        """
        events = [
            HathorEvents.NETWORK_NEW_TX_ACCEPTED,
            HathorEvents.NETWORK_PEER_CONNECTED,
            HathorEvents.NETWORK_PEER_DISCONNECTED,
        ]

        for event in events:
            self.pubsub.subscribe(event, self.handle_publish)

    def handle_publish(self, key, args):
        """ This method is called when pubsub publishes an event that we subscribed
        """
        data = args.__dict__
        if key == HathorEvents.NETWORK_NEW_TX_ACCEPTED:
            if data['tx'].is_block:
                self.blocks += 1
                self.hash_rate = self.calculate_new_hashrate(data['tx'])
            else:
                self.transactions += 1
        elif key == HathorEvents.NETWORK_PEER_CONNECTED:
            self.peers += 1
        elif key == HathorEvents.NETWORK_PEER_DISCONNECTED:
            # Check if peer was ready before disconnecting
            if data['state_name'] == HathorProtocol.PeerState.READY.name:
                self.peers -= 1
        else:
            raise ValueError('Invalid key')

    def calculate_new_hashrate(self, block):
        """ Weight formula: w = log2(avg_time_between_blocks) + log2(hash_rate)
        """
        return 2**(block.weight - log(self.avg_time_between_blocks, 2))
