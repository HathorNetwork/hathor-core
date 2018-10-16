from hathor.pubsub import HathorEvents
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage


class Metrics:
    def __init__(self, pubsub, tx_storage=None):
        """
        :param pubsub: If not given, a new one is created.
        :type pubsub: :py:class:`hathor.pubsub.PubSubManager`

        :param tx_storage: If not given, a new one is created.
        :type tx_storage: :py:class:`hathor.storage.TransactionStorage`
        """
        # Transactions count in the network
        self.transactions = 0

        # Blocks count in the network
        self.blocks = 0

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

    def subscribe(self):
        """ Subscribe to defined events for the pubsub received
        """
        events = [
            HathorEvents.NETWORK_NEW_TX_ACCEPTED,
        ]

        for event in events:
            self.pubsub.subscribe(event, self.handle_publish)

    def handle_publish(self, key, args):
        """ This method is called when pubsub publishes an event that we subscribed
        """
        data = args.__dict__
        if data['tx'].is_block:
            self.blocks += 1
        else:
            self.transactions += 1
