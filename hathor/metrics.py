from hathor.pubsub import PubSubManager, HathorEvents
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage


class Metrics:
    def __init__(self, pubsub=None, tx_storage=None):
        self.transactions = 0
        self.blocks = 0

        self.pubsub = pubsub or PubSubManager()

        self.tx_storage = tx_storage or TransactionMemoryStorage()

        self._initial_setup()

    def _initial_setup(self):
        self._start_initial_values()
        self.subscribe()

    def _start_initial_values(self):
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
            Then we broadcast the data to all connected clients
        """
        data = args.__dict__
        if data['tx'].is_block:
            self.blocks += 1
        else:
            self.transactions += 1
