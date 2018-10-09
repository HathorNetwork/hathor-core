from hathor.pubsub import PubSubManager, HathorEvents


class Metrics:
    def __init__(self, pubsub=None):
        self.transactions = 0
        self.blocks = 0

        self.pubsub = pubsub or PubSubManager()

        self._initial_setup()

    def _initial_setup(self):
        self.subscribe()

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