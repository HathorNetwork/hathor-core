from hathor.pubsub import HathorEvents
from hathor.websocket import HathorAdminWebsocketProtocol
from hathor.metrics import Metrics
from twisted.internet import reactor
from autobahn.twisted.websocket import WebSocketServerFactory
import json
from collections import deque
from hathor.p2p.rate_limiter import RateLimiter

# CONTROLLED_TYPES define each Rate Limit parameter for each message type that should be limited
# buffer_size (int): size of the deque that will hold the messages that will be processed in the future
# time_buffering (int): Interval that we will try to process the deque with unprocessed messages
# max_hits (int) and hits_window_seconds (int): together they define the Rate Limit
# It's how many hits can this message make in the window interval

CONTROLLED_TYPES = {
    HathorEvents.NETWORK_NEW_TX_ACCEPTED.value: {
        'buffer_size': 20,
        'time_buffering': 0.1,
        'max_hits': 20,
        'hits_window_seconds': 2,
    }, HathorEvents.WALLET_OUTPUT_RECEIVED.value: {
        'buffer_size': 20,
        'time_buffering': 0.1,
        'max_hits': 10,
        'hits_window_seconds': 2,
    }, HathorEvents.WALLET_INPUT_SPENT.value: {
        'buffer_size': 20,
        'time_buffering': 0.1,
        'max_hits': 10,
        'hits_window_seconds': 2,
    }, HathorEvents.WALLET_BALANCE_UPDATED.value: {
        'buffer_size': 3,
        'time_buffering': 0.4,
        'max_hits': 3,
        'hits_window_seconds': 1,
    }
}


class HathorAdminWebsocketFactory(WebSocketServerFactory):
    """ Factory of the admin websocket protocol so we can subscribe to events and
        send messages in the Admin page to clients when the events are published
    """
    protocol = HathorAdminWebsocketProtocol

    def buildProtocol(self, addr):
        return self.protocol(self)

    def __init__(self, metrics=None):
        """
        :param metrics: If not given, a new one is created.
        :type metrics: :py:class:`hathor.metrics.Metrics`
        """
        # Opened websocket connections so I can broadcast messages later
        self.connections = set()
        super().__init__()

        # Limit the send message rate for specific type of data
        self.rate_limiter = RateLimiter(reactor=reactor)
        # Stores the buffer of messages that exceeded the rate limit and will be sent
        self.buffer_deques = {}

        self.metrics = metrics or Metrics()

        # Start limiter
        self._setup_rate_limit()

        # Start metric sender
        self._schedule_and_send_metric()

    def _setup_rate_limit(self):
        """ Set the limit of the RateLimiter and start the buffer deques with BUFFER_SIZE
        """
        for control_type, config in CONTROLLED_TYPES.items():
            self.rate_limiter.set_limit(control_type, config['max_hits'], config['hits_window_seconds'])
            self.buffer_deques[control_type] = deque(maxlen=config['buffer_size'])

    def _schedule_and_send_metric(self):
        """ Send dashboard metric to websocket and schedule next message
        """
        data = {
            'transactions': self.metrics.transactions,
            'blocks': self.metrics.blocks,
            'hash_rate': self.metrics.hash_rate,
            'block_hash_rate': self.metrics.block_hash_rate,
            'tx_hash_rate': self.metrics.tx_hash_rate,
            'network_hash_rate': self.metrics.tx_hash_rate + self.metrics.block_hash_rate,
            'peers': self.metrics.peers,
            'type': 'dashboard:metrics',
            'time': reactor.seconds(),
        }
        self.broadcast_message(data)
        # Schedule next message
        reactor.callLater(
            1,
            self._schedule_and_send_metric
        )

    def subscribe(self, pubsub):
        """ Subscribe to defined events for the pubsub received
        """
        events = [
            HathorEvents.NETWORK_NEW_TX_ACCEPTED,
            HathorEvents.WALLET_OUTPUT_RECEIVED,
            HathorEvents.WALLET_INPUT_SPENT,
            HathorEvents.WALLET_BALANCE_UPDATED,
            HathorEvents.WALLET_KEYS_GENERATED,
            HathorEvents.WALLET_GAP_LIMIT,
            HathorEvents.WALLET_HISTORY_UPDATED,
        ]

        for event in events:
            pubsub.subscribe(event, self.handle_publish)

    def handle_publish(self, key, args):
        """ This method is called when pubsub publishes an event that we subscribed
            Then we broadcast the data to all connected clients
        """
        data = self.serialize_message_data(key, args)
        data['type'] = key.value
        self.send_or_enqueue(data)

    def serialize_message_data(self, event, args):
        """ Receives the event and the args from the pubsub
            and serializes the data so it can be passed in the websocket
        """
        # Ready events don't need extra serialization
        ready_events = [
            HathorEvents.WALLET_BALANCE_UPDATED,
            HathorEvents.WALLET_KEYS_GENERATED,
            HathorEvents.WALLET_GAP_LIMIT,
            HathorEvents.WALLET_HISTORY_UPDATED,
        ]
        data = args.__dict__
        if event in ready_events:
            return data
        elif event == HathorEvents.WALLET_OUTPUT_RECEIVED:
            data['output'] = data['output'].to_dict()
            return data
        elif event == HathorEvents.WALLET_INPUT_SPENT:
            data['output_spent'] = data['output_spent'].to_dict()
            return data
        elif event == HathorEvents.NETWORK_NEW_TX_ACCEPTED:
            tx = data['tx']
            data = tx.to_json()
            data['is_block'] = tx.is_block
            return data
        else:
            raise ValueError('Should never have entered here! We dont know this event')

    def broadcast_message(self, data):
        """ Broadcast the update message to all connected clients
        """
        payload = json.dumps(data).encode('utf-8')
        for c in self.connections:
            c.sendMessage(payload, False)

    def send_or_enqueue(self, data):
        """ Try to broadcast the message, or enqueue it when rate limit is exceeded and we've been throttled.
            Enqueued messages are automatically sent after a while if they are not discarded first.
            A message is discarded when new messages arrive and the queue buffer is full.
            Rate limits change according to the message type, which is obtained from data['type'].

            :param data: message to be sent
            :type data: Dict[string, X] -> X can be different types, depending on the type of message
        """
        if data['type'] in CONTROLLED_TYPES:
            # This type is controlled, so I need to check the deque
            if len(self.buffer_deques[data['type']]) or not self.rate_limiter.add_hit(data['type']):
                # If I am already with a buffer or if I hit the limit now, I enqueue for later
                self.enqueue_for_later(data)
            else:
                data['throttled'] = False
                self.broadcast_message(data)
        else:
            self.broadcast_message(data)

    def enqueue_for_later(self, data):
        """ Add this date to the correct deque to be processed later
            If this deque is not programed to be called later yet, we call it

            :param data: message to be sent
            :type data: Dict[string, X] -> X can be different types, depending on the type of message
        """
        # Add data to deque
        # We always add the new messages in the end
        # Adding parameter deque=True, so the admin can know this message was delayed
        data['throttled'] = True
        self.buffer_deques[data['type']].append(data)
        if len(self.buffer_deques[data['type']]) == 1:
            # If it's the first time we hit the limit (only one message in deque), we schedule process_deque
            reactor.callLater(
                CONTROLLED_TYPES[data['type']]['time_buffering'],
                self.process_deque,
                data_type=data['type']
            )

    def process_deque(self, data_type):
        """ Process the deque and check if I have limit to send the messages now

            :param data_type: Type of the message to be sent
            :type data_type: string
        """
        while len(self.buffer_deques[data_type]) > 0:
            if self.rate_limiter.add_hit(data_type):
                # We always process the older message first
                data = self.buffer_deques[data_type].popleft()
                if len(self.buffer_deques[data_type]) == 0:
                    data['throttled'] = False
                self.broadcast_message(data)
            else:
                reactor.callLater(
                    CONTROLLED_TYPES[data_type]['time_buffering'],
                    self.process_deque,
                    data_type=data_type
                )
                break

    def handle_message(self, connection, data):
        message = json.loads(data.decode('utf-8'))
        # we only handle ping messages for now
        if message['type'] == 'ping':
            payload = json.dumps({'type': 'pong'}).encode('utf-8')
            connection.sendMessage(payload, False)
