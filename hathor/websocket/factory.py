from hathor.pubsub import HathorEvents
from hathor.websocket import HathorAdminWebsocketProtocol
from autobahn.twisted.websocket import WebSocketServerFactory
import json


class HathorAdminWebsocketFactory(WebSocketServerFactory):
    """ Factory of the admin websocket protocol so we can subscribe to events and
        send messages in the Admin page to clients when the events are published
    """
    protocol = HathorAdminWebsocketProtocol

    def buildProtocol(self, addr):
        return self.protocol(self)

    def __init__(self):
        self.connections = set()
        super().__init__()

    def subscribe(self, pubsub):
        """ Subscribe to defined events for the pubsub received
        """
        events = [
            HathorEvents.NETWORK_NEW_TX_ACCEPTED,
            HathorEvents.WALLET_OUTPUT_RECEIVED,
            HathorEvents.WALLET_INPUT_SPENT,
            HathorEvents.WALLET_BALANCE_UPDATED,
            HathorEvents.WALLET_KEYS_GENERATED
        ]

        for event in events:
            pubsub.subscribe(event, self.handle_publish)

    def handle_publish(self, key, args):
        """ This method is called when pubsub publishes an event that we subscribed
            Then we broadcast the data to all connected clients
        """
        data = self.serialize_message_data(key, args)
        data['type'] = key.value
        self.broadcast_message(data)

    def serialize_message_data(self, event, args):
        """ Receives the event and the args from the pubsub
            and serializes the data so it can be passed in the websocket
        """
        # Ready events don't need extra serialization
        ready_events = [
            HathorEvents.WALLET_BALANCE_UPDATED,
            HathorEvents.WALLET_KEYS_GENERATED
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
