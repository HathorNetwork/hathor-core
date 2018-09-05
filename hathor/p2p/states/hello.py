# encoding: utf-8

from hathor.p2p.states.base import BaseState
import hathor

from enum import Enum
import json
import uuid


class HelloState(BaseState):
    class ProtocolCommand(Enum):
        # Identifies the app and network the peer would like to connect to.
        HELLO = 'HELLO'

        # Notifies an error.
        ERROR = 'ERROR'

    def __init__(self, protocol):
        self.protocol = protocol
        self.cmd_map = {
            self.ProtocolCommand.HELLO: self.handle_hello,
            self.ProtocolCommand.ERROR: self.handle_error,
        }

    def on_enter(self):
        # The nonce that was sent to the peer to check its identity.
        self.protocol.hello_nonce_sent = str(uuid.uuid4())

        # After a connection is made, we just send a HELLO message.
        self.send_hello()

    def handle_error(self, payload):
        self.protocol.handle_error(payload)

    def send_hello(self):
        """ Send a HELLO message, identifying the app and giving a `nonce`
        value which must be signed in the PEER-ID response to ensure the
        identity of the peer.
        """
        protocol = self.protocol
        remote = protocol.transport.getPeer()
        data = {
            'app': 'Hathor v{}'.format(hathor.__version__),
            'network': protocol.factory.network,
            'remote_address': '{}:{}'.format(remote.host, remote.port),
            'nonce': protocol.hello_nonce_sent,
        }
        self.send_message(self.ProtocolCommand.HELLO, json.dumps(data))

    def handle_hello(self, payload):
        """ Executed when a HELLO message is received. It basically
        checks the application compatibility.
        """
        protocol = self.protocol
        try:
            data = json.loads(payload)
        except ValueError:
            protocol.send_error_and_close_connection('Invalid payload.')
            return

        if {'app', 'network', 'remote_address', 'nonce'} != set(data):
            protocol.send_error_and_close_connection('Invalid payload.')
            return

        app = 'Hathor v{}'.format(hathor.__version__)
        if data['app'] != app:
            print('WARNING Different app versions:', data['app'])

        if data['network'] != protocol.factory.network:
            protocol.send_error_and_close_connection('Wrong network.')
            return

        protocol.hello_nonce_received = data['nonce']
        protocol.change_state(protocol.PeerState.PEER_ID)
