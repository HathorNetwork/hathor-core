import json
import uuid
from typing import TYPE_CHECKING

import hathor
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.states.base import BaseState

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol  # noqa: F401


class HelloState(BaseState):
    def __init__(self, protocol: 'HathorProtocol') -> None:
        super().__init__(protocol)
        self.cmd_map.update({
            ProtocolMessages.HELLO: self.handle_hello,
        })

    def on_enter(self) -> None:
        # The nonce that was sent to the peer to check its identity.
        self.protocol.hello_nonce_sent = str(uuid.uuid4())

        # After a connection is made, we just send a HELLO message.
        self.send_hello()

    def send_hello(self) -> None:
        """ Send a HELLO message, identifying the app and giving a `nonce`
        value which must be signed in the PEER-ID response to ensure the
        identity of the peer.
        """
        protocol = self.protocol
        remote = protocol.transport.getPeer()
        data = {
            'app': 'Hathor v{}'.format(hathor.__version__),
            'network': protocol.network,
            'remote_address': '{}:{}'.format(remote.host, remote.port),
            'nonce': protocol.hello_nonce_sent,
        }
        self.send_message(ProtocolMessages.HELLO, json.dumps(data))

    def handle_hello(self, payload: str) -> None:
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
            self.log.info('WARNING Different app versions: {data[app]}', data=data)
            protocol.send_error_and_close_connection('Different version.')

        if data['network'] != protocol.network:
            protocol.send_error_and_close_connection('Wrong network.')
            return

        protocol.app_version = data['app']
        protocol.hello_nonce_received = data['nonce']
        protocol.change_state(protocol.PeerState.PEER_ID)
