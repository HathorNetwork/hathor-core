import json
from typing import TYPE_CHECKING

import hathor
from hathor.conf import HathorSettings
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.states.base import BaseState
from hathor.p2p.utils import get_genesis_short_hash, get_settings_hello_dict

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol  # noqa: F401

settings = HathorSettings()


class HelloState(BaseState):
    def __init__(self, protocol: 'HathorProtocol') -> None:
        super().__init__(protocol)
        self.cmd_map.update({
            ProtocolMessages.HELLO: self.handle_hello,
        })

    def _app(self) -> str:
        return f'Hathor v{hathor.__version__}'

    def on_enter(self) -> None:
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
            'app': self._app(),
            'network': protocol.network,
            'remote_address': '{}:{}'.format(remote.host, remote.port),
            'genesis_short_hash': get_genesis_short_hash(),
            'timestamp': protocol.node.reactor.seconds(),
            'settings_dict': get_settings_hello_dict(),
            'capabilities': [],
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

        required_fields = {'app', 'network', 'remote_address', 'genesis_short_hash', 'timestamp', 'capabilities'}
        # settings_dict is optional
        if not set(data).issuperset(required_fields):
            # If data does not contain all required fields
            protocol.send_error_and_close_connection('Invalid payload.')
            return

        if data['app'] != self._app():
            self.log.info('WARNING Different app versions: {data[app]}', data=data)
            protocol.send_error_and_close_connection('Different version.')
            return

        if data['network'] != protocol.network:
            protocol.send_error_and_close_connection('Wrong network.')
            return

        if data['genesis_short_hash'] != get_genesis_short_hash():
            protocol.send_error_and_close_connection('Different genesis.')
            return

        settings_dict = get_settings_hello_dict()
        if 'settings_dict' in data and data['settings_dict'] != settings_dict:
            # If settings_dict is sent we must validate it
            protocol.send_error_and_close_connection(
                'Settings values are different. {}'.format(json.dumps(settings_dict))
            )
            return

        protocol.app_version = data['app']
        protocol.change_state(protocol.PeerState.PEER_ID)
