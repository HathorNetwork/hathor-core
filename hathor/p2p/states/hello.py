from typing import TYPE_CHECKING

import hathor
from hathor.conf import HathorSettings
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.states.base import BaseState
from hathor.p2p.utils import get_genesis_short_hash, get_settings_hello_dict
from hathor.util import JsonDict, json_dumpb, json_loadb

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

    def _get_hello_data(self) -> JsonDict:
        """ Returns a dict with information about this node that will
        be sent to a peer.
        """
        protocol = self.protocol
        remote = protocol.transport.getPeer()
        return {
            'app': self._app(),
            'network': protocol.network,
            'remote_address': '{}:{}'.format(remote.host, remote.port),
            'genesis_short_hash': get_genesis_short_hash(),
            'timestamp': protocol.node.reactor.seconds(),
            'settings_dict': get_settings_hello_dict(),
            'capabilities': [],
        }

    def on_enter(self) -> None:
        # After a connection is made, we just send a HELLO message.
        self.send_hello()

    def send_hello(self) -> None:
        """ Send a HELLO message, identifying the app and giving extra
        information about this node to the peer.
        """
        data = self._get_hello_data()
        self.send_message(ProtocolMessages.HELLO, json_dumpb(data))

    def handle_hello(self, payload: str) -> None:
        """ Executed when a HELLO message is received. It basically
        checks the application compatibility.
        """
        protocol = self.protocol
        try:
            data = json_loadb(payload)
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
            self.log.warn('different versions', theirs=data['app'], ours=self._app())

        if data['network'] != protocol.network:
            protocol.send_error_and_close_connection('Wrong network.')
            return

        if data['genesis_short_hash'] != get_genesis_short_hash():
            protocol.send_error_and_close_connection('Different genesis.')
            return

        if abs(data['timestamp'] - protocol.node.reactor.seconds()) > settings.MAX_FUTURE_TIMESTAMP_ALLOWED/2:
            protocol.send_error_and_close_connection('Nodes timestamps too far apart.')
            return

        settings_dict = get_settings_hello_dict()
        if 'settings_dict' in data and data['settings_dict'] != settings_dict:
            # If settings_dict is sent we must validate it
            protocol.send_error_and_close_connection(
                'Settings values are different. {}'.format(json_dumpb(settings_dict))
            )
            return

        protocol.app_version = data['app']
        protocol.change_state(protocol.PeerState.PEER_ID)
