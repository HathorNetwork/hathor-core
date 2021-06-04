# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
from typing import TYPE_CHECKING, Any, Dict

from structlog import get_logger

import hathor
from hathor.conf import HathorSettings
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.states.base import BaseState
from hathor.p2p.utils import get_genesis_short_hash, get_settings_hello_dict

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol  # noqa: F401

logger = get_logger()

settings = HathorSettings()


class HelloState(BaseState):
    def __init__(self, protocol: 'HathorProtocol') -> None:
        super().__init__(protocol)
        self.log = logger.new(**protocol.get_logger_context())
        self.cmd_map.update({
            ProtocolMessages.HELLO: self.handle_hello,
        })

    def _app(self) -> str:
        return f'Hathor v{hathor.__version__}'

    def _get_hello_data(self) -> Dict[str, Any]:
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
            'capabilities': protocol.node.capabilities,
        }

    def on_enter(self) -> None:
        # After a connection is made, we just send a HELLO message.
        self.send_hello()

    def send_hello(self) -> None:
        """ Send a HELLO message, identifying the app and giving extra
        information about this node to the peer.
        """
        data = self._get_hello_data()
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

        if settings.ENABLE_PEER_WHITELIST and settings.CAPABILITY_WHITELIST not in data['capabilities']:
            # If peer is not sending whitelist capability we must close the connection
            protocol.send_error_and_close_connection('Must have whitelist capability.')
            return

        if data['app'] != self._app():
            self.log.warn('different versions', theirs=data['app'], ours=self._app())

        if data['network'] != protocol.network:
            protocol.send_error_and_close_connection('Wrong network.')
            return

        if data['genesis_short_hash'] != get_genesis_short_hash():
            protocol.send_error_and_close_connection('Different genesis.')
            return

        dt = data['timestamp'] - protocol.node.reactor.seconds()
        if abs(dt) > settings.MAX_FUTURE_TIMESTAMP_ALLOWED / 2:
            protocol.send_error_and_close_connection('Nodes timestamps too far apart.')
            return

        if 'settings_dict' in data:
            # If settings_dict is sent we must validate it
            settings_dict = get_settings_hello_dict()
            if data['settings_dict'] != settings_dict:
                protocol.send_error_and_close_connection(
                    'Settings values are different. {}'.format(json.dumps(settings_dict))
                )
                return

        protocol.app_version = data['app']
        protocol.diff_timestamp = dt

        from hathor.p2p.netfilter import get_table
        from hathor.p2p.netfilter.context import NetfilterContext
        context = NetfilterContext(
            protocol=self.protocol,
            connections=self.protocol.connections,
            addr=self.protocol.transport.getPeer(),
        )
        verdict = get_table('filter').get_chain('post_hello').process(context)
        if not bool(verdict):
            self.protocol.disconnect('rejected by netfilter: filter post_hello', force=True)
            return

        protocol.change_state(protocol.PeerState.PEER_ID)
