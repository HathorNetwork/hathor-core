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
from hathor.p2p.protocol_version import ProtocolVersion
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

        # start with sync-v2, which has higher priority
        if protocol.enable_sync_v2:
            # we accept sync-v2, but does the remote accept too?
            assert settings.CAPABILITY_SYNC_V2 in protocol.node.capabilities
            if settings.CAPABILITY_SYNC_V2 in data['capabilities']:
                # ok we both support sync-v2, so we'll use that
                self.log.debug('set protocol version to sync-v2')
                protocol.protocol_version = ProtocolVersion.V2
            elif protocol.enable_sync_v1:
                # the remote does not accept sync-v2, but we can still proceed because we accept sync-v1
                self.log.debug('set protocol version to sync-v1 (remote-fallback)')
                protocol.protocol_version = ProtocolVersion.V1
            else:
                # no compatible sync version to use, this is fine though we just can't connect to this peer
                self.log.info('no compatible sync version to use')
                protocol.send_error_and_close_connection('no compatible sync version to use')
                return
        elif protocol.enable_sync_v1:
            # we don't accept sync-v2, so it doesn't matter much whether the remote supports but we'll check anyway
            assert settings.CAPABILITY_SYNC_V2 not in protocol.node.capabilities
            if settings.CAPABILITY_SYNC_V2 in data['capabilities']:
                # they do support it so we should fallback because we don't
                self.log.debug('set protocol version to sync-v1 (local-fallback)')
            else:
                # same old sync-v1-only to sync-v1-only, should be the most common path for a now
                self.log.debug('set protocol version to sync-v1')
            protocol.protocol_version = ProtocolVersion.V1
        else:
            # XXX: this shouldn't be possible to configure normally, but if you mess up setting up tests or messing
            # with a custom capabilities it might end up here, should we raise a RuntimeError?
            self.log.error('no protocol version configured')
            protocol.send_error_and_close_connection('no protocol version supported')
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
