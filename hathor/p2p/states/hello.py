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

from typing import TYPE_CHECKING, Any

from structlog import get_logger

import hathor
from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.exception import HathorError
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.states.base import BaseState
from hathor.p2p.sync_version import SyncVersion
from hathor.p2p.utils import format_address, get_genesis_short_hash, get_settings_hello_dict
from hathor.util import json_dumps, json_loads

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol  # noqa: F401

logger = get_logger()


class HelloState(BaseState):
    def __init__(self, protocol: 'HathorProtocol', settings: HathorSettings) -> None:
        super().__init__(protocol, settings)
        self.log = logger.new(**protocol.get_logger_context())
        self.cmd_map.update({
            ProtocolMessages.HELLO: self.handle_hello,
        })

    def _app(self) -> str:
        return f'Hathor v{hathor.__version__}'

    def _get_hello_data(self) -> dict[str, Any]:
        """ Returns a dict with information about this node that will
        be sent to a peer.
        """
        protocol = self.protocol
        assert protocol.transport is not None
        remote = protocol.transport.getPeer()
        data = {
            'app': self._app(),
            'network': self._settings.NETWORK_NAME,
            'remote_address': format_address(remote),
            'genesis_short_hash': get_genesis_short_hash(),
            'timestamp': protocol.node.reactor.seconds(),
            'settings_dict': get_settings_hello_dict(self._settings),
            'capabilities': protocol.node.capabilities,
        }
        if self.protocol.node.has_sync_version_capability():
            data['sync_versions'] = [x.value for x in self._get_sync_versions()]
        return data

    def _get_sync_versions(self) -> set[SyncVersion]:
        """Shortcut to ConnectionManager.get_enabled_sync_versions"""
        connections_manager = self.protocol.connections
        assert connections_manager is not None
        return connections_manager.get_enabled_sync_versions()

    def on_enter(self) -> None:
        # After a connection is made, we just send a HELLO message.
        self.send_hello()

    def send_hello(self) -> None:
        """ Send a HELLO message, identifying the app and giving extra
        information about this node to the peer.
        """
        data = self._get_hello_data()
        self.send_message(ProtocolMessages.HELLO, json_dumps(data))

    def handle_hello(self, payload: str) -> None:
        """ Executed when a HELLO message is received. It basically
        checks the application compatibility.
        """
        from hathor.p2p.netfilter import get_table
        from hathor.p2p.netfilter.context import NetfilterContext

        protocol = self.protocol
        assert protocol.transport is not None
        try:
            data = json_loads(payload)
        except ValueError:
            protocol.send_error_and_close_connection('Invalid payload.')
            return

        required_fields = {'app', 'network', 'remote_address', 'genesis_short_hash', 'timestamp', 'capabilities'}
        # settings_dict is optional
        if not set(data).issuperset(required_fields):
            # If data does not contain all required fields
            protocol.send_error_and_close_connection('Invalid payload.')
            return

        if self._settings.CAPABILITY_WHITELIST not in data['capabilities']:
            # If peer is not sending whitelist capability we must close the connection
            protocol.send_error_and_close_connection('Must have whitelist capability.')
            return

        # another status can use the informed capabilities
        protocol.capabilities = set(data['capabilities'])

        my_sync_versions = self._get_sync_versions()
        try:
            remote_sync_versions = _parse_sync_versions(data)
        except HathorError as e:
            # this will only happen if the remote implementation is wrong
            self.log.warn('invalid protocol', error=e)
            protocol.send_error_and_close_connection('invalid protocol')
            return

        common_sync_versions = my_sync_versions & remote_sync_versions
        if not common_sync_versions:
            # no compatible sync version to use, this is fine though we just can't connect to this peer
            self.log.info('no compatible sync version to use')
            protocol.send_error_and_close_connection('no compatible sync version to use')
            return

        # choose the best version, sorting is implemented in hathor.p2p.sync_versions.__lt__
        protocol.sync_version = max(common_sync_versions)

        if data['app'] != self._app():
            remote_app = data['app'].encode().hex()
            our_app = self._app().encode().hex()
            # XXX: this used to be a warning, but it shouldn't be since it's perfectly normal
            self.log.debug('different versions', theirs=remote_app, ours=our_app)

        if data['network'] != self._settings.NETWORK_NAME:
            protocol.send_error_and_close_connection('Wrong network.')
            return

        if data['genesis_short_hash'] != get_genesis_short_hash():
            protocol.send_error_and_close_connection('Different genesis.')
            return

        dt = data['timestamp'] - protocol.node.reactor.seconds()
        if abs(dt) > self._settings.MAX_FUTURE_TIMESTAMP_ALLOWED / 2:
            protocol.send_error_and_close_connection('Nodes timestamps too far apart.')
            return

        if 'settings_dict' in data:
            # If settings_dict is sent we must validate it
            settings_dict = get_settings_hello_dict(self._settings)
            if data['settings_dict'] != settings_dict:
                protocol.send_error_and_close_connection(
                    'Settings values are different. {}'.format(json_dumps(settings_dict))
                )
                return

        protocol.app_version = data['app']
        protocol.diff_timestamp = dt

        context = NetfilterContext(
            protocol=protocol,
            connections=protocol.connections,
            addr=protocol.transport.getPeer(),
        )
        verdict = get_table('filter').get_chain('post_hello').process(context)
        if not bool(verdict):
            self.protocol.disconnect('rejected by netfilter: filter post_hello', force=True)
            return

        protocol.change_state(protocol.PeerState.PEER_ID)


def _parse_sync_versions(hello_data: dict[str, Any]) -> set[SyncVersion]:
    """Versions that are not recognized will not be included."""
    settings = get_global_settings()
    if settings.CAPABILITY_SYNC_VERSION in hello_data['capabilities']:
        if 'sync_versions' not in hello_data:
            raise HathorError('protocol error, expected sync_versions field')
        known_values = set(x.value for x in SyncVersion)
        recognized_values = set(hello_data['sync_versions']) & known_values
        return set(SyncVersion(x) for x in recognized_values)
    else:
        # XXX: implied value when sync-version capability isn't present
        return {SyncVersion.V2}
