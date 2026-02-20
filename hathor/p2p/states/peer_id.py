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

from hathor.conf.settings import HathorSettings
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.peer import PublicPeer
from hathor.p2p.peer_id import PeerId
from hathor.p2p.states.base import BaseState
from hathor.util import json_dumps, json_loads

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol  # noqa: F401

logger = get_logger()


class PeerIdState(BaseState):
    def __init__(self, protocol: 'HathorProtocol', settings: HathorSettings) -> None:
        super().__init__(protocol, settings)
        self.log = logger.new(remote=protocol.get_short_remote())
        self.cmd_map.update({
            ProtocolMessages.PEER_ID: self.handle_peer_id,
            ProtocolMessages.READY: self.handle_ready,
        })

        # Flags to know when each peer is valid to change state to ready
        self.my_peer_ready = False
        self.other_peer_ready = False

        # Common capabilities between the two peers
        common_capabilities = protocol.capabilities & set(protocol.node.capabilities)

        # whether to relay IPV6 entrypoints
        self.should_relay_ipv6_entrypoints: bool = self._settings.CAPABILITY_IPV6 in common_capabilities

    def on_enter(self) -> None:
        self.send_peer_id()

    def send_ready(self) -> None:
        """ Send a READY message, so the other peer knows you have already finished peer id validations
        """
        self.my_peer_ready = True
        self.send_message(ProtocolMessages.READY)
        if self.other_peer_ready:
            # In case both peers are already ready, we change the state to READY
            self.protocol.change_state(self.protocol.PeerState.READY)

    def handle_ready(self, payload: str) -> None:
        """ Handles a received READY message
        """
        self.other_peer_ready = True
        if self.my_peer_ready:
            # In this case this peer already completed the peer-id validation
            # So it was just waiting for the ready message from the other peer to change the state to READY
            self.protocol.change_state(self.protocol.PeerState.READY)

    def _get_peer_id_data(self) -> dict[str, Any]:
        my_peer = self.protocol.my_peer

        if not self.should_relay_ipv6_entrypoints:
            entrypoints_as_str = my_peer.info.ipv4_entrypoints_as_str()
        else:
            entrypoints_as_str = my_peer.info.entrypoints_as_str()

        return dict(
            id=str(my_peer.id),
            pubKey=my_peer.get_public_key(),
            entrypoints=entrypoints_as_str,
        )

    def send_peer_id(self) -> None:
        """ Send a PEER-ID message, identifying the peer.
        """
        data = self._get_peer_id_data()
        self.send_message(ProtocolMessages.PEER_ID, json_dumps(data))

    async def handle_peer_id(self, payload: str) -> None:
        """ Executed when a PEER-ID is received. It basically checks
        the identity of the peer. Only after this step, the peer connection
        is considered established and ready to communicate.
        """
        from hathor.p2p.netfilter import get_table
        from hathor.p2p.netfilter.context import NetfilterContext

        protocol = self.protocol
        assert protocol.transport is not None

        data = json_loads(payload)

        try:
            peer = PublicPeer.create_from_json(data)
        except ValueError as e:
            protocol.send_error_and_close_connection(f'Unable to parse peer id. Reason: {str(e)}')
            return

        assert peer.id is not None

        # If the connection URL had a peer-id parameter we need to check it's the same
        if protocol.expected_peer_id and peer.id != protocol.expected_peer_id:
            protocol.send_error_and_close_connection('Peer id different from the requested one.')
            return

        # is it on the whitelist?
        if not self._is_peer_allowed(peer.id):
            if self._settings.WHITELIST_WARN_BLOCKED_PEERS:
                protocol.send_error_and_close_connection(f'Blocked (by {peer.id}). Get in touch with Hathor team.')
            else:
                protocol.send_error_and_close_connection('Connection rejected.')
            return

        if peer.id == protocol.my_peer.id:
            protocol.send_error_and_close_connection('Are you my clone?!')
            return

        if protocol.connections is not None:
            if protocol.connections.is_peer_connected(peer.id):
                protocol.send_error_and_close_connection('We are already connected.')
                return

        entrypoint_valid = await peer.info.validate_entrypoint(protocol)
        if not entrypoint_valid:
            protocol.send_error_and_close_connection('Connection string is not in the entrypoints.')
            return

        if protocol.entrypoint is not None and protocol.entrypoint.peer_id is not None:
            assert protocol.entrypoint.peer_id == peer.id

        if protocol.use_ssl:
            certificate_valid = peer.validate_certificate(protocol)
            if not certificate_valid:
                protocol.send_error_and_close_connection('Public keys from peer and certificate are not the same.')
                return

        # If it gets here, the peer is validated, and we are ready to start communicating.
        protocol._peer = peer

        context = NetfilterContext(
            protocol=protocol,
            connections=protocol.connections,
            addr=protocol.transport.getPeer(),
        )
        verdict = get_table('filter').get_chain('post_peerid').process(context)
        if not bool(verdict):
            protocol.disconnect('rejected by netfilter: filter post_peerid', force=True)
            return

        self.send_ready()

    def _is_peer_allowed(self, peer_id: PeerId) -> bool:
        """Return True if peer is allowed to connect; False otherwise."""
        peers_whitelist = self.protocol.connections.peers_whitelist
        if peers_whitelist is None:
            return True
        return peers_whitelist.is_peer_allowed(peer_id)
