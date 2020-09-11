from typing import TYPE_CHECKING, Any, Generator

from twisted.internet.defer import inlineCallbacks

from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.peer_id import PeerId
from hathor.p2p.states.base import BaseState
from hathor.util import json_dumps, json_loads

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol  # noqa: F401


class PeerIdState(BaseState):
    def __init__(self, protocol: 'HathorProtocol') -> None:
        super().__init__(protocol)
        self.cmd_map.update({
            ProtocolMessages.PEER_ID: self.handle_peer_id,
            ProtocolMessages.READY: self.handle_ready,
        })

        # Flags to know when each peer is valid to change state to ready
        self.my_peer_ready = False
        self.other_peer_ready = False

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

    def send_peer_id(self) -> None:
        """ Send a PEER-ID message, identifying the peer.
        """
        protocol = self.protocol
        my_peer = protocol.my_peer
        hello = {
            'id': my_peer.id,
            'pubKey': my_peer.get_public_key(),
            'entrypoints': my_peer.entrypoints,
        }
        self.send_message(ProtocolMessages.PEER_ID, json_dumps(hello))

    @inlineCallbacks
    def handle_peer_id(self, payload: str) -> Generator[Any, Any, None]:
        """ Executed when a PEER-ID is received. It basically checks
        the identity of the peer. Only after this step, the peer connection
        is considered established and ready to communicate.
        """
        protocol = self.protocol
        data = json_loads(payload)

        peer = PeerId.create_from_json(data)
        peer.validate()
        assert peer.id is not None

        # If the connection URL had a peer-id parameter we need to check it's the same
        if protocol.expected_peer_id and peer.id != protocol.expected_peer_id:
            protocol.send_error_and_close_connection('Peer id different from the requested one.')
            return

        if peer.id == protocol.my_peer.id:
            protocol.send_error_and_close_connection('Are you my clone?!')
            return

        if protocol.connections:
            if protocol.connections.is_peer_connected(peer.id):
                protocol.send_error_and_close_connection('We are already connected.')
                return

        entrypoint_valid = yield peer.validate_entrypoint(protocol)
        if not entrypoint_valid:
            protocol.send_error_and_close_connection('Connection string is not in the entrypoints.')
            return

        if protocol.use_ssl:
            certificate_valid = peer.validate_certificate(protocol)
            if not certificate_valid:
                protocol.send_error_and_close_connection('Public keys from peer and certificate are not the same.')
                return

        # If it gets here, the peer is validated, and we are ready to start communicating.
        protocol.peer = peer

        self.send_ready()
