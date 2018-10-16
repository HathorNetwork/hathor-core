# encoding: utf-8

from hathor.p2p.states.base import BaseState
from hathor.p2p.peer_id import PeerId
from hathor.p2p.messages import ProtocolMessages

import base64
import json


class PeerIdState(BaseState):
    def __init__(self, protocol):
        super().__init__(protocol)
        self.cmd_map.update({
            ProtocolMessages.PEER_ID: self.handle_peer_id,
        })

    def on_enter(self):
        self.send_peer_id()

    def send_peer_id(self):
        """ Send a PEER-ID message, identifying the peer. It goes with a
        signature of the `nonce` value received in the HELLO message.
        """
        protocol = self.protocol
        nonce = protocol.hello_nonce_received
        my_peer = protocol.my_peer
        hello = {
            'id': my_peer.id,
            'pubKey': my_peer.get_public_key(),
            'entrypoints': my_peer.entrypoints,
            'nonce': nonce,
            'signature': base64.b64encode(my_peer.sign(nonce.encode('ascii'))).decode('ascii'),
        }
        self.send_message(ProtocolMessages.PEER_ID, json.dumps(hello))

    def handle_peer_id(self, payload):
        """ Executed when a PEER-ID is received. It basically checks
        the identity of the peer. Only after this step, the peer connection
        is considered established and ready to communicate.
        """
        protocol = self.protocol
        data = json.loads(payload)

        if protocol.hello_nonce_sent != data['nonce']:
            protocol.send_error_and_close_connection('Invalid nonce.')
            return

        peer = PeerId.create_from_json(data)
        peer.validate()

        if peer.id == protocol.my_peer.id:
            protocol.send_error_and_close_connection('Are you my clone?!')
            return

        signature = base64.b64decode(data['signature'])
        if not peer.verify_signature(signature, protocol.hello_nonce_sent.encode('ascii')):
            protocol.send_error_and_close_connection('Invalid signature.')
            return

        if protocol.connections.is_peer_connected(peer.id):
            protocol.send_error_and_close_connection('We are already connected.')
            return

        # If it gets here, the peer is validated, and we are ready to start communicating.
        protocol.peer = peer
        protocol.change_state(protocol.PeerState.READY)
