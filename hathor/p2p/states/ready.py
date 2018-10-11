# encoding: utf-8

from twisted.internet.task import LoopingCall

from hathor.p2p.states.base import BaseState
from hathor.p2p.peer_id import PeerId
from hathor.p2p.node_sync import NodeSyncTimestamp
from hathor.p2p.messages import ProtocolMessages

import json


class ReadyState(BaseState):
    def __init__(self, protocol):
        super().__init__(protocol)

        # It triggers an event to send a ping message if necessary.
        self.lc_ping = LoopingCall(self.send_ping_if_necessary)
        self.lc_ping.clock = self.protocol.node.reactor

        self.cmd_map.update({
            # p2p control messages
            ProtocolMessages.PING: self.handle_ping,
            ProtocolMessages.PONG: self.handle_pong,
            ProtocolMessages.GET_PEERS: self.handle_get_peers,
            ProtocolMessages.PEERS: self.handle_peers,
            ProtocolMessages.ERROR: self.handle_error,

            # Other messages are added by plugins.
        })

        # List of plugins.
        self.plugins = {}
        self.add_plugin(NodeSyncTimestamp(self.protocol))

    def add_plugin(self, plugin):
        self.plugins[plugin.get_name()] = plugin
        cmd_list = plugin.get_cmd_dict()
        self.cmd_map.update(cmd_list)

    def on_enter(self):
        self.protocol.connections.on_peer_ready(self.protocol)

        self.lc_ping.start(1)
        self.send_get_peers()

        for plugin in self.plugins.values():
            plugin.start()

    def on_exit(self):
        if self.lc_ping.running:
            self.lc_ping.stop()

        for plugin in self.plugins.values():
            plugin.stop()

    def send_get_best_height(self):
        self.send_message(ProtocolMessages.GET_BEST_HEIGHT)

    def send_tx_to_peer(self, tx):
        self.plugins['node-sync-timestamp'].send_tx_to_peer_if_possible(tx)

    def handle_get_best_height(self, unused_payload):
        print('handle_get_best_height')
        payload = self.protocol.node.tx_storage.get_best_height()
        self.send_message(ProtocolMessages.BEST_HEIGHT, str(payload))

    def handle_best_height(self, payload):
        print('handle_best_height:', payload)
        best_height = int(payload)
        self.protocol.node.on_best_height(best_height, conn=self.protocol)

    def send_get_blocks(self, hash_hex):
        self.send_message(ProtocolMessages.GET_BLOCKS, hash_hex)

    def handle_get_blocks(self, payload):
        print('handle_get_blocks:', payload)
        hash_hex = payload
        blocks = self.protocol.node.tx_storage.get_blocks_before(hash_hex, num_blocks=20)
        block_hashes_hex = [x.hash.hex() for x in blocks]
        output_payload = json.dumps(block_hashes_hex)
        self.send_message(ProtocolMessages.BLOCKS, output_payload)

    def handle_blocks(self, payload):
        print('handle_blocks')
        block_hashes = json.loads(payload)
        self.protocol.node.on_block_hashes_received(block_hashes, conn=self.protocol)

    def send_get_transactions(self, hash_hex):
        self.send_message(ProtocolMessages.GET_TRANSACTIONS, hash_hex)

    def handle_get_transactions(self, payload):
        print('handle_get_transactions:', payload)
        hash_hex = payload
        transactions = self.protocol.node.tx_storage.get_transactions_before(hash_hex, num_blocks=20)
        txs_hashes_hex = [x.hash.hex() for x in transactions]
        output_payload = json.dumps(txs_hashes_hex)
        print('@@', output_payload)
        self.send_message(ProtocolMessages.TRANSACTIONS, output_payload)

    def handle_transactions(self, payload):
        print('handle_transactions:', payload)
        txs_hashes = json.loads(payload)
        self.protocol.node.on_transactions_hashes_received(txs_hashes, conn=self.protocol)

    def send_get_peers(self):
        """ Send a GET-PEERS command, requesting a list of nodes.
        """
        self.send_message(ProtocolMessages.GET_PEERS)

    def handle_get_peers(self, payload):
        """ Executed when a GET-PEERS command is received. It just responds with
        a list of all known peers.
        """
        self.send_peers(self.protocol.connections.get_ready_connections())

    def send_peers(self, connections):
        """ Send a PEERS command with a list of all known peers.
        """
        peers = []
        for conn in connections:
            peers.append({
                'id': conn.peer.id,
                'entrypoints': conn.peer.entrypoints,
                'last_message': conn.last_message,
            })
        self.send_message(ProtocolMessages.PEERS, json.dumps(peers))
        print('Peers: %s' % str(peers))

    def handle_peers(self, payload):
        """ Executed when a PEERS command is received. It updates the list
        of known peers (and tries to connect to new ones).
        """
        received_peers = json.loads(payload)
        for data in received_peers:
            peer = PeerId.create_from_json(data)
            peer.validate()
            self.protocol.connections.on_receive_peer(peer, origin=self)
        remote = self.protocol.transport.getPeer()
        print(remote, 'PEERS', payload)

    def send_ping_if_necessary(self):
        """ Send a PING command if the connection has been idle for 3 seconds or more.
        """
        dt = self.protocol.node.reactor.seconds() - self.protocol.last_message
        if dt > 3:
            self.send_ping()

    def send_ping(self):
        """ Send a PING command. Usually you would use `send_ping_if_necessary` to
        prevent wasting bandwidth.
        """
        self.send_message(ProtocolMessages.PING)

    def send_pong(self):
        """ Send a PONG command as a response to a PING command.
        """
        self.send_message(ProtocolMessages.PONG)

    def handle_ping(self, payload):
        """ Executed when a PING command is received. It responds with a
        PONG message.
        """
        self.send_pong()

    def handle_pong(self, payload):
        """ Executed when a PONG message is received. It only updates
        the last time a message has been received by this peer.
        """
        self.protocol.last_message = self.protocol.node.reactor.seconds()
