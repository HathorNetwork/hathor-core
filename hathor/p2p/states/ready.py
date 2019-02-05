import json
from typing import TYPE_CHECKING, Dict, Iterable

from twisted.internet.task import LoopingCall
from twisted.logger import Logger

from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.node_sync import NodeSyncTimestamp
from hathor.p2p.peer_id import PeerId
from hathor.p2p.plugin import Plugin
from hathor.p2p.states.base import BaseState
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol  # noqa: F401


class ReadyState(BaseState):
    log = Logger()

    SYNC_PLUGIN_NAME = 'node-sync-timestamp'

    plugins: Dict[str, Plugin]

    def __init__(self, protocol: 'HathorProtocol') -> None:
        super().__init__(protocol)

        self.reactor = self.protocol.node.reactor

        # It triggers an event to send a ping message if necessary.
        self.lc_ping = LoopingCall(self.send_ping_if_necessary)
        self.lc_ping.clock = self.reactor

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
        self.add_plugin(self.SYNC_PLUGIN_NAME, NodeSyncTimestamp(self.protocol, reactor=self.reactor))

    def add_plugin(self, name: str, plugin: Plugin) -> None:
        self.plugins[name] = plugin
        cmd_list = plugin.get_cmd_dict()
        self.cmd_map.update(cmd_list)

    def on_enter(self) -> None:
        if self.protocol.connections:
            self.protocol.connections.on_peer_ready(self.protocol)

        self.lc_ping.start(1)
        self.send_get_peers()

        for plugin in self.plugins.values():
            plugin.start()

    def on_exit(self) -> None:
        if self.lc_ping.running:
            self.lc_ping.stop()

        for plugin in self.plugins.values():
            plugin.stop()

    def get_sync_plugin(self) -> Plugin:
        return self.plugins[self.SYNC_PLUGIN_NAME]

    def send_tx_to_peer(self, tx: BaseTransaction) -> None:
        self.plugins[self.SYNC_PLUGIN_NAME].send_tx_to_peer_if_possible(tx)

    def send_get_peers(self) -> None:
        """ Send a GET-PEERS command, requesting a list of nodes.
        """
        self.send_message(ProtocolMessages.GET_PEERS)

    def handle_get_peers(self, payload: str) -> None:
        """ Executed when a GET-PEERS command is received. It just responds with
        a list of all known peers.
        """
        if self.protocol.connections:
            self.send_peers(self.protocol.connections.get_ready_connections())

    def send_peers(self, connections: Iterable['HathorProtocol']) -> None:
        """ Send a PEERS command with a list of all known peers.
        """
        peers = []
        for conn in connections:
            assert conn.peer is not None
            peers.append({
                'id': conn.peer.id,
                'entrypoints': conn.peer.entrypoints,
                'last_message': conn.last_message,
            })
        self.send_message(ProtocolMessages.PEERS, json.dumps(peers))
        self.log.debug('Peers: {peers}', peers=peers)

    def handle_peers(self, payload: str) -> None:
        """ Executed when a PEERS command is received. It updates the list
        of known peers (and tries to connect to new ones).
        """
        received_peers = json.loads(payload)
        for data in received_peers:
            peer = PeerId.create_from_json(data)
            peer.validate()
            if self.protocol.connections:
                self.protocol.connections.on_receive_peer(peer, origin=self)
        remote = self.protocol.transport.getPeer()
        self.log.info('{remote} PEERS {payload}', remote=remote, payload=payload)

    def send_ping_if_necessary(self) -> None:
        """ Send a PING command if the connection has been idle for 3 seconds or more.
        """
        dt = self.protocol.node.reactor.seconds() - self.protocol.last_message
        if dt > 3:
            self.send_ping()

    def send_ping(self) -> None:
        """ Send a PING command. Usually you would use `send_ping_if_necessary` to
        prevent wasting bandwidth.
        """
        self.send_message(ProtocolMessages.PING)

    def send_pong(self) -> None:
        """ Send a PONG command as a response to a PING command.
        """
        self.send_message(ProtocolMessages.PONG)

    def handle_ping(self, payload: str) -> None:
        """ Executed when a PING command is received. It responds with a
        PONG message.
        """
        self.send_pong()

    def handle_pong(self, payload: str) -> None:
        """ Executed when a PONG message is received. It only updates
        the last time a message has been received by this peer.
        """
        self.protocol.last_message = self.protocol.node.reactor.seconds()
