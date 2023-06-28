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

from math import inf
from typing import TYPE_CHECKING, Iterable, Optional

from structlog import get_logger
from twisted.internet.task import LoopingCall

from hathor.conf import HathorSettings
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.peer_id import PeerId
from hathor.p2p.states.base import BaseState
from hathor.p2p.sync_agent import SyncAgent
from hathor.transaction import BaseTransaction
from hathor.types import BlockInfo
from hathor.util import json_dumps, json_loads

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol  # noqa: F401

logger = get_logger()

settings = HathorSettings()


class ReadyState(BaseState):
    def __init__(self, protocol: 'HathorProtocol') -> None:
        super().__init__(protocol)

        self.log = logger.new(**self.protocol.get_logger_context())

        self.reactor = self.protocol.node.reactor

        # It triggers an event to send a ping message if necessary.
        self.lc_ping = LoopingCall(self.send_ping_if_necessary)
        self.lc_ping.clock = self.reactor

        # Minimum interval between PING messages (in seconds).
        self.ping_interval: int = 3

        # Time we sent last PING message.
        self.ping_start_time: Optional[float] = None

        # Time we got last PONG response to a PING message.
        self.ping_last_response: float = 0

        # Round-trip time of the last PING/PONG.
        self.ping_rtt: float = inf

        # Minimum round-trip time among PING/PONG.
        self.ping_min_rtt: float = inf

        # The last blocks from the best blockchain in the peer
        self.best_blockchain: list[BlockInfo] = []

        self.cmd_map.update({
            # p2p control messages
            ProtocolMessages.PING: self.handle_ping,
            ProtocolMessages.PONG: self.handle_pong,
            ProtocolMessages.GET_PEERS: self.handle_get_peers,
            ProtocolMessages.PEERS: self.handle_peers,
            # Other messages are added by the sync manager.
        })

        self.lc_get_best_blockchain: Optional[LoopingCall] = None

        # if the peer has the GET-BEST-BLOCKCHAIN capability
        common_capabilities = protocol.capabilities & set(protocol.node.capabilities)
        if (settings.CAPABILITY_GET_BEST_BLOCKCHAIN in common_capabilities):
            # set the loop to get the best blockchain from the peer
            self.lc_get_best_blockchain = LoopingCall(self.send_get_best_blockchain)
            self.lc_get_best_blockchain.clock = self.reactor
            self.cmd_map.update({
                # extend the p2p control messages
                ProtocolMessages.GET_BEST_BLOCKCHAIN: self.handle_get_best_blockchain,
                ProtocolMessages.BEST_BLOCKCHAIN: self.handle_best_blockchain,
            })

        # Initialize sync manager and add its commands to the list of available commands.
        connections = self.protocol.connections
        assert connections is not None

        # Get the sync factory and create a sync manager from it
        sync_version = self.protocol.sync_version
        assert sync_version is not None
        self.log.debug(f'loading {sync_version}')
        sync_factory = connections.get_sync_factory(sync_version)

        self.sync_agent: SyncAgent = sync_factory.create_sync_agent(self.protocol, reactor=self.reactor)
        self.cmd_map.update(self.sync_agent.get_cmd_dict())

    def on_enter(self) -> None:
        if self.protocol.connections:
            self.protocol.on_peer_ready()

        self.lc_ping.start(1, now=False)
        self.send_get_peers()

        if self.lc_get_best_blockchain is not None:
            self.lc_get_best_blockchain.start(settings.BEST_BLOCKCHAIN_INTERVAL, now=False)

        self.sync_agent.start()

    def on_exit(self) -> None:
        if self.lc_ping.running:
            self.lc_ping.stop()

        if self.lc_get_best_blockchain is not None and self.lc_get_best_blockchain.running:
            self.lc_get_best_blockchain.stop()

        if self.sync_agent.is_started():
            self.sync_agent.stop()

        if self.sync_agent.is_started():
            self.sync_agent.stop()

    def prepare_to_disconnect(self) -> None:
        if self.sync_agent.is_started():
            self.sync_agent.stop()

    def send_tx_to_peer(self, tx: BaseTransaction) -> None:
        self.sync_agent.send_tx_to_peer_if_possible(tx)

    def is_synced(self) -> bool:
        return self.sync_agent.is_synced()

    def send_get_peers(self) -> None:
        """ Send a GET-PEERS command, requesting a list of nodes.
        """
        self.send_message(ProtocolMessages.GET_PEERS)

    def handle_get_peers(self, payload: str) -> None:
        """ Executed when a GET-PEERS command is received. It just responds with
        a list of all known peers.
        """
        if self.protocol.connections:
            self.send_peers(self.protocol.connections.iter_ready_connections())

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
        self.send_message(ProtocolMessages.PEERS, json_dumps(peers))
        self.log.debug('send peers', peers=peers)

    def handle_peers(self, payload: str) -> None:
        """ Executed when a PEERS command is received. It updates the list
        of known peers (and tries to connect to new ones).
        """
        received_peers = json_loads(payload)
        for data in received_peers:
            peer = PeerId.create_from_json(data)
            peer.validate()
            if self.protocol.connections:
                self.protocol.connections.on_receive_peer(peer, origin=self)
        self.log.debug('received peers', payload=payload)

    def send_ping_if_necessary(self) -> None:
        """ Send a PING command after 3 seconds of receiving last PONG response.
        """
        if self.ping_start_time is not None:
            return
        dt = self.reactor.seconds() - self.ping_last_response
        if dt <= self.ping_interval:
            return
        self.send_ping()

    def send_ping(self) -> None:
        """ Send a PING command. Usually you would use `send_ping_if_necessary` to
        prevent wasting bandwidth.
        """
        self.ping_start_time = self.reactor.seconds()
        self.send_message(ProtocolMessages.PING)

    def send_pong(self) -> None:
        """ Send a PONG command as a response to a PING command.
        """
        self.send_message(ProtocolMessages.PONG)

    def handle_ping(self, payload: str) -> None:
        """Executed when a PING command is received. It responds with a PONG message."""
        self.send_pong()

    def handle_pong(self, payload: str) -> None:
        """Executed when a PONG message is received."""
        if self.ping_start_time is None:
            # This should never happen.
            return
        self.ping_last_response = self.reactor.seconds()
        self.ping_rtt = self.ping_last_response - self.ping_start_time
        self.ping_min_rtt = min(self.ping_min_rtt, self.ping_rtt)
        self.ping_start_time = None
        self.log.debug('rtt updated', rtt=self.ping_rtt, min_rtt=self.ping_min_rtt)

    def send_get_best_blockchain(
            self, n_blocks: int = settings.DEFAULT_BEST_BLOCKCHAIN_BLOCKS) -> None:
        """ Send a GET-BEST-BLOCKCHAIN command, requesting a list of the latest
        N blocks from the best blockchain.
        """
        self.send_message(ProtocolMessages.GET_BEST_BLOCKCHAIN, str(n_blocks))

    def handle_get_best_blockchain(self, payload: str) -> None:
        """ Executed when a GET-BEST-BLOCKCHAIN command is received.
        It just responds with a list with N blocks from the best blockchain
        in descending order.
        """
        try:
            n_blocks = int(payload)
        except ValueError:
            self.protocol.send_error_and_close_connection(
                f'Invalid param type. \'payload\' should be an int but we got {payload}.'
            )
            return

        if not (0 < n_blocks <= settings.MAX_BEST_BLOCKCHAIN_BLOCKS):
            self.protocol.send_error_and_close_connection(
                f'N out of bounds. Valid range: [1, {settings.MAX_BEST_BLOCKCHAIN_BLOCKS}].'
            )
            return

        try:
            best_blockchain = self.protocol.node.get_best_blockchain(n_blocks)
        except ValueError as e:
            self.protocol.send_error_and_close_connection(msg=str(e))
            return

        self.send_best_blockchain(best_blockchain)

    def send_best_blockchain(self, best_blockchain: list[BlockInfo]) -> None:
        """ Send a BEST-BLOCKCHAIN command with a best blockchain of N blocks.
        """
        self.send_message(ProtocolMessages.BEST_BLOCKCHAIN, json_dumps(best_blockchain))

    def handle_best_blockchain(self, payload: str) -> None:
        """ Executed when a BEST-BLOCKCHAIN command is received. It updates
        the best blockchain.
        """
        restored_blocks = json_loads(payload)
        try:
            best_blockchain = [BlockInfo.from_raw(block_info_raw) for block_info_raw in restored_blocks]
        except ValueError:
            self.protocol.send_error_and_close_connection(
                'Invalid block_info while handling best_blockchain response.'
            )
            return
        self.best_blockchain = best_blockchain
