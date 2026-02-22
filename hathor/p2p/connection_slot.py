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

from collections import deque
from typing import Optional

from hathor.conf.settings import HathorSettings
from hathor.p2p.peer_endpoint import PeerAddress
from hathor.p2p.protocol import HathorProtocol


class Slot:
    """
        Class of a connection pool slot - outgoing, incoming, discovered or check_entrypoints connections.
    """
    connection_slot: set[HathorProtocol]
    entrypoint_queue_slot: deque[PeerAddress]
    type: HathorProtocol.ConnectionType
    max_slot_connections: int
    queue_size_entrypoints: int
    entrypoint_set: set[PeerAddress | None]

    def __init__(self, type: HathorProtocol.ConnectionType, _settings: HathorSettings, max_connections: int):
        self.type = type
        self.connection_slot = set()
        self.entrypoint_queue_slot = deque()
        self.entrypoint_set = set()

        if max_connections <= 0:
            raise ValueError("Slot max number must allow at least one connection")
        
        max_outgoing: int = _settings.P2P_PEER_MAX_OUTGOING_CONNECTIONS
        max_incoming: int = _settings.P2P_PEER_MAX_INCOMING_CONNECTIONS
        max_discovered: int = _settings.P2P_PEER_MAX_DISCOVERED_PEERS_CONNECTIONS
        max_check_ep: int = _settings.P2P_PEER_MAX_CHECK_PEER_CONNECTIONS

        type = self.type

        # For each type of slot, there is a maximum of connections allowed.
        if type == HathorProtocol.ConnectionType.OUTGOING:
            assert max_connections <= max_outgoing

        if type == HathorProtocol.ConnectionType.INCOMING:
            assert max_connections <= max_incoming

        if type == HathorProtocol.ConnectionType.DISCOVERED:
            assert max_connections <= max_discovered

        if type == HathorProtocol.ConnectionType.CHECK_ENTRYPOINTS:
            assert max_connections <= max_check_ep

        self.max_slot_connections = max_connections
        # All slots have the same maximum size.
        # Only valid for check_entrypoin
        self.queue_size_entrypoints = _settings.QUEUE_SIZE

    def add_connection(self, protocol: HathorProtocol) -> bool:
        """
            Adds connection protocol to the slot. Checks whether the slot is full or not. If full,
            disconnects the protocol. If the type is 'check_entrypoints', the returns peers of it
            may go to a queue.

        """
        # Make sure connection types match
        assert self.type == protocol.connection_type

        if protocol in self.connection_slot:
            return False

        # If check_entrypoints, there is a set.
        # If set minus queue >= 1, a dequeued entrypoint in remove_connection is being connected
        # We leave at least one space for it.
        if len(self.entrypoint_set) > len(self.entrypoint_queue_slot):
            if len(self.connection_slot) == self.max_slot_connections - 1:
                protocol.disconnect(reason="Dequeued connection being added. Leaving space for it.")
                return False

        # Check if slot is full. If type is check_entrypoints, there is a queue.
        if len(self.connection_slot) >= self.max_slot_connections:
            if self.type == HathorProtocol.ConnectionType.OUTGOING:

                # The connection must be turned into CHECK_ENTRYPOINTS.
                # Will return to on_peer_connect and slot it into check_entrypoints.
                protocol.connection_type = HathorProtocol.ConnectionType.CHECK_ENTRYPOINTS
                return False

            # Check_EP is disconnected too, as we only queue endpoints of ready/valid peers.
            protocol.disconnect(reason="Connection Slot if full. Try again later.")
            return False

        # If not full, add to slot if types match.
        assert protocol.connection_type == self.type
        self.connection_slot.add(protocol)

        return True

    def remove_connection(self, protocol: HathorProtocol, revisit: bool = False,
                          previous_entrypoint: PeerAddress | None = None) -> Optional[PeerAddress] | None:
        """
            Removes from given instance the protocol passed. Returns protocol from queue
            when disconnection leads to free space in slot. Revisit flag for continuously popping verified entrypoints
            from queue and deleting previous entrypoints from set.
        """
        if not revisit:
            self.connection_slot.discard(protocol)

        if protocol.connection_type == HathorProtocol.ConnectionType.CHECK_ENTRYPOINTS and not revisit:
            dequeued_entrypoint = None
            # If protocol READY, the peer was verified. We take its EP's to the queue.
            # If protocol e.p. not in set, it is a new protocol with new e.p.'s to check.
            # If in set, it is a connection from a previously dequeued entrypoint.
            if protocol.connection_state == HathorProtocol.ConnectionState.READY:
                if protocol.entrypoint and protocol.entrypoint.addr not in self.entrypoint_set:
                    entrypoints = protocol.peer.info.entrypoints
                    # Unpack the entrypoints and put them in the queue and the set.
                    for each_entrypoint in entrypoints:
                        if protocol.entrypoint and each_entrypoint != protocol.entrypoint.addr:
                            if len(self.entrypoint_queue_slot) == self.queue_size_entrypoints:
                                # Limit achieved for QUEUE
                                break

                            if each_entrypoint not in self.entrypoint_queue_slot:
                                self.entrypoint_queue_slot.appendleft(each_entrypoint)

                            if each_entrypoint not in self.entrypoint_set:
                                self.entrypoint_set.add(each_entrypoint)

        # If protocol not READY, it was a timeout.
        # Take one from the queue and turn it into a connection.
        if self.entrypoint_queue_slot:
            if revisit:
                self.entrypoint_set.discard(previous_entrypoint)

            dequeued_entrypoint = self.entrypoint_queue_slot.pop()
            return dequeued_entrypoint

        return None