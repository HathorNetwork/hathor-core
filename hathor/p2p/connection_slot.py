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
from dataclasses import dataclass
from typing import Optional

from typing_extensions import assert_never

from hathor.conf.settings import HathorSettings
from hathor.p2p.peer_endpoint import PeerAddress, PeerEndpoint
from hathor.p2p.protocol import HathorProtocol


@dataclass
class ConnectionAllowed:
    confirmation: str


@dataclass
class ConnectionChanged:
    shift: str


@dataclass
class ConnectionRejected:
    reason: str


@dataclass
class ConnectionRemoved:
    reason: str


@dataclass
class EntrypointQueued:
    stratum: str


@dataclass
class EntrypointDenied:
    stratum: str


ConnectionResult = ConnectionAllowed | ConnectionChanged | ConnectionRejected | ConnectionRemoved
EntrypointResult = EntrypointQueued | EntrypointDenied

SlotResult = ConnectionResult | EntrypointResult

class ConnectionSlots:
    """ Class of a connection pool slot - outgoing, incoming, discovered or
    check_entrypoints connections. """
    connection_slot: set[HathorProtocol]
    entrypoint_queue_slot: deque[PeerAddress]
    type: HathorProtocol.ConnectionType
    max_slot_connections: int
    queue_size_entrypoints: int
    entrypoint_set: set[PeerAddress | None]

    def __init__(self, type: HathorProtocol.ConnectionType, settings: HathorSettings, max_connections: int):
        self.type = type
        self.connection_slot = set()
        self.entrypoint_queue_slot = deque()
        self.entrypoint_set = set()

        if max_connections <= 0:
            raise ValueError("Slot max number must allow at least one connection")

        max_outgoing: int = settings.P2P_PEER_MAX_OUTGOING_CONNECTIONS
        max_incoming: int = settings.P2P_PEER_MAX_INCOMING_CONNECTIONS
        max_discovered: int = settings.P2P_PEER_MAX_DISCOVERED_PEERS_CONNECTIONS
        max_check_ep: int = settings.P2P_PEER_MAX_CHECK_PEER_CONNECTIONS

        type = self.type

        # For each type of slot, there is a maximum of connections allowed.
        match type:
            case HathorProtocol.ConnectionType.OUTGOING:
                assert max_connections <= max_outgoing

            case HathorProtocol.ConnectionType.INCOMING:
                assert max_connections <= max_incoming

            case HathorProtocol.ConnectionType.BOOTSTRAP:
                assert max_connections <= max_discovered

            case HathorProtocol.ConnectionType.CHECK_ENTRYPOINTS:
                assert max_connections <= max_check_ep

            case _:
                assert_never(type)

        self.max_slot_connections = max_connections
        # All slots have the same maximum size.
        # Only valid for check_entrypoin
        self.queue_size_entrypoints = settings.P2P_QUEUE_SIZE

    def add_connection(self, protocol: HathorProtocol) -> ConnectionAllowed | ConnectionChanged | ConnectionRejected:
        """
            Adds connection protocol to the slot. Checks whether the slot is full or not. If full,
            disconnects the protocol. If the type is 'check_entrypoints', the returns peers of it
            may go to a queue.

        """
        # Make sure connection types match
        assert self.type == protocol.connection_type
        connection_status: ConnectionResult

        if protocol in self.connection_slot:
            return ConnectionRejected("Protocol already in Slot.")

        # If check_entrypoints, there is a set.
        # If set minus queue >= 1, a dequeued entrypoint in remove_connection is being connected
        # We leave at least one space for it.
        if len(self.entrypoint_set) > len(self.entrypoint_queue_slot):
            if len(self.connection_slot) == self.max_slot_connections - 1:
                protocol.disconnect(reason="Dequeued connection being added. Leaving space for it.")
                return ConnectionRejected("Queue is full.")

        # Check if slot is full. If type is check_entrypoints, there is a queue.
        if len(self.connection_slot) >= self.max_slot_connections:
            if self.type == HathorProtocol.ConnectionType.OUTGOING:

                # The connection must be turned into CHECK_ENTRYPOINTS.
                # Will return to on_peer_connect and slot it into check_entrypoints.
                protocol.connection_type = HathorProtocol.ConnectionType.CHECK_ENTRYPOINTS
                return ConnectionChanged("Outgoing -> Check Entrypoints")

            # Check_EP is disconnected too, as we only queue endpoints of ready/valid peers.
            protocol.disconnect(reason="Connection Slot if full. Try again later.")
            return ConnectionRejected(f"Slot {self.type} is full")

        # If not full, add to slot if types match.
        assert protocol.connection_type == self.type
        self.connection_slot.add(protocol)

        connection_status = ConnectionAllowed(f"Type {self.type} added, slot length: {len(self.connection_slot)}")
        return connection_status

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

            if protocol.connection_state != HathorProtocol.ConnectionState.READY:
                return None

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

    def is_full(self) -> bool:
        return len(self.connection_slot) >= self.max_slot_connections

class SlotsManager:
    """Manager of slot connections - selects the slot to which must we send the]
     arriving protocol.
     
    Four protocol slots: OUTGOING, INCOMING, DISCOVERED and CHECK_ENTRYPOINTS.
    
    If the OUTGOING slot is full, the manager will send this connection to CHECK_ENTRYPOINTS slot.
    If this slot is full, the protocol will be finished and the endpoint will be grabbed onto a QUEUE.
    When some connection in the CHECK_ENTRYPOINTS slot is finished, we pop the endpoint from the queue
    and create a connection to be put into the slot."""
    outgoing_slot: ConnectionSlots
    incoming_slot: ConnectionSlots
    bootstrap_slot: ConnectionSlots
    check_ep_slot: ConnectionSlots
    queue_entrypoints: deque[PeerEndpoint | None]
    verified_entrypoints: set[PeerEndpoint | None]
    types_allowed: dict[str ,HathorProtocol.ConnectionType] = {
        'outgoing': HathorProtocol.ConnectionType.OUTGOING,
        'incoming' : HathorProtocol.ConnectionType.INCOMING,
        'bootstrap': HathorProtocol.ConnectionType.BOOTSTRAP,
        'check_ep': HathorProtocol.ConnectionType.CHECK_ENTRYPOINTS,
    }

    def __init__(self, _settings: HathorSettings) -> None:
        types = self.types_allowed
        self.outgoing_slot = ConnectionSlots(types['outgoing'], _settings)
        self.incoming_slot = ConnectionSlots(types['incoming'], _settings)
        self.bootstrap_slot = ConnectionSlots(types['bootstrap'], _settings)
        self.check_ep_slot = ConnectionSlots(types['check'], _settings)
        self.queue_entrypoints = deque()
        self.queue_max_size = _settings.P2P_QUEUE_SIZE

    def add_to_slot(self, protocol: HathorProtocol) -> ConnectionResult:
        """Add received protocol to one of the slots. 
        
        If INCOMING and BOOTSTRAP slot are full, protocol is disconnected.
        If OUTGOING is full, protocol is sent to CHECK_EP slot.
        If CHECK_EP slot is full, endpoint is added to the queue.
        If queue is full, protocol is disconnected. """

        conn_type = protocol.connection_type
        assert conn_type in self.types_allowed

        types = self.types_allowed
        queue = self.queue_entrypoints

        slot: ConnectionSlots | None = None
        match conn_type:
            case HathorProtocol.ConnectionType.OUTGOING:
                slot = self.outgoing_slot
                if slot.is_full():
                    protocol.connection_type = types['check_ep']
                    conn_type = protocol.connection_type
                    slot = self.check_ep_slot
                    # No connection changed?
                    
            case HathorProtocol.ConnectionType.INCOMING:
                slot = self.incoming_slot
            case HathorProtocol.ConnectionType.BOOTSTRAP:
                slot = self.bootstrap_slot
            case _:
                assert_never()

        if protocol in slot.connection_slot:
            return ConnectionRejected('Protocol already in the slot.')

        if not slot.is_full():
            slot.add_connection(protocol)
            return ConnectionAllowed(f"Allowed: Connection {conn_type} added to slot")

        # If slot is full, proceed to error handling.

        if slot.type in [types['incoming'], types['bootstrap']]:
            return ConnectionRejected(f'Slot {slot.type} is full.')
    

        if slot.type == types['check_ep']:
            if len(queue) >= self.queue_max_size:
                protocol.disconnect(force=True, reason="p2p_queue is full")
                return ConnectionRejected('Queue is full')

            entrypoint = protocol.entrypoint
            queue.appendleft(entrypoint)
            protocol.disconnect(force=True, reason="Slot full, entrypoint added to the p2p_queue.")
            return ConnectionRejected("Slot full, entrypoint added to p2p_queue.")
        
        # We handled the case of slot full in match, we must assure type is not outgoing in the end.
        assert slot.type != types['outgoing']

    def remove_from_slot(self, protocol: HathorProtocol) -> None:
        """ Removes protocol from slot of same type.
            If OUTGOING, INCOMING or BOOTSTRAP, simply remove from slot and disconnect.
            If CHECK_ENTRYPOINTS, entrypoint queue must also be managed."""

        conn_type = protocol.connection_type
        assert conn_type in self.types_allowed

        slot: ConnectionSlots | None = None
        match conn_type:
            case HathorProtocol.ConnectionType.OUTGOING:
                slot = self.outgoing_slot
            case HathorProtocol.ConnectionType.INCOMING:
                slot = self.incoming_slot
            case HathorProtocol.ConnectionType.BOOTSTRAP:
                slot = self.bootstrap_slot
            case HathorProtocol.ConnectionType.CHECK_ENTRYPOINTS:
                slot = self.check_ep_slot
            case _:
                assert_never()

        if protocol not in slot.connection_slot:
            return ConnectionRejected("Protocol not in slot - can't be removed.")

        slot.remove_connection(protocol)
        
        types = self.types_allowed
        if slot.type == types['check_ep']:
            # Remove connection from CHECK_EP
            # If READY, we fetch the entrypoints and put them into the queue.
            # Regardless, we'll need to 
            if protocol.connection_state != HathorProtocol.ConnectionState.READY:
                return ConnectionRemoved('Protocol state NOT READY.')

            # If ready, protocol entrypoint mustn't be None
            assert protocol.entrypoint != None, ConnectionRejected('Entrypoint should not be None')

            verified_entrypoints = self.verified_entrypoints
            verified_entrypoints.add(PeerEndpoint(protocol.entrypoint))

            peer_entrypoints = protocol.peer.info.entrypoints
            queue = self.queue_entrypoints

            for entrypoint in peer_entrypoints:
                entrypoint = PeerEndpoint(entrypoint, peer_id=None)
                if entrypoint in verified_entrypoints:
                    continue
                # Change from previous implementation: ALWAYS put the endpoint on the queue.
                # even if slot not full. 

                if self.is_queue_full():
                    return ConnectionRemoved('Entrypoint queue is full.')

                queue.appendleft(entrypoint)


            return ConnectionRemoved(f'Protocol {slot.type} removed from slot.')
            # If not, we simply discard it. 

    def is_queue_full(self) -> bool:
        return len(self.queue_entrypoints) >= self.queue_max_size

"Still needs:"
"1. Connect to entrypoints in queue"
"2. When connection arrives, it outgoing is not full, it will become an outgoing connection."
"3. Check perfectly the dequeuing mechanism."