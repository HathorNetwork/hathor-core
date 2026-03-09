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
class ConnectionRejected:
    reason: str


@dataclass
class ConnectionRemoved:
    reason: str


ConnectionResult = ConnectionAllowed | ConnectionRejected | ConnectionRemoved

class ConnectionSlots:
    """ Class of a connection pool slot - outgoing, incoming, discovered connections. """
    connection_slot: set[HathorProtocol]
    type: HathorProtocol.ConnectionType
    max_slot_connections: int

    def __init__(self, type: HathorProtocol.ConnectionType, max_connections: int):

        if max_connections <= 0:
            raise ValueError("Slot max number must allow at least one connection")
        
        self.type = type
        self.connection_slot = set()
        self.max_slot_connections = max_connections

    def add_connection(self, protocol: HathorProtocol) -> ConnectionAllowed | ConnectionRejected:
        """
            Adds connection protocol to the slot. Checks whether the slot is full or not. If full,
            disconnects the protocol. If the type is 'check_entrypoints', the returns peers of it
            may go to a queue.

        """

        assert self.type == protocol.connection_type

        if protocol in self.connection_slot:
            return ConnectionRejected("Protocol already in Slot.")
        
        if self.is_full():
            return ConnectionRejected(f"Slot {self.type} is full")

        self.connection_slot.add(protocol)

        return ConnectionAllowed(f"Added to slot {self.type}.")

    def remove_connection(self, protocol: HathorProtocol) -> None:
        """ Removes from given instance the protocol passed. Returns protocol from queue
            when disconnection leads to free space in slot."""

        # Discard does nothing if protocol not in connection_slot.
        self.connection_slot.discard(protocol)

    def is_full(self) -> bool:
        return len(self.connection_slot) >= self.max_slot_connections

    def is_in_slot(self, protocol: HathorSettings) -> bool:
        return protocol in self.connection_slot

@dataclass
class SlotsManagerSettings:
    max_outgoing: int
    max_incoming: int
    max_bootstrap: int

class SlotsManager:
    """Manager of slot connections - selects the slot to which must we send the
     arriving protocol.
     
    Three protocol slots: OUTGOING, INCOMING, DISCOVERED.
    """
    outgoing_slot: ConnectionSlots
    incoming_slot: ConnectionSlots
    bootstrap_slot: ConnectionSlots

    types_allowed: dict[str ,HathorProtocol.ConnectionType] = {
        'outgoing': HathorProtocol.ConnectionType.OUTGOING,
        'incoming' : HathorProtocol.ConnectionType.INCOMING,
        'bootstrap': HathorProtocol.ConnectionType.BOOTSTRAP,
    }

    def __init__(self, settings: SlotsManagerSettings) -> None:
        types = self.types_allowed
        self.outgoing_slot = ConnectionSlots(types['outgoing'], settings.max_outgoing)
        self.incoming_slot = ConnectionSlots(types['incoming'], settings.max_incoming)
        self.bootstrap_slot = ConnectionSlots(types['bootstrap'], settings.max_bootstrap)

    def add_to_slot(self, protocol: HathorProtocol) -> ConnectionResult:
        """Add received protocol to one of the slots. 
        If slot is full, protocol is disconnected. """

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
            case _:
                assert_never()

        return slot.add_connection(protocol)
    
    def remove_from_slot(self, protocol: HathorProtocol) -> None:
        """ Removes protocol from slot of same type.
            If OUTGOING, INCOMING or BOOTSTRAP, simply remove from slot and disconnect."""

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
            case _:
                assert_never()

        if protocol not in slot.connection_slot:
            return ConnectionRejected("Protocol not in slot - can't be removed.")

        slot.remove_connection(protocol)

"Still needs:"
"1. Connect to entrypoints in queue"
"2. When connection arrives, it outgoing is not full, it will become an outgoing connection."
"3. Check perfectly the dequeuing mechanism."