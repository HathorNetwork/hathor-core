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

from typing_extensions import assert_never

from hathor.conf.settings import HathorSettings
from hathor.p2p.protocol import HathorProtocol, PeerEndpoint


@dataclass
class ConnectionAllowed:
    confirmation: str


@dataclass
class ConnectionRejected:
    reason: str


@dataclass
class ConnectionRemoved:
    reason: str
    entrypoint: PeerEndpoint | None


@dataclass
class ConnectionNotRemoved:
    reason: str


@dataclass
class LockSlot:
    """Struct for reserving a spot in the check_ep slot for a specific entrypoint.
    This is done so to avoid that a connection made with an entrypoint popped from the queue
    loses its spot in the slot to another arriving connection which cuts the line.

    We reserve on place on the slot spefically for this entrypoint.

    If, however, many attempts are made and the correct entrypoint connection has not
    arrived still, the reserve is unlocked by the increase in counter. """

    is_spot_reserved: bool
    key_entrypoint: PeerEndpoint | None
    attempts: int
    attemp_limit: int = 3


AddToSlotResult = ConnectionAllowed | ConnectionRejected
RemoveFromSlotResult = ConnectionRemoved | ConnectionNotRemoved


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

    def add_connection(self, protocol: HathorProtocol) -> AddToSlotResult:
        """ Adds connection protocol to the slot. Checks whether the slot is full or not. If full,
            disconnects the protocol. If the type is 'check_entrypoints', the returns peers of it
            may go to a queue."""

        assert self.type == protocol.connection_type

        if protocol in self.connection_slot:
            return ConnectionRejected("Protocol already in Slot.")

        if self.is_full():
            return ConnectionRejected(f"Slot {self.type} is full")

        self.connection_slot.add(protocol)

        return ConnectionAllowed(f"Added to slot {self.type}.")

    def remove_connection(self, protocol: HathorProtocol) -> RemoveFromSlotResult:
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
    max_check_ep: int


class SlotsManager:
    """Manager of slot connections - selects the slot to which must we send the
     arriving protocol. Three protocol slots: OUTGOING, INCOMING, DISCOVERED.
    """
    outgoing_slot: ConnectionSlots
    incoming_slot: ConnectionSlots
    bootstrap_slot: ConnectionSlots
    check_ep_slot: ConnectionSlots
    entrypoints_queue: deque[PeerEndpoint | None]
    seen_entrypoints: set[PeerEndpoint | None]
    untrustworthy_entrypoints: set[PeerEndpoint | None]
    spot_locked: LockSlot

    types_allowed: dict[str, HathorProtocol.ConnectionType] = {
        'outgoing': HathorProtocol.ConnectionType.OUTGOING,
        'incoming': HathorProtocol.ConnectionType.INCOMING,
        'bootstrap': HathorProtocol.ConnectionType.BOOTSTRAP,
        'check_ep': HathorProtocol.ConnectionType.CHECK_ENTRYPOINTS,
    }

    states_allowed: dict[str, HathorProtocol.ConnectionState] = {
        'created': HathorProtocol.ConnectionState.CREATED,
        'connecting': HathorProtocol.ConnectionState.CONNECTING,
        'ready': HathorProtocol.ConnectionState.READY,
    }

    def __init__(self, settings: SlotsManagerSettings) -> None:
        types = self.types_allowed
        self.outgoing_slot = ConnectionSlots(types['outgoing'], settings.max_outgoing)
        self.incoming_slot = ConnectionSlots(types['incoming'], settings.max_incoming)
        self.bootstrap_slot = ConnectionSlots(types['bootstrap'], settings.max_bootstrap)
        self.check_ep_slot = ConnectionSlots(types['check_ep'], settings.max_check_ep)
        self.entrypoints_queue = deque()
        self.seen_entrypoints = set()
        self.untrustworthy_entrypoints = set()
        self.spot_locked = LockSlot(is_spot_reserved=False, key_entrypoint=None, attempts=0)

    def add_to_slot(self, protocol: HathorProtocol) -> AddToSlotResult:
        """Add received protocol to one of the slots.
        If slot is full, protocol is not added. """

        conn_type = protocol.connection_type
        types = self.types_allowed

        assert conn_type in types

        slot: ConnectionSlots | None = None
        match conn_type:
            case HathorProtocol.ConnectionType.OUTGOING:
                slot = self.outgoing_slot
                if slot.is_full():
                    protocol.connection_type = types['check_ep']
                    return self.add_to_slot(protocol)
            case HathorProtocol.ConnectionType.INCOMING:
                slot = self.incoming_slot
            case HathorProtocol.ConnectionType.BOOTSTRAP:
                slot = self.bootstrap_slot
            case HathorProtocol.ConnectionType.CHECK_ENTRYPOINTS:
                slot = self.check_ep_slot
                locked = self.spot_locked.is_spot_reserved
                if locked:
                    self.spot_locked.attempts += 1
                    unlocked = self.unlock_the_spot(slot, protocol.entrypoint)
                    if not unlocked:
                        return ConnectionRejected('Check Entrypoints Slot is locked.')

            case _:
                assert_never()

        if self.should_queue_entrypoint(slot):
            self.put_on_queue(protocol)

        status = slot.add_connection(protocol)

        return status

    def remove_from_slot(self, protocol: HathorProtocol) -> RemoveFromSlotResult:
        """ Removes protocol from slot of same type.
            If OUTGOING, INCOMING or BOOTSTRAP, simply remove from slot and disconnect.
            Should be called by manager when disconnecting a protocol."""

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
            return ConnectionNotRemoved(reason='Protocol not in slot.')

        types = self.types_allowed
        if slot.type != types['check_ep']:
            slot.remove_connection(protocol)
            return ConnectionRemoved(reason=f'Connection on slot {slot.type} removed.', entrypoint=None)

        # From now on, we're dealing solely with the check_entrypoints slot.

        entrypoint = protocol.entrypoint
        connection_state = protocol.connection_state
        states = self.states_allowed

        # If disconnected due to a time-out, we don't trust the entrypoint.
        if connection_state != states['ready']:
            self.untrustworthy_entrypoints.add(entrypoint)

        # Check if the protocol has its entrypoint being one we already saw before.
        # If so, grab the entrypoints and queue them.

        if not self.has_been_seen(entrypoint) and connection_state == states['ready']:
            peer_entrypoints = protocol.peer.info.entrypoints

            for peer_entrypoint in peer_entrypoints:
                if not self.has_been_seen(peer_entrypoint):
                    self.put_on_queue(protocol)

        self.seen_entrypoints.add(entrypoint)
        slot.remove_connection(protocol)

        new_entrypoint = self.entrypoints_queue.pop()

        if self.should_lock_the_spot(slot, new_entrypoint):
            self.lock_the_spot(slot, new_entrypoint)

        return ConnectionRemoved(reason=f'Connection on slot {slot.type} removed', entrypoint=new_entrypoint)

    def should_queue_entrypoint(self, slot: ConnectionSlots) -> bool:
        """See if the protocol should have its entrypoint thrown into the queue."""
        types = self.types_allowed
        conn_type = slot.type
        locked = self.spot_locked.is_spot_reserved
        slot_closed = slot.is_full() or locked

        return slot_closed and conn_type == types['check_ep']

    def put_on_queue(self, protocol: HathorProtocol) -> None:
        """Put on queue the entrypoint of the protocol, for later connection attempt."""
        entrypoint = protocol.entrypoint
        queue = self.entrypoints_queue

        queue.appendleft(entrypoint)

    def has_been_seen(self, entrypoint: PeerEndpoint) -> bool:
        """If an entrypoint has been seen before, regardless of being considered trustworthy."""

        return entrypoint in self.seen_entrypoints

    def should_lock_the_spot(self, slot: ConnectionSlots, entrypoint: PeerEndpoint | None) -> bool:
        """ Reserve one spot in the slot for a pending connection.
            When pulling an entrypoint from the queue, we create a protocol
            with that entrypoint and connect to it. Eventually the protocol
            will attempt to connect, but if some other protocol takes its
            place, we'll not be able to check the entrypoint we dequeued.

            For this reason, we lock the spot when necessary. """

        types = self.types_allowed
        max_length = slot.max_slot_connections

        if slot.type != types['check_ep']:
            return False

        if len(slot.connection_slot) != max_length - 1:
            return False

        if entrypoint is None:
            return False

        return True

    def lock_the_spot(self, slot: ConnectionSlots, entrypoint: PeerEndpoint) -> None:
        """ Guarantee a reserved spot for a protocol in the check entrypoints slot.
        This is done so we can connect to the entrypoint we popped from the queue, as
        amidst the connection attempt one may try to connect as well. """
        if not self.should_lock_the_spot(slot):
            return

        assert entrypoint is not None

        self.spot_locked.is_spot_reserved = True
        self.spot_locked.key_entrypoint = entrypoint
        self.spot_locked.attempts = 0

    def unlock_the_spot(self, slot: ConnectionSlots, entrypoint: PeerEndpoint) -> bool:
        """ Called if the check_ep slot reserves a spot for an expected protocol, and we wish to attempt to unlock it.
        If the entrypoint provided matches the entrypoint we previously popped from the queue, we can unlock the slot.

        If, however, after some attempts, the counter reaches the limit, we can unlock it regardless."""
        assert slot.type == self.types_allowed['check_ep']
        assert entrypoint is not None

        lockspot = self.spot_locked
        counter = lockspot.attempts
        limit = lockspot.attemp_limit

        if lockspot.key_entrypoint != entrypoint and counter < limit:
            return False

        lockspot.is_spot_reserved = False
        lockspot.key_entrypoint = None
        lockspot.attempts = 0

        return True

    def slot_number(self, slot: ConnectionSlots) -> int:
        return len(slot.connection_slot)

    def slot_size(self, slot: ConnectionSlots) -> int:
        return slot.max_slot_connections


"Still needs:"
"1. Connect to entrypoints in queue"
"2. When connection arrives, it outgoing is not full, it will become an outgoing connection."
"3. Check perfectly the dequeuing mechanism."
