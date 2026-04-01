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
from hathor.p2p.connect_classes import (
    ConnectionAllowed,
    ConnectionNotRemoved,
    ConnectionRejected,
    ConnectionRemoved,
    ConnectionState,
    ConnectionType,
)
from hathor.p2p.protocol import HathorProtocol, PeerEndpoint

AddToSlotResult = ConnectionAllowed | ConnectionRejected

TIME_PENALTY = 10*60  # 10 minutes penalty for blacklisted entrypoints.


class BlacklistedSet:
    """ Set of blacklisted entrypoints, with the timestamp of blacklisting.
        If a connection is opened with an entrypoint in blacklist, it is terminated.

        After TIME_INTERVAL seconds have passed since the blacklisting timestamp, a
        new connection can be opened with this entrypoint.

        entrypoint_set: set of peer entrypoints.
        time_map: Dictionary which maps the entrypoint to its blacklisting timestamp. """

    entrypoint_set: set[PeerEndpoint]
    time_map: dict[PeerEndpoint, int]

    def __init__(self) -> None:
        self.entrypoint_set = set()
        self.time_map = dict()

    def __contains__(self, entrypoint: PeerEndpoint) -> bool:
        return entrypoint in self.entrypoint_set

    def add_to_blacklist(self, protocol: HathorProtocol) -> None:
        entrypoint = protocol.entrypoint
        timestamp = protocol.reactor.seconds()

        assert timestamp > 0, ValueError
        assert entrypoint is not None, AssertionError

        # Add to sets
        self.entrypoint_set.add(entrypoint)
        self.time_map[entrypoint] = timestamp

    def remove_from_blacklist(self, entrypoint: PeerEndpoint) -> None:
        self.entrypoint_set.discard(entrypoint)
        self.time_map.pop(entrypoint, None)

    def may_unblacklist(self, protocol: HathorProtocol) -> bool:

        entrypoint = protocol.entrypoint
        timestamp = self.time_map.get(entrypoint)
        if not timestamp:
            return False

        current_time = protocol.reactor.seconds()
        dt = current_time - timestamp

        if dt > TIME_PENALTY:
            return True
        return False


class ConnectionSlots:
    """ Class of a connection pool slot - outgoing, incoming, discovered connections. """
    connection_slot: set[HathorProtocol]
    type: ConnectionType
    max_slot_connections: int

    def __init__(self, type: ConnectionType, max_connections: int):

        if max_connections <= 0:
            raise ValueError("Slot max number must allow at least one connection")

        self.type = type
        self.connection_slot = set()
        self.max_slot_connections = max_connections

    def __contains__(self, connection: HathorProtocol) -> None:
        return connection in self.connection_slot

    def add_connection(self, protocol: HathorProtocol) -> AddToSlotResult:
        """ Adds connection protocol to the slot. Checks whether the slot is full or not. If full,
            disconnects the protocol. If the type is 'check_entrypoints', the returns peers of it
            may go to a queue."""

        assert self.type == protocol.connection_type
        # PROB: CONN STILL OPEN
        if protocol in self.connection_slot:
            return ConnectionRejected("Protocol already in Slot.")

        if self.is_slot_full():
            return ConnectionRejected(f"Slot {self.type} is full")

        self.connection_slot.add(protocol)

        return ConnectionAllowed(f"Added to slot {self.type}.")

    def remove_connection(self, protocol: HathorProtocol) -> ConnectionRemoved | ConnectionNotRemoved:
        """ Removes from given instance the protocol passed. Returns protocol from queue
            when disconnection leads to free space in slot."""

        if not self.is_in_slot(protocol):
            return ConnectionNotRemoved('Connection not in slot for removal.')

        # Discard does nothing if protocol not in connection_slot.
        self.connection_slot.discard(protocol)
        return ConnectionRemoved('Connection successfully removed.', None)

    def is_slot_full(self) -> bool:
        return len(self.connection_slot) >= self.max_slot_connections

    def is_in_slot(self, protocol: HathorSettings) -> bool:
        return protocol in self


class CheckEntrypoints(ConnectionSlots):
    """ Checks the entrypoints of protocols and the ones provided by the peer.


     Outflown connections from the outgoing slot arrive to the CheckEntrypoints class.
     They are added to the connection_slot set.

     If the slot is full, the entrypoint is appended to the queue. If the queue is full,
     the entrypoint is discarded.

     Whenever a connection is removed, we pop an entrypoint from the queue and connect
     to it, in the rebound_slot.

     If they do, then the entrypoints provided by the peer are appended to the
     entrypoint queue, for later connection attempt.

     CONNECTION_SLOT: When a protocol comes to an OUTGOING slot, and it is full, we
            redirect it to the CONNECTION_SLOT of CheckEntrypoints class, adding it here.
            This is done for analysis, since the OUTGOING slot being full is anomalous.
            We use the slot to check the entrypoint of the protocol. If it passes the check
            (should NOT be blacklisted), we grab the other entrypoints provided by the peer,
            queue them, and we'll check them later one by one.

     UNTRUSTWORTHY_PEERS: If the connection is called to be removed, and it is NOT ready by a TIMEOUT,
            we consider it not to be trustworthy. If so, we add it to this set.

     DEQUEUED_ENTRYPOINTS: The set of entrypoints which have been taken out of the entrypoint queue.
            When a protocol is to be added to the slot, if its core entrypoint is in this set, thence
            it has been dequeued, hence needs to be analyzed in the rebound_slot.

     SEEN_ENTRYPOINTS: All protocols which have been removed (ready or not) are added to this set. If
            a protocol arrives to the add_slot method and its entrypoint has not been seen yet, when
            at removal (and if ready) we queue all the entrypoints provided by this protocol, as we
            are unaware of the other entrypoints of such peer.

     REBOUND_SLOT: The rebound_slot is a separate space, of size 1, meant to only analyze protocols
            instantiated from a previosly dequeued entrypoint. When the analysis is done (and we must remove it),
            we pull another entrypoint from the queue, wrap it into a protocol via connect_to_endpoint
            (in the p2p_manager) and later it will be added to the slot via SlotsManager.
            When it's over, we remove it, pull another entrypoint, and keep the chain flowing.

            At kickstart, when there is no protocol in rebound_slot to begin, we use the removal of a
            connection_slot to kickstart the process, calling to dequeue an entrypoint and wrapping it
            into a rebound protocol.

            When a protocol meant to arrive at rebound can't (if it is full), we put it back into the queue
            for a later attempt.

            We establish a one-by-one analysis chain.

            The rebound slot also analyzes entrypoints of connections which have tried to be checked earlier,
            yet the slot was full so the entrypoint has been queued, for a later attempt. In this case, regardless
            of having been seen or not, we do not fetch the other provided entrypoints by the peer into the queue.

     """

    entrypoint_queue: deque[PeerEndpoint]
    dequeued_entrypoints: set[PeerEndpoint]
    rebound_slot: HathorProtocol
    blacklisted_entrypoints: BlacklistedSet

    def __init__(self, slot_type: ConnectionType, max_connections: int, max_queue_size: int) -> None:

        assert slot_type == ConnectionType.CHECK_ENTRYPOINTS

        if max_queue_size <= 0:
            raise ValueError('Entrypoint queue has no valid size.')

        super().__init__(slot_type, max_connections)

        # Shared data structures with the Slots Manager.
        self.entrypoint_queue = deque()
        self.dequeued_entrypoints = set()
        self.seen_entrypoints = set()
        self.blacklisted_entrypoints = BlacklistedSet()

        # Slots parameters
        self.max_queue_size = max_queue_size
        self.rebound_slot = None

    def __contains__(self, protocol: HathorProtocol) -> bool:
        return protocol in self.connection_slot or protocol == self.rebound_slot

    def add_connection(self, protocol: HathorProtocol) -> AddToSlotResult:

        assert protocol.connection_type in [ConnectionType.CHECK_ENTRYPOINTS, ConnectionType.REBOUNDED]

        if protocol.connection_type == ConnectionType.REBOUNDED:
            assert self.has_been_dequeued(protocol.entrypoint), "Entrypoint should've been dequeued before."

            if not self.rebound_slot:
                self.rebound_slot = protocol
                return ConnectionAllowed('Connection added to rebound slot.')

            # If rebound_slot occupied, queue the entrypoint back and try later.
            self.put_on_queue(protocol.entrypoint)

            return ConnectionRejected('Rebound slot occupied. Trying later... ')

        # Now, connection is only check_entrypoints type, so can be added to connection_slot.
        connection_status = super().add_connection(protocol)

        if isinstance(connection_status, ConnectionRejected):

            if not self.is_slot_full():
                return connection_status

            self.put_on_queue(protocol.entrypoint)
            # PROB: CONN STILL OPEN
        return connection_status

    def remove_connection(self, protocol: HathorProtocol) -> ConnectionRemoved | ConnectionNotRemoved:
        """ Removes protocol from the class.

         The protocol can be either in the connection_slot or in the rebound_slot.

         If in rebound, pull entrypoint from the queue.

         If in slot, and there is no protocol in rebound, pull entrypoint from queue.
         If the connection removed in slot is ready and the entrypoint has not been seen,
         queue all provided entrypoints by the peer for later analysis. If it is not ready
         due to a timeout, we blacklist the entrypoint."""

        if not self.is_in_slot(protocol):
            return ConnectionNotRemoved('Connection not in slot for removal.')

        # Check if needs to blacklist protocol.
        self.should_blacklist(protocol)

        entrypoint = protocol.entrypoint
        ready = ConnectionState.READY
        connection_state = protocol.connection_state

        if not self.has_been_seen(entrypoint) and connection_state == ready:
            peer_entrypoints = protocol.peer.info.entrypoints

            for peer_entrypoint in peer_entrypoints:
                if not self.has_been_seen(peer_entrypoint):
                    self.put_on_queue(peer_entrypoint)

        if protocol in self.connection_slot:
            self.connection_slot.discard(protocol)
        elif protocol == self.rebound_slot:
            self.rebound_slot = None
        else:
            raise AttributeError

        new_entrypoint: PeerEndpoint | None = None
        if self.should_dequeue_entrypoint(protocol):
            new_entrypoint = self.pop_from_queue()

        # Removal message:
        msg = 'CheckEp connection removed from'
        msg += 'Rebound Slot' if protocol.connection_type == ConnectionType.REBOUNDED else 'Slot'

        return ConnectionRemoved(msg, new_entrypoint)

    def has_been_dequeued(self, entrypoint: PeerEndpoint) -> bool:
        return entrypoint in self.dequeued_entrypoints

    def has_been_seen(self, entrypoint: PeerEndpoint) -> bool:
        return entrypoint in self.seen_entrypoints

    def is_queue_full(self) -> bool:
        return len(self.entrypoint_queue) == self.max_queue_size

    def is_queue_empty(self) -> bool:
        return len(self.entrypoint_queue) == 0

    def put_on_queue(self, entrypoint: PeerEndpoint) -> bool:

        full = self.is_queue_full()
        if not full:
            self.entrypoint_queue.appendleft(entrypoint)
            self.seen_entrypoints.add(entrypoint)

        return full

    def pop_from_queue(self) -> PeerEndpoint | None:
        """Pops entrypoint from queue, if not empty. Adds entrypoint to the
        'dequeued entrypoints' set. """

        empty_queue = self.is_queue_empty()
        entrypoint_queue = self.entrypoint_queue
        dequeued_entrypoints = self.dequeued_entrypoints

        if not empty_queue:
            entrypoint = entrypoint_queue.pop()
            dequeued_entrypoints.add(entrypoint)
            return entrypoint
        return None

    def should_blacklist(self, protocol: HathorProtocol) -> None:
        """ Decides if peer is not trustworthy.

            Criteria: If time taken is timeout time and it is not ready.

            If blacklisted, we reject connection attempts"""

        if protocol.connection_state == ConnectionState.READY:
            return

        # Check if exceeded time matches time-out limit.
        dt = protocol.diff_timestamp
        dt_max = protocol.idle_timeout
        if dt < dt_max:
            # Does not exceed timeout, it was only disconnected, so valid protocol.
            return

        # If not ready and exceeded time-out, we consider it not trustworthy - blacklist.
        self.blacklist_entrypoint(protocol)

    def blacklist_entrypoint(self, protocol: HathorProtocol) -> None:
        self.blacklisted_entrypoints.add_to_blacklist(protocol)

    def should_dequeue_entrypoint(self, protocol: HathorProtocol) -> bool:
        """There are two scenarios where should dequeue:
        1. We are disconnecting a protocol in the rebound slot, and it will pull an entrypoint
        from the queue by doing so (usual situation: one removal pulls one entrypoint).

        This first scenario we call 'usual_flow'.

        2. We disconnect a protocol in the slot, but there is no other connection in the rebound slot.
        In this exception scenario, we also pull from the queue to engage into a new connection down the line.

        This second scenario is called 'kickstart', as it is meant to kickstart the usual_flow, as there is no
        protocol in the rebound slot still.

        This method should only be called when a protocol is disconnected.
        """
        kickstart = protocol in self.connection_slot and not self.rebound_slot
        usual_flow = protocol == self.rebound_slot

        return kickstart or usual_flow


# To-Do: kw_only and update all dataclasses.
@dataclass(slots=True, frozen=True)
class SlotsManagerSettings:
    max_outgoing: int
    max_incoming: int
    max_bootstrap: int
    max_check_ep: int
    max_queue_ep: int


class SlotsManager:
    """Manager of slot connections - selects the slot to which must we send the
     arriving protocol. Three protocol slots: OUTGOING, INCOMING, DISCOVERED.
    """
    outgoing_slot: ConnectionSlots
    incoming_slot: ConnectionSlots
    bootstrap_slot: ConnectionSlots
    check_ep_slot: CheckEntrypoints
    seen_entrypoints: set[PeerEndpoint]
    blacklisted_entrypoints: BlacklistedSet

    types_allowed: list[ConnectionType] = {
        ConnectionType.OUTGOING,
        ConnectionType.INCOMING,
        ConnectionType.BOOTSTRAP,
        ConnectionType.CHECK_ENTRYPOINTS,
        ConnectionType.REBOUNDED
    }

    states_allowed: list[ConnectionState] = {
        ConnectionState.CREATED,
        ConnectionState.CONNECTING,
        ConnectionState.READY,
    }

    def __init__(self, settings: SlotsManagerSettings) -> None:
        self.outgoing_slot = ConnectionSlots(ConnectionType.OUTGOING, settings.max_outgoing)
        self.incoming_slot = ConnectionSlots(ConnectionType.INCOMING, settings.max_incoming)
        self.bootstrap_slot = ConnectionSlots(ConnectionType.BOOTSTRAP, settings.max_bootstrap)

        # Setting up Check Entrypoints Slot Class
        type_check = ConnectionType.CHECK_ENTRYPOINTS
        max_check = settings.max_check_ep
        max_queue = settings.max_queue_ep

        self.check_ep_slot = CheckEntrypoints(type_check, max_check, max_queue)

        # Sharing access SlotsManager ~ CheckEntrypoints Class
        self.entrypoints_queue = self.check_ep_slot.entrypoint_queue
        self.dequeued_entrypoints = self.check_ep_slot.dequeued_entrypoints
        self.seen_entrypoints = self.check_ep_slot.seen_entrypoints
        self.blacklisted_entrypoints = self.check_ep_slot.blacklisted_entrypoints

    def add_to_slot(self, protocol: HathorProtocol) -> AddToSlotResult:
        """Add received protocol to one of the slots.

         If protocol is INCOMING or BOOTSTRAP, if slot full protocol is voided.
         If OUTGOING and slot full, type shifts to CHECK ENTRYPOINTS.
         If the entrypoint of the protocol is in 'dequeued_entrypoints' set,
         the protocol was constructed in a remove_connection execution. This
         protocol must go to the REBOUND slot, so the type shifts to REBOUNDED.
         It will go to the rebound slot, within the CHECK ENTRYPOINTS class.

         There must not have any CHECK ENTRYPOINTS or REBOUNDED protocol being directly added
         to the slot.
         """

        assert protocol.connection_type != ConnectionType.CHECK_ENTRYPOINTS
        assert protocol.connection_type != ConnectionType.REBOUNDED

        # If entrypoint in dequeued, it is a rebound connection.
        if protocol.entrypoint in self.dequeued_entrypoints:
            protocol.connection_type = ConnectionType.REBOUNDED

        conn_type = protocol.connection_type
        types = self.types_allowed

        assert conn_type in types

        slot: ConnectionSlots | CheckEntrypoints = None
        match conn_type:

            case ConnectionType.OUTGOING:
                slot = self.outgoing_slot

                if slot.is_slot_full():
                    protocol.connection_type = ConnectionType.CHECK_ENTRYPOINTS
                    slot = self.check_ep_slot

            case ConnectionType.INCOMING:
                slot = self.incoming_slot

            case ConnectionType.BOOTSTRAP:
                slot = self.bootstrap_slot

            case ConnectionType.REBOUNDED:
                slot = self.check_ep_slot

            case _:
                assert_never(conn_type)

        # If connection is rejected, p2p_manager needs to disconnect protocol.
        return slot.add_connection(protocol)

    def remove_from_slot(self, protocol: HathorProtocol) -> ConnectionRemoved | ConnectionNotRemoved:
        """ Removes protocol from slot of same type.
            If OUTGOING, INCOMING, BOOTSTRAP, its remove_connection method will simply discard
            the protocol from the set.

            If CHECK ENTRYPOINTS or REBOUNDED, it will call its remove_connection method, but it
            will also manage the flow of entrypoints - queueing, dequeueing, blacklisting -
            depending on the conditions of the received protocol.
            Both refer to the same slot object - check_ep_slot.

            This method should be called by p2p_manager when disconnecting a protocol."""

        conn_type = protocol.connection_type
        assert conn_type in self.types_allowed

        slot: ConnectionSlots | CheckEntrypoints | None = None
        match conn_type:
            case ConnectionType.OUTGOING:
                slot = self.outgoing_slot
            case ConnectionType.INCOMING:
                slot = self.incoming_slot
            case ConnectionType.BOOTSTRAP:
                slot = self.bootstrap_slot
            case ConnectionType.CHECK_ENTRYPOINTS:
                slot = self.check_ep_slot
            case ConnectionType.REBOUNDED:
                slot = self.check_ep_slot
            case _:
                assert_never(conn_type)

        assert slot.type in self.types_allowed
        assert protocol.connection_state in self.states_allowed

        return slot.remove_connection(protocol)

    def has_been_seen(self, entrypoint: PeerEndpoint) -> bool:
        """If an entrypoint has been seen before, regardless of being considered trustworthy."""
        return self.check_ep_slot.has_been_seen(entrypoint)

    def is_blacklisted(self, entrypoint: PeerEndpoint) -> bool:
        return entrypoint in self.blacklisted_entrypoints

    def may_unblacklist(self, protocol: HathorProtocol) -> bool:
        return self.blacklisted_entrypoints.may_unblacklist(protocol)

    def remove_from_blacklist(self, protocol: HathorProtocol) -> bool:
        return self.blacklisted_entrypoints.remove_from_blacklist(protocol.entrypoint)
