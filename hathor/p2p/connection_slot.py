# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass

from typing_extensions import assert_never

from hathor.p2p.connect_classes import (
    ConnectionAllowed,
    ConnectionNotRemoved,
    ConnectionRejected,
    ConnectionRemoved,
    ConnectionType,
)
from hathor.p2p.protocol import HathorProtocol

AddToSlotResult = ConnectionAllowed | ConnectionRejected
RemoveFromSlotResult = ConnectionRemoved | ConnectionNotRemoved


class ConnectionSlots:
    """ Class of a connection pool slot - outgoing, incoming, bootstrap connections. """
    connection_slot: set[HathorProtocol]
    max_slot_connections: int

    def __init__(self, type: ConnectionType, max_connections: int) -> None:

        assert max_connections > 0, 'Slot max number must allow at least one connection'

        self.connection_slot = set()
        self.max_slot_connections = max_connections

    def __contains__(self, protocol: HathorProtocol) -> bool:
        return protocol in self.connection_slot

    def add_connection(self, protocol: HathorProtocol) -> AddToSlotResult:
        """ Adds connection protocol to the slot. Checks whether the slot is full or not. If full,
            disconnects the protocol. If the type is 'check_entrypoints', the returns peers of it
            may go to a queue."""

        if protocol in self.connection_slot:
            return ConnectionRejected("Protocol already in Slot.")

        if self.is_full():
            return ConnectionRejected(f"Slot {protocol.connection_type} is full")

        self.connection_slot.add(protocol)

        return ConnectionAllowed(f"Added to slot {protocol.connection_type}.")

    def remove_connection(self, protocol: HathorProtocol) -> ConnectionRemoved:
        """ Removes from given instance the protocol passed. Returns protocol from queue
            when disconnection leads to free space in slot."""

        # Discard does nothing if protocol not in connection_slot.
        self.connection_slot.discard(protocol)
        return ConnectionRemoved('Connection successfully removed from slot.')

    def is_full(self) -> bool:
        """ Checks if connection slot has reached the limit of allowed connections."""
        return len(self.connection_slot) >= self.max_slot_connections


@dataclass(frozen=True, slots=True, kw_only=True)
class SlotsManagerSettings:
    max_outgoing: int
    max_incoming: int
    max_bootstrap: int


class SlotsManager:
    """Manager of slot connections - selects the slot to which must we send the
     arriving protocol. Three protocol slots: OUTGOING, INCOMING, BOOTSTRAP.
    """
    outgoing_slot: ConnectionSlots
    incoming_slot: ConnectionSlots
    bootstrap_slot: ConnectionSlots

    def __init__(self, settings: SlotsManagerSettings) -> None:
        self.outgoing_slot = ConnectionSlots(ConnectionType.OUTGOING, settings.max_outgoing)
        self.incoming_slot = ConnectionSlots(ConnectionType.INCOMING, settings.max_incoming)
        self.bootstrap_slot = ConnectionSlots(ConnectionType.BOOTSTRAP, settings.max_bootstrap)

    def add_to_slot(self, protocol: HathorProtocol) -> AddToSlotResult:
        """Add received protocol to one of the slots.
        If slot is full, protocol is not added. """

        conn_type = protocol.connection_type
        slot: ConnectionSlots
        match conn_type:
            case ConnectionType.OUTGOING:
                slot = self.outgoing_slot
            case ConnectionType.INCOMING:
                slot = self.incoming_slot
            case ConnectionType.BOOTSTRAP:
                slot = self.bootstrap_slot
            case _:
                assert_never(conn_type)

        status = slot.add_connection(protocol)

        return status

    def remove_from_slot(self, protocol: HathorProtocol) -> None:
        """ Removes protocol from slot of same type.
            If OUTGOING, INCOMING or BOOTSTRAP, simply remove from slot and disconnect.
            Should be called by manager when disconnecting a protocol.
            Wraps _remove_from_slot_result and reduces API exposure."""

        self._remove_from_slot_result(protocol)

    def _remove_from_slot_result(self, protocol: HathorProtocol) -> RemoveFromSlotResult:
        """ Removes protocol from slot of same type.
            If OUTGOING, INCOMING or BOOTSTRAP, simply remove from slot and disconnect.
            Returns type for result, used in tests."""

        conn_type = protocol.connection_type
        slot: ConnectionSlots
        match conn_type:
            case ConnectionType.OUTGOING:
                slot = self.outgoing_slot
            case ConnectionType.INCOMING:
                slot = self.incoming_slot
            case ConnectionType.BOOTSTRAP:
                slot = self.bootstrap_slot
            case _:
                assert_never(conn_type)

        return slot.remove_connection(protocol)
