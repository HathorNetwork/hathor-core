#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from dataclasses import dataclass

from hathor.p2p.peer_endpoint import PeerAddress
from hathor.p2p.peer_id import PeerId
from hathor.p2p.protocol import HathorProtocol


@dataclass(slots=True, frozen=True, kw_only=True)
class PeerCounts:
    """Simple wrapper for metrics."""
    connecting: int
    handshaking: int
    ready: int


class PeerConnections:
    """
    This class represents all peer connections made by a ConnectionsManager.
    It's also responsible for reacting for state changes on those connections.
    """

    __slots__ = ('_connecting_outbound', '_handshaking', '_ready', '_addr_by_id')

    def __init__(self) -> None:
        # Peers that are in the "connecting" state, between starting a connection and Twisted calling `connectionMade`.
        # This is only for outbound peers, that is, connections initiated by us.
        # They're uniquely identified by the address we're connecting to.
        self._connecting_outbound: set[PeerAddress] = set()

        # Peers that are handshaking, in a state after being connected and before reaching the READY state.
        # They're uniquely identified by the address we're connected to.
        self._handshaking: dict[PeerAddress, HathorProtocol] = {}

        # Peers that are in the READY state.
        # They're uniquely identified by the address we're connected to.
        # Note: there may be peers with duplicate PeerIds in this structure.
        self._ready: dict[PeerAddress, HathorProtocol] = {}

        # Auxiliary structure for uniquely identifying READY peers by their PeerId. When there are peers with
        # duplicate PeerIds, this identifies the connection we chose to keep.
        self._addr_by_id: dict[PeerId, PeerAddress] = {}

    def connecting_outbound_peers(self) -> set[PeerAddress]:
        """Get connecting outbound peers."""
        return self._connecting_outbound.copy()

    def handshaking_peers(self) -> dict[PeerAddress, HathorProtocol]:
        """Get handshaking peers."""
        return self._handshaking.copy()

    def ready_peers(self) -> dict[PeerAddress, HathorProtocol]:
        """Get ready peers, not including possible PeerId duplicates."""
        return {
            addr: self._ready[addr]
            for addr in self._addr_by_id.values()
        }

    def not_ready_peers(self) -> list[PeerAddress]:
        """Get not ready peers, that is, peers that are either connecting or handshaking."""
        return list(self._connecting_outbound) + list(self._handshaking)

    def connected_peers(self) -> dict[PeerAddress, HathorProtocol]:
        """
        Get peers that are connected, that is, peers that are either handshaking or ready.
        Does not include possible PeerId duplicates.
        """
        return self.handshaking_peers() | self.ready_peers()

    def all_peers(self) -> list[PeerAddress]:
        """Get all peers, ready or not. Does not include possible PeerId duplicates."""
        return self.not_ready_peers() + list(self.ready_peers())

    def get_ready_peer_by_id(self, peer_id: PeerId) -> HathorProtocol | None:
        """
        Get a ready peer by its PeerId. If there are connections with duplicate PeerIds,
        we return the one that we chose to keep.
        """
        addr = self._addr_by_id.get(peer_id)
        return self._ready[addr] if addr else None

    def get_peer_counts(self) -> PeerCounts:
        """Return the peer counts, for metrics."""
        return PeerCounts(
            connecting=len(self._connecting_outbound),
            handshaking=len(self._handshaking),
            ready=len(self._ready),
        )

    def is_peer_ready(self, peer_id: PeerId) -> bool:
        """Return whether a peer is ready, by its PeerId."""
        return peer_id in self._addr_by_id

    def on_connecting(self, *, addr: PeerAddress) -> bool:
        """
        Callback for when an outbound connection is initiated.
        Returns True if this address already exists, either connecting or connected, and False otherwise."""
        if addr in self.all_peers():
            return True

        self._connecting_outbound.add(addr)
        return False

    def on_failed_to_connect(self, *, addr: PeerAddress) -> None:
        """Callback for when an outbound connection fails before getting connected."""
        assert addr in self._connecting_outbound
        assert addr not in self.connected_peers()
        self._connecting_outbound.remove(addr)

    def on_connected(self, *, protocol: HathorProtocol) -> None:
        """Callback for when an outbound connection gets connected."""
        assert protocol.addr not in self.connected_peers()

        if protocol.inbound:
            assert protocol.addr not in self._connecting_outbound
        else:
            assert protocol.addr in self._connecting_outbound
            self._connecting_outbound.remove(protocol.addr)

        self._handshaking[protocol.addr] = protocol

    def on_handshake_disconnect(self, *, addr: PeerAddress) -> None:
        """
        Callback for when a connection is closed during a handshaking state, that is,
        after getting connected and before getting READY.
        """
        assert addr not in self._connecting_outbound
        assert addr in self._handshaking
        assert addr not in self._ready
        self._handshaking.pop(addr)

    def on_ready(self, *, addr: PeerAddress, peer_id: PeerId) -> HathorProtocol | None:
        """
        Callback for when a connection gets to the READY state.
        If the PeerId of this connection is duplicate, return the protocol that we should disconnect.
        Return None otherwise.
        """
        assert addr not in self._connecting_outbound
        assert addr in self._handshaking
        assert addr not in self._ready

        protocol = self._handshaking.pop(addr)
        self._ready[addr] = protocol  # We always index it by address, even if its PeerId is duplicate.

        connection_to_drop: HathorProtocol | None = None

        # If there's an existing connection with the same PeerId, this is a duplicate connection
        if old_connection := self.get_ready_peer_by_id(protocol.peer.id):
            # We choose to drop either the new or the old connection.
            if self._should_drop_new_connection(protocol):
                # We return early when we drop the new connection,
                # so we don't override the old connection in _addr_by_id with it below.
                return protocol

            # When dropping the old connection, we do override it in _addr_by_id below.
            connection_to_drop = old_connection

        self._addr_by_id[peer_id] = addr
        return connection_to_drop

    def on_ready_disconnect(self, *, addr: PeerAddress, peer_id: PeerId) -> None:
        """Callback for when a connection is closed during the READY state."""
        assert addr not in self._connecting_outbound
        assert addr not in self._handshaking
        assert addr in self._ready
        self._ready.pop(addr)

        if self._addr_by_id[peer_id] == addr:
            self._addr_by_id.pop(peer_id)

    def on_unknown_disconnect(self, *, addr: PeerAddress) -> None:
        """Callback for when a connection is closed during an unknown state."""
        assert addr not in self._handshaking
        assert addr not in self._ready
        if addr in self._connecting_outbound:
            self._connecting_outbound.remove(addr)

    @staticmethod
    def _should_drop_new_connection(new_conn: HathorProtocol) -> bool:
        """
        When there are connections with duplicate PeerIds, determine which one should be dropped, the old or the new.
        Return True if we should drop the new connection, and False otherwise.

        The logic to determine this is `(my_peer_id > other_peer_id) XNOR new_conn.inbound`.
        """
        my_peer_is_larger = bytes(new_conn.my_peer.id) > bytes(new_conn.peer.id)
        return my_peer_is_larger == new_conn.inbound
