# Copyright 2026 Hathor Labs
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

"""
p2p implementation of `FinalityTransport`.

It sends finality messages over the existing peer connections. The "committee overlay" is, in v1,
simply the set of connected peers that advertise the finality capability — vote authenticity is
guaranteed by BLS verification against the committee (see `FinalityService`), not by peer identity, so
a non-validator peer can neither forge a vote nor reach a quorum. Certificates are broadcast to all
peers; the rest of the network learns certified transactions only through this path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterator

from structlog import get_logger

from hathor.p2p.messages import ProtocolMessages
from hathor.util import json_dumps

if TYPE_CHECKING:  # pragma: no cover
    from hathor.conf.settings import HathorSettings
    from hathor.p2p.manager import ConnectionsManager
    from hathor.p2p.protocol import HathorProtocol

logger = get_logger()


class P2PFinalityTransport:
    """Sends finality messages (submissions, votes, certificates) over the p2p network."""

    def __init__(self, *, connections: 'ConnectionsManager', settings: 'HathorSettings') -> None:
        self._log = logger.new()
        self._connections = connections
        self._capability = settings.CAPABILITY_FINALITY

    def _finality_peers(self, *, exclude: object | None = None) -> Iterator['HathorProtocol']:
        for conn in self._connections.iter_ready_connections():
            if conn is exclude:
                continue
            if self._capability in conn.capabilities:
                yield conn

    def _all_peers(self, *, exclude: object | None = None) -> Iterator['HathorProtocol']:
        for conn in self._connections.iter_ready_connections():
            if conn is exclude:
                continue
            yield conn

    @staticmethod
    def _send(conn: 'HathorProtocol', message: ProtocolMessages, payload: str) -> None:
        assert conn.state is not None
        conn.state.send_message(message, payload)

    def submit_to_validator(self, tx_bytes: bytes) -> None:
        # Send to a single validator. v1 picks the first available finality peer deterministically;
        # the validator gossip then fans the transaction out to the rest of the committee.
        for conn in self._finality_peers():
            self._send(conn, ProtocolMessages.SUBMIT_FINALITY_TX, tx_bytes.hex())
            return

    def flood_to_validators(self, tx_bytes: bytes, *, exclude: object | None = None) -> None:
        for conn in self._finality_peers(exclude=exclude):
            self._send(conn, ProtocolMessages.SUBMIT_FINALITY_TX, tx_bytes.hex())

    def flood_vote(self, vote_bytes: bytes, *, exclude: object | None = None) -> None:
        for conn in self._finality_peers(exclude=exclude):
            self._send(conn, ProtocolMessages.FINALITY_VOTE, vote_bytes.hex())

    def broadcast_certificate(self, tx_bytes: bytes, fc_bytes: bytes, *, exclude: object | None = None) -> None:
        payload = json_dumps({'tx': tx_bytes.hex(), 'fc': fc_bytes.hex()})
        for conn in self._all_peers(exclude=exclude):
            self._send(conn, ProtocolMessages.FINALITY_CERTIFICATE, payload)
