# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from enum import Enum


class ConnectionType(Enum):
    """ Types of Connection as inputs for an instance of the Hathor Protocol. """
    OUTGOING = 0
    INCOMING = 1
    BOOTSTRAP = 2

    def is_outbound(self) -> bool:
        """ If value is 1, then the connection is inbound. If not, outbound."""
        return self in (ConnectionType.OUTGOING, ConnectionType.BOOTSTRAP)


@dataclass(slots=True, frozen=True)
class ConnectionAllowed:
    confirmation: str


@dataclass(slots=True, frozen=True)
class ConnectionRejected:
    reason: str


@dataclass(slots=True, frozen=True)
class ConnectionRemoved:
    reason: str


@dataclass(slots=True, frozen=True)
class ConnectionNotRemoved:
    reason: str
