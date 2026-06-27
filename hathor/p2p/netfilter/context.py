# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from twisted.internet.interfaces import IAddress

    from hathor.p2p.manager import ConnectionsManager
    from hathor.p2p.protocol import HathorProtocol


class NetfilterContext:
    """Context sent to the targets when a match occurs."""
    def __init__(self, *, connections: Optional['ConnectionsManager'] = None, addr: Optional['IAddress'] = None,
                 protocol: Optional['HathorProtocol'] = None):
        """Initialize the context."""
        self.addr = addr
        self.protocol = protocol
        self.connections = connections
