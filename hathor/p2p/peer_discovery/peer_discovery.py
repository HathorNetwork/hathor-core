# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod
from typing import Callable

from hathor.p2p.peer_endpoint import PeerEndpoint


class PeerDiscovery(ABC):
    """ Base class to implement peer discovery strategies.
    """

    @abstractmethod
    async def discover_and_connect(self, connect_to_endpoint: Callable[[PeerEndpoint], None]) -> None:
        """ This method must discover the peers and call `connect_to_endpoint` for each of them.

        :param connect_to_endpoint: Function which will be called for each discovered peer.
        :type connect_to_endpoint: function
        """
        raise NotImplementedError
