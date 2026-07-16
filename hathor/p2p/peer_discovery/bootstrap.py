# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import Callable

from structlog import get_logger
from typing_extensions import override

from hathor.p2p.peer_endpoint import PeerEndpoint

from .peer_discovery import PeerDiscovery

logger = get_logger()


class BootstrapPeerDiscovery(PeerDiscovery):
    """ It implements a bootstrap peer discovery, which receives a static list of peers.
    """

    def __init__(self, entrypoints: list[PeerEndpoint]):
        """
        :param entrypoints: Addresses of peers to connect to.
        """
        super().__init__()
        self.log = logger.new()
        self.entrypoints = entrypoints

    @override
    async def discover_and_connect(self, connect_to_endpoint: Callable[[PeerEndpoint], None]) -> None:
        for entrypoint in self.entrypoints:
            connect_to_endpoint(entrypoint)
